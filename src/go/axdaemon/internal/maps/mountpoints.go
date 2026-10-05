package maps

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Mount point prefix reconstruction for paths that cross a mount
// boundary whose mountpoint is not a directory entry.
//
// mountArtifact() (artifacts.go) handles the OPPOSITE problem: it
// removes a component that is visible in the dentry chain but not in
// the real path (the btrfs subvolume root "root"). This file handles
// a component that is in the real path but NOT in the dentry chain.
//
// /tmp on Fedora 44 is a tmpfs mount:
//
//	/proc/self/mountinfo: root=/ mountpoint=/tmp
//	/tmp/ax-pintest -> dentry chain: ax-pintest -> "/"
//
// "tmp" is not a directory entry; it is a mount attachment. The
// dentry walk therefore yields "/ax-pintest" and the "/tmp" prefix is
// lost. Measured on the VM:
//
//	cat /etc/ax-pintest2  -> Operation not permitted   (correct)
//	cat /tmp/ax-pintest   -> succeeds, leaks content   (bug)
//
// Rules mentioning /tmp silently never matched. This is the most
// dangerous class of bug in this project: "reload successful" plus
// no enforcement.
//
// The kernel cannot solve it. struct vfsmount in the generated BTF
// carries neither mnt_mountpoint nor mnt_parent, so the BPF program
// cannot find the mountpoint name. The daemon reads mountinfo and
// publishes a map that the BPF program consults when the dentry walk
// terminates at a mount root.

// MountPointMax mirrors AX_MP_MAX in src/bpf/axbpf.h. The two must
// agree: the value is the number of leading path components a
// mountpoint may have (/run/user/1000 is 3).
const MountPointMax = 4

// MountPointKey identifies the ROOT of a mount: the superblock
// device plus the root inode.
//
// Both parts are required. Every tmpfs root has inode 1:
//
//	/tmp         dev=39 ino=1
//	/dev/shm     dev=25 ino=1
//	/run         dev=27 ino=1
//
// Each tmpfs instance is a separate superblock, so st_dev differs
// and the pair is unique. Keying on the inode alone would map /tmp,
// /dev/shm and /run onto a single entry and the wrong prefix would be
// prepended to the others.
//
// Must stay byte-identical to struct ax_mp_key.
type MountPointKey struct {
	Dev uint64
}

// MountPointVal is the mountpoint path, pre-split into the same
// fixed-size blocks the policy key uses.
//
// Pre-splitting in userspace keeps the BPF side free of string
// scanning: it copies AX_PATH_SLOT bytes per block, exactly as it
// already does for dentry names.
//
// Must stay byte-identical to struct ax_mp_val.
type MountPointVal struct {
	Slot  [MountPointMax][PathSlot]byte
	N     uint32
	Bytes uint32
}

// mountPoint returns the mounts whose mountpoint prefix is invisible
// to a dentry walk.
//
// The discriminator is root == "/" combined with mountpoint != "/":
//
//	mountpoint=/tmp  root=/      -> register "/tmp"  (lost by dentries)
//	mountpoint=/var  root=/var   -> skip; "var" is a real directory entry
//	mountpoint=/     root=/root  -> not ours; handled by mountArtifact()
//
// A mount whose root inside the filesystem is not "/" reaches its
// mountpoint THROUGH that path, so the mountpoint name is a genuine
// component of the visible path and must not be added twice.
func mountPoint() ([]MountPointKey, []MountPointVal, []string, error) {
	f, err := openMountInfo()
	if err != nil {
		return nil, nil, nil, err
	}
	defer f.Close()

	type entry struct {
		key MountPointKey
		val MountPointVal
	}
	seenDev := map[MountPointKey]bool{}
	var entries []entry
	var names []string

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		root := fields[3]
		mountpoint := fields[4]

		if root != "/" || mountpoint == "/" {
			continue
		}

		// mountinfo escapes spaces (\040) and tabs (\011).
		mp := strings.ReplaceAll(mountpoint, `\040`, " ")
		mp = strings.ReplaceAll(mp, `\011`, "\t")

		// Superblock cihazi mountinfo'nun 3. alaninda
		// ("MAJ:MIN") zaten yazilidir. stat() kullanmamak
		// bir tercihtir ama zorunluluktur: daemon'in SELinux
		// alani bu dizinlerin cogunu stat'layamaz ve inode
		// mountinfo'da hic bulunmaz.
		//
		//   stat /sys/fs/cgroup: permission denied
		//   stat /run/user/1000: permission denied
		//
		// 12 mount noktasi EACCES aliyordu; /tmp ve /dev/shm
		// yalnizca o listede olmadigi icin calisiyordu.
		dev, ok := parseDev(fields[2])
		if !ok {
			continue
		}

		key := MountPointKey{Dev: dev}
		if seenDev[key] {
			continue
		}

		val, ok := buildMountPointVal(mp)
		if !ok {
			// Cok derin mount noktasi. Atlanir: yarim yazilmis
			// bir yol, hic yazilmamis yoldan daha kotudur.
			continue
		}

		seenDev[key] = true
		entries = append(entries, entry{key: key, val: val})
		names = append(names, mp)
	}
	if err := sc.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("mountinfo okunamadi: %w", err)
	}

	keys := make([]MountPointKey, 0, len(entries))
	vals := make([]MountPointVal, 0, len(entries))
	for _, e := range entries {
		keys = append(keys, e.key)
		vals = append(vals, e.val)
	}
	return keys, vals, names, nil
}

// buildMountPointVal splits "/dev/shm" into Slot[0]="/shm",
// Slot[1]="/dev", N=2.
//
// The order is REVERSED on purpose. The policy key layout puts the
// deepest path component in the highest slot, so a mountpoint is
// written from its end towards its start:
//
//	Path[7]="/ax-f"  Path[6]="/shm"  Path[5]="/dev"
//
// ax_fill_path() copies Slot[jj] into Path[7-ncomp-jj], so Slot must
// hold the components in reverse path order for the two sides to
// agree.
//
// Bytes is the sum of len(component)+1 per component, which is the
// same accounting ax_fill_path() uses for dentry names (the +1 is
// the '/' separator). It lets the BPF program reject an over-long
// path before writing anything.
func buildMountPointVal(mp string) (MountPointVal, bool) {
	var v MountPointVal

	var parts []string
	for _, p := range strings.Split(mp, "/") {
		if p == "" {
			continue
		}
		// PathSlot-1: one byte for the leading '/', one for NUL.
		if len(p) > PathSlot-2 {
			return v, false
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 || len(parts) > MountPointMax {
		return v, false
	}

	n := len(parts)
	for i, p := range parts {
		v.Slot[n-1-i][0] = '/'
		copy(v.Slot[n-1-i][1:], p)
		v.Bytes += uint32(len(p) + 1)
	}
	v.N = uint32(n)
	return v, true
}

// PopulateMountPoints fills mount_point_map from mountinfo.
//
// Without this, every rule under a separate mount (/tmp, /dev/shm,
// /run, /run/user/N) silently fails to match.
//
// Failure is logged by the caller and is NOT fatal: the map stays
// empty and behaviour degrades to the previous (wrong for mounted
// paths) reconstruction rather than breaking enforcement entirely.
func (m *Manager) PopulateMountPoints() ([]string, error) {
	if m == nil || m.mountPointM == nil {
		return nil, fmt.Errorf("%s haritasi yuklu degil", MountPointMapName)
	}

	keys, vals, names, err := mountPoint()
	if err != nil {
		return nil, err
	}

	for i := range keys {
		if err := m.mountPointM.Put(keys[i], vals[i]); err != nil {
			return names, fmt.Errorf("mount noktasi '%s' yazilamadi: %w",
				names[i], err)
		}
	}
	return names, nil
}

// openMountInfo opens the mount table that enforcement must describe.
//
// /proc/1/mountinfo is the init process's table, i.e. the namespace
// the daemon is asked to protect. /proc/self/mountinfo is the
// daemon's own view and may differ.
func openMountInfo() (*os.File, error) {
	const initMountInfo = "/proc/1/mountinfo"

	f, err := os.Open(initMountInfo)
	if err == nil {
		return f, nil
	}
	f2, err2 := os.Open("/proc/self/mountinfo")
	if err2 != nil {
		return nil, fmt.Errorf("mountinfo acilamadi (%s: %v; %s: %v)",
			initMountInfo, err, "/proc/self/mountinfo", err2)
	}
	return f2, nil
}

// parseDev converts mountinfo's "MAJ:MIN" field into the dev_t the
// kernel reports as i_sb->s_dev.
//
// makedev(MAJOR, MINOR) is the standard glibc encoding:
//
//	(minor & 0xff) | (major << 8) | ((major & ^0xff) << 12)
//
// Verified against stat(2) on Fedora 44: /tmp "0:39" -> 39,
// /dev/shm "0:25" -> 25, /boot/efi "253:2" -> 64770.
func parseDev(field string) (uint64, bool) {
	majStr, minStr, ok := strings.Cut(field, ":")
	if !ok {
		return 0, false
	}
	maj, err1 := strconv.ParseUint(majStr, 10, 32)
	min, err2 := strconv.ParseUint(minStr, 10, 32)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	return (min & 0xff) | (maj << 8) | ((maj &^ 0xff) << 12), true
}

// MountPointDev renders a key for diagnostics and tests.
func MountPointDev(k MountPointKey) string {
	return strconv.FormatUint(k.Dev, 10)
}

// MountPointString renders a value back to its mountpoint path, for
// diagnostics and tests.
//
// Note the order: slots hold components end-first, so joining them
// reproduces the reversed sequence rather than the original path.
// That is intentional and matches what ax_fill_path() writes.
func MountPointString(v MountPointVal) string {
	var sb strings.Builder
	for i := 0; i < int(v.N) && i < MountPointMax; i++ {
		sb.WriteString(strings.TrimRight(string(v.Slot[i][:]), "\x00"))
	}
	return sb.String()
}
