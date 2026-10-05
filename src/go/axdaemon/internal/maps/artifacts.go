package maps

import (
	"bufio"
	"fmt"
	"path/filepath"
	"strings"
)

// mountArtifact returns the mount roots that do NOT appear in any
// visible absolute path.
//
// /proc/self/mountinfo fields used here:
//
//	(4) root       - mount root inside its filesystem
//	(5) mountpoint - where it is attached in this namespace
//
// A mount root is an artifact (invisible) exactly when the mount is
// attached at the NAMESPACE ROOT ("/") and its own root inside the
// filesystem has a different, non-trivial name:
//
//	mountpoint=/  root=/root  -> hide "root"
//	mountpoint=/  root=/      -> nothing to hide
//	mountpoint=/var  root=/var   -> keep "var" (it IS the path)
//	mountpoint=/tmp  root=/       -> keep nothing
//
// The mountpoint=="/" condition is REQUIRED, not cosmetic. Without
// it every mount whose root basename differs from its mountpoint
// becomes an artifact, and systemd's per-service private mounts
// (PrivateTmp, ProtectSystem) inject names such as "tmp", "dir" and
// "axlinux" into the map. Those names then get dropped from EVERY
// path, so a rule for /tmp/secret silently stops matching.
//
// Only the namespace root can have an invisible root: every other
// mount is reached THROUGH its mountpoint, so its root's name is by
// definition part of the visible path.
//
// The kernel cannot decide this on its own: struct vfsmount in the
// generated BTF carries neither mnt_parent nor mnt_mountpoint, and
// the dentry view is identical for "root" (invisible) and "var"
// (visible).
func mountArtifact() ([]string, error) {
	f, err := openMountInfo()
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := map[string]bool{}
	var out []string

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		// Fields are escaped for spaces (\040) and tabs (\011).
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		root := fields[3]
		mountpoint := fields[4]

		// Yalnizca ad alani (namespace) kokune bagli mount'lar
		// goz ardi edilir. Baska tum mount'lar mount noktalari
		// UZERINDEN erisilir, dolayisiyla kok adlari gorunur
		// yolun parcasidir.
		if mountpoint != "/" {
			continue
		}
		if root == "/" || root == mountpoint {
			continue
		}
		name := filepath.Base(strings.ReplaceAll(root, `\040`, " "))
		name = strings.TrimSpace(name)
		if name == "" || name == "." || name == "/" {
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("mountinfo okunamadi: %w", err)
	}
	return out, nil
}

// PopulateMountArtifacts fills mount_artifact_map from mountinfo.
//
// Without this, every path rule under the root filesystem silently
// fails on Fedora: the BPF program sees "/root/etc/secret" where the
// policy wrote "/etc/secret".
//
// Failure here is logged by the caller and is NOT fatal: the map is
// then empty, which degrades to the previous (wrong on btrfs) path
// behaviour rather than breaking enforcement entirely.
func (m *Manager) PopulateMountArtifacts() ([]string, error) {
	if m == nil || m.artifactM == nil {
		return nil, fmt.Errorf("%s haritasi yuklu degil", MountArtifactMapName)
	}

	names, err := mountArtifact()
	if err != nil {
		return nil, err
	}

	for _, n := range names {
		key := make([]byte, PathSlot)
		copy(key, n)
		if err := m.artifactM.Put(key, []byte{1}); err != nil {
			return names, fmt.Errorf("koz '%s' yazilamadi: %w", n, err)
		}
	}
	return names, nil
}
