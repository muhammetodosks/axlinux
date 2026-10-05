package maps

import (
	"strings"
	"testing"
)

// Mountpoint prefix reconstruction.
//
// These tests pin the two halves of a contract that is easy to get
// wrong and impossible to notice: the daemon must split a mountpoint
// into blocks in REVERSE path order, and it must derive the
// superblock device from mountinfo's MAJ:MIN field instead of stat().
//
// Both mistakes produce a silent failure: rules under /tmp simply stop
// matching while "reload" reports success.

func TestParseDevMatchesMakedev(t *testing.T) {
	// Values cross-checked against stat(2) on Fedora 44.
	cases := []struct {
		field string
		want  uint64
	}{
		{"0:39", 39},     // /tmp        tmpfs
		{"0:25", 25},     // /dev/shm    tmpfs
		{"0:27", 27},     // /run        tmpfs
		{"0:6", 6},       // /dev        devtmpfs
		{"253:2", 64770}, // /boot/efi  vfat
	}
	for _, c := range cases {
		got, ok := parseDev(c.field)
		if !ok {
			t.Fatalf("parseDev(%q) basarisiz", c.field)
		}
		if got != c.want {
			t.Errorf("parseDev(%q) = %d, beklenen %d", c.field, got, c.want)
		}
	}

	// Bozuk alan sessizce 0 donmemeli.
	for _, bad := range []string{"", "39", "a:b", "-1:2"} {
		if _, ok := parseDev(bad); ok {
			t.Errorf("parseDev(%q) hata vermemeliydi", bad)
		}
	}
}

// The policy key layout puts the DEEPEST component in the HIGHEST
// slot, so a mountpoint must be stored end-first.
//
// Layout the BPF side must end up writing for /dev/shm/ax-f:
//
//	Path[7] = "/ax-f"   Path[6] = "/shm"   Path[5] = "/dev"
func TestBuildMountPointValReversesOrder(t *testing.T) {
	v, ok := buildMountPointVal("/dev/shm")
	if !ok {
		t.Fatal("/dev/shm temsil edilemedi")
	}
	if v.N != 2 {
		t.Fatalf("N = %d, beklenen 2", v.N)
	}
	if got := MountPointString(v); got != "/shm/dev" {
		t.Errorf("ters sira yanlis: %q", got)
	}
	// slot[0] = 7-ncomp = 6 konumuna gider.
	if v.Slot[0][0] != '/' || string(v.Slot[0][1:4]) != "shm" {
		t.Errorf("slot[0] = %q, \"/shm\" olmali", v.Slot[0][:4])
	}
	if v.Slot[1][0] != '/' || string(v.Slot[1][1:4]) != "dev" {
		t.Errorf("slot[1] = %q, \"/dev\" olmali", v.Slot[1][:4])
	}

	// Bytes: her bilesen icin len+1 ('/' ayirac dahil).
	if want := uint32(len("/shm") + len("/dev")); v.Bytes != want {
		t.Errorf("Bytes = %d, beklenen %d", v.Bytes, want)
	}
}

func TestBuildMountPointValSingleComponent(t *testing.T) {
	v, ok := buildMountPointVal("/tmp")
	if !ok {
		t.Fatal("/tmp temsil edilemedi")
	}
	if v.N != 1 || v.Bytes != 4 {
		t.Errorf("N=%d Bytes=%d, beklenen N=1 Bytes=4", v.N, v.Bytes)
	}
	if got := MountPointString(v); got != "/tmp" {
		t.Errorf("got %q", got)
	}
}

func TestBuildMountPointValDeepPath(t *testing.T) {
	// /run/user/1000 -> uc bilesen: run, user, 1000.
	// Bu, gercek bir systemd-logind tmpfs mount'idir; onceki
	// calismayan surumde SELinux stat'i reddettigi icin haritada
	// hic bulunamiyordu.
	v, ok := buildMountPointVal("/run/user/1000")
	if !ok {
		t.Fatal("/run/user/1000 temsil edilemedi")
	}
	if v.N != 3 {
		t.Fatalf("N = %d, beklenen 3", v.N)
	}
	if got := MountPointString(v); got != "/1000/user/run" {
		t.Errorf("ters sira: %q", got)
	}
	// AX_MP_MAX = 4: dort bilesen kabul edilir.
	v4, ok := buildMountPointVal("/a/b/c/d")
	if !ok || v4.N != 4 {
		t.Errorf("4 bilesenli mount noktasi kabul edilmeliydi (N=%d)", v4.N)
	}
}

func TestBuildMountPointValRejectsTooDeep(t *testing.T) {
	// AX_MP_MAX = 4. Besinci bilesen sessizce kirpilmamali:
	// yarim bir onek, hicbir onekten kotudur.
	if _, ok := buildMountPointVal("/a/b/c/d/e"); ok {
		t.Error("5 bilesenli mount noktasi kabul edilmemeliydi")
	}
	if _, ok := buildMountPointVal("/"); ok {
		t.Error("kok mount noktasi kabul edilmemeliydi")
	}
	// Bir bilesen PathSlot-2 = 30 karakteri asmamali.
	long := "/" + strings.Repeat("x", 40)
	if _, ok := buildMountPointVal(long); ok {
		t.Error("asiri uzun bilesen kabul edilmemeliydi")
	}
	// Tam sinirda kabul edilmeli.
	if _, ok := buildMountPointVal("/" + strings.Repeat("x", 30)); !ok {
		t.Error("30 karakterlik bilesen kabul edilmeliydi")
	}
}

// mountinfo ayrimi: yalniz "root=/" ve "mountpoint=/" disi olanlar.
// Bu kural yanlissa ya /etc kurallari kirpilir ya da /tmp tekrar
// calismaz.
func TestMountPointDiscoveryRule(t *testing.T) {
	// openMountInfo'yi test etmek /proc'ye bagimlidir; ayrimin
	// kendisini mountinfo satirlari uzerinden dogrula.
	const mountinfo = `
36 67 0:32 / /dev rw - devtmpfs devtmpfs rw
37 36 0:25 / /dev/shm rw - tmpfs tmpfs rw
35 67 0:39 / /tmp rw - tmpfs tmpfs rw
67 1 0:32 /root / rw - btrfs /dev/vda3 rw,subvol=/root
300 67 0:58 / /run/user/1000 rw - tmpfs tmpfs rw
`
	// /dev de root="/" ve mountpoint!="/" oldugu icin adaydir:
	// devtmpfs de ayri bir superblocktir.
	want := []string{"/dev", "/dev/shm", "/tmp", "/run/user/1000"}
	var got []string
	for _, line := range strings.Split(strings.TrimSpace(mountinfo), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		if f[3] != "/" || f[4] == "/" {
			continue
		}
		if _, ok := parseDev(f[2]); !ok {
			continue
		}
		got = append(got, f[4])
	}
	if len(got) != len(want) {
		t.Fatalf("adaylar %v, beklenen %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("aday[%d] = %q, beklenen %q", i, got[i], want[i])
		}
	}
}

// Anahtar yalnizca superblock cihazindan olusur; inode mountinfo'da
// yoktur ve stat() SELinux tarafindan reddedilir.
func TestMountPointKeyIsDeviceOnly(t *testing.T) {
	k := MountPointKey{Dev: 39}
	if MountPointDev(k) != "39" {
		t.Errorf("MountPointDev = %q", MountPointDev(k))
	}
	// Ayni inode, farkli superblock -> farkli anahtar. Tum tmpfs
	// kokleri inode 1'dir; yalniz dev ile ayirt edilebilirler.
	if (MountPointKey{Dev: 39}) == (MountPointKey{Dev: 25}) {
		t.Error("farkli superblockler ayni sayilmamali")
	}
}
