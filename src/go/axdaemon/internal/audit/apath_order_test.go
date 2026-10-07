package audit

import "testing"

// TestJoinAPathOrder kilitler: audit yolu dogru SIRADA olmali.
//
// ax_fill_audit_path bilesenleri dosya adindan baslayip yukari
// dogru yazar (apath[0] = en derin). Duz iterate edilirse yol
// TERS kurulur:
//
//	"/tmp/olcum/uzun.txt"  ->  "/uzun.txt/olcum/tmp"
//
// Bu hata uretimde goruldu: 49 karakterlik dosya adi icin kayit
// "/aaaa...txt/olcum/tmp" yaziyordu. Operator hangi dizin oldugunu
// goremiyor.
func TestJoinAPathOrder(t *testing.T) {
	cases := []struct {
		name string
		set  func(e *Event)
		want string
	}{
		{
			name: "iki bilesen",
			set: func(e *Event) {
				e.APath[0] = [AuditSlot]byte{'/', 'b', '.', 't', 'x', 't'}
				e.APath[1] = [AuditSlot]byte{'/', 'd', 'i', 'r'}
				e.APCount = 2
			},
			want: "/dir/b.txt",
		},
		{
			name: "tek bilesen",
			set: func(e *Event) {
				e.APath[0] = [AuditSlot]byte{'/', 'o', 'n', 'l', 'y'}
				e.APCount = 1
			},
			want: "/only",
		},
		{
			name: "uc bilesen, aradaki bos",
			set: func(e *Event) {
				e.APath[0] = [AuditSlot]byte{'/', 'c'}
				e.APath[1] = [AuditSlot]byte{}
				e.APath[2] = [AuditSlot]byte{'/', 'a'}
				e.APCount = 3
			},
			want: "/a/c",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var e Event
			c.set(&e)
			got, _ := e.JoinAPath()
			if got != c.want {
				t.Errorf("JoinAPath() = %q, beklenen %q", got, c.want)
			}
		})
	}
}

// TestJoinAPathTruncated isaretin gecmesini dogrular.
func TestJoinAPathTruncated(t *testing.T) {
	e := Event{}
	e.APath[0] = [AuditSlot]byte{'/', 'x'}
	e.APCount = 1
	if _, tr := e.JoinAPath(); tr {
		t.Error("kirpma yokken Truncated=true dondu")
	}
	e.APFlags = PathFlagTruncated
	if _, tr := e.JoinAPath(); !tr {
		t.Error("kirpma varken Truncated=false dondu")
	}
}
