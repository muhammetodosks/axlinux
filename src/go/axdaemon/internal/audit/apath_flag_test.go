package audit

import (
	"encoding/binary"
	"testing"
)

// TestParseEventReadsAPathFlags, parseEvent'in kirpma bayragini
// DOGRU OLAYDAN okudugunu dogrular.
//
// Go decoder elle yazilmis bir offset listesiyle yuruyor. BPF
// tarafi bayragi 1340'a yaziyor; burada ayni baytlar uretilip
// cozucu geciriliyor. Kirmizi test: cozucu bayragi yanlis
// offsetten okursa kirpma hicbir zaman bildirilmez ve operator
// eksik yola "tam" sanir.
func TestParseEventReadsAPathFlags(t *testing.T) {
	for _, flags := range []uint32{0, PathFlagTruncated} {
		buf := make([]byte, EventSize)
		off := 8 + 4 + 16 + 8*PathSlot + 5*4 // ts,pid,comm,path,5x u32
		off += 8 + 4                         // ino, dev
		off += AuditDepth * AuditSlot        // apath
		binary.LittleEndian.PutUint32(buf[off:], flags)

		e, err := parseEvent(buf)
		if err != nil {
			t.Fatalf("flags=%d: parseEvent hatasi: %v", flags, err)
		}
		if e.APFlags != flags {
			t.Errorf("APFlags = %d, beklenen %d (offset %d yanlis)",
				e.APFlags, flags, off)
		}
		_, trunc := e.JoinAPath()
		if trunc != (flags != 0) {
			t.Errorf("flags=%d: JoinAPath truncated=%v", flags, trunc)
		}
	}
}
