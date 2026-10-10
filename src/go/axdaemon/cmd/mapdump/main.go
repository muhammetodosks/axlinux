// AXlinux teşhis aracı: iki map'in ham baytlarını karşılaştırır.
// Cilium/ebpf ile gerçek bpf syscall'ını kullanır; bpftool'un
// 276 baytlık hex değerleri çözme sınırına takılmaz.
//
// Kullanım: mapdump <mapA> <mapB>   (pinned yol veya "id N")
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
)

func load(ref string) *ebpf.Map {
	m, err := ebpf.LoadPinnedMap(ref, nil)
	if err != nil {
		fmt.Printf("HATA %s: %v\n", ref, err)
		os.Exit(1)
	}
	return m
}

// rawKeys, verilen map'in tüm anahtarlarını ikili biçimde döndürür.
func rawKeys(m *ebpf.Map) [][]byte {
	var out [][]byte
	k := make([]byte, m.KeySize())
	v := make([]byte, m.ValueSize())
	iter := m.Iterate()
	for iter.Next(k, v) {
		key := make([]byte, m.KeySize())
		copy(key, k)
		out = append(out, key)
	}
	if err := iter.Err(); err != nil {
		fmt.Println("iter hatası:", err)
	}
	return out
}

func hex(b []byte) string {
	out := make([]byte, 0, len(b)*2)
	const hexd = "0123456789abcdef"
	for _, c := range b {
		out = append(out, hexd[c>>4], hexd[c&0xf])
	}
	return string(out)
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("kullanım: mapdump <mapA> <mapB>")
		os.Exit(1)
	}
	a, b := load(os.Args[1]), load(os.Args[2])

	fmt.Printf("A: %s  keySize=%d valueSize=%d  girdi=%d\n",
		os.Args[1], a.KeySize(), a.ValueSize(), len(rawKeys(a)))
	fmt.Printf("B: %s  keySize=%d valueSize=%d  girdi=%d\n",
		os.Args[2], b.KeySize(), b.ValueSize(), len(rawKeys(b)))

	ka, kb := rawKeys(a), rawKeys(b)
	if len(ka) == 0 {
		fmt.Println("A harici (deny_map bos olmali)")
		return
	}
	if len(kb) == 0 {
		fmt.Println("B harici (stat_lastkey bos -> cat hic tetiklenmedi)")
		return
	}

	fmt.Println("\n--- A anahtari (hex) ---")
	fmt.Println(hex(ka[0]))
	fmt.Println("--- B anahtari (hex) ---")
	fmt.Println(hex(kb[0]))

	if len(ka[0]) != len(kb[0]) {
		fmt.Println("\nSONUC: anahtar boyutlari FARKLI")
		return
	}
	if bytes.Equal(ka[0], kb[0]) {
		fmt.Println("\nSONUC: anahtarlar BIREBIR AYNI")
		return
	}
	fmt.Println("\nSONUC: anahtarlar FARKLI")
	for i := range ka[0] {
		if ka[0][i] != kb[0][i] {
			fmt.Printf("  ilk fark offset %d: A=0x%02x B=0x%02x\n",
				i, ka[0][i], kb[0][i])
			for _, off := range []int{0, 16, 272} {
				end := off + 16
				if end > len(ka[0]) {
					end = len(ka[0])
				}
				fmt.Printf("    [%3d] A=%q B=%q\n", off,
					string(trim(ka[0][off:end])), string(trim(kb[0][off:end])))
			}
			fmt.Printf("    action A=%d B=%d\n",
				binary.LittleEndian.Uint32(ka[0][272:276]),
				binary.LittleEndian.Uint32(kb[0][272:276]))
			break
		}
	}
}

func trim(b []byte) []byte {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
}
