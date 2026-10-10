// AXlinux teşhis: deny_map anahtarı ile çekirdeğin ürettiği key'i
// ham bayt düzeyinde karşılaştırır.
//
// A = deny_map'in KEY'i    (Go'nun yazdığı 276 bayt)
// B = stat_lastkey'in VALUE'u (çekirdeğin ürettiği 276 bayt)
//
// Kullanım: mapcmp <deny_map_pin> <stat_lastkey_pin>
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
)

func must(err error) {
	if err != nil {
		fmt.Println("HATA:", err)
		os.Exit(1)
	}
}

func hex(b []byte) string {
	out := make([]byte, 0, len(b)*2)
	const d = "0123456789abcdef"
	for _, c := range b {
		out = append(out, d[c>>4], d[c&0xf])
	}
	return string(out)
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("kullanım: mapcmp <deny_map> <stat_lastkey>")
		os.Exit(1)
	}
	deny, err := ebpf.LoadPinnedMap(os.Args[1], nil)
	must(err)
	last, err := ebpf.LoadPinnedMap(os.Args[2], nil)
	must(err)

	fmt.Printf("deny_map     keySize=%d valueSize=%d\n", deny.KeySize(), deny.ValueSize())
	fmt.Printf("stat_lastkey keySize=%d valueSize=%d\n", last.KeySize(), last.ValueSize())

	// A: deny_map'ten ilk key
	var ka []byte
	{
		k := make([]byte, deny.KeySize())
		v := make([]byte, deny.ValueSize())
		it := deny.Iterate()
		if it.Next(k, v) {
			ka = append([]byte{}, k...)
		} else {
			must(it.Err())
			fmt.Println("deny_map BOS")
			os.Exit(1)
		}
	}

	// B: stat_lastkey'in value'su (çekirdeğin kurduğu key)
	var kb []byte
	{
		k := make([]byte, last.KeySize())
		v := make([]byte, last.ValueSize())
		it := last.Iterate()
		if it.Next(k, v) {
			kb = append([]byte{}, v...)
		} else {
			must(it.Err())
			fmt.Println("stat_lastkey BOS (kanca hic tetiklenmedi)")
			os.Exit(1)
		}
	}

	fmt.Printf("\nA (deny_map key)     %d bayt\n", len(ka))
	fmt.Printf("B (cekirdek key)     %d bayt\n", len(kb))

	// Alan bazlı karşılaştırma
	fmt.Printf("\n  alan        A                          B\n")
	fmt.Printf("  comm   [%2d] %-26q %q\n", 0, cstr(ka[0:16]), cstr(kb[0:16]))
	fmt.Printf("  path   [%2d] %-26q %q\n", 16, cstr(ka[16:272]), cstr(kb[16:272]))
	fmt.Printf("  action[%3d] %-26d %d\n", 272,
		binary.LittleEndian.Uint32(ka[272:276]),
		binary.LittleEndian.Uint32(kb[272:276]))

	if bytes.Equal(ka, kb) {
		fmt.Println("\nSONUC: anahtarlar BIREBIR AYNI -> sorun map yaziminda degil")
		return
	}
	fmt.Println("\nSONUC: anahtarlar FARKLI")
	for i := range ka {
		if i >= len(kb) || ka[i] != kb[i] {
			fmt.Printf("  ilk fark offset %d: A=0x%02x", i, ka[i])
			if i < len(kb) {
				fmt.Printf(" B=0x%02x", kb[i])
			}
			fmt.Println()
			break
		}
	}
	fmt.Println("\nA hex:", hex(ka))
	fmt.Println("B hex:", hex(kb))
}
