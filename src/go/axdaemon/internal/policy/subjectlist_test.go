package policy

import (
	"encoding/json"
	"testing"
)

// TestSubjectListAcceptsScalarAndList, Go ayristiricinin
// Python ayristiriciyla AYNI girdi kumesini kabul etmesini garanti
// eder.
//
// GERCEK HATA: `axctl policy check` politika gecerli diyordu,
// ama acilista daemon ayni politikayi REDDEDIYORDU:
//
//	subject: curl
//	-> json: cannot unmarshal string into Go struct field
//	   Rule.rules.subject of type []string
//	-> "sistem politikasi yuklenemedi; sistem KISITLAMASIZ kaliyor"
//
// Iki bagimsiz ayristirici (Python dogrulayici, Go uygulayici)
// farkli kabul kumesi tasiyordu. Operator'a "gecerli" denilen
// politika uygulanmiyordu. MAC'te en kotu hata modu.
func TestSubjectListAcceptsScalarAndList(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want []string
	}{
		{
			name: "tekil (deep_verify'in kullandigi bicim)",
			doc:  `{"id":"f","subject":"curl","object":"/etc/ax-secret","action":"file.read","effect":"deny"}`,
			want: []string{"curl"},
		},
		{
			name: "liste",
			doc:  `{"id":"f","subject":["curl","wget"],"object":"/etc/ax-secret","action":"file.read","effect":"deny"}`,
			want: []string{"curl", "wget"},
		},
		{
			name: "tek elemanli liste",
			doc:  `{"id":"f","subject":["curl"],"object":"/tmp/x","action":"file.read","effect":"deny"}`,
			want: []string{"curl"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var r Rule
			if err := json.Unmarshal([]byte(c.doc), &r); err != nil {
				t.Fatalf("ayristirma basarisiz: %v", err)
			}
			if len(r.Subject) != len(c.want) {
				t.Fatalf("subject = %v, beklenen %v", r.Subject, c.want)
			}
			for i := range c.want {
				if r.Subject[i] != c.want[i] {
					t.Errorf("subject[%d] = %q, beklenen %q",
						i, r.Subject[i], c.want[i])
				}
			}
		})
	}
}

// TestSubjectListRejectsGarbage sessizce bos listeye cevrilmemeli.
// Aksi halde hatali bir politika "subject yok" gibi gorunur ve
// operator yanlis bir sonuca varir.
func TestSubjectListRejectsGarbage(t *testing.T) {
	for _, doc := range []string{
		`{"id":"f","subject":123}`,
		`{"id":"f","subject":{"a":"b"}}`,
		`{"id":"f","subject":true}`,
	} {
		var r Rule
		if err := json.Unmarshal([]byte(doc), &r); err == nil {
			t.Errorf("gecersiz subject sessizce kabul edildi: %s -> %v",
				doc, r.Subject)
		}
	}
}

// TestSubjectListNilIsEmpty, subject verilmediginde nil doner;
// dogrulama "subject gerekli" hatasini uretir.
func TestSubjectListNilIsEmpty(t *testing.T) {
	var r Rule
	if err := json.Unmarshal([]byte(`{"id":"f"}`), &r); err != nil {
		t.Fatalf("ayristirma basarisiz: %v", err)
	}
	if len(r.Subject) != 0 {
		t.Errorf("subject verilmedigi halde %v dolu", r.Subject)
	}
}
