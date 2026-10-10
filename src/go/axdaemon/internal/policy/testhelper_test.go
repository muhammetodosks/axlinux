package policy

import (
	"encoding/json"
	"testing"
)

func mustParsePolicy(t *testing.T, b []byte) Policy {
	t.Helper()
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatalf("ayristirma: %v", err)
	}
	return p
}
