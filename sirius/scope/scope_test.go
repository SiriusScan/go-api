package scope

import (
	"encoding/json"
	"testing"
)

func TestWireCompatibility(t *testing.T) {
	for _, tt := range []struct {
		scope  ResourceScope
		wire   string
		global bool
	}{
		{Global(), `{}`, true},
		{ForSubject("opaque"), `{"owner_subject_id":"opaque"}`, false},
	} {
		b, err := json.Marshal(tt.scope)
		if err != nil || string(b) != tt.wire {
			t.Fatalf("marshal %s: %v", b, err)
		}
		var got ResourceScope
		if err := json.Unmarshal(b, &got); err != nil || got != tt.scope || got.IsGlobal() != tt.global {
			t.Fatalf("round trip: %+v, %v", got, err)
		}
	}
}
