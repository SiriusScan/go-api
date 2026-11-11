package message

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/SiriusScan/go-api/sirius/scope"
)

func TestScanJobEnvelope(t *testing.T) {
	resourceScope := scope.ForSubject("opaque")
	job := ScanJob{ScanID: "scan-1", Targets: []ScanTarget{{Value: "192.0.2.1", Type: "single_ip"}}}
	payload, _ := json.Marshal(job)
	env := Envelope{SpecVersion: SpecVersion, ID: "event-1", Type: ScanRequested, Source: "scanner", SchemaVersion: ScanJobSchemaVersion, CreatedAt: time.Now().UTC(), ResourceScope: &resourceScope, Payload: payload}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Envelope
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	got, err := decoded.ValidateScanJob()
	if err != nil || got.ScanID != job.ScanID || decoded.ResourceScope.OwnerSubjectID != "opaque" {
		t.Fatalf("got %+v, %v", got, err)
	}
	decoded.SpecVersion = "2.0"
	if _, err := decoded.ValidateScanJob(); err == nil {
		t.Fatal("accepted unsupported version")
	}
	decoded.SpecVersion = SpecVersion
	decoded.Payload = json.RawMessage(`{"scan_id":"","targets":[]}`)
	if _, err := decoded.ValidateScanJob(); err == nil {
		t.Fatal("accepted missing fields")
	}
}

func TestScanControlRequiresExactIDAndKnownAction(t *testing.T) {
	env := Envelope{SpecVersion: SpecVersion, ID: "control-1", Type: ScanCancelRequested, Source: "control", SchemaVersion: ScanControlSchemaVersion, CreatedAt: time.Now().UTC(), Payload: json.RawMessage(`{"scan_id":"scan-1","action":"cancel","state_mode":"keyed"}`)}
	got, err := env.ValidateScanControl()
	if err != nil || got.ScanID != "scan-1" || got.StateMode != "keyed" {
		t.Fatalf("control %+v: %v", got, err)
	}
	for _, payload := range []string{`{"action":"cancel"}`, `{"scan_id":"scan-1","action":"other"}`} {
		env.Payload = json.RawMessage(payload)
		if _, err := env.ValidateScanControl(); err == nil {
			t.Fatalf("accepted %s", payload)
		}
	}
}
