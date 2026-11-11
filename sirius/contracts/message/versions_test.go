package message

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/SiriusScan/go-api/sirius/scope"
)

func TestPublishedVersionsMatchContracts(t *testing.T) {
	data, err := os.ReadFile("../../../contracts/versions.json")
	if err != nil {
		t.Fatal(err)
	}
	var versions map[string]string
	if err := json.Unmarshal(data, &versions); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"resource_scope": scope.Version, "message_envelope": SpecVersion, "scan_job": ScanJobSchemaVersion, "scan_control": ScanControlSchemaVersion, "core_schema_latest": "010_host_resource_scope"} {
		if versions[key] != want {
			t.Fatalf("%s = %q, want %q", key, versions[key], want)
		}
	}
}
