package message

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

func TestJSONSchemasWithFixtures(t *testing.T) {
	root := filepath.Join("..", "..", "..", "contracts", "message", "v1")
	for _, name := range []string{"envelope", "scan-job", "scan-control"} {
		t.Run(name, func(t *testing.T) {
			schema, err := jsonschema.Compile(filepath.Join(root, name+".schema.json"))
			if err != nil {
				t.Fatal(err)
			}
			for _, valid := range []bool{true, false} {
				suffix := "invalid"
				if valid {
					suffix = "valid"
				}
				data, err := os.ReadFile(filepath.Join(root, "fixtures", name+"-"+suffix+".json"))
				if err != nil {
					t.Fatal(err)
				}
				var value any
				if err = json.Unmarshal(data, &value); err != nil {
					t.Fatal(err)
				}
				err = schema.Validate(value)
				if (err == nil) != valid {
					t.Fatalf("%s fixture: %v", suffix, err)
				}
			}
		})
	}
}
