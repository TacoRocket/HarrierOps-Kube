package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type schemaFile struct {
	Model          string   `json:"model"`
	TopLevelFields []string `json:"top_level_fields"`
}

func TestSchemaContractsMatchRegistry(t *testing.T) {
	schemaDir := absPath(t, filepath.Join("..", "..", "schemas"))

	for _, command := range CommandNames() {
		t.Run(command, func(t *testing.T) {
			contract, ok := CommandContractFor(command)
			if !ok {
				t.Fatalf("missing contract for %s", command)
			}

			data, err := os.ReadFile(filepath.Join(schemaDir, command+".schema.json"))
			if err != nil {
				t.Fatalf("read schema: %v", err)
			}

			var payload schemaFile
			if err := json.Unmarshal(data, &payload); err != nil {
				t.Fatalf("json.Unmarshal(): %v", err)
			}

			if payload.Model != contract.Model {
				t.Fatalf("model = %s, want %s", payload.Model, contract.Model)
			}
			if !reflect.DeepEqual(payload.TopLevelFields, contract.TopLevelFields) {
				t.Fatalf("top_level_fields = %#v, want %#v", payload.TopLevelFields, contract.TopLevelFields)
			}
		})
	}
}

func absPath(t *testing.T, path string) string {
	t.Helper()
	absolute, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("filepath.Abs(%q): %v", path, err)
	}
	return absolute
}
