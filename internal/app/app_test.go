package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCLICommandsSmoke(t *testing.T) {
	fixtureDir := testFixtureDir(t)
	commands := []string{
		"whoami",
		"inventory",
		"rbac",
		"service-accounts",
		"workloads",
		"exposure",
	}

	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			outDir := t.TempDir()
			stdout := &bytes.Buffer{}
			stderr := &bytes.Buffer{}

			exitCode := Run(
				[]string{"--outdir", outDir, "--output", "json", command},
				stdout,
				stderr,
				[]string{"HARRIEROPS_KUBE_FIXTURE_DIR=" + fixtureDir},
			)

			if exitCode != 0 {
				t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
			}

			payload := decodeJSONMap(t, stdout.Bytes())
			metadata := requireMap(t, payload["metadata"])
			if metadata["command"] != command {
				t.Fatalf("metadata.command = %v, want %s", metadata["command"], command)
			}

			lootPath := filepath.Join(outDir, "loot", command+".json")
			if _, err := os.Stat(lootPath); err != nil {
				t.Fatalf("expected artifact %s: %v", lootPath, err)
			}
		})
	}
}

func TestPlannedPhaseOneCommandsReturnHelpfulError(t *testing.T) {
	fixtureDir := testFixtureDir(t)
	for _, command := range []string{"permissions", "secrets", "privesc"} {
		t.Run(command, func(t *testing.T) {
			stdout := &bytes.Buffer{}
			stderr := &bytes.Buffer{}

			exitCode := Run(
				[]string{command},
				stdout,
				stderr,
				[]string{"HARRIEROPS_KUBE_FIXTURE_DIR=" + fixtureDir},
			)

			if exitCode != 2 {
				t.Fatalf("exit code = %d, want 2", exitCode)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", stdout.String())
			}
			if !strings.Contains(stderr.String(), "planned for Phase 1 but is not implemented yet") {
				t.Fatalf("stderr = %q, want planned-phase1 guidance", stderr.String())
			}
		})
	}
}

func TestLaterDepthSurfaceReturnsHelpfulError(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run([]string{"images"}, stdout, stderr, nil)
	if exitCode != 2 {
		t.Fatalf("exit code = %d, want 2", exitCode)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "later depth surface") {
		t.Fatalf("stderr = %q, want later-depth guidance", stderr.String())
	}
}

func TestUsageTextReflectsCurrentSurface(t *testing.T) {
	usage := usageText()

	if strings.Contains(usage, "all-checks") {
		t.Fatalf("usage text still references all-checks: %q", usage)
	}
	for _, want := range []string{
		"implemented commands: exposure, inventory, rbac, service-accounts, whoami, workloads",
		"planned phase 1 commands: permissions, privesc, secrets",
		"later depth surfaces: images",
	} {
		if !strings.Contains(usage, want) {
			t.Fatalf("usage text missing %q in %q", want, usage)
		}
	}
}

func TestGoldenOutputsForImplementedCommands(t *testing.T) {
	fixtureDir := testFixtureDir(t)
	goldenDir := testGoldenDir(t)

	for _, command := range []string{
		"whoami",
		"inventory",
		"rbac",
		"service-accounts",
		"exposure",
		"workloads",
	} {
		t.Run(command, func(t *testing.T) {
			payload, err := buildCommandPayload(command, Options{FixtureDir: fixtureDir})
			if err != nil {
				t.Fatalf("buildCommandPayload() error = %v", err)
			}

			got := normalizeGeneratedAt(t, payload)
			wantBytes, err := os.ReadFile(filepath.Join(goldenDir, command+".json"))
			if err != nil {
				t.Fatalf("read golden file: %v", err)
			}
			want := decodeJSONMap(t, wantBytes)

			if !reflect.DeepEqual(got, want) {
				t.Fatalf("payload mismatch\n got: %#v\nwant: %#v", got, want)
			}
		})
	}
}

func testFixtureDir(t *testing.T) string {
	t.Helper()
	return absPath(t, filepath.Join("..", "..", "testdata", "fixtures", "lab_cluster"))
}

func testGoldenDir(t *testing.T) string {
	t.Helper()
	return absPath(t, filepath.Join("..", "..", "testdata", "golden"))
}

func absPath(t *testing.T, path string) string {
	t.Helper()
	absolute, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("filepath.Abs(%q): %v", path, err)
	}
	return absolute
}

func decodeJSONMap(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("json.Unmarshal(): %v", err)
	}
	return payload
}

func requireMap(t *testing.T, value any) map[string]any {
	t.Helper()
	mapping, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("value = %T, want map[string]any", value)
	}
	return mapping
}

func normalizeGeneratedAt(t *testing.T, payload map[string]any) map[string]any {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal(): %v", err)
	}

	normalized := decodeJSONMap(t, data)
	metadata := requireMap(t, normalized["metadata"])
	metadata["generated_at"] = "<generated_at>"
	return normalized
}
