package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
)

var rowCollections = map[string]string{
	"rbac":             "role_grants",
	"service-accounts": "service_accounts",
	"exposure":         "exposure_assets",
	"workloads":        "workload_assets",
	"images":           "image_assets",
}

func WriteArtifacts(command string, payload map[string]any, outDir string) (map[string]string, error) {
	jsonPayload, err := marshalJSON(payload)
	if err != nil {
		return nil, err
	}

	tablePayload, err := renderTable(command, payload)
	if err != nil {
		return nil, err
	}

	csvPayload, err := renderCSV(command, payload)
	if err != nil {
		return nil, err
	}

	paths := map[string]string{
		"loot":  filepath.Join(outDir, "loot", command+".json"),
		"json":  filepath.Join(outDir, "json", command+".json"),
		"table": filepath.Join(outDir, "table", command+".txt"),
		"csv":   filepath.Join(outDir, "csv", command+".csv"),
	}

	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
	}

	if err := os.WriteFile(paths["loot"], jsonPayload, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(paths["json"], jsonPayload, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(paths["table"], []byte(tablePayload), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(paths["csv"], []byte(csvPayload), 0o644); err != nil {
		return nil, err
	}

	return paths, nil
}

func Render(mode string, command string, payload map[string]any) (string, error) {
	switch mode {
	case "table":
		return renderTable(command, payload)
	case "json":
		data, err := marshalJSON(payload)
		if err != nil {
			return "", err
		}
		return string(data) + "\n", nil
	case "csv":
		return renderCSV(command, payload)
	default:
		return "", fmt.Errorf("unsupported output mode: %s", mode)
	}
}

func marshalJSON(payload map[string]any) ([]byte, error) {
	return json.MarshalIndent(payload, "", "  ")
}

func renderTable(command string, payload map[string]any) (string, error) {
	rowKey, ok := rowCollections[command]
	if !ok {
		return renderKeyValueTable(payload)
	}

	rows, err := rowsForKey(payload, rowKey)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", nil
	}

	headers := collectHeaders(rows)
	var builder strings.Builder
	writer := tabwriter.NewWriter(&builder, 0, 0, 2, ' ', 0)

	fmt.Fprintln(writer, strings.Join(headers, "\t"))
	for _, row := range rows {
		values := make([]string, 0, len(headers))
		for _, header := range headers {
			values = append(values, stringify(row[header]))
		}
		fmt.Fprintln(writer, strings.Join(values, "\t"))
	}

	if err := writer.Flush(); err != nil {
		return "", err
	}
	return builder.String(), nil
}

func renderCSV(command string, payload map[string]any) (string, error) {
	rowKey, ok := rowCollections[command]
	if !ok {
		rowKey = ""
	}

	var rows []map[string]any
	var err error
	if rowKey == "" {
		rows = []map[string]any{payload}
	} else {
		rows, err = rowsForKey(payload, rowKey)
		if err != nil {
			return "", err
		}
	}

	if len(rows) == 0 {
		return "", nil
	}

	headers := collectHeaders(rows)
	buffer := &bytes.Buffer{}
	writer := csv.NewWriter(buffer)

	if err := writer.Write(headers); err != nil {
		return "", err
	}

	for _, row := range rows {
		record := make([]string, 0, len(headers))
		for _, header := range headers {
			record = append(record, stringify(row[header]))
		}
		if err := writer.Write(record); err != nil {
			return "", err
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return "", err
	}

	return buffer.String(), nil
}

func renderKeyValueTable(payload map[string]any) (string, error) {
	keys := make([]string, 0, len(payload))
	for key := range payload {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var builder strings.Builder
	writer := tabwriter.NewWriter(&builder, 0, 0, 2, ' ', 0)
	for _, key := range keys {
		fmt.Fprintf(writer, "%s\t%s\n", key, stringify(payload[key]))
	}
	if err := writer.Flush(); err != nil {
		return "", err
	}
	return builder.String(), nil
}

func rowsForKey(payload map[string]any, key string) ([]map[string]any, error) {
	rawRows, ok := payload[key]
	if !ok {
		return nil, nil
	}

	items, ok := rawRows.([]any)
	if !ok {
		return nil, fmt.Errorf("payload field %q is not a list", key)
	}

	rows := make([]map[string]any, 0, len(items))
	for _, item := range items {
		row, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("payload field %q contains a non-object row", key)
		}
		rows = append(rows, row)
	}

	return rows, nil
}

func collectHeaders(rows []map[string]any) []string {
	seen := map[string]struct{}{}
	for _, row := range rows {
		for key := range row {
			seen[key] = struct{}{}
		}
	}

	headers := make([]string, 0, len(seen))
	for key := range seen {
		headers = append(headers, key)
	}
	sort.Strings(headers)
	return headers
}

func stringify(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case float64:
		if typed == float64(int64(typed)) {
			return fmt.Sprintf("%d", int64(typed))
		}
		return fmt.Sprintf("%v", typed)
	default:
		data, err := json.Marshal(typed)
		if err != nil {
			return fmt.Sprintf("%v", typed)
		}
		return string(data)
	}
}
