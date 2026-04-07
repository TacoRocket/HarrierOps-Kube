package app

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"harrierops-kube/internal/contracts"
	"harrierops-kube/internal/model"
	"harrierops-kube/internal/output"
	"harrierops-kube/internal/provider"
)

const (
	OutputTable = "table"
	OutputJSON  = "json"
	OutputCSV   = "csv"
)

type Options struct {
	Context    string
	Namespace  string
	Output     string
	OutDir     string
	Debug      bool
	FixtureDir string
}

type CommandSpec struct {
	Name    string
	Section string
	Status  string
}

var commandSpecs = []CommandSpec{
	{Name: "whoami", Section: "identity", Status: "implemented"},
	{Name: "inventory", Section: "core", Status: "implemented"},
	{Name: "rbac", Section: "identity", Status: "implemented"},
	{Name: "service-accounts", Section: "identity", Status: "implemented"},
	{Name: "workloads", Section: "workload", Status: "implemented"},
	{Name: "exposure", Section: "exposure", Status: "implemented"},
	{Name: "permissions", Section: "identity", Status: "planned-phase1"},
	{Name: "secrets", Section: "identity", Status: "planned-phase1"},
	{Name: "privesc", Section: "identity", Status: "planned-phase1"},
	{Name: "images", Section: "supply-chain", Status: "later-depth"},
}

func Run(args []string, stdout io.Writer, stderr io.Writer, env []string) int {
	options, remaining, err := parseRootOptions(args, stderr, env)
	if err != nil {
		fmt.Fprintf(stderr, "error: %s\n", err)
		return 2
	}

	if len(remaining) == 0 {
		fmt.Fprintln(stderr, usageText())
		return 2
	}

	command := remaining[0]

	if len(remaining) > 1 {
		fmt.Fprintf(stderr, "unexpected arguments after command %q: %s\n", command, strings.Join(remaining[1:], " "))
		return 2
	}

	spec, ok := commandSpec(command)
	if !ok {
		fmt.Fprintf(stderr, "unknown command %q\n", command)
		fmt.Fprintln(stderr, usageText())
		return 2
	}
	if spec.Status != "implemented" {
		fmt.Fprintln(stderr, commandStatusText(spec))
		return 2
	}

	return runSingleCommand(options, command, stdout, stderr)
}

func parseRootOptions(args []string, stderr io.Writer, env []string) (Options, []string, error) {
	options := Options{
		Output: OutputTable,
		OutDir: ".",
	}

	flags := flag.NewFlagSet("harrierops-kube", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.Context, "context", "", "Kubernetes context name")
	flags.StringVar(&options.Namespace, "namespace", "", "Kubernetes namespace")
	flags.StringVar(&options.Output, "output", OutputTable, "Output format: table, json, csv")
	flags.StringVar(&options.OutDir, "outdir", ".", "Output directory")
	flags.BoolVar(&options.Debug, "debug", false, "Enable verbose errors")

	if err := flags.Parse(args); err != nil {
		return Options{}, nil, err
	}

	options.FixtureDir = resolveFixtureDir(env)
	options.Output = strings.ToLower(options.Output)
	options.OutDir = filepath.Clean(options.OutDir)

	if !validOutput(options.Output) {
		return Options{}, nil, fmt.Errorf("invalid output %q; valid values: table, json, csv", options.Output)
	}

	return options, flags.Args(), nil
}

func runSingleCommand(options Options, command string, stdout io.Writer, stderr io.Writer) int {
	payload, err := buildCommandPayload(command, options)
	if err != nil {
		writeError(stderr, err, options.Debug)
		return 2
	}

	if _, err := output.WriteArtifacts(command, payload, options.OutDir); err != nil {
		writeError(stderr, err, options.Debug)
		return 1
	}

	rendered, err := output.Render(options.Output, command, payload)
	if err != nil {
		writeError(stderr, err, options.Debug)
		return 1
	}

	if _, err := io.WriteString(stdout, rendered); err != nil {
		writeError(stderr, err, options.Debug)
		return 1
	}

	return 0
}

func buildCommandPayload(command string, options Options) (map[string]any, error) {
	factProvider, err := provider.NewFixtureProvider(options.FixtureDir)
	if err != nil {
		return nil, err
	}

	query := provider.QueryOptions{
		ContextName: options.Context,
		Namespace:   options.Namespace,
	}
	metadataContext, err := factProvider.MetadataContext(query)
	if err != nil {
		return nil, err
	}

	switch command {
	case "whoami":
		data, err := factProvider.WhoAmI(query)
		if err != nil {
			return nil, err
		}
		metadata := buildMetadata(command, metadataContext, data.KubeContext.ClusterName)
		return structToMap(model.WhoAmIOutput{
			Metadata:    metadata,
			KubeContext: data.KubeContext,
			Docker:      data.Docker,
			Issues:      data.Issues,
		})
	case "inventory":
		data, err := factProvider.Inventory(query)
		if err != nil {
			return nil, err
		}
		metadata := buildMetadata(command, metadataContext, "")
		return structToMap(model.InventoryOutput{
			Metadata:         metadata,
			KubernetesCounts: data.KubernetesCounts,
			DockerCounts:     data.DockerCounts,
			Issues:           data.Issues,
		})
	case "rbac":
		data, err := factProvider.RBACBindings(query)
		if err != nil {
			return nil, err
		}
		metadata := buildMetadata(command, metadataContext, "")
		return structToMap(model.RbacOutput{
			Metadata:   metadata,
			RoleGrants: data.RoleGrants,
			Issues:     data.Issues,
		})
	case "service-accounts":
		data, err := factProvider.ServiceAccounts(query)
		if err != nil {
			return nil, err
		}
		metadata := buildMetadata(command, metadataContext, "")
		return structToMap(model.ServiceAccountsOutput{
			Metadata:        metadata,
			ServiceAccounts: data.ServiceAccounts,
			Findings:        data.Findings,
			Issues:          data.Issues,
		})
	case "workloads":
		data, err := factProvider.Workloads(query)
		if err != nil {
			return nil, err
		}
		metadata := buildMetadata(command, metadataContext, "")
		return structToMap(model.WorkloadsOutput{
			Metadata:       metadata,
			WorkloadAssets: data.WorkloadAssets,
			Findings:       data.Findings,
			Issues:         data.Issues,
		})
	case "exposure":
		data, err := factProvider.Exposures(query)
		if err != nil {
			return nil, err
		}
		metadata := buildMetadata(command, metadataContext, "")
		return structToMap(model.ExposureOutput{
			Metadata:       metadata,
			ExposureAssets: data.ExposureAssets,
			Findings:       data.Findings,
			Issues:         data.Issues,
		})
	default:
		return nil, fmt.Errorf("unsupported implemented command %q", command)
	}
}

func buildMetadata(command string, metadataContext model.MetadataContext, clusterName string) contracts.Metadata {
	return contracts.Metadata{
		Command:       command,
		ContextName:   contracts.OptionalString(metadataContext.ContextName),
		ClusterName:   contracts.OptionalString(clusterName),
		Namespace:     contracts.OptionalString(metadataContext.Namespace),
		DockerContext: contracts.OptionalString(metadataContext.DockerContext),
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		SchemaVersion: contracts.SchemaVersion,
	}
}

func commandSpec(name string) (CommandSpec, bool) {
	for _, spec := range commandSpecs {
		if spec.Name == name {
			return spec, true
		}
	}
	return CommandSpec{}, false
}

func commandNamesWithStatus(status string) []string {
	filtered := make([]string, 0, len(commandSpecs))
	for _, spec := range commandSpecs {
		if spec.Status == status {
			filtered = append(filtered, spec.Name)
		}
	}
	sort.Strings(filtered)
	return filtered
}

func implementedSectionNames() []string {
	seen := map[string]struct{}{}
	for _, spec := range commandSpecs {
		if spec.Status != "implemented" {
			continue
		}
		seen[spec.Section] = struct{}{}
	}

	sections := make([]string, 0, len(seen))
	for section := range seen {
		sections = append(sections, section)
	}
	sort.Strings(sections)
	return sections
}

func validOutput(output string) bool {
	switch output {
	case OutputTable, OutputJSON, OutputCSV:
		return true
	default:
		return false
	}
}

func resolveFixtureDir(env []string) string {
	envMap := map[string]string{}
	for _, pair := range env {
		key, value, ok := strings.Cut(pair, "=")
		if ok {
			envMap[key] = value
		}
	}

	if value := envMap["HARRIEROPS_KUBE_FIXTURE_DIR"]; value != "" {
		return value
	}
	return ""
}

func usageText() string {
	return strings.Join([]string{
		"usage: harrierops-kube [global options] <command> [command options]",
		"",
		"implemented commands: " + strings.Join(commandNamesWithStatus("implemented"), ", "),
		"planned phase 1 commands: " + strings.Join(commandNamesWithStatus("planned-phase1"), ", "),
		"later depth surfaces: " + strings.Join(commandNamesWithStatus("later-depth"), ", "),
		"implemented sections: " + strings.Join(implementedSectionNames(), ", "),
	}, "\n")
}

func commandStatusText(spec CommandSpec) string {
	switch spec.Status {
	case "planned-phase1":
		return fmt.Sprintf("command %q is planned for Phase 1 but is not implemented yet", spec.Name)
	case "later-depth":
		return fmt.Sprintf("command %q is a later depth surface and is not in the current runnable Phase 1 set", spec.Name)
	default:
		return fmt.Sprintf("command %q is not runnable", spec.Name)
	}
}

func writeError(stderr io.Writer, err error, debug bool) {
	if debug {
		fmt.Fprintf(stderr, "error: %+v\n", err)
		return
	}
	fmt.Fprintf(stderr, "error: %s\n", err)
}

func structToMap(value any) (map[string]any, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}
