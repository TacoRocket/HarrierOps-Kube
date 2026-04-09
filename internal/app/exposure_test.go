package app

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"harrierops-kube/internal/model"
	"harrierops-kube/internal/provider"
)

func TestExposurePayloadRanksPublicAttributedPaths(t *testing.T) {
	payload, err := buildCommandPayload("exposure", Options{FixtureDir: testFixtureDir(t)})
	if err != nil {
		t.Fatalf("buildCommandPayload() error = %v", err)
	}

	rows, ok := payload["exposure_assets"].([]any)
	if !ok || len(rows) == 0 {
		t.Fatalf("exposure_assets = %T, want non-empty []any", payload["exposure_assets"])
	}

	first := requireMap(t, rows[0])
	if first["name"] != "web-ing" {
		t.Fatalf("first name = %v, want web-ing", first["name"])
	}
	if first["priority"] != "high" {
		t.Fatalf("first priority = %v, want high", first["priority"])
	}
	if first["attribution_status"] != "heuristic" {
		t.Fatalf("first attribution_status = %v, want heuristic", first["attribution_status"])
	}
	if !strings.Contains(first["identity_summary"].(string), "can change workloads") {
		t.Fatalf("first identity_summary = %v, want backend identity signal", first["identity_summary"])
	}

	metrics := findExposureRow(t, rows, "kube-system", "metrics")
	if metrics["priority"] != "high" {
		t.Fatalf("metrics priority = %v, want high", metrics["priority"])
	}

	blocked := findExposureRow(t, rows, "build", "docker-builder")
	if blocked["attribution_status"] != "visibility blocked" {
		t.Fatalf("docker-builder attribution_status = %v, want visibility blocked", blocked["attribution_status"])
	}
	if !strings.Contains(blocked["why_care"].(string), "not visible from current credentials") {
		t.Fatalf("docker-builder why_care = %q, want clearer visibility reason", blocked["why_care"])
	}
}

func TestExposureEnrichmentPrioritizesDirectAttributionOverHeuristic(t *testing.T) {
	rows := enrichExposurePaths(
		model.ExposureData{
			ExposureAssets: []model.Exposure{
				{ID: "ingress:app:frontend-ing", Namespace: "app", Name: "frontend-ing", AssetType: "Ingress", ExposureType: "Ingress", Public: true, ExternalTargets: []string{"front.example.com"}, RelatedWorkloads: []string{"frontend"}},
				{ID: "service:app:frontend-svc", Namespace: "app", Name: "frontend-svc", AssetType: "Service", ExposureType: "LoadBalancer", Public: true, ExternalTargets: []string{"34.10.0.10"}},
				{ID: "service:ops:metrics", Namespace: "ops", Name: "metrics", AssetType: "Service", ExposureType: "NodePort", Public: true, ExternalTargets: []string{"nodePort:30090"}},
			},
		},
		model.WorkloadsData{
			WorkloadAssets: []model.Workload{
				{ID: "pod:app:frontend", Namespace: "app", Name: "frontend", Kind: "Pod", ServiceAccountName: "frontend"},
			},
		},
		model.ServiceAccountsData{
			ServiceAccounts: []model.ServiceAccount{
				{ID: "serviceaccount:app:frontend", Namespace: "app", Name: "frontend"},
			},
		},
		model.RBACData{
			RoleGrants: []model.RBACGrant{
				{ID: "grant-frontend", SubjectKind: "ServiceAccount", SubjectNamespace: stringPtr("app"), SubjectName: "frontend", DangerousRights: []string{"read secrets"}, EvidenceStatus: "direct", Scope: "namespace/app"},
			},
		},
	)

	if len(rows) != 3 {
		t.Fatalf("len(rows) = %d, want 3", len(rows))
	}
	if rows[0].Name != "frontend-ing" || rows[0].AttributionStatus != "direct" {
		t.Fatalf("first row = %s (%s), want frontend-ing (direct)", rows[0].Name, rows[0].AttributionStatus)
	}
	if rows[1].Name != "frontend-svc" || rows[1].AttributionStatus != "heuristic" {
		t.Fatalf("second row = %s (%s), want frontend-svc (heuristic)", rows[1].Name, rows[1].AttributionStatus)
	}
	if !strings.Contains(rows[1].WhyCare, "backend attribution is heuristic") {
		t.Fatalf("frontend-svc why_care = %q, want heuristic wording", rows[1].WhyCare)
	}
	if rows[2].Name != "metrics" {
		t.Fatalf("third row = %s, want metrics", rows[2].Name)
	}
}

func TestExposureEnrichmentPrefersIdentityBearingPublicPathOverWeakerManagementHint(t *testing.T) {
	rows := enrichExposurePaths(
		model.ExposureData{
			ExposureAssets: []model.Exposure{
				{ID: "service:ops:aaa-metrics", Namespace: "ops", Name: "aaa-metrics", AssetType: "Service", ExposureType: "NodePort", Public: true, ExternalTargets: []string{"nodePort:30090"}},
				{ID: "service:ops:zzz-frontend", Namespace: "ops", Name: "zzz-frontend", AssetType: "Service", ExposureType: "NodePort", Public: true, ExternalTargets: []string{"nodePort:30091"}},
			},
		},
		model.WorkloadsData{
			WorkloadAssets: []model.Workload{
				{ID: "pod:ops:frontend", Namespace: "ops", Name: "frontend", Kind: "Pod", ServiceAccountName: "frontend"},
			},
		},
		model.ServiceAccountsData{
			ServiceAccounts: []model.ServiceAccount{
				{ID: "serviceaccount:ops:frontend", Namespace: "ops", Name: "frontend"},
			},
		},
		model.RBACData{
			RoleGrants: []model.RBACGrant{
				{ID: "grant-frontend", SubjectKind: "ServiceAccount", SubjectNamespace: stringPtr("ops"), SubjectName: "frontend", DangerousRights: []string{"read secrets"}, EvidenceStatus: "direct", Scope: "namespace/ops"},
			},
		},
	)

	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(rows))
	}
	if rows[0].Name != "zzz-frontend" {
		t.Fatalf("first row = %s, want zzz-frontend", rows[0].Name)
	}
	if rows[0].AttributionStatus != "heuristic" {
		t.Fatalf("first attribution_status = %s, want heuristic", rows[0].AttributionStatus)
	}
	if !strings.Contains(rows[0].IdentitySummary, "read secrets") {
		t.Fatalf("first identity_summary = %q, want identity-bearing backend", rows[0].IdentitySummary)
	}
	if rows[1].Name != "aaa-metrics" {
		t.Fatalf("second row = %s, want aaa-metrics", rows[1].Name)
	}
}

func TestExposurePayloadKeepsRowsWhenSupportReadsFail(t *testing.T) {
	payload, err := buildExposurePayload(stubInventoryProvider{
		metadataContext: model.MetadataContext{
			ContextName: "lab-cluster",
			Namespace:   "default",
		},
		exposuresData: model.ExposureData{
			ExposureAssets: []model.Exposure{
				{ID: "service:default:web", Namespace: "default", Name: "web", AssetType: "Service", ExposureType: "LoadBalancer", Public: true, ExternalTargets: []string{"34.0.0.1"}},
			},
		},
		workloadsErr:       errors.New("forbidden"),
		serviceAccountsErr: errors.New("forbidden"),
		rbacErr:            errors.New("forbidden"),
	}, provider.QueryOptions{})
	if err != nil {
		t.Fatalf("buildExposurePayload() error = %v", err)
	}

	rows, ok := payload["exposure_assets"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("exposure_assets = %#v, want one row", payload["exposure_assets"])
	}

	issues, ok := payload["issues"].([]any)
	if !ok || len(issues) < 3 {
		t.Fatalf("issues = %#v, want propagated support issues", payload["issues"])
	}

	scopes := map[string]bool{}
	for _, issue := range issues {
		mapping := requireMap(t, issue)
		scope, _ := mapping["scope"].(string)
		scopes[scope] = true
	}
	for _, want := range []string{"exposure.workloads", "exposure.service-accounts", "exposure.rbac"} {
		if !scopes[want] {
			t.Fatalf("missing issue scope %q in %#v", want, scopes)
		}
	}
}

func TestExposureDirectAttributionChoosesStrongestVisibleBackend(t *testing.T) {
	buildRows := func(relatedWorkloads []string) []model.ExposurePath {
		return enrichExposurePaths(
			model.ExposureData{
				ExposureAssets: []model.Exposure{
					{ID: "service:app:frontend", Namespace: "app", Name: "frontend", AssetType: "Service", ExposureType: "LoadBalancer", Public: true, ExternalTargets: []string{"34.10.0.10"}, RelatedWorkloads: relatedWorkloads},
				},
			},
			model.WorkloadsData{
				WorkloadAssets: []model.Workload{
					{ID: "pod:app:quiet", Namespace: "app", Name: "quiet", Kind: "Pod", ServiceAccountName: "default"},
					{ID: "pod:app:strong", Namespace: "app", Name: "strong", Kind: "Pod", ServiceAccountName: "strong", HostPathMounts: []string{"/var/run"}},
				},
			},
			model.ServiceAccountsData{
				ServiceAccounts: []model.ServiceAccount{
					{ID: "serviceaccount:app:default", Namespace: "app", Name: "default"},
					{ID: "serviceaccount:app:strong", Namespace: "app", Name: "strong"},
				},
			},
			model.RBACData{
				RoleGrants: []model.RBACGrant{
					{ID: "grant-strong", SubjectKind: "ServiceAccount", SubjectNamespace: stringPtr("app"), SubjectName: "strong", DangerousRights: []string{"change workloads"}, EvidenceStatus: "direct", Scope: "namespace/app"},
				},
			},
		)
	}

	for _, related := range [][]string{{"quiet", "strong"}, {"strong", "quiet"}} {
		rows := buildRows(related)
		if len(rows) != 1 {
			t.Fatalf("len(rows) = %d, want 1", len(rows))
		}
		if !strings.Contains(rows[0].IdentitySummary, "app/strong") {
			t.Fatalf("identity_summary = %q, want strongest backend", rows[0].IdentitySummary)
		}
		if !strings.Contains(rows[0].BackendSignal, "strongest visible backend is app/strong") {
			t.Fatalf("backend_signal = %q, want strongest backend summary", rows[0].BackendSignal)
		}
	}
}

func TestExposureDirectAttributionPrefersOperationallyCentralBackendWhenPowerIsOtherwiseEqual(t *testing.T) {
	rows := enrichExposurePaths(
		model.ExposureData{
			ExposureAssets: []model.Exposure{
				{ID: "service:ops:shared-edge", Namespace: "ops", Name: "shared-edge", AssetType: "Service", ExposureType: "LoadBalancer", Public: true, ExternalTargets: []string{"34.10.0.10"}, RelatedWorkloads: []string{"frontend", "ingress-controller"}},
			},
		},
		model.WorkloadsData{
			WorkloadAssets: []model.Workload{
				{ID: "pod:ops:frontend", Namespace: "ops", Name: "frontend", Kind: "Pod", ServiceAccountName: "frontend"},
				{ID: "deployment:ops:ingress-controller", Namespace: "ops", Name: "ingress-controller", Kind: "Deployment", ServiceAccountName: "ingress"},
			},
		},
		model.ServiceAccountsData{
			ServiceAccounts: []model.ServiceAccount{
				{ID: "serviceaccount:ops:frontend", Namespace: "ops", Name: "frontend"},
				{ID: "serviceaccount:ops:ingress", Namespace: "ops", Name: "ingress"},
			},
		},
		model.RBACData{
			RoleGrants: []model.RBACGrant{},
		},
	)

	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	if !strings.Contains(rows[0].BackendSignal, "strongest visible backend is ops/ingress-controller") {
		t.Fatalf("backend_signal = %q, want operationally central backend", rows[0].BackendSignal)
	}
	if !strings.Contains(rows[0].WhyCare, "backs an operationally central workload") {
		t.Fatalf("why_care = %q, want central backend wording", rows[0].WhyCare)
	}
}

func TestExposureTableOutputStaysOperatorReadable(t *testing.T) {
	fixtureDir := testFixtureDir(t)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run([]string{"exposure"}, stdout, stderr, []string{"HARRIEROPS_KUBE_FIXTURE_DIR=" + fixtureDir})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}

	rendered := stdout.String()
	for _, want := range []string{
		"priority",
		"exposure",
		"attribution",
		"backend",
		"web-ing",
		"can change workloads",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("table output missing %q in %q", want, rendered)
		}
	}
}
