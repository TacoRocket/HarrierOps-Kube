package app

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"harrierops-kube/internal/model"
	"harrierops-kube/internal/provider"
)

func TestServiceAccountsPayloadRanksWorkloadIdentityPaths(t *testing.T) {
	payload, err := buildCommandPayload("service-accounts", Options{FixtureDir: testFixtureDir(t)})
	if err != nil {
		t.Fatalf("buildCommandPayload() error = %v", err)
	}

	rows, ok := payload["service_accounts"].([]any)
	if !ok || len(rows) == 0 {
		t.Fatalf("service_accounts = %T, want non-empty []any", payload["service_accounts"])
	}

	first := requireMap(t, rows[0])
	if first["name"] != "fox-admin" {
		t.Fatalf("first name = %v, want fox-admin", first["name"])
	}
	if first["priority"] != "high" {
		t.Fatalf("first priority = %v, want high", first["priority"])
	}
	if first["power_summary"] != "has cluster-wide admin-like access" {
		t.Fatalf("first power_summary = %v", first["power_summary"])
	}

	web := findServiceAccountRow(t, rows, "storefront", "web")
	if web["power_summary"] != "can change workloads" {
		t.Fatalf("web power_summary = %v, want can change workloads", web["power_summary"])
	}
	if web["exposed_workload_count"] != float64(1) {
		t.Fatalf("web exposed_workload_count = %v, want 1", web["exposed_workload_count"])
	}
	if web["workload_count"] != float64(1) {
		t.Fatalf("web workload_count = %v, want 1", web["workload_count"])
	}
	if web["priority"] != "medium" {
		t.Fatalf("web priority = %v, want medium", web["priority"])
	}
	if !strings.Contains(web["why_care"].(string), "fronts 1 exposed workload") {
		t.Fatalf("web why_care = %q, want exposed workload wording", web["why_care"])
	}
}

func TestServiceAccountEnrichmentRanksExposedReusedAndQuietPaths(t *testing.T) {
	rows := enrichServiceAccountPaths(
		[]model.ServiceAccount{
			{ID: "serviceaccount:edge:api", Namespace: "edge", Name: "api"},
			{ID: "serviceaccount:ops:builder", Namespace: "ops", Name: "builder"},
			{ID: "serviceaccount:default:quiet", Namespace: "default", Name: "quiet", AutomountServiceAccountToken: boolPtr(false)},
		},
		model.WorkloadsData{
			WorkloadAssets: []model.Workload{
				{ID: "pod:edge:api-5d4f6", Namespace: "edge", Name: "api-5d4f6", ServiceAccountName: "api", AutomountServiceAccountToken: boolPtr(true), HostPathMounts: []string{"/var/run"}},
				{ID: "pod:ops:builder-a", Namespace: "ops", Name: "builder-a", ServiceAccountName: "builder", AutomountServiceAccountToken: boolPtr(false)},
				{ID: "pod:ops:builder-b", Namespace: "ops", Name: "builder-b", ServiceAccountName: "builder", AutomountServiceAccountToken: boolPtr(false)},
				{ID: "pod:default:quiet", Namespace: "default", Name: "quiet", ServiceAccountName: "quiet", AutomountServiceAccountToken: boolPtr(false)},
			},
		},
		model.ExposureData{
			ExposureAssets: []model.Exposure{
				{ID: "ingress:edge:api", Namespace: "edge", RelatedWorkloads: []string{"api-5d4f6"}},
			},
		},
		model.RBACData{
			RoleGrants: []model.RBACGrant{
				{ID: "grant-edge", SubjectKind: "ServiceAccount", SubjectNamespace: stringPtr("edge"), SubjectName: "api", DangerousRights: []string{"change workloads"}, EvidenceStatus: "direct", Scope: "namespace/edge"},
				{ID: "grant-builder", SubjectKind: "ServiceAccount", SubjectNamespace: stringPtr("ops"), SubjectName: "builder", DangerousRights: []string{"change workloads"}, EvidenceStatus: "direct", Scope: "namespace/ops"},
			},
		},
	)

	if len(rows) != 3 {
		t.Fatalf("len(rows) = %d, want 3", len(rows))
	}
	if rows[0].Namespace != "edge" || rows[0].Name != "api" {
		t.Fatalf("first row = %s/%s, want edge/api", rows[0].Namespace, rows[0].Name)
	}
	if rows[0].Priority != "high" {
		t.Fatalf("edge/api priority = %s, want high", rows[0].Priority)
	}
	if rows[1].Namespace != "ops" || rows[1].Name != "builder" {
		t.Fatalf("second row = %s/%s, want ops/builder", rows[1].Namespace, rows[1].Name)
	}
	if rows[1].WorkloadCount != 2 {
		t.Fatalf("ops/builder workload_count = %d, want 2", rows[1].WorkloadCount)
	}
	if rows[2].Namespace != "default" || rows[2].Name != "quiet" {
		t.Fatalf("third row = %s/%s, want default/quiet", rows[2].Namespace, rows[2].Name)
	}
	if rows[2].Priority != "low" {
		t.Fatalf("default/quiet priority = %s, want low", rows[2].Priority)
	}
	if rows[2].PowerSummary != "" {
		t.Fatalf("default/quiet power_summary = %q, want empty", rows[2].PowerSummary)
	}
}

func TestServiceAccountsPayloadKeepsRowsWhenSupportReadsFail(t *testing.T) {
	payload, err := buildServiceAccountsPayload(stubInventoryProvider{
		metadataContext: model.MetadataContext{
			ContextName: "lab-cluster",
			Namespace:   "default",
		},
		serviceAccountsData: model.ServiceAccountsData{
			ServiceAccounts: []model.ServiceAccount{
				{ID: "serviceaccount:default:quiet", Namespace: "default", Name: "quiet"},
			},
		},
		workloadsErr: errors.New("forbidden"),
		exposuresErr: errors.New("forbidden"),
		rbacErr:      errors.New("forbidden"),
	}, provider.QueryOptions{})
	if err != nil {
		t.Fatalf("buildServiceAccountsPayload() error = %v", err)
	}

	rows, ok := payload["service_accounts"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("service_accounts = %#v, want one row", payload["service_accounts"])
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
	for _, want := range []string{"service-accounts.workloads", "service-accounts.exposure", "service-accounts.rbac"} {
		if !scopes[want] {
			t.Fatalf("missing issue scope %q in %#v", want, scopes)
		}
	}
}

func TestServiceAccountPowerKeepsBestDirectSignalWhenBlockedGrantIsStronger(t *testing.T) {
	rows := enrichServiceAccountPaths(
		[]model.ServiceAccount{
			{ID: "serviceaccount:app:api", Namespace: "app", Name: "api"},
		},
		model.WorkloadsData{
			WorkloadAssets: []model.Workload{
				{ID: "pod:app:api", Namespace: "app", Name: "api", ServiceAccountName: "api"},
			},
		},
		model.ExposureData{},
		model.RBACData{
			RoleGrants: []model.RBACGrant{
				{ID: "grant-direct", SubjectKind: "ServiceAccount", SubjectNamespace: stringPtr("app"), SubjectName: "api", DangerousRights: []string{"read secrets", "change workloads"}, EvidenceStatus: "direct", Scope: "namespace/app"},
				{ID: "grant-blocked", SubjectKind: "ServiceAccount", SubjectNamespace: stringPtr("app"), SubjectName: "api", DangerousRights: []string{"admin-like wildcard access"}, EvidenceStatus: "visibility blocked", Scope: "cluster-wide"},
			},
		},
	)

	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	if rows[0].PowerSummary != "can change workloads" {
		t.Fatalf("power_summary = %q, want can change workloads", rows[0].PowerSummary)
	}
	if rows[0].EvidenceStatus != "direct" {
		t.Fatalf("evidence_status = %q, want direct", rows[0].EvidenceStatus)
	}
}

func TestServiceAccountTokenPostureKeepsInheritedStateHonest(t *testing.T) {
	rows := enrichServiceAccountPaths(
		[]model.ServiceAccount{
			{ID: "serviceaccount:default:default", Namespace: "default", Name: "default"},
		},
		model.WorkloadsData{},
		model.ExposureData{},
		model.RBACData{},
	)

	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	if rows[0].TokenPosture != "service account token posture is inherited or not visible" {
		t.Fatalf("token_posture = %q", rows[0].TokenPosture)
	}
}

func TestServiceAccountsTableOutputStaysOperatorReadable(t *testing.T) {
	fixtureDir := testFixtureDir(t)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run([]string{"service-accounts"}, stdout, stderr, []string{"HARRIEROPS_KUBE_FIXTURE_DIR=" + fixtureDir})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}

	rendered := stdout.String()
	for _, want := range []string{
		"priority",
		"service_account",
		"power",
		"token_posture",
		"default/fox-admin",
		"can change workloads",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("table output missing %q in %q", want, rendered)
		}
	}
}
