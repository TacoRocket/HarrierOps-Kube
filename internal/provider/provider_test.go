package provider

import (
	"path/filepath"
	"testing"
)

func TestMetadataContextUsesWhoAmIFixtureDefaults(t *testing.T) {
	provider := newFixtureProvider(t)

	metadata, err := provider.MetadataContext(QueryOptions{})
	if err != nil {
		t.Fatalf("MetadataContext() error = %v", err)
	}

	if metadata.ContextName != "lab-cluster" {
		t.Fatalf("ContextName = %q, want lab-cluster", metadata.ContextName)
	}
	if metadata.ClusterName != "lab-cluster" {
		t.Fatalf("ClusterName = %q, want lab-cluster", metadata.ClusterName)
	}
	if metadata.Namespace != "default" {
		t.Fatalf("Namespace = %q, want default", metadata.Namespace)
	}
	if metadata.DockerContext != "default" {
		t.Fatalf("DockerContext = %q, want default", metadata.DockerContext)
	}
}

func TestMetadataContextAppliesOverrides(t *testing.T) {
	provider := newFixtureProvider(t)

	metadata, err := provider.MetadataContext(QueryOptions{
		ContextName: "prod-cluster",
		Namespace:   "payments",
	})
	if err != nil {
		t.Fatalf("MetadataContext() error = %v", err)
	}

	if metadata.ContextName != "prod-cluster" {
		t.Fatalf("ContextName = %q, want prod-cluster", metadata.ContextName)
	}
	if metadata.Namespace != "payments" {
		t.Fatalf("Namespace = %q, want payments", metadata.Namespace)
	}
	if metadata.ClusterName != "lab-cluster" {
		t.Fatalf("ClusterName = %q, want lab-cluster", metadata.ClusterName)
	}
}

func TestWhoAmIAppliesOverrides(t *testing.T) {
	provider := newFixtureProvider(t)

	data, err := provider.WhoAmI(QueryOptions{
		ContextName: "prod-cluster",
		Namespace:   "payments",
	})
	if err != nil {
		t.Fatalf("WhoAmI() error = %v", err)
	}

	if data.KubeContext.CurrentContext != "prod-cluster" {
		t.Fatalf("CurrentContext = %q, want prod-cluster", data.KubeContext.CurrentContext)
	}
	if data.KubeContext.Namespace != "payments" {
		t.Fatalf("Namespace = %q, want payments", data.KubeContext.Namespace)
	}
	if data.KubeContext.ClusterName != "lab-cluster" {
		t.Fatalf("ClusterName = %q, want lab-cluster", data.KubeContext.ClusterName)
	}
}

func TestRBACBindingsDecodeNormalizedGrantRows(t *testing.T) {
	provider := newFixtureProvider(t)

	data, err := provider.RBACBindings(QueryOptions{})
	if err != nil {
		t.Fatalf("RBACBindings() error = %v", err)
	}

	if len(data.RoleGrants) != 3 {
		t.Fatalf("len(RoleGrants) = %d, want 3", len(data.RoleGrants))
	}

	first := data.RoleGrants[0]
	if first.RoleName != "cluster-admin" {
		t.Fatalf("RoleName = %q, want cluster-admin", first.RoleName)
	}
	if first.SubjectName != "fox-admin" {
		t.Fatalf("SubjectName = %q, want fox-admin", first.SubjectName)
	}
}

func TestServiceAccountsRestoresReferenceFindingsWhenFixturesAreThin(t *testing.T) {
	provider := newFixtureProvider(t)

	data, err := provider.ServiceAccounts(QueryOptions{})
	if err != nil {
		t.Fatalf("ServiceAccounts() error = %v", err)
	}

	if len(data.Findings) != 3 {
		t.Fatalf("len(Findings) = %d, want 3", len(data.Findings))
	}
	if data.Findings[0].Title == "" {
		t.Fatalf("first finding title is empty")
	}
}

func newFixtureProvider(t *testing.T) Provider {
	t.Helper()

	fixtureDir, err := filepath.Abs(filepath.Join("..", "..", "testdata", "fixtures", "lab_cluster"))
	if err != nil {
		t.Fatalf("filepath.Abs(): %v", err)
	}

	provider, err := NewFixtureProvider(fixtureDir)
	if err != nil {
		t.Fatalf("NewFixtureProvider() error = %v", err)
	}
	return provider
}
