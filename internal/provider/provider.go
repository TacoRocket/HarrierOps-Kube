package provider

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"harrierops-kube/internal/model"
)

type QueryOptions struct {
	ContextName string
	Namespace   string
}

type Provider interface {
	MetadataContext(QueryOptions) (model.MetadataContext, error)
	WhoAmI(QueryOptions) (model.WhoAmIData, error)
	Inventory(QueryOptions) (model.InventoryData, error)
	RBACBindings(QueryOptions) (model.RBACData, error)
	ServiceAccounts(QueryOptions) (model.ServiceAccountsData, error)
	Workloads(QueryOptions) (model.WorkloadsData, error)
	Exposures(QueryOptions) (model.ExposureData, error)
}

func NewFixtureProvider(fixtureDir string) (Provider, error) {
	if fixtureDir == "" {
		return nil, fmt.Errorf(
			"live kubectl collection is not implemented yet; set HARRIEROPS_KUBE_FIXTURE_DIR to load reference fixtures",
		)
	}

	return fixtureProvider{fixtureDir: fixtureDir}, nil
}

type fixtureProvider struct {
	fixtureDir string
}

func (p fixtureProvider) MetadataContext(options QueryOptions) (model.MetadataContext, error) {
	data, err := p.WhoAmI(options)
	if err != nil {
		return model.MetadataContext{}, err
	}

	metadata := model.MetadataContext{
		ContextName:   data.KubeContext.CurrentContext,
		ClusterName:   data.KubeContext.ClusterName,
		Namespace:     data.KubeContext.Namespace,
		DockerContext: "",
	}
	if data.Docker != nil {
		metadata.DockerContext = data.Docker.ContextName
	}
	return metadata, nil
}

func (p fixtureProvider) WhoAmI(options QueryOptions) (model.WhoAmIData, error) {
	var data model.WhoAmIData
	if err := p.load("whoami", &data); err != nil {
		return model.WhoAmIData{}, err
	}

	if options.ContextName != "" {
		data.KubeContext.CurrentContext = options.ContextName
	}
	if options.Namespace != "" {
		data.KubeContext.Namespace = options.Namespace
	}
	return data, nil
}

func (p fixtureProvider) Inventory(options QueryOptions) (model.InventoryData, error) {
	var data model.InventoryData
	if err := p.load("inventory", &data); err != nil {
		return model.InventoryData{}, err
	}
	return data, nil
}

func (p fixtureProvider) RBACBindings(options QueryOptions) (model.RBACData, error) {
	var data model.RBACData
	if err := p.load("rbac", &data); err != nil {
		return model.RBACData{}, err
	}
	return data, nil
}

func (p fixtureProvider) ServiceAccounts(options QueryOptions) (model.ServiceAccountsData, error) {
	var data model.ServiceAccountsData
	if err := p.load("service-accounts", &data); err != nil {
		return model.ServiceAccountsData{}, err
	}
	if len(data.Findings) == 0 {
		var reference model.ServiceAccountsOutput
		if err := p.loadReference("service-accounts", &reference); err == nil {
			data.Findings = reference.Findings
		}
	}
	return data, nil
}

func (p fixtureProvider) Workloads(options QueryOptions) (model.WorkloadsData, error) {
	var data model.WorkloadsData
	if err := p.load("workloads", &data); err != nil {
		return model.WorkloadsData{}, err
	}
	if len(data.Findings) == 0 {
		var reference model.WorkloadsOutput
		if err := p.loadReference("workloads", &reference); err == nil {
			data.Findings = reference.Findings
		}
	}
	return data, nil
}

func (p fixtureProvider) Exposures(options QueryOptions) (model.ExposureData, error) {
	var data model.ExposureData
	if err := p.load("exposure", &data); err != nil {
		return model.ExposureData{}, err
	}
	if len(data.Findings) == 0 {
		var reference model.ExposureOutput
		if err := p.loadReference("exposure", &reference); err == nil {
			data.Findings = reference.Findings
		}
	}
	return data, nil
}

func (p fixtureProvider) load(command string, target any) error {
	path := filepath.Join(p.fixtureDir, command+".json")
	return p.decode(path, command, target)
}

func (p fixtureProvider) loadReference(command string, target any) error {
	testdataRoot := filepath.Dir(filepath.Dir(p.fixtureDir))
	path := filepath.Join(testdataRoot, "golden", command+".json")
	return p.decode(path, command+" reference", target)
}

func (p fixtureProvider) decode(path string, label string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read fixture for %s: %w", label, err)
	}

	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("decode fixture for %s: %w", label, err)
	}

	return nil
}
