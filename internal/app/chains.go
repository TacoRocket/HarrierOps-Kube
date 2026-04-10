package app

import (
	"harrierops-kube/internal/chains"
	"harrierops-kube/internal/model"
	"harrierops-kube/internal/provider"
)

func buildChainsPayload(selectedFamily string, options ...Options) (map[string]any, error) {
	if selectedFamily == "" {
		output, err := chains.BuildScaffoldOutput(buildMetadata(chains.GroupedCommandName, model.MetadataContext{}, ""), selectedFamily)
		if err != nil {
			return nil, err
		}
		return structToMap(output)
	}

	spec, ok := chains.FamilySpecFor(selectedFamily)
	if !ok {
		output, err := chains.BuildScaffoldOutput(buildMetadata(chains.GroupedCommandName, model.MetadataContext{}, ""), selectedFamily)
		if err != nil {
			return nil, err
		}
		return structToMap(output)
	}
	if spec.State != "implemented" {
		output, err := chains.BuildScaffoldOutput(buildMetadata(chains.GroupedCommandName, model.MetadataContext{}, ""), selectedFamily)
		if err != nil {
			return nil, err
		}
		return structToMap(output)
	}

	var chainOptions Options
	if len(options) > 0 {
		chainOptions = options[0]
	}

	factProvider, err := provider.NewFixtureProvider(chainOptions.FixtureDir)
	if err != nil {
		return nil, err
	}

	query := provider.QueryOptions{
		ContextName: chainOptions.Context,
		Namespace:   chainOptions.Namespace,
	}
	return buildSelectedChainPayload(factProvider, query, selectedFamily)
}

func buildSelectedChainPayload(factProvider provider.Provider, query provider.QueryOptions, selectedFamily string) (map[string]any, error) {
	metadataContext, err := factProvider.MetadataContext(query)
	if err != nil {
		return nil, err
	}

	whoamiData, err := factProvider.WhoAmI(query)
	if err != nil {
		return nil, err
	}
	workloadData, err := factProvider.Workloads(query)
	if err != nil {
		return nil, err
	}
	serviceAccountData, err := factProvider.ServiceAccounts(query)
	if err != nil {
		return nil, err
	}
	exposureData, err := factProvider.Exposures(query)
	if err != nil {
		return nil, err
	}
	rbacData, err := factProvider.RBACBindings(query)
	if err != nil {
		return nil, err
	}

	workloadRows := enrichWorkloadPaths(workloadData, serviceAccountData, exposureData, rbacData)
	serviceAccountRows := enrichServiceAccountPaths(serviceAccountData.ServiceAccounts, workloadData, exposureData, rbacData)
	permissionRows, permissionIssues := derivePermissionPaths(whoamiData.CurrentIdentity, rbacData.RoleGrants)
	if permissionRows == nil {
		permissionRows = []model.PermissionPath{}
	}
	secretRows := enrichSecretPaths(serviceAccountData.ServiceAccounts, workloadData, exposureData, rbacData)
	privescRows := derivePrivescPaths(whoamiData.CurrentIdentity, permissionRows, secretRows, serviceAccountRows, workloadRows)

	issues := append([]model.Issue{}, whoamiData.Issues...)
	issues = append(issues, workloadData.Issues...)
	issues = append(issues, serviceAccountData.Issues...)
	issues = append(issues, exposureData.Issues...)
	issues = append(issues, rbacData.Issues...)
	issues = append(issues, permissionIssues...)

	metadata := buildMetadata(chains.GroupedCommandName, metadataContext, metadataContext.ClusterName)

	switch selectedFamily {
	case "workload-identity-pivot":
		output, err := chains.BuildWorkloadIdentityPivotOutput(metadata, chains.WorkloadIdentityPivotInputs{
			StartingFoothold: currentFootholdLabel(whoamiData.CurrentIdentity),
			Workloads:        workloadRows,
			ServiceAccounts:  serviceAccountRows,
			Permissions:      permissionRows,
			Secrets:          secretRows,
			Privesc:          privescRows,
			Issues:           issues,
		})
		if err != nil {
			return nil, err
		}
		return structToMap(output)
	default:
		output, err := chains.BuildScaffoldOutput(metadata, selectedFamily)
		if err != nil {
			return nil, err
		}
		return structToMap(output)
	}
}
