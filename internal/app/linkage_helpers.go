package app

import (
	"sort"
	"strings"

	"harrierops-kube/internal/model"
)

type exposureWorkloadMatch struct {
	Labels    []string
	Matched   []model.Workload
	Heuristic bool
}

func relatedWorkloadKey(namespace string, rawName string) string {
	if strings.Contains(rawName, "/") {
		return rawName
	}
	return namespace + "/" + rawName
}

func matchExposureWorkloads(
	exposure model.Exposure,
	workloadsByKey map[string]model.Workload,
	workloadsByNamespace map[string][]model.Workload,
) exposureWorkloadMatch {
	if len(exposure.RelatedWorkloads) > 0 {
		labels := make([]string, 0, len(exposure.RelatedWorkloads))
		matched := []model.Workload{}
		for _, rawName := range exposure.RelatedWorkloads {
			label := relatedWorkloadKey(exposure.Namespace, rawName)
			labels = append(labels, label)
			if workload, ok := workloadsByKey[label]; ok {
				matched = append(matched, workload)
			}
		}
		sort.Strings(labels)
		return exposureWorkloadMatch{
			Labels:  labels,
			Matched: matched,
		}
	}

	candidates := heuristicExposureMatches(exposure, workloadsByNamespace[exposure.Namespace])
	if len(candidates) != 1 {
		return exposureWorkloadMatch{}
	}

	workload := candidates[0]
	return exposureWorkloadMatch{
		Labels:    []string{workload.Namespace + "/" + workload.Name},
		Matched:   []model.Workload{workload},
		Heuristic: true,
	}
}

func workloadLooksOperationallyCentral(workload model.Workload) bool {
	switch workload.Kind {
	case "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob":
		return true
	}

	for _, marker := range []string{"controller", "operator", "ingress", "gateway", "coredns", "dns", "metrics", "autoscaler"} {
		if strings.Contains(strings.ToLower(workload.Name), marker) {
			return true
		}
	}
	return false
}
