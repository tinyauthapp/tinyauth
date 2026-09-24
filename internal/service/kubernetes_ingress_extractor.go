package service

import (
	"slices"

	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	networking "k8s.io/api/networking/v1"
)

type KubernetesIngressExtractor struct {
	log *logger.Logger
}

type KubernetesIngressExtractorInput struct {
	Log *logger.Logger
}

func NewKubernetesIngressExtractor(i KubernetesIngressExtractorInput) *KubernetesIngressExtractor {
	return &KubernetesIngressExtractor{
		log: i.Log,
	}
}

func (k *KubernetesIngressExtractor) getPaths(rule networking.IngressRule) []string {
	var paths []string

	if rule.HTTP == nil {
		return paths
	}

	for _, path := range rule.HTTP.Paths {
		paths = append(paths, path.Path)
	}

	return paths
}

func (k *KubernetesIngressExtractor) getHosts(rules []networking.IngressRule) []string {
	var hosts []string

	for _, rule := range rules {
		hosts = append(hosts, rule.Host)
		paths := k.getPaths(rule)

		if len(paths) == 0 {
			continue
		}

		if !slices.Contains(paths, "/") {
			k.log.App.Warn().Strs("hosts", hosts).Strs("paths", paths).Msg("Ingress rule does not contain a catch-all path, another ingress may be able to bypass auth checks if it routes the same host with a different path. Consider adding a catch-all path to this rule to ensure auth checks are applied to all paths for this host.")
		}
	}

	return hosts
}

func (k *KubernetesIngressExtractor) Extract(ingress *networking.Ingress) *ExtractionResult {
	annotations := ingress.GetAnnotations()
	hosts := k.getHosts(ingress.Spec.Rules)

	return &ExtractionResult{
		typ:         ResourceTypeIngress,
		name:        ingress.GetName(),
		namespace:   ingress.GetNamespace(),
		hosts:       hosts,
		annotations: annotations,
	}
}
