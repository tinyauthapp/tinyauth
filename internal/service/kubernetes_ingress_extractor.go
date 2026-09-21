package service

import (
	"slices"
	"strings"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/decoders"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	networking "k8s.io/api/networking/v1"
)

func hostMatchesHostname(host string, hostname string) bool {
	host = normalizeDomain(host)
	hostname = normalizeDomain(hostname)
	if suffix, ok := strings.CutPrefix(host, "*."); ok {
		return strings.HasSuffix(hostname, "."+suffix)
	}
	return host == hostname
}

func hostCoversName(host string, name string) bool {
	host = strings.ToLower(host)
	if strings.HasPrefix(host, "*.") {
		return true
	}
	return strings.HasPrefix(host, strings.ToLower(name+"."))
}

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

func (k *KubernetesIngressExtractor) Extract(ingress *networking.Ingress) ExtractionResult {
	meta := &ResourceMeta{
		Name:      ingress.GetName(),
		Namespace: ingress.GetNamespace(),
	}

	if !ensureResourceMeta(meta) {
		k.log.App.Warn().Str("namespace", meta.Namespace).Str("name", meta.Name).Msg("Resource has no namespace or name, skipping")
		return ExtractionResult{}
	}

	annotations := ingress.GetAnnotations()
	hosts := k.getHosts(ingress.Spec.Rules)

	if len(hosts) == 0 {
		k.log.App.Warn().Str("namespace", meta.Namespace).Str("name", meta.Name).Msg("No hosts found in resource, skipping")
		return ExtractionResult{
			Meta: meta,
		}
	}

	labels, err := decoders.DecodeLabels[model.Apps](annotations, "apps")
	if err != nil {
		k.log.App.Warn().Err(err).Str("namespace", meta.Namespace).Str("name", meta.Name).Msg("Failed to decode resource labels, skipping")
		return ExtractionResult{
			Meta: meta,
		}
	}

	apps := make(map[string]model.App)

	for name, config := range labels.Apps {
		if config.Config.Domain != "" {
			if !ensureAscii(config.Config.Domain) {
				k.log.App.Warn().Err(err).Str("namespace", meta.Namespace).Str("name", meta.Name).Str("domain", config.Config.Domain).Msg("Domain is invalid, matching will rely on app name")
			} else {
				if slices.ContainsFunc(hosts, func(host string) bool {
					return hostMatchesHostname(host, config.Config.Domain)
				}) {
					apps[name] = config
					continue
				}
			}
		}

		if slices.ContainsFunc(hosts, func(host string) bool {
			return hostCoversName(host, name)
		}) {
			apps[name] = config
		}
	}

	return ExtractionResult{
		Meta: meta,
		Apps: &apps,
	}
}
