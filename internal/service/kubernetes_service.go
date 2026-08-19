package service

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/steveiliop56/ding"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/decoders"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/tinyauthapp/tinyauth/pkg/validators"
	"go.uber.org/dig"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

// watchedResource describes a kind of resource that can carry tinyauth
// annotations, along with the specifics of extracting the hosts it routes.
type watchedResource struct {
	gvr schema.GroupVersionResource
	// gatewayAPI resources declare their hosts in spec.hostnames instead of
	// spec.rules[].host and may use the wildcard label (`*.`).
	gatewayAPI bool
	// httpPaths marks resources that route on HTTP paths, which means another
	// resource may claim the same host on a different path.
	httpPaths bool
}

// api returns a human readable identifier for the watched resource.
func (r watchedResource) api() string {
	return r.gvr.GroupVersion().String() + "/" + r.gvr.Resource
}

var watchedResources = []watchedResource{
	{
		gvr: schema.GroupVersionResource{
			Group:    "networking.k8s.io",
			Version:  "v1",
			Resource: "ingresses",
		},
		httpPaths: true,
	},
	{
		gvr: schema.GroupVersionResource{
			Group:    "gateway.networking.k8s.io",
			Version:  "v1",
			Resource: "httproutes",
		},
		gatewayAPI: true,
		httpPaths:  true,
	},
	{
		gvr: schema.GroupVersionResource{
			Group:    "gateway.networking.k8s.io",
			Version:  "v1",
			Resource: "grpcroutes",
		},
		gatewayAPI: true,
	},
}

type resourceEntry struct {
	name string
	app  model.App
}

// routedApps holds the apps annotated on a resource along with the hosts that
// resource routes, which bound the domains those apps may define ACLs for.
type routedApps struct {
	hosts   []string
	entries []resourceEntry
}

// resourceKey identifies a watched resource. The kind is part of the key
// because an Ingress and an HTTPRoute may share a name within a namespace.
type resourceKey struct {
	resource  string
	namespace string
	name      string
}

type KubernetesService struct {
	log *logger.Logger

	client       dynamic.Interface
	connected    bool
	mu           sync.RWMutex
	resourceApps map[resourceKey]routedApps
}

type KubernetesServiceInput struct {
	dig.In

	Log  *logger.Logger
	Ctx  context.Context
	Ding *ding.Ding
}

func NewKubernetesService(i KubernetesServiceInput) (*KubernetesService, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get in-cluster kubernetes config: %w", err)
	}

	client, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	service := &KubernetesService{
		log:          i.Log,
		client:       client,
		resourceApps: make(map[resourceKey]routedApps),
	}

	watching := 0

	for _, res := range watchedResources {
		accessCtx, accessCancel := context.WithTimeout(i.Ctx, 5*time.Second)
		_, err := client.Resource(res.gvr).List(accessCtx, metav1.ListOptions{Limit: 1})
		accessCancel()

		if err != nil {
			// The Gateway API CRDs are not installed on every cluster, so a
			// single unreachable API is not fatal
			i.Log.App.Warn().Err(err).Str("api", res.api()).Msg("Failed to access API, skipping watcher")
			continue
		}

		i.Log.App.Debug().Str("api", res.api()).Msg("Successfully accessed API, starting watcher")

		i.Ding.Go(func(ctx context.Context) {
			service.watchGVR(res, ctx)
		}, ding.RingMajor)

		watching++
	}

	if watching == 0 {
		return nil, fmt.Errorf("failed to access any supported kubernetes api (ingresses, httproutes, grpcroutes)")
	}

	service.connected = true
	i.Log.App.Debug().Msg("Kubernetes label provider started successfully")

	return service, nil
}

func (k *KubernetesService) addResourceEntries(key resourceKey, hosts []string, entries []resourceEntry) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.resourceApps[key] = routedApps{
		hosts:   hosts,
		entries: entries,
	}
}

func (k *KubernetesService) removeResource(key resourceKey) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.resourceApps, key)
}

func (k *KubernetesService) getEntry(domain string, locator func(name string, app *model.App) bool) {
	v := validators.NewDomainValidator(validators.DomainValidatorOptions{})

	hostname, err := v.SafeHostname(domain)
	if err != nil {
		k.log.App.Debug().Err(err).Str("domain", domain).Msg("Domain is invalid, skipping lookup")
		return
	}

	k.mu.RLock()
	defer k.mu.RUnlock()

	// O(n^2) is not great but the number of resource entries is expected to be small
	for _, apps := range k.resourceApps {
		// Only a resource that routes the domain may define its ACLs, otherwise
		// an app could claim any domain that happens to start with its name
		if !slices.ContainsFunc(apps.hosts, func(host string) bool {
			return hostMatches(host, hostname)
		}) {
			continue
		}
		for _, entry := range apps.entries {
			if ok := locator(entry.name, &entry.app); ok {
				return
			}
		}
	}
}

// hostMatches reports whether hostname is routed by host. It honours the
// Gateway API wildcard label (`*.`), which is a suffix match, so
// `*.example.com` matches `test.example.com` and `foo.test.example.com` but
// not `example.com`.
func hostMatches(host string, hostname string) bool {
	host = strings.ToLower(host)

	if suffix, ok := strings.CutPrefix(host, "*."); ok {
		return strings.HasSuffix(hostname, "."+suffix)
	}

	return host == hostname
}

// hostCoversName reports whether an app name could resolve to a host routed by
// the resource. A wildcard host covers any app name since `*.example.com`
// routes `<name>.example.com` for every name.
func hostCoversName(host string, name string) bool {
	host = strings.ToLower(host)

	if strings.HasPrefix(host, "*.") {
		return true
	}

	return strings.HasPrefix(host, strings.ToLower(name+"."))
}

func (k *KubernetesService) extractPaths(rule map[string]any) ([]string, error) {
	http, found, err := unstructured.NestedMap(rule, "http")
	if err != nil {
		return nil, fmt.Errorf("reading http from rule: %w", err)
	}
	if !found {
		return nil, nil
	}
	paths, found, err := unstructured.NestedSlice(http, "paths")
	if err != nil {
		return nil, fmt.Errorf("reading http.paths: %w", err)
	}
	if !found {
		return nil, nil
	}
	var result []string
	for _, p := range paths {
		path, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if p, ok := path["path"].(string); ok && p != "" {
			result = append(result, p)
		}
	}
	return result, nil
}

// extractRoutePaths returns the paths matched by a Gateway API route rule and
// whether the rule matches every path for its hosts.
func (k *KubernetesService) extractRoutePaths(rule map[string]any) ([]string, bool, error) {
	matches, found, err := unstructured.NestedSlice(rule, "matches")
	if err != nil {
		return nil, false, fmt.Errorf("reading matches from rule: %w", err)
	}
	if !found || len(matches) == 0 {
		// An omitted matches list defaults to a PathPrefix match on "/"
		return nil, true, nil
	}
	var result []string
	catchAll := false
	for _, m := range matches {
		match, ok := m.(map[string]any)
		if !ok {
			continue
		}
		path, ok := match["path"].(map[string]any)
		if !ok {
			// A match without a path constrains something else, such as headers
			// or a gRPC method, and leaves the path unrestricted
			catchAll = true
			continue
		}
		// Both fields are optional and default to a PathPrefix match on "/"
		pathType, ok := path["type"].(string)
		if !ok || pathType == "" {
			pathType = "PathPrefix"
		}
		value, ok := path["value"].(string)
		if !ok || value == "" {
			value = "/"
		}
		result = append(result, value)
		if pathType == "PathPrefix" && value == "/" {
			catchAll = true
		}
	}
	return result, catchAll, nil
}

// warnMissingCatchAllPath warns when a Gateway API route does not match every
// path for the hosts it routes. Unlike an Ingress, a route declares its hosts
// once for all of its rules, so the rules are checked as a whole.
func (k *KubernetesService) warnMissingCatchAllPath(item *unstructured.Unstructured) {
	rules, found, err := unstructured.NestedSlice(item.Object, "spec", "rules")
	if err != nil {
		// This is purely to warn users
		// It doesn't affect our ability to extract hosts, so we won't fail the whole operation
		k.log.App.Warn().Err(err).Str("namespace", item.GetNamespace()).Str("name", item.GetName()).Msg("Failed to extract paths from route rules")
		return
	}
	if !found || len(rules) == 0 {
		return
	}
	var paths []string
	for _, r := range rules {
		rule, ok := r.(map[string]any)
		if !ok {
			continue
		}
		rulePaths, catchAll, err := k.extractRoutePaths(rule)
		if err != nil {
			k.log.App.Warn().Err(err).Str("namespace", item.GetNamespace()).Str("name", item.GetName()).Msg("Failed to extract paths from route rule")
			continue
		}
		if catchAll {
			return
		}
		paths = append(paths, rulePaths...)
	}
	if len(paths) == 0 {
		return
	}
	k.log.App.Warn().Str("namespace", item.GetNamespace()).Str("name", item.GetName()).Strs("paths", paths).Msg("Route does not contain a catch-all path, another route may be able to bypass auth checks if it routes the same host with a different path. Consider adding a catch-all path to this route to ensure auth checks are applied to all paths for this host.")
}

func (k *KubernetesService) extractIngressHosts(item *unstructured.Unstructured) ([]string, error) {
	rules, found, err := unstructured.NestedSlice(item.Object, "spec", "rules")
	if err != nil {
		return nil, fmt.Errorf("reading spec.rules: %w", err)
	}
	if !found {
		return nil, nil
	}
	var hosts []string
	for _, r := range rules {
		rule, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if host, ok := rule["host"].(string); ok && host != "" {
			hosts = append(hosts, host)
		}
		paths, err := k.extractPaths(rule)
		if err != nil {
			// This is purely to warn users
			// It doesn't affect our ability to extract hosts, so we won't fail the whole operation
			k.log.App.Warn().Err(err).Str("namespace", item.GetNamespace()).Str("name", item.GetName()).Msg("Failed to extract paths from ingress rule")
			continue
		}
		if len(paths) == 0 {
			continue
		}
		if !slices.Contains(paths, "/") {
			k.log.App.Warn().Str("namespace", item.GetNamespace()).Str("name", item.GetName()).Strs("paths", paths).Msg("Ingress rule does not contain a catch-all path, another ingress may be able to bypass auth checks if it routes the same host with a different path. Consider adding a catch-all path to this rule to ensure auth checks are applied to all paths for this host.")
		}
	}
	k.log.App.Trace().Strs("hosts", hosts).Msg("Extracted hosts from ingress rules")
	return hosts, nil
}

func (k *KubernetesService) extractRouteHosts(res watchedResource, item *unstructured.Unstructured) ([]string, error) {
	hostnames, found, err := unstructured.NestedStringSlice(item.Object, "spec", "hostnames")
	if err != nil {
		return nil, fmt.Errorf("reading spec.hostnames: %w", err)
	}
	if !found {
		// A route without hostnames inherits the ones of the gateway listeners
		// it attaches to, which we cannot resolve from the route alone
		return nil, nil
	}
	var hosts []string
	for _, hostname := range hostnames {
		if hostname != "" {
			hosts = append(hosts, hostname)
		}
	}
	if res.httpPaths {
		k.warnMissingCatchAllPath(item)
	}
	k.log.App.Trace().Strs("hosts", hosts).Msg("Extracted hosts from route hostnames")
	return hosts, nil
}

func (k *KubernetesService) extractHosts(res watchedResource, item *unstructured.Unstructured) ([]string, error) {
	if res.gatewayAPI {
		return k.extractRouteHosts(res, item)
	}
	return k.extractIngressHosts(item)
}

func (k *KubernetesService) updateFromItem(res watchedResource, item *unstructured.Unstructured) {
	key := resourceKey{
		resource:  res.gvr.Resource,
		namespace: item.GetNamespace(),
		name:      item.GetName(),
	}

	annotations := item.GetAnnotations()
	if annotations == nil {
		k.removeResource(key)
		return
	}

	hosts, err := k.extractHosts(res, item)
	if err != nil {
		k.removeResource(key)
		return
	}

	if len(hosts) == 0 {
		k.log.App.Warn().Str("api", res.api()).Str("namespace", key.namespace).Str("name", key.name).Msg("No hosts found in resource, skipping")
		k.removeResource(key)
		return
	}

	labels, err := decoders.DecodeLabels[model.Apps](annotations, "apps")
	if err != nil {
		k.log.App.Warn().Err(err).Str("namespace", key.namespace).Str("name", key.name).Msg("Failed to decode resource labels, skipping")
		k.removeResource(key)
		return
	}

	var entries []resourceEntry

	v := validators.NewDomainValidator(validators.DomainValidatorOptions{})

	for name, config := range labels.Apps {
		if config.Config.Domain != "" {
			hostname, err := v.SafeHostname(config.Config.Domain)
			if err != nil {
				k.log.App.Warn().Err(err).Str("namespace", key.namespace).Str("name", key.name).Str("domain", config.Config.Domain).Msg("Domain is invalid, matching will rely on app name")
			} else if slices.ContainsFunc(hosts, func(host string) bool {
				return hostMatches(host, hostname)
			}) {
				entries = append(entries, resourceEntry{
					name: name,
					app:  config,
				})
				continue
			}
		}

		if slices.ContainsFunc(hosts, func(host string) bool {
			return hostCoversName(host, name)
		}) {
			entries = append(entries, resourceEntry{
				name: name,
				app:  config,
			})
		}
	}

	if len(entries) == 0 {
		k.removeResource(key)
		return
	}

	k.addResourceEntries(key, hosts, entries)
}

func (k *KubernetesService) resyncGVR(res watchedResource, ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	list, err := k.client.Resource(res.gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		k.log.App.Warn().Err(err).Str("api", res.api()).Msg("Failed to list resources for resync")
		return err
	}
	for i := range list.Items {
		k.updateFromItem(res, &list.Items[i])
	}
	k.log.App.Debug().Str("api", res.api()).Int("count", len(list.Items)).Msg("Resync complete")
	return nil
}

// runWatcher drains events from an active watcher until it closes or the context is done.
// Returns true if the caller should restart the watcher, false if it should exit.
func (k *KubernetesService) runWatcher(res watchedResource, w watch.Interface, resyncTicker *time.Ticker, ctx context.Context) bool {
	for {
		select {
		case <-ctx.Done():
			w.Stop()
			return false
		case event, ok := <-w.ResultChan():
			if !ok {
				k.log.App.Warn().Str("api", res.api()).Msg("Watcher channel closed, restarting watcher")
				w.Stop()
				time.Sleep(5 * time.Second)
				return true
			}
			item, ok := event.Object.(*unstructured.Unstructured)
			if !ok {
				k.log.App.Warn().Str("api", res.api()).Msg("Received unexpected event object, skipping")
				continue
			}
			switch event.Type {
			case watch.Added, watch.Modified:
				k.updateFromItem(res, item)
			case watch.Deleted:
				k.removeResource(resourceKey{
					resource:  res.gvr.Resource,
					namespace: item.GetNamespace(),
					name:      item.GetName(),
				})
			}
		case <-resyncTicker.C:
			if err := k.resyncGVR(res, ctx); err != nil {
				k.log.App.Warn().Err(err).Str("api", res.api()).Msg("Periodic resync failed during watcher run")
			}
		}
	}
}

func (k *KubernetesService) watchGVR(res watchedResource, ctx context.Context) {
	resyncTicker := time.NewTicker(5 * time.Minute)
	defer resyncTicker.Stop()

	if err := k.resyncGVR(res, ctx); err != nil {
		k.log.App.Warn().Err(err).Str("api", res.api()).Msg("Initial resync failed, will retry")
		time.Sleep(30 * time.Second)
	}

	for {
		select {
		case <-ctx.Done():
			k.log.App.Debug().Str("api", res.api()).Msg("Shutting down kubernetes watcher")
			return
		case <-resyncTicker.C:
			if err := k.resyncGVR(res, ctx); err != nil {
				k.log.App.Warn().Err(err).Str("api", res.api()).Msg("Periodic resync failed, will retry")
			}
		default:
			ctx, cancel := context.WithCancel(ctx)
			watcher, err := k.client.Resource(res.gvr).Watch(ctx, metav1.ListOptions{})
			if err != nil {
				k.log.App.Warn().Err(err).Str("api", res.api()).Msg("Failed to start watcher, will retry")
				cancel()
				time.Sleep(10 * time.Second)
				continue
			}
			k.log.App.Debug().Str("api", res.api()).Msg("Watcher started successfully")
			if !k.runWatcher(res, watcher, resyncTicker, ctx) {
				cancel()
				return
			}
			cancel()
		}
	}
}

// Lookup yields the apps annotated on the resources that route domain. Apps
// annotated on any other resource are withheld, since they are served
// elsewhere and must not define the ACLs of this domain.
func (k *KubernetesService) Lookup(domain string, locator func(name string, app *model.App) bool) error {
	if !k.connected {
		k.log.App.Debug().Msg("Kubernetes label provider not started, skipping")
		return nil
	}

	k.getEntry(domain, locator)

	return nil
}
