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

type ingressEntry struct {
	name string
	app  model.App
}

type ingressKey struct {
	namespace string
	name      string
}

type KubernetesService struct {
	log *logger.Logger

	client         dynamic.Interface
	connected      bool
	mu             sync.RWMutex
	ingressEntries map[ingressKey][]ingressEntry
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

	gvr := schema.GroupVersionResource{
		Group:    "networking.k8s.io",
		Version:  "v1",
		Resource: "ingresses",
	}

	accessCtx, accessCancel := context.WithTimeout(i.Ctx, 5*time.Second)
	defer accessCancel()

	_, err = client.Resource(gvr).List(accessCtx, metav1.ListOptions{Limit: 1})
	if err != nil {
		i.Log.App.Warn().Err(err).Str("api", gvr.GroupVersion().String()).Msg("Failed to access Ingress API, Kubernetes label provider will be disabled")
		return nil, fmt.Errorf("failed to access ingress api: %w", err)
	}

	i.Log.App.Debug().Str("api", gvr.GroupVersion().String()).Msg("Successfully accessed Ingress API, starting watcher")

	service := &KubernetesService{
		log:            i.Log,
		client:         client,
		ingressEntries: make(map[ingressKey][]ingressEntry),
	}

	i.Ding.Go(func(ctx context.Context) {
		service.watchGVR(gvr, ctx)
	}, ding.RingMajor)

	service.connected = true
	i.Log.App.Debug().Msg("Kubernetes label provider started successfully")

	return service, nil
}

func (k *KubernetesService) addIngressEntries(key ingressKey, entries []ingressEntry) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.ingressEntries[key] = entries
}

func (k *KubernetesService) removeIngress(key ingressKey) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.ingressEntries, key)
}

func (k *KubernetesService) getEntry(locator func(name string, app *model.App) bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	// O(n^2) is not great but the number of ingress entries is expected to be small
	for _, entries := range k.ingressEntries {
		for _, entry := range entries {
			if ok := locator(entry.name, &entry.app); ok {
				return
			}
		}
	}
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

func (k *KubernetesService) extractHosts(item *unstructured.Unstructured) ([]string, error) {
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

func (k *KubernetesService) updateFromItem(item *unstructured.Unstructured) {
	key := ingressKey{
		namespace: item.GetNamespace(),
		name:      item.GetName(),
	}

	annotations := item.GetAnnotations()
	if annotations == nil {
		k.removeIngress(key)
		return
	}

	hosts, err := k.extractHosts(item)
	if err != nil {
		k.removeIngress(key)
		return
	}

	labels, err := decoders.DecodeLabels[model.Apps](annotations, "apps")
	if err != nil {
		k.log.App.Warn().Err(err).Str("namespace", key.namespace).Str("name", key.name).Msg("Failed to decode ingress labels, skipping")
		k.removeIngress(key)
		return
	}

	var entries []ingressEntry

	v := validators.NewDomainValidator(validators.DomainValidatorOptions{})

	for name, config := range labels.Apps {
		registerApp := len(hosts) == 0

		if config.Config.Domain != "" {
			hostname, err := v.SafeHostname(config.Config.Domain)
			if err != nil {
				k.log.App.Warn().Err(err).Str("namespace", key.namespace).Str("name", key.name).Str("domain", config.Config.Domain).Msg("Domain is invalid, matching will rely on app name")
			} else if slices.Contains(hosts, hostname) {
				registerApp = true
			}
		}

		if !registerApp {
			for _, host := range hosts {
				if strings.HasPrefix(strings.ToLower(host), strings.ToLower(name+".")) {
					registerApp = true
					break
				}
			}
		}

		if !registerApp {
			k.log.App.Warn().Str("namespace", key.namespace).Str("name", name).Str("appName", name).Msg("App name or domain does not match with ingress")
			continue
		}

		entries = append(entries, ingressEntry{
			name: name,
			app:  config,
		})
	}

	if len(entries) == 0 {
		k.removeIngress(key)
		return
	}

	k.addIngressEntries(key, entries)
}

func (k *KubernetesService) resyncGVR(gvr schema.GroupVersionResource, ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	list, err := k.client.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		k.log.App.Warn().Err(err).Str("api", gvr.GroupVersion().String()).Msg("Failed to list resources for resync")
		return err
	}
	for i := range list.Items {
		k.updateFromItem(&list.Items[i])
	}
	k.log.App.Debug().Str("api", gvr.GroupVersion().String()).Int("count", len(list.Items)).Msg("Resync complete")
	return nil
}

// runWatcher drains events from an active watcher until it closes or the context is done.
// Returns true if the caller should restart the watcher, false if it should exit.
func (k *KubernetesService) runWatcher(gvr schema.GroupVersionResource, w watch.Interface, resyncTicker *time.Ticker, ctx context.Context) bool {
	for {
		select {
		case <-ctx.Done():
			w.Stop()
			return false
		case event, ok := <-w.ResultChan():
			if !ok {
				k.log.App.Warn().Str("api", gvr.GroupVersion().String()).Msg("Watcher channel closed, restarting watcher")
				w.Stop()
				time.Sleep(5 * time.Second)
				return true
			}
			item, ok := event.Object.(*unstructured.Unstructured)
			if !ok {
				k.log.App.Warn().Str("api", gvr.GroupVersion().String()).Msg("Received unexpected event object, skipping")
				continue
			}
			switch event.Type {
			case watch.Added, watch.Modified:
				k.updateFromItem(item)
			case watch.Deleted:
				k.removeIngress(ingressKey{
					namespace: item.GetNamespace(),
					name:      item.GetName(),
				})
			}
		case <-resyncTicker.C:
			if err := k.resyncGVR(gvr, ctx); err != nil {
				k.log.App.Warn().Err(err).Str("api", gvr.GroupVersion().String()).Msg("Periodic resync failed during watcher run")
			}
		}
	}
}

func (k *KubernetesService) watchGVR(gvr schema.GroupVersionResource, ctx context.Context) {
	resyncTicker := time.NewTicker(5 * time.Minute)
	defer resyncTicker.Stop()

	if err := k.resyncGVR(gvr, ctx); err != nil {
		k.log.App.Warn().Err(err).Str("api", gvr.GroupVersion().String()).Msg("Initial resync failed, will retry")
		time.Sleep(30 * time.Second)
	}

	for {
		select {
		case <-ctx.Done():
			k.log.App.Debug().Str("api", gvr.GroupVersion().String()).Msg("Shutting down kubernetes watcher")
			return
		case <-resyncTicker.C:
			if err := k.resyncGVR(gvr, ctx); err != nil {
				k.log.App.Warn().Err(err).Str("api", gvr.GroupVersion().String()).Msg("Periodic resync failed, will retry")
			}
		default:
			ctx, cancel := context.WithCancel(ctx)
			watcher, err := k.client.Resource(gvr).Watch(ctx, metav1.ListOptions{})
			if err != nil {
				k.log.App.Warn().Err(err).Str("api", gvr.GroupVersion().String()).Msg("Failed to start watcher, will retry")
				cancel()
				time.Sleep(10 * time.Second)
				continue
			}
			k.log.App.Debug().Str("api", gvr.GroupVersion().String()).Msg("Watcher started successfully")
			if !k.runWatcher(gvr, watcher, resyncTicker, ctx) {
				cancel()
				return
			}
			cancel()
		}
	}
}

func (k *KubernetesService) Lookup(locator func(name string, app *model.App) bool) error {
	if !k.connected {
		k.log.App.Debug().Msg("Kubernetes label provider not started, skipping")
		return nil
	}

	k.getEntry(locator)

	return nil
}
