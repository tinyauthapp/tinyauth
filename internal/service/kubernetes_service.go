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
	"go.uber.org/dig"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

type watchedResource struct {
	gvr schema.GroupVersionResource
	typ ResourceType
}

func (w watchedResource) pretty() string {
	return w.gvr.Group + "/" + w.gvr.Version + "/" + w.gvr.Resource
}

type ResourceType string

const (
	ResourceTypeIngress ResourceType = "ingress"
)

var supportedResources = []watchedResource{
	{
		gvr: schema.GroupVersionResource{
			Group:    "networking.k8s.io",
			Version:  "v1",
			Resource: "ingresses",
		},
		typ: ResourceTypeIngress,
	},
}

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

type ExtractionResult struct {
	typ         ResourceType
	name        string
	namespace   string
	hosts       []string
	annotations map[string]string
}

type typedItem struct {
	typ     ResourceType
	ingress *networking.Ingress
}

func convertFromUnstructured[T any](obj *unstructured.Unstructured) (*T, error) {
	var typed *T
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &typed)
	if err != nil {
		var zero *T
		return zero, fmt.Errorf("failed to convert ingress to typed object: %w", err)
	}
	return typed, nil
}

func (ti *typedItem) fromUnstructured(typ ResourceType, obj *unstructured.Unstructured) (*typedItem, error) {
	switch typ {
	case ResourceTypeIngress:
		typed, err := convertFromUnstructured[networking.Ingress](obj)
		if err != nil {
			return nil, err
		}
		return &typedItem{
			typ:     ResourceTypeIngress,
			ingress: typed,
		}, nil
	default:
		return nil, fmt.Errorf("unknown resource type %s", typ)
	}
}

type resourceEntry struct {
	name string
	app  model.App
}

type routedApps struct {
	hosts   []string
	entries []resourceEntry
}

type resourceKey struct {
	typ       ResourceType
	namespace string
	name      string
}

type KubernetesService struct {
	log *logger.Logger

	apps      map[resourceKey]routedApps
	client    dynamic.Interface
	mu        sync.RWMutex
	connected bool

	extractors struct {
		ingress *KubernetesIngressExtractor
	}
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
		log:    i.Log,
		client: client,
		apps:   make(map[resourceKey]routedApps),
	}

	service.extractors.ingress = NewKubernetesIngressExtractor(KubernetesIngressExtractorInput{
		Log: i.Log,
	})

	watchedGVRs := make(map[string]bool)

	for _, res := range supportedResources {
		ctx, cancel := context.WithTimeout(i.Ctx, 5*time.Second)
		_, err := client.Resource(res.gvr).List(ctx, metav1.ListOptions{Limit: 1})
		cancel()

		if err != nil {
			// The Gateway API CRDs are not installed on every cluster, so a
			// single unreachable resource is not fatal
			i.Log.App.Warn().Err(err).Str("res", res.pretty()).Msg("Failed to access resource, skipping watcher")
			continue
		}

		i.Log.App.Debug().Str("res", res.pretty()).Msg("Successfully accessed resource, starting watcher")

		i.Ding.Go(func(ctx context.Context) {
			service.watchGVR(res, ctx)
		}, ding.RingMajor)

		watchedGVRs[res.gvr.Resource] = true
	}

	if len(watchedGVRs) == 0 {
		return nil, fmt.Errorf("failed to access any supported kubernetes api (ingresses, httproutes, grpcroutes)")
	}

	service.connected = true
	i.Log.App.Debug().Msg("Kubernetes label provider started successfully")

	return service, nil
}

func (k *KubernetesService) addResourceEntries(key resourceKey, hosts []string, entries []resourceEntry) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.apps[key] = routedApps{
		hosts:   hosts,
		entries: entries,
	}
}

func (k *KubernetesService) removeResource(key resourceKey) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.apps, key)
}

func (k *KubernetesService) getEntry(locator func(name string, app *model.App) bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	// O(n^2) is not great but the number of resource entries is expected to be small
	for _, app := range k.apps {
		for _, entry := range app.entries {
			if ok := locator(entry.name, &entry.app); ok {
				return
			}
		}
	}
}

func (k *KubernetesService) updateFromItem(res watchedResource, typedItem *typedItem) {
	var result *ExtractionResult

	if typedItem == nil {
		k.log.App.Warn().Str("res", res.pretty()).Msg("Resource is nil, skipping")
		return
	}

	switch typedItem.typ {
	case ResourceTypeIngress:
		if typedItem.ingress == nil {
			k.log.App.Warn().Str("res", res.pretty()).Msg("Ingress is nil, skipping")
			return
		}
		result = k.extractors.ingress.Extract(typedItem.ingress)
	}

	if result == nil {
		k.log.App.Warn().Str("res", res.pretty()).Msg("Failed to extract resource, skipping")
		return
	}

	key := resourceKey{
		typ:       res.typ,
		namespace: result.namespace,
		name:      result.name,
	}

	if len(result.hosts) == 0 {
		k.log.App.Warn().Str("res", res.pretty()).Str("namespace", key.namespace).Str("name", key.name).Msg("No hosts found in resource, skipping")
		k.removeResource(key)
		return
	}

	labels, err := decoders.DecodeLabels[model.Apps](result.annotations, "apps")
	if err != nil {
		k.log.App.Warn().Err(err).Str("namespace", key.namespace).Str("name", key.name).Msg("Failed to decode resource labels, skipping")
		k.removeResource(key)
		return
	}

	var entries []resourceEntry

	for name, config := range labels.Apps {
		if config.Config.Domain != "" {
			if !ensureAscii(config.Config.Domain) {
				k.log.App.Warn().Err(err).Str("namespace", key.namespace).Str("name", key.name).Str("domain", config.Config.Domain).Msg("Domain is invalid, matching will rely on app name")
			} else {
				if slices.ContainsFunc(result.hosts, func(host string) bool {
					return hostMatchesHostname(host, config.Config.Domain)
				}) {
					entries = append(entries, resourceEntry{
						name: name,
						app:  config,
					})
					continue
				}
			}
		}

		if slices.ContainsFunc(result.hosts, func(host string) bool {
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

	k.addResourceEntries(key, result.hosts, entries)
}

func (k *KubernetesService) resyncGVR(res watchedResource, ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	list, err := k.client.Resource(res.gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		k.log.App.Warn().Err(err).Str("res", res.pretty()).Msg("Failed to list resources for resync")
		return err
	}
	for _, item := range list.Items {
		newTypedItem, err := new(typedItem).fromUnstructured(res.typ, &item)
		if err != nil {
			k.log.App.Warn().Err(err).Str("res", res.pretty()).Msg("Failed to decode resource, skipping")
			continue
		}
		k.updateFromItem(res, newTypedItem)
	}
	k.log.App.Debug().Str("res", res.pretty()).Int("count", len(list.Items)).Msg("Resync complete")
	return nil
}

func (k *KubernetesService) runWatcher(res watchedResource, w watch.Interface, resyncTicker *time.Ticker, ctx context.Context) bool {
	for {
		select {
		case <-ctx.Done():
			w.Stop()
			return false
		case event, ok := <-w.ResultChan():
			if !ok {
				k.log.App.Warn().Str("res", res.pretty()).Msg("Watcher channel closed, restarting watcher")
				w.Stop()
				time.Sleep(5 * time.Second)
				return true
			}
			item, ok := event.Object.(*unstructured.Unstructured)
			if !ok {
				k.log.App.Warn().Str("res", res.pretty()).Msg("Received unexpected event object, skipping")
				continue
			}
			newTypedItem, err := new(typedItem).fromUnstructured(res.typ, item)
			if err != nil {
				k.log.App.Warn().Err(err).Str("res", res.pretty()).Msg("Failed to decode resource, skipping")
				continue
			}
			switch event.Type {
			case watch.Added, watch.Modified:
				k.updateFromItem(res, newTypedItem)
			case watch.Deleted:
				k.removeResource(resourceKey{
					typ:       res.typ,
					namespace: item.GetNamespace(),
					name:      item.GetName(),
				})
			}
		case <-resyncTicker.C:
			if err := k.resyncGVR(res, ctx); err != nil {
				k.log.App.Warn().Err(err).Str("res", res.pretty()).Msg("Periodic resync failed during watcher run")
			}
		}
	}
}

func (k *KubernetesService) watchGVR(res watchedResource, ctx context.Context) {
	resyncTicker := time.NewTicker(5 * time.Minute)
	defer resyncTicker.Stop()

	if err := k.resyncGVR(res, ctx); err != nil {
		k.log.App.Warn().Err(err).Str("res", res.pretty()).Msg("Initial resync failed, will retry")
		time.Sleep(30 * time.Second)
	}

	for {
		select {
		case <-ctx.Done():
			k.log.App.Debug().Str("res", res.pretty()).Msg("Shutting down kubernetes watcher")
			return
		case <-resyncTicker.C:
			if err := k.resyncGVR(res, ctx); err != nil {
				k.log.App.Warn().Err(err).Str("res", res.pretty()).Msg("Periodic resync failed, will retry")
			}
		default:
			ctx, cancel := context.WithCancel(ctx)
			watcher, err := k.client.Resource(res.gvr).Watch(ctx, metav1.ListOptions{})
			if err != nil {
				k.log.App.Warn().Err(err).Str("res", res.pretty()).Msg("Failed to start watcher, will retry")
				cancel()
				time.Sleep(10 * time.Second)
				continue
			}
			k.log.App.Debug().Str("res", res.pretty()).Msg("Watcher started successfully")
			if !k.runWatcher(res, watcher, resyncTicker, ctx) {
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
