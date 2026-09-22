package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/steveiliop56/ding"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/tinyauthapp/tinyauth/pkg/apis/tinyauth/v1alpha1"
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

func ensureResourceMeta(meta *ResourceMeta) bool {
	return meta.Name != "" && meta.Namespace != ""
}

type ResourceMeta struct {
	Typ       ResourceType
	Name      string
	Namespace string
}

type ExtractionResult struct {
	Meta *ResourceMeta
	Apps map[string]model.App
}

type ResourceType string

const (
	ResourceTypeIngress ResourceType = "ingress"
	ResourceTypeCRD     ResourceType = "crd"
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
	{
		gvr: schema.GroupVersionResource{
			Group:    "tinyauth.app",
			Version:  "v1alpha1",
			Resource: "applications",
		},
	},
}

type typedItem struct {
	typ     ResourceType
	ingress *networking.Ingress
	crd     *v1alpha1.Application
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
	case ResourceTypeCRD:
		typed, err := convertFromUnstructured[v1alpha1.Application](obj)
		if err != nil {
			return nil, err
		}
		return &typedItem{
			typ: ResourceTypeCRD,
			crd: typed,
		}, nil
	default:
		return nil, fmt.Errorf("unknown resource type %s", typ)
	}
}

type KubernetesService struct {
	log *logger.Logger

	apps      map[ResourceMeta]map[string]model.App
	client    dynamic.Interface
	mu        sync.RWMutex
	connected bool
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
		apps:   make(map[ResourceMeta]map[string]model.App),
	}

	watchedGVRs := make(map[string]bool)

	for _, res := range supportedResources {
		ctx, cancel := context.WithTimeout(i.Ctx, 5*time.Second)
		_, err := client.Resource(res.gvr).List(ctx, metav1.ListOptions{Limit: 1})
		cancel()

		if err != nil {
			// The CRD may not be available yet, so we'll fall back to ingress
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

func (k *KubernetesService) addResource(result ExtractionResult) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.apps[*result.Meta] = result.Apps
}

func (k *KubernetesService) removeResource(meta ResourceMeta) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.apps, meta)
}

func (k *KubernetesService) getEntry(locator func(name string, app *model.App) bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	for _, apps := range k.apps {
		for name, app := range apps {
			if ok := locator(name, &app); ok {
				return
			}
		}
	}
}

func (k *KubernetesService) watchedItemChange(res watchedResource, typedItem *typedItem, event watch.EventType) {
	if typedItem == nil {
		k.log.App.Warn().Str("res", res.pretty()).Msg("Resource is nil, skipping")
		return
	}

	var result ExtractionResult

	switch typedItem.typ {
	case ResourceTypeIngress:
		if typedItem.ingress == nil {
			k.log.App.Warn().Str("res", res.pretty()).Msg("Ingress is nil, skipping")
			return
		}
		extractor := NewKubernetesIngressExtractor(KubernetesIngressExtractorInput{
			Log: k.log,
		})
		result = extractor.Extract(typedItem.ingress)
	case ResourceTypeCRD:
		if typedItem.crd == nil {
			k.log.App.Warn().Str("res", res.pretty()).Msg("CRD is nil, skipping")
			return
		}
		extractor := NewKubernetesCRDExtractor(KubernetesCRDInput{
			Log: k.log,
		})
		result = extractor.Extract(typedItem.crd)
	}

	if event == watch.Deleted {
		if result.Meta != nil {
			k.removeResource(*result.Meta)
		}
		return
	}

	if result.Apps == nil {
		k.log.App.Warn().Str("res", res.pretty()).Msg("Failed to extract resource, skipping")
		if result.Meta != nil {
			k.removeResource(*result.Meta)
		}
		return
	}

	k.addResource(result)
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
		k.watchedItemChange(res, newTypedItem, watch.Modified)
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
			case watch.Added, watch.Modified, watch.Deleted:
				k.watchedItemChange(res, newTypedItem, event.Type)
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
