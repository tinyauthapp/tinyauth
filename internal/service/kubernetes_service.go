package service

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/decoders"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

type ingressKey struct {
	namespace string
	name      string
}

type ingressAppKey struct {
	ingressKey
	appName string
}

type ingressApp struct {
	domain  string
	appName string
	app     model.App
}

type KubernetesService struct {
	client       dynamic.Interface
	ctx          context.Context
	cancel       context.CancelFunc
	started      bool
	mu           sync.RWMutex
	ingressApps  map[ingressKey][]ingressApp
	domainIndex  map[string]ingressAppKey
	appNameIndex map[string]ingressAppKey
}

func NewKubernetesService() *KubernetesService {
	return &KubernetesService{
		ingressApps:  make(map[ingressKey][]ingressApp),
		domainIndex:  make(map[string]ingressAppKey),
		appNameIndex: make(map[string]ingressAppKey),
	}
}

func (k *KubernetesService) addIngressApps(namespace, name string, apps []ingressApp) {
	k.mu.Lock()
	defer k.mu.Unlock()

	key := ingressKey{namespace, name}
	// Remove existing entries for this ingress
	if existing, ok := k.ingressApps[key]; ok {
		for _, app := range existing {
			delete(k.domainIndex, app.domain)
			delete(k.appNameIndex, app.appName)
		}
	}
	// Add new entries
	k.ingressApps[key] = apps
	for _, app := range apps {
		appKey := ingressAppKey{key, app.appName}
		k.domainIndex[app.domain] = appKey
		k.appNameIndex[app.appName] = appKey
	}
}

func (k *KubernetesService) removeIngress(namespace, name string) {
	k.mu.Lock()
	defer k.mu.Unlock()

	key := ingressKey{namespace, name}
	if apps, ok := k.ingressApps[key]; ok {
		for _, app := range apps {
			delete(k.domainIndex, app.domain)
			delete(k.appNameIndex, app.appName)
		}
		delete(k.ingressApps, key)
	}
}

func (k *KubernetesService) getByDomain(domain string) *model.App {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if appKey, ok := k.domainIndex[domain]; ok {
		if apps, ok := k.ingressApps[appKey.ingressKey]; ok {
			for i := range apps {
				app := &apps[i]
				if app.domain == domain && app.appName == appKey.appName {
					return &app.app
				}
			}
		}
	}
	return nil
}

func (k *KubernetesService) getByAppName(appName string) *model.App {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if appKey, ok := k.appNameIndex[appName]; ok {
		if apps, ok := k.ingressApps[appKey.ingressKey]; ok {
			for i := range apps {
				app := &apps[i]
				if app.appName == appName {
					return &app.app
				}
			}
		}
	}
	return nil
}

func (k *KubernetesService) updateFromItem(item *unstructured.Unstructured) {
	namespace := item.GetNamespace()
	name := item.GetName()
	annotations := item.GetAnnotations()
	if annotations == nil {
		k.removeIngress(namespace, name)
		return
	}
	labels, err := decoders.DecodeLabels[model.Apps](annotations, "apps")
	if err != nil {
		tlog.App.Debug().Err(err).Msg("Failed to decode labels from annotations")
		k.removeIngress(namespace, name)
		return
	}
	var apps []ingressApp
	for appName, appLabels := range labels.Apps {
		if appLabels.Config.Domain == "" {
			continue
		}
		apps = append(apps, ingressApp{
			domain:  appLabels.Config.Domain,
			appName: appName,
			app:     appLabels,
		})
	}
	if len(apps) == 0 {
		k.removeIngress(namespace, name)
	} else {
		k.addIngressApps(namespace, name, apps)
	}
}

func (k *KubernetesService) resyncGVR(gvr schema.GroupVersionResource) error {
	ctx, cancel := context.WithTimeout(k.ctx, 30*time.Second)
	defer cancel()

	list, err := k.client.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		tlog.App.Debug().Err(err).Str("api", gvr.GroupVersion().String()).Msg("Failed to list ingresses during resync")
		return err
	}
	for i := range list.Items {
		k.updateFromItem(&list.Items[i])
	}
	tlog.App.Debug().Str("api", gvr.GroupVersion().String()).Int("count", len(list.Items)).Msg("Resynced ingress cache")
	return nil
}

// runWatcher drains events from an active watcher until it closes or the context is done.
// Returns true if the caller should restart the watcher, false if it should exit.
func (k *KubernetesService) runWatcher(gvr schema.GroupVersionResource, w watch.Interface, resyncTicker *time.Ticker) bool {
	for {
		select {
		case <-k.ctx.Done():
			w.Stop()
			return false
		case event, ok := <-w.ResultChan():
			if !ok {
				tlog.App.Debug().Str("api", gvr.GroupVersion().String()).Msg("Watcher channel closed, restarting in 5 seconds")
				w.Stop()
				time.Sleep(5 * time.Second)
				return true
			}
			item, ok := event.Object.(*unstructured.Unstructured)
			if !ok {
				tlog.App.Warn().Str("api", gvr.GroupVersion().String()).Msg("Failed to cast watched object")
				continue
			}
			switch event.Type {
			case watch.Added, watch.Modified:
				k.updateFromItem(item)
			case watch.Deleted:
				k.removeIngress(item.GetNamespace(), item.GetName())
			}
		case <-resyncTicker.C:
			if err := k.resyncGVR(gvr); err != nil {
				tlog.App.Warn().Err(err).Str("api", gvr.GroupVersion().String()).Msg("Periodic resync failed")
			}
		}
	}
}

func (k *KubernetesService) watchGVR(gvr schema.GroupVersionResource) {
	resyncTicker := time.NewTicker(5 * time.Minute)
	defer resyncTicker.Stop()

	if err := k.resyncGVR(gvr); err != nil {
		tlog.App.Error().Err(err).Str("api", gvr.GroupVersion().String()).Msg("Initial resync failed, retrying in 30 seconds")
		time.Sleep(30 * time.Second)
	}

	for {
		select {
		case <-k.ctx.Done():
			tlog.App.Debug().Str("api", gvr.GroupVersion().String()).Msg("Stopping watcher")
			return
		case <-resyncTicker.C:
			if err := k.resyncGVR(gvr); err != nil {
				tlog.App.Warn().Err(err).Str("api", gvr.GroupVersion().String()).Msg("Periodic resync failed")
			}
		default:
			ctx, cancel := context.WithCancel(k.ctx)
			watcher, err := k.client.Resource(gvr).Watch(ctx, metav1.ListOptions{})
			if err != nil {
				tlog.App.Error().Err(err).Str("api", gvr.GroupVersion().String()).Msg("Failed to start watcher")
				cancel()
				time.Sleep(10 * time.Second)
				continue
			}
			tlog.App.Debug().Str("api", gvr.GroupVersion().String()).Msg("Watcher started")
			if !k.runWatcher(gvr, watcher, resyncTicker) {
				cancel()
				return
			}
			cancel()
		}
	}
}

func (k *KubernetesService) Init() error {
	var cfg *rest.Config
	var err error

	cfg, err = rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to get in-cluster Kubernetes config: %w", err)
	}

	client, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	k.client = client
	k.ctx, k.cancel = context.WithCancel(context.Background())

	gvr := schema.GroupVersionResource{
		Group:    "networking.k8s.io",
		Version:  "v1",
		Resource: "ingresses",
	}

	accessCtx, accessCancel := context.WithTimeout(k.ctx, 5*time.Second)
	defer accessCancel()
	_, err = k.client.Resource(gvr).List(accessCtx, metav1.ListOptions{Limit: 1})
	if err != nil {
		tlog.App.Warn().Err(err).Msg("Insufficient permissions for networking.k8s.io/v1 Ingress, Kubernetes label provider will not work")
		k.started = false
		return nil
	}

	tlog.App.Debug().Msg("networking.k8s.io/v1 Ingress API accessible")
	go k.watchGVR(gvr)

	k.started = true
	tlog.App.Info().Msg("Kubernetes label provider initialized")
	return nil
}

func (k *KubernetesService) GetLabels(appDomain string) (*model.App, error) {
	if !k.started {
		tlog.App.Debug().Msg("Kubernetes not connected, returning empty labels")
		return nil, nil
	}

	// First check cache
	app := k.getByDomain(appDomain)
	if app != nil {
		tlog.App.Debug().Str("domain", appDomain).Msg("Found labels in cache by domain")
		return app, nil
	}
	appName := strings.SplitN(appDomain, ".", 2)[0]
	app = k.getByAppName(appName)
	if app != nil {
		tlog.App.Debug().Str("domain", appDomain).Str("appName", appName).Msg("Found labels in cache by app name")
		return app, nil
	}

	tlog.App.Debug().Str("domain", appDomain).Msg("Cache miss, no matching ingress found")
	return nil, nil
}
