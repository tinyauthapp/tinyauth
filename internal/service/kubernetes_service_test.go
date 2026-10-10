package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/tinyauthapp/tinyauth/pkg/apis/tinyauth/v1alpha1"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clientfake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func kubernetesTestLogger() *logger.Logger {
	log := logger.NewLogger().WithTestConfig()
	log.Init()
	return log
}

func newKubernetesServiceForTest() *KubernetesService {
	return &KubernetesService{
		apps:        make(map[ResourceMeta]map[string]model.App),
		log:         kubernetesTestLogger(),
		typedClient: clientfake.NewClientset(),
	}
}

func testIngress(name string, annotations map[string]string, hosts ...string) *networking.Ingress {
	rules := make([]networking.IngressRule, 0, len(hosts))
	for _, host := range hosts {
		rules = append(rules, networking.IngressRule{Host: host})
	}
	return &networking.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", Annotations: annotations},
		Spec:       networking.IngressSpec{Rules: rules},
	}
}

func testApplication(name, domain string) *v1alpha1.Application {
	return &v1alpha1.Application{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec:       v1alpha1.ApplicationSpec{Config: v1alpha1.AppConfig{Domain: domain}},
	}
}

func testResource(typ ResourceType) watchedResource {
	for _, res := range supportedResources {
		if res.typ == typ {
			return res
		}
	}
	panic("unsupported test resource")
}

func TestTypedItemFromUnstructured(t *testing.T) {
	tests := []struct {
		name    string
		typ     ResourceType
		object  map[string]any
		wantErr bool
		check   func(*testing.T, *typedItem)
	}{
		{
			name: "ingress", typ: ResourceTypeIngress,
			object: map[string]any{
				"metadata": map[string]any{"name": "route", "namespace": "default"},
				"spec":     map[string]any{"rules": []any{map[string]any{"host": "app.example.com"}}},
			},
			check: func(t *testing.T, item *typedItem) {
				require.NotNil(t, item.ingress)
				assert.Equal(t, "app.example.com", item.ingress.Spec.Rules[0].Host)
			},
		},
		{
			name: "application", typ: ResourceTypeCRD,
			object: map[string]any{
				"metadata": map[string]any{"name": "app", "namespace": "default"},
				"spec":     map[string]any{"config": map[string]any{"domain": "app.example.com"}},
			},
			check: func(t *testing.T, item *typedItem) {
				require.NotNil(t, item.crd)
				assert.Equal(t, "app.example.com", item.crd.Spec.Config.Domain)
			},
		},
		{name: "malformed ingress", typ: ResourceTypeIngress, object: map[string]any{"spec": "invalid"}, wantErr: true},
		{name: "malformed application", typ: ResourceTypeCRD, object: map[string]any{"spec": "invalid"}, wantErr: true},
		{name: "unknown resource", typ: "unknown", object: map[string]any{}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item, err := new(typedItem).fromUnstructured(tt.typ, &unstructured.Unstructured{Object: tt.object})
			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, item)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.typ, item.typ)
			tt.check(t, item)
		})
	}
}

func TestKubernetesServiceWatchedItemChange(t *testing.T) {
	ingress := testIngress("shared", map[string]string{"tinyauth.apps.app.users.allow": "alice"}, "app.example.com")
	crd := testApplication("shared", "app.example.com")
	crd.Spec.Users.Allow = "bob"
	key := ResourceMeta{Typ: ResourceTypeIngress, Name: "shared", Namespace: "default"}
	crdKey := ResourceMeta{Typ: ResourceTypeCRD, Name: "shared", Namespace: "default"}
	tests := []struct {
		name    string
		res     watchedResource
		item    *typedItem
		event   watch.EventType
		initial map[ResourceMeta]map[string]model.App
		want    map[ResourceMeta]map[string]model.App
	}{
		{"add ingress", testResource(ResourceTypeIngress), &typedItem{typ: ResourceTypeIngress, ingress: ingress}, watch.Added, nil,
			map[ResourceMeta]map[string]model.App{key: {"app": {Users: model.AppUsers{Allow: "alice"}}}}},
		{"modify ingress", testResource(ResourceTypeIngress), &typedItem{typ: ResourceTypeIngress, ingress: testIngress("shared", map[string]string{"tinyauth.apps.app.users.allow": "carol"}, "app.example.com")}, watch.Modified,
			map[ResourceMeta]map[string]model.App{key: {"old": {}}}, map[ResourceMeta]map[string]model.App{key: {"app": {Users: model.AppUsers{Allow: "carol"}}}}},
		{"delete ingress", testResource(ResourceTypeIngress), &typedItem{typ: ResourceTypeIngress, ingress: ingress}, watch.Deleted,
			map[ResourceMeta]map[string]model.App{key: {"app": {}}}, nil},
		{"update without annotations replaces stale apps", testResource(ResourceTypeIngress), &typedItem{typ: ResourceTypeIngress, ingress: testIngress("shared", nil, "app.example.com")}, watch.Modified,
			map[ResourceMeta]map[string]model.App{key: {"app": {}}}, map[ResourceMeta]map[string]model.App{key: {}}},
		{"invalid annotations remove stale entry", testResource(ResourceTypeIngress), &typedItem{typ: ResourceTypeIngress, ingress: testIngress("shared", map[string]string{"tinyauth.apps.app.users.invalid": "alice"}, "app.example.com")}, watch.Modified,
			map[ResourceMeta]map[string]model.App{key: {"app": {}}}, nil},
		{"nil item leaves cache untouched", testResource(ResourceTypeIngress), nil, watch.Added,
			map[ResourceMeta]map[string]model.App{key: {"app": {}}}, map[ResourceMeta]map[string]model.App{key: {"app": {}}}},
		{"nil ingress leaves cache untouched", testResource(ResourceTypeIngress), &typedItem{typ: ResourceTypeIngress}, watch.Modified,
			map[ResourceMeta]map[string]model.App{key: {"app": {}}}, map[ResourceMeta]map[string]model.App{key: {"app": {}}}},
		{"nil CRD leaves cache untouched", testResource(ResourceTypeCRD), &typedItem{typ: ResourceTypeCRD}, watch.Modified,
			map[ResourceMeta]map[string]model.App{crdKey: {"shared": {}}}, map[ResourceMeta]map[string]model.App{crdKey: {"shared": {}}}},
		{"add CRD alongside ingress", testResource(ResourceTypeCRD), &typedItem{typ: ResourceTypeCRD, crd: crd}, watch.Added,
			map[ResourceMeta]map[string]model.App{key: {"app": {}}}, map[ResourceMeta]map[string]model.App{key: {"app": {}}, crdKey: {"shared": {Config: model.AppConfig{Domain: "app.example.com"}, Users: model.AppUsers{Allow: "bob"}}}}},
		{"invalid CRD removes stale entry", testResource(ResourceTypeCRD), &typedItem{typ: ResourceTypeCRD, crd: testApplication("shared", "")}, watch.Modified,
			map[ResourceMeta]map[string]model.App{crdKey: {"shared": {}}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := newKubernetesServiceForTest()
			for meta, apps := range tt.initial {
				service.addResource(ExtractionResult{Meta: &meta, Apps: apps})
			}
			service.watchedItemChange(tt.res, tt.item, tt.event)
			if tt.want == nil {
				assert.Empty(t, service.apps)
			} else {
				assert.Equal(t, tt.want, service.apps)
			}
		})
	}
}

func TestKubernetesServiceResyncGVR(t *testing.T) {
	for _, typ := range []ResourceType{ResourceTypeIngress, ResourceTypeCRD} {
		t.Run(string(typ), func(t *testing.T) {
			service := newKubernetesServiceForTest()
			res := testResource(typ)
			var obj *unstructured.Unstructured
			if typ == ResourceTypeIngress {
				obj = &unstructured.Unstructured{Object: map[string]any{
					"apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
					"metadata": map[string]any{"name": "keep", "namespace": "default", "annotations": map[string]any{"tinyauth.apps.app.users.allow": "alice"}},
					"spec":     map[string]any{"rules": []any{map[string]any{"host": "app.example.com"}}},
				}}
			} else {
				obj = &unstructured.Unstructured{Object: map[string]any{
					"apiVersion": "tinyauth.app/v1alpha1", "kind": "Application",
					"metadata": map[string]any{"name": "keep", "namespace": "default"},
					"spec":     map[string]any{"config": map[string]any{"domain": "app.example.com"}},
				}}
			}
			client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{res.gvr: obj.GetKind() + "List"}, obj)
			service.client = client
			keep := ResourceMeta{Typ: typ, Name: "keep", Namespace: "default"}
			stale := ResourceMeta{Typ: typ, Name: "gone", Namespace: "default"}
			other := ResourceMeta{Typ: ResourceTypeIngress, Name: "other", Namespace: "default"}
			if typ == ResourceTypeIngress {
				other.Typ = ResourceTypeCRD
			}
			service.addResource(ExtractionResult{Meta: &stale, Apps: map[string]model.App{"old": {}}})
			service.addResource(ExtractionResult{Meta: &other, Apps: map[string]model.App{"unrelated": {}}})
			require.NoError(t, service.resyncGVR(res, context.Background()))
			assert.Contains(t, service.apps, keep)
			assert.NotContains(t, service.apps, stale)
			assert.Contains(t, service.apps, other)

			require.NoError(t, client.Resource(res.gvr).Namespace("default").Delete(context.Background(), "keep", metav1.DeleteOptions{}))
			require.NoError(t, service.resyncGVR(res, context.Background()))
			assert.NotContains(t, service.apps, keep)
			assert.Contains(t, service.apps, other)
		})
	}
}

func TestKubernetesServiceResyncGVRListFailure(t *testing.T) {
	service := newKubernetesServiceForTest()
	res := testResource(ResourceTypeIngress)
	key := ResourceMeta{Typ: res.typ, Name: "keep", Namespace: "default"}
	service.addResource(ExtractionResult{Meta: &key, Apps: map[string]model.App{"app": {}}})
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{res.gvr: "IngressList"})
	client.PrependReactor("list", "ingresses", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("list failed")
	})
	service.client = client
	require.Error(t, service.resyncGVR(res, context.Background()))
	assert.Contains(t, service.apps, key)
}

func TestKubernetesServiceRunWatcher(t *testing.T) {
	service := newKubernetesServiceForTest()
	res := testResource(ResourceTypeIngress)
	key := ResourceMeta{Typ: res.typ, Name: "route", Namespace: "default"}
	obj := &unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "route", "namespace": "default", "annotations": map[string]any{"tinyauth.apps.app.users.allow": "alice"}},
		"spec":     map[string]any{"rules": []any{map[string]any{"host": "app.example.com"}}},
	}}
	w := watch.NewRaceFreeFake()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan bool, 1)
	go func() { done <- service.runWatcher(res, w, ticker, ctx) }()

	w.Add(obj)
	require.Eventually(t, func() bool {
		service.mu.RLock()
		defer service.mu.RUnlock()
		return service.apps[key]["app"].Users.Allow == "alice"
	}, time.Second, time.Millisecond)
	w.Delete(obj)
	require.Eventually(t, func() bool {
		service.mu.RLock()
		defer service.mu.RUnlock()
		_, ok := service.apps[key]
		return !ok
	}, time.Second, time.Millisecond)
	cancel()
	select {
	case restart := <-done:
		assert.False(t, restart)
	case <-time.After(time.Second):
		t.Fatal("watcher did not stop on cancellation")
	}
}

func TestKubernetesServiceLookup(t *testing.T) {
	for _, tt := range []struct {
		name      string
		connected bool
		wantCalls int
	}{
		{"connected", true, 1},
		{"disconnected", false, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			service := newKubernetesServiceForTest()
			service.connected = tt.connected
			meta := ResourceMeta{Typ: ResourceTypeIngress, Name: "route", Namespace: "default"}
			service.addResource(ExtractionResult{Meta: &meta, Apps: map[string]model.App{"app": {Config: model.AppConfig{Domain: "app.example.com"}}}})
			calls := 0
			err := service.Lookup(func(name string, app *model.App) bool {
				calls++
				assert.Equal(t, "app", name)
				assert.Equal(t, "app.example.com", app.Config.Domain)
				return true
			})
			require.NoError(t, err)
			assert.Equal(t, tt.wantCalls, calls)
		})
	}
}

func TestKubernetesServiceGetEntryStopsOnMatch(t *testing.T) {
	service := newKubernetesServiceForTest()
	meta := ResourceMeta{Typ: ResourceTypeIngress, Name: "route", Namespace: "default"}
	service.addResource(ExtractionResult{Meta: &meta, Apps: map[string]model.App{"app": {}}})
	calls := 0
	service.getEntry(func(_ string, _ *model.App) bool { calls++; return true })
	assert.Equal(t, 1, calls)
	service.removeResource(meta)
	assert.Empty(t, service.apps)
}
