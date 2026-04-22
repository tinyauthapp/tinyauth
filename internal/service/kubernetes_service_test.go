package service

import (
	"testing"

	"github.com/steveiliop56/tinyauth/internal/config"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestKubernetesService() *KubernetesService {
	return &KubernetesService{
		ingressApps:  make(map[ingressKey][]ingressApp),
		domainIndex:  make(map[string]ingressAppKey),
		appNameIndex: make(map[string]ingressAppKey),
	}
}

func TestKubernetesService_CacheByDomain(t *testing.T) {
	svc := newTestKubernetesService()

	app := config.App{Config: config.AppConfig{Domain: "foo.example.com"}}
	svc.addIngressApps("default", "my-ingress", []ingressApp{
		{domain: "foo.example.com", appName: "foo", app: app},
	})

	got, ok := svc.getByDomain("foo.example.com")
	require.True(t, ok)
	assert.Equal(t, "foo.example.com", got.Config.Domain)

	_, ok = svc.getByDomain("notfound.example.com")
	assert.False(t, ok)
}

func TestKubernetesService_CacheByAppName(t *testing.T) {
	svc := newTestKubernetesService()

	app := config.App{Config: config.AppConfig{Domain: "bar.example.com"}}
	svc.addIngressApps("default", "my-ingress", []ingressApp{
		{domain: "bar.example.com", appName: "bar", app: app},
	})

	got, ok := svc.getByAppName("bar")
	require.True(t, ok)
	assert.Equal(t, "bar.example.com", got.Config.Domain)

	_, ok = svc.getByAppName("notfound")
	assert.False(t, ok)
}

func TestKubernetesService_RemoveIngress(t *testing.T) {
	svc := newTestKubernetesService()

	app := config.App{Config: config.AppConfig{Domain: "baz.example.com"}}
	svc.addIngressApps("default", "my-ingress", []ingressApp{
		{domain: "baz.example.com", appName: "baz", app: app},
	})

	svc.removeIngress("default", "my-ingress")

	_, ok := svc.getByDomain("baz.example.com")
	assert.False(t, ok)
	_, ok = svc.getByAppName("baz")
	assert.False(t, ok)
}

func TestKubernetesService_AddIngressApps_Replaces(t *testing.T) {
	svc := newTestKubernetesService()

	old := config.App{Config: config.AppConfig{Domain: "old.example.com"}}
	svc.addIngressApps("default", "my-ingress", []ingressApp{
		{domain: "old.example.com", appName: "old", app: old},
	})

	updated := config.App{Config: config.AppConfig{Domain: "new.example.com"}}
	svc.addIngressApps("default", "my-ingress", []ingressApp{
		{domain: "new.example.com", appName: "new", app: updated},
	})

	// Old entry should be gone
	_, ok := svc.getByDomain("old.example.com")
	assert.False(t, ok)

	// New entry should be present
	got, ok := svc.getByDomain("new.example.com")
	require.True(t, ok)
	assert.Equal(t, "new.example.com", got.Config.Domain)
}

func TestKubernetesService_GetLabels_CacheHit(t *testing.T) {
	svc := newTestKubernetesService()
	svc.started = true

	app := config.App{Config: config.AppConfig{Domain: "hit.example.com"}}
	svc.addIngressApps("default", "ing", []ingressApp{
		{domain: "hit.example.com", appName: "hit", app: app},
	})

	got, err := svc.GetLabels("hit.example.com")
	require.NoError(t, err)
	assert.Equal(t, "hit.example.com", got.Config.Domain)
}

func TestKubernetesService_GetLabels_CacheMiss(t *testing.T) {
	svc := newTestKubernetesService()
	svc.started = true

	got, err := svc.GetLabels("notfound.example.com")
	require.NoError(t, err)
	assert.Equal(t, config.App{}, got)
}

func TestKubernetesService_GetLabels_ByAppName(t *testing.T) {
	svc := newTestKubernetesService()
	svc.started = true

	app := config.App{Config: config.AppConfig{Domain: "myapp.internal.example.com"}}
	svc.addIngressApps("default", "ing", []ingressApp{
		{domain: "myapp.internal.example.com", appName: "myapp", app: app},
	})

	// Look up by subdomain prefix matching appName
	got, err := svc.GetLabels("myapp.internal.example.com")
	require.NoError(t, err)
	assert.Equal(t, "myapp.internal.example.com", got.Config.Domain)
}

func TestKubernetesService_GetLabels_NotStarted(t *testing.T) {
	svc := newTestKubernetesService()
	// started is false by default

	got, err := svc.GetLabels("anything.example.com")
	require.NoError(t, err)
	assert.Equal(t, config.App{}, got)
}

func TestKubernetesService_UpdateFromItem(t *testing.T) {
	svc := newTestKubernetesService()

	item := unstructured.Unstructured{}
	item.SetNamespace("default")
	item.SetName("test-ingress")
	item.SetAnnotations(map[string]string{
		"tinyauth.apps.myapp.config.domain": "myapp.example.com",
		"tinyauth.apps.myapp.users.allow":   "alice",
	})

	svc.updateFromItem(&item)

	got, ok := svc.getByDomain("myapp.example.com")
	require.True(t, ok)
	assert.Equal(t, "myapp.example.com", got.Config.Domain)
	assert.Equal(t, "alice", got.Users.Allow)
}

func TestKubernetesService_UpdateFromItem_NoAnnotations(t *testing.T) {
	svc := newTestKubernetesService()

	// First add something to the cache
	app := config.App{Config: config.AppConfig{Domain: "todelete.example.com"}}
	svc.addIngressApps("default", "test-ingress", []ingressApp{
		{domain: "todelete.example.com", appName: "todelete", app: app},
	})

	// Now update with an item that has no annotations
	item := unstructured.Unstructured{}
	item.SetNamespace("default")
	item.SetName("test-ingress")

	svc.updateFromItem(&item)

	_, ok := svc.getByDomain("todelete.example.com")
	assert.False(t, ok)
}
