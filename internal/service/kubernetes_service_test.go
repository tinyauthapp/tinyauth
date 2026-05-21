package service

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

func TestKubernetesService(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	type testCase struct {
		description string
		run         func(t *testing.T, svc *KubernetesService)
	}

	tests := []testCase{
		{
			description: "Cache by domain returns app and misses unknown domain",
			run: func(t *testing.T, svc *KubernetesService) {
				app := model.App{Config: model.AppConfig{Domain: "foo.example.com"}}
				svc.addResourceApps("default", "my-ingress", []resourceApp{
					{domain: "foo.example.com", appName: "foo", app: app},
				})

				got := svc.getByDomain("foo.example.com")
				require.NotNil(t, got)
				assert.Equal(t, "foo.example.com", got.Config.Domain)

				got = svc.getByDomain("notfound.example.com")
				assert.Nil(t, got)
			},
		},
		{
			description: "Cache by app name returns app and misses unknown name",
			run: func(t *testing.T, svc *KubernetesService) {
				app := model.App{Config: model.AppConfig{Domain: "bar.example.com"}}
				svc.addResourceApps("default", "my-ingress", []resourceApp{
					{domain: "bar.example.com", appName: "bar", app: app},
				})

				got := svc.getByAppName("bar")
				require.NotNil(t, got)
				assert.Equal(t, "bar.example.com", got.Config.Domain)

				got = svc.getByAppName("notfound")
				assert.Nil(t, got)
			},
		},
		{
			description: "RemoveResource clears domain and app name entries",
			run: func(t *testing.T, svc *KubernetesService) {
				app := model.App{Config: model.AppConfig{Domain: "baz.example.com"}}
				svc.addResourceApps("default", "my-ingress", []resourceApp{
					{domain: "baz.example.com", appName: "baz", app: app},
				})

				svc.removeResource("default", "my-ingress")

				got := svc.getByDomain("baz.example.com")
				assert.Nil(t, got)
				got = svc.getByAppName("baz")
				assert.Nil(t, got)
			},
		},
		{
			description: "AddResourceApps replaces stale entries for the same resource",
			run: func(t *testing.T, svc *KubernetesService) {
				old := model.App{Config: model.AppConfig{Domain: "old.example.com"}}
				svc.addResourceApps("default", "my-ingress", []resourceApp{
					{domain: "old.example.com", appName: "old", app: old},
				})

				updated := model.App{Config: model.AppConfig{Domain: "new.example.com"}}
				svc.addResourceApps("default", "my-ingress", []resourceApp{
					{domain: "new.example.com", appName: "new", app: updated},
				})

				got := svc.getByDomain("old.example.com")
				assert.Nil(t, got)

				got = svc.getByDomain("new.example.com")
				require.NotNil(t, got)
				assert.Equal(t, "new.example.com", got.Config.Domain)
			},
		},
		{
			description: "GetLabels returns app from cache when started",
			run: func(t *testing.T, svc *KubernetesService) {
				svc.started = true

				app := model.App{Config: model.AppConfig{Domain: "hit.example.com"}}
				svc.addResourceApps("default", "ing", []resourceApp{
					{domain: "hit.example.com", appName: "hit", app: app},
				})

				got, err := svc.GetLabels("hit.example.com")
				require.NoError(t, err)
				assert.Equal(t, "hit.example.com", got.Config.Domain)
			},
		},
		{
			description: "GetLabels returns empty app on cache miss when started",
			run: func(t *testing.T, svc *KubernetesService) {
				svc.started = true

				got, err := svc.GetLabels("notfound.example.com")
				require.NoError(t, err)
				assert.Nil(t, got)
			},
		},
		{
			description: "GetLabels resolves app by app name",
			run: func(t *testing.T, svc *KubernetesService) {
				svc.started = true

				app := model.App{Config: model.AppConfig{Domain: "myapp.internal.example.com"}}
				svc.addResourceApps("default", "ing", []resourceApp{
					{domain: "myapp.internal.example.com", appName: "myapp", app: app},
				})

				got, err := svc.GetLabels("myapp.internal.example.com")
				require.NoError(t, err)
				assert.Equal(t, "myapp.internal.example.com", got.Config.Domain)
			},
		},
		{
			description: "GetLabels returns empty app when service not yet started",
			run: func(t *testing.T, svc *KubernetesService) {
				got, err := svc.GetLabels("anything.example.com")
				require.NoError(t, err)
				assert.Nil(t, got)
			},
		},
		{
			description: "UpdateFromItem parses annotations and populates cache from ingress",
			run: func(t *testing.T, svc *KubernetesService) {
				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("test-ingress")
				item.SetAnnotations(map[string]string{
					"tinyauth.apps.myapp.config.domain": "myapp.example.com",
					"tinyauth.apps.myapp.users.allow":   "alice",
				})

				svc.updateFromItem(&item)

				got := svc.getByDomain("myapp.example.com")
				require.NotNil(t, got)
				assert.Equal(t, "myapp.example.com", got.Config.Domain)
				assert.Equal(t, "alice", got.Users.Allow)
			},
		},
		{
			description: "UpdateFromItem parses annotations and populates cache from httproute",
			run: func(t *testing.T, svc *KubernetesService) {
				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("test-httproute")
				item.SetAnnotations(map[string]string{
					"tinyauth.apps.gwapp.config.domain": "gwapp.example.com",
					"tinyauth.apps.gwapp.users.allow":   "bob",
				})

				svc.updateFromItem(&item)

				got := svc.getByDomain("gwapp.example.com")
				require.NotNil(t, got)
				assert.Equal(t, "gwapp.example.com", got.Config.Domain)
				assert.Equal(t, "bob", got.Users.Allow)
			},
		},
		{
			description: "UpdateFromItem with no annotations removes existing cache entries",
			run: func(t *testing.T, svc *KubernetesService) {
				app := model.App{Config: model.AppConfig{Domain: "todelete.example.com"}}
				svc.addResourceApps("default", "test-ingress", []resourceApp{
					{domain: "todelete.example.com", appName: "todelete", app: app},
				})

				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("test-ingress")

				svc.updateFromItem(&item)

				got := svc.getByDomain("todelete.example.com")
				assert.Nil(t, got)
			},
		},
		{
			description: "UpdateFromItem parses annotations and populates cache from grpcroute",
			run: func(t *testing.T, svc *KubernetesService) {
				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("test-grpcroute")
				item.SetAnnotations(map[string]string{
					"tinyauth.apps.grpcapp.config.domain": "grpcapp.example.com",
					"tinyauth.apps.grpcapp.users.allow":   "carol",
				})

				svc.updateFromItem(&item)

				got := svc.getByDomain("grpcapp.example.com")
				require.NotNil(t, got)
				assert.Equal(t, "grpcapp.example.com", got.Config.Domain)
				assert.Equal(t, "carol", got.Users.Allow)
			},
		},
		{
			description: "Ingress and HTTPRoute apps coexist in cache",
			run: func(t *testing.T, svc *KubernetesService) {
				ingress := unstructured.Unstructured{}
				ingress.SetNamespace("default")
				ingress.SetName("my-ingress")
				ingress.SetAnnotations(map[string]string{
					"tinyauth.apps.ingapp.config.domain": "ingapp.example.com",
				})

				httproute := unstructured.Unstructured{}
				httproute.SetNamespace("default")
				httproute.SetName("my-httproute")
				httproute.SetAnnotations(map[string]string{
					"tinyauth.apps.gwapp.config.domain": "gwapp.example.com",
				})

				svc.updateFromItem(&ingress)
				svc.updateFromItem(&httproute)

				got := svc.getByDomain("ingapp.example.com")
				require.NotNil(t, got)
				assert.Equal(t, "ingapp.example.com", got.Config.Domain)

				got = svc.getByDomain("gwapp.example.com")
				require.NotNil(t, got)
				assert.Equal(t, "gwapp.example.com", got.Config.Domain)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			svc := &KubernetesService{
				resourceApps: make(map[resourceKey][]resourceApp),
				domainIndex:  make(map[string]resourceAppKey),
				appNameIndex: make(map[string]resourceAppKey),
				log:          log,
			}
			test.run(t, svc)
		})
	}
}
