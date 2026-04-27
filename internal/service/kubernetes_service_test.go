package service

import (
	"testing"

	"github.com/tinyauthapp/tinyauth/internal/config"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKubernetesService(t *testing.T) {
	type testCase struct {
		description string
		run         func(t *testing.T, svc *KubernetesService)
	}

	tests := []testCase{
		{
			description: "Cache by domain returns app and misses unknown domain",
			run: func(t *testing.T, svc *KubernetesService) {
				app := config.App{Config: config.AppConfig{Domain: "foo.example.com"}}
				svc.addIngressApps("default", "my-ingress", []ingressApp{
					{domain: "foo.example.com", appName: "foo", app: app},
				})

				got, ok := svc.getByDomain("foo.example.com")
				require.True(t, ok)
				assert.Equal(t, "foo.example.com", got.Config.Domain)

				_, ok = svc.getByDomain("notfound.example.com")
				assert.False(t, ok)
			},
		},
		{
			description: "Cache by app name returns app and misses unknown name",
			run: func(t *testing.T, svc *KubernetesService) {
				app := config.App{Config: config.AppConfig{Domain: "bar.example.com"}}
				svc.addIngressApps("default", "my-ingress", []ingressApp{
					{domain: "bar.example.com", appName: "bar", app: app},
				})

				got, ok := svc.getByAppName("bar")
				require.True(t, ok)
				assert.Equal(t, "bar.example.com", got.Config.Domain)

				_, ok = svc.getByAppName("notfound")
				assert.False(t, ok)
			},
		},
		{
			description: "RemoveIngress clears domain and app name entries",
			run: func(t *testing.T, svc *KubernetesService) {
				app := config.App{Config: config.AppConfig{Domain: "baz.example.com"}}
				svc.addIngressApps("default", "my-ingress", []ingressApp{
					{domain: "baz.example.com", appName: "baz", app: app},
				})

				svc.removeIngress("default", "my-ingress")

				_, ok := svc.getByDomain("baz.example.com")
				assert.False(t, ok)
				_, ok = svc.getByAppName("baz")
				assert.False(t, ok)
			},
		},
		{
			description: "AddIngressApps replaces stale entries for the same ingress",
			run: func(t *testing.T, svc *KubernetesService) {
				old := config.App{Config: config.AppConfig{Domain: "old.example.com"}}
				svc.addIngressApps("default", "my-ingress", []ingressApp{
					{domain: "old.example.com", appName: "old", app: old},
				})

				updated := config.App{Config: config.AppConfig{Domain: "new.example.com"}}
				svc.addIngressApps("default", "my-ingress", []ingressApp{
					{domain: "new.example.com", appName: "new", app: updated},
				})

				_, ok := svc.getByDomain("old.example.com")
				assert.False(t, ok)

				got, ok := svc.getByDomain("new.example.com")
				require.True(t, ok)
				assert.Equal(t, "new.example.com", got.Config.Domain)
			},
		},
		{
			description: "GetLabels returns app from cache when started",
			run: func(t *testing.T, svc *KubernetesService) {
				svc.started = true

				app := config.App{Config: config.AppConfig{Domain: "hit.example.com"}}
				svc.addIngressApps("default", "ing", []ingressApp{
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
				assert.Equal(t, config.App{}, got)
			},
		},
		{
			description: "GetLabels resolves app by app name",
			run: func(t *testing.T, svc *KubernetesService) {
				svc.started = true

				app := config.App{Config: config.AppConfig{Domain: "myapp.internal.example.com"}}
				svc.addIngressApps("default", "ing", []ingressApp{
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
				assert.Equal(t, config.App{}, got)
			},
		},
		{
			description: "UpdateFromItem parses annotations and populates cache",
			run: func(t *testing.T, svc *KubernetesService) {
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
			},
		},
		{
			description: "UpdateFromItem with no annotations removes existing cache entries",
			run: func(t *testing.T, svc *KubernetesService) {
				app := config.App{Config: config.AppConfig{Domain: "todelete.example.com"}}
				svc.addIngressApps("default", "test-ingress", []ingressApp{
					{domain: "todelete.example.com", appName: "todelete", app: app},
				})

				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("test-ingress")

				svc.updateFromItem(&item)

				_, ok := svc.getByDomain("todelete.example.com")
				assert.False(t, ok)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			svc := &KubernetesService{
				ingressApps:  make(map[ingressKey][]ingressApp),
				domainIndex:  make(map[string]ingressAppKey),
				appNameIndex: make(map[string]ingressAppKey),
			}
			test.run(t, svc)
		})
	}
}
