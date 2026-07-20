package service

import (
	"strings"
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
				svc.addIngressEntries(ingressKey{
					namespace: "default",
					name:      "my-ingress",
				}, []ingressEntry{
					{
						app:  app,
						name: "foo",
					},
				})

				var got *model.App
				svc.getEntry(func(name string, app *model.App) bool {
					if app.Config.Domain == "foo.example.com" {
						got = app
						return true
					}
					return false
				})
				require.NotNil(t, got)
				assert.Equal(t, "foo.example.com", got.Config.Domain)
			},
		},
		{
			description: "RemoveIngress clears domain and app name entries",
			run: func(t *testing.T, svc *KubernetesService) {
				app := model.App{Config: model.AppConfig{Domain: "foo.example.com"}}
				svc.addIngressEntries(ingressKey{
					namespace: "default",
					name:      "my-ingress",
				}, []ingressEntry{
					{
						app:  app,
						name: "foo",
					},
				})

				var got *model.App
				svc.getEntry(func(name string, app *model.App) bool {
					if app.Config.Domain == "foo.example.com" {
						got = app
						return true
					}
					return false
				})
				require.NotNil(t, got)
				assert.Equal(t, "foo.example.com", got.Config.Domain)

				got = nil
				svc.removeIngress(ingressKey{
					namespace: "default",
					name:      "my-ingress",
				})

				svc.getEntry(func(name string, app *model.App) bool {
					if app.Config.Domain == "foo.example.com" {
						got = app
						return true
					}
					return false
				})
				assert.Nil(t, got)
			},
		},
		{
			description: "AddIngressApps replaces stale entries for the same ingress",
			run: func(t *testing.T, svc *KubernetesService) {
				old := model.App{Config: model.AppConfig{Domain: "old.example.com"}}
				svc.addIngressEntries(ingressKey{
					namespace: "default",
					name:      "my-ingress",
				}, []ingressEntry{
					{
						app:  old,
						name: "foo",
					},
				})

				updated := model.App{Config: model.AppConfig{Domain: "new.example.com"}}
				svc.addIngressEntries(ingressKey{
					namespace: "default",
					name:      "my-ingress",
				}, []ingressEntry{
					{
						app:  updated,
						name: "foo",
					},
				})

				var got *model.App
				svc.getEntry(func(name string, app *model.App) bool {
					if app.Config.Domain == "old.example.com" {
						got = app
						return true
					}
					return false
				})
				assert.Nil(t, got)

				svc.getEntry(func(name string, app *model.App) bool {
					if app.Config.Domain == "new.example.com" {
						got = app
						return true
					}
					return false
				})
				require.NotNil(t, got)
				assert.Equal(t, "new.example.com", got.Config.Domain)
			},
		},
		{
			description: "GetLabels returns app from cache when connected",
			run: func(t *testing.T, svc *KubernetesService) {
				svc.connected = true

				app := model.App{Config: model.AppConfig{Domain: "hit.example.com"}}
				svc.addIngressEntries(ingressKey{
					namespace: "default",
					name:      "my-ingress",
				}, []ingressEntry{
					{
						app:  app,
						name: "foo",
					},
				})

				var got *model.App
				err := svc.Lookup(func(name string, app *model.App) bool {
					if app.Config.Domain == "hit.example.com" {
						got = app
						return true
					}
					return false
				})
				require.NoError(t, err)
				require.NotNil(t, got)
				assert.Equal(t, "hit.example.com", got.Config.Domain)
			},
		},
		{
			description: "GetLabels returns empty app on cache miss when started",
			run: func(t *testing.T, svc *KubernetesService) {
				svc.connected = true

				var got *model.App
				err := svc.Lookup(func(name string, app *model.App) bool {
					if app.Config.Domain == "notfound.example.com" {
						got = app
						return true
					}
					return false
				})
				require.NoError(t, err)
				require.Nil(t, got)
			},
		},
		{
			description: "GetLabels resolves app by app name",
			run: func(t *testing.T, svc *KubernetesService) {
				svc.connected = true

				app := model.App{Path: model.AppPath{Allow: "/foo"}}
				svc.addIngressEntries(ingressKey{
					namespace: "default",
					name:      "my-ingress",
				}, []ingressEntry{
					{
						app:  app,
						name: "foo",
					},
				})

				var got *model.App
				err := svc.Lookup(func(name string, app *model.App) bool {
					if strings.HasPrefix("foo.internal.example.com", "foo.") {
						got = app
						return true
					}
					return false
				})
				require.NoError(t, err)
				require.NotNil(t, got)
				assert.Equal(t, "/foo", got.Path.Allow)
			},
		},
		{
			description: "GetLabels returns empty app when service not yet started",
			run: func(t *testing.T, svc *KubernetesService) {
				var got *model.App
				err := svc.Lookup(func(name string, app *model.App) bool {
					return false
				})
				require.NoError(t, err)
				assert.Nil(t, got)
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

				var got *model.App
				svc.getEntry(func(name string, app *model.App) bool {
					if app.Config.Domain == "myapp.example.com" {
						got = app
						return true
					}
					return false
				})

				require.NotNil(t, got)
				assert.Equal(t, "myapp.example.com", got.Config.Domain)
				assert.Equal(t, "alice", got.Users.Allow)
			},
		},
		{
			description: "UpdateFromItem with no annotations removes existing cache entries",
			run: func(t *testing.T, svc *KubernetesService) {
				app := model.App{Config: model.AppConfig{Domain: "todelete.example.com"}}
				svc.addIngressEntries(ingressKey{
					namespace: "default",
					name:      "my-ingress",
				}, []ingressEntry{
					{
						app:  app,
						name: "foo",
					},
				})

				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("my-ingress")

				svc.updateFromItem(&item)

				var got *model.App
				svc.getEntry(func(name string, app *model.App) bool {
					if app.Config.Domain == "todelete.example.com" {
						got = app
						return true
					}
					return false
				})
				assert.Nil(t, got)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			svc := &KubernetesService{
				ingressEntries: make(map[ingressKey][]ingressEntry),
				log:            log,
			}
			test.run(t, svc)
		})
	}
}
