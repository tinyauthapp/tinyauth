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
		{
			description: "ExtractPaths returns all non empty paths from a rule",
			run: func(t *testing.T, svc *KubernetesService) {
				rule := map[string]any{
					"http": map[string]any{
						"paths": []any{
							map[string]any{"path": "/"},
							map[string]any{"path": "/api"},
							map[string]any{"path": ""},
							map[string]any{"pathType": "Prefix"},
							"not-a-map",
						},
					},
				}

				paths, err := svc.extractPaths(rule)
				require.NoError(t, err)
				assert.Equal(t, []string{"/", "/api"}, paths)
			},
		},
		{
			description: "ExtractPaths returns nothing when http or paths are missing",
			run: func(t *testing.T, svc *KubernetesService) {
				paths, err := svc.extractPaths(map[string]any{})
				require.NoError(t, err)
				assert.Empty(t, paths)

				paths, err = svc.extractPaths(map[string]any{
					"http": map[string]any{},
				})
				require.NoError(t, err)
				assert.Empty(t, paths)
			},
		},
		{
			description: "ExtractPaths errors when http is not a map",
			run: func(t *testing.T, svc *KubernetesService) {
				paths, err := svc.extractPaths(map[string]any{
					"http": "invalid",
				})
				require.Error(t, err)
				assert.Nil(t, paths)
			},
		},
		{
			description: "ExtractPaths errors when paths is not a slice",
			run: func(t *testing.T, svc *KubernetesService) {
				paths, err := svc.extractPaths(map[string]any{
					"http": map[string]any{
						"paths": "invalid",
					},
				})
				require.Error(t, err)
				assert.Nil(t, paths)
			},
		},
		{
			description: "ExtractHosts returns hosts from all rules",
			run: func(t *testing.T, svc *KubernetesService) {
				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("test-ingress")
				require.NoError(t, unstructured.SetNestedSlice(item.Object, []any{
					map[string]any{
						"host": "foo.example.com",
						"http": map[string]any{
							"paths": []any{
								map[string]any{"path": "/"},
							},
						},
					},
					map[string]any{
						"host": "bar.example.com",
					},
					map[string]any{
						"host": "",
					},
					"not-a-map",
				}, "spec", "rules"))

				hosts, err := svc.extractHosts(&item)
				require.NoError(t, err)
				assert.Equal(t, []string{"foo.example.com", "bar.example.com"}, hosts)
			},
		},
		{
			description: "ExtractHosts still returns hosts when a rule has no catch all path",
			run: func(t *testing.T, svc *KubernetesService) {
				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("test-ingress")
				require.NoError(t, unstructured.SetNestedSlice(item.Object, []any{
					map[string]any{
						"host": "foo.example.com",
						"http": map[string]any{
							"paths": []any{
								map[string]any{"path": "/api"},
							},
						},
					},
				}, "spec", "rules"))

				hosts, err := svc.extractHosts(&item)
				require.NoError(t, err)
				assert.Equal(t, []string{"foo.example.com"}, hosts)
			},
		},
		{
			description: "ExtractHosts still returns hosts when path extraction fails",
			run: func(t *testing.T, svc *KubernetesService) {
				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("test-ingress")
				require.NoError(t, unstructured.SetNestedSlice(item.Object, []any{
					map[string]any{
						"host": "foo.example.com",
						"http": "invalid",
					},
				}, "spec", "rules"))

				hosts, err := svc.extractHosts(&item)
				require.NoError(t, err)
				assert.Equal(t, []string{"foo.example.com"}, hosts)
			},
		},
		{
			description: "ExtractHosts returns nothing when spec.rules is missing",
			run: func(t *testing.T, svc *KubernetesService) {
				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("test-ingress")

				hosts, err := svc.extractHosts(&item)
				require.NoError(t, err)
				assert.Empty(t, hosts)
			},
		},
		{
			description: "ExtractHosts errors when spec.rules is not a slice",
			run: func(t *testing.T, svc *KubernetesService) {
				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("test-ingress")
				require.NoError(t, unstructured.SetNestedField(item.Object, "invalid", "spec", "rules"))

				hosts, err := svc.extractHosts(&item)
				require.Error(t, err)
				assert.Nil(t, hosts)
			},
		},
		{
			description: "UpdateFromItem registers app when its domain matches an ingress host",
			run: func(t *testing.T, svc *KubernetesService) {
				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("test-ingress")
				item.SetAnnotations(map[string]string{
					"tinyauth.apps.myapp.config.domain": "myapp.example.com",
				})
				require.NoError(t, unstructured.SetNestedSlice(item.Object, []any{
					map[string]any{
						"host": "myapp.example.com",
					},
				}, "spec", "rules"))

				svc.updateFromItem(&item)

				var got *model.App
				svc.getEntry(func(name string, app *model.App) bool {
					if name == "myapp" {
						got = app
						return true
					}
					return false
				})
				require.NotNil(t, got)
				assert.Equal(t, "myapp.example.com", got.Config.Domain)
			},
		},
		{
			description: "UpdateFromItem registers app when its name matches an ingress host prefix",
			run: func(t *testing.T, svc *KubernetesService) {
				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("test-ingress")
				item.SetAnnotations(map[string]string{
					"tinyauth.apps.myapp.users.allow": "alice",
				})
				require.NoError(t, unstructured.SetNestedSlice(item.Object, []any{
					map[string]any{
						"host": "MyApp.example.com",
					},
				}, "spec", "rules"))

				svc.updateFromItem(&item)

				var got *model.App
				svc.getEntry(func(name string, app *model.App) bool {
					if name == "myapp" {
						got = app
						return true
					}
					return false
				})
				require.NotNil(t, got)
				assert.Equal(t, "alice", got.Users.Allow)
			},
		},
		{
			description: "UpdateFromItem skips apps that match neither host nor name",
			run: func(t *testing.T, svc *KubernetesService) {
				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("test-ingress")
				item.SetAnnotations(map[string]string{
					"tinyauth.apps.myapp.config.domain": "myapp.example.com",
				})
				require.NoError(t, unstructured.SetNestedSlice(item.Object, []any{
					map[string]any{
						"host": "other.example.com",
					},
				}, "spec", "rules"))

				svc.updateFromItem(&item)

				var got *model.App
				svc.getEntry(func(name string, app *model.App) bool {
					got = app
					return true
				})
				assert.Nil(t, got)
			},
		},
		{
			description: "UpdateFromItem falls back to app name when the domain is invalid",
			run: func(t *testing.T, svc *KubernetesService) {
				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("test-ingress")
				item.SetAnnotations(map[string]string{
					"tinyauth.apps.myapp.config.domain": "not a domain",
				})
				require.NoError(t, unstructured.SetNestedSlice(item.Object, []any{
					map[string]any{
						"host": "myapp.example.com",
					},
				}, "spec", "rules"))

				svc.updateFromItem(&item)

				var got *model.App
				svc.getEntry(func(name string, app *model.App) bool {
					if name == "myapp" {
						got = app
						return true
					}
					return false
				})
				require.NotNil(t, got)
			},
		},
		{
			description: "UpdateFromItem removes entries when host extraction fails",
			run: func(t *testing.T, svc *KubernetesService) {
				key := ingressKey{
					namespace: "default",
					name:      "test-ingress",
				}
				svc.addIngressEntries(key, []ingressEntry{
					{
						app:  model.App{Config: model.AppConfig{Domain: "stale.example.com"}},
						name: "foo",
					},
				})

				item := unstructured.Unstructured{}
				item.SetNamespace(key.namespace)
				item.SetName(key.name)
				item.SetAnnotations(map[string]string{
					"tinyauth.apps.myapp.config.domain": "myapp.example.com",
				})
				require.NoError(t, unstructured.SetNestedField(item.Object, "invalid", "spec", "rules"))

				svc.updateFromItem(&item)

				var got *model.App
				svc.getEntry(func(name string, app *model.App) bool {
					got = app
					return true
				})
				assert.Nil(t, got)
			},
		},
		{
			description: "UpdateFromItem removes entries when annotations are not decodable",
			run: func(t *testing.T, svc *KubernetesService) {
				key := ingressKey{
					namespace: "default",
					name:      "test-ingress",
				}
				svc.addIngressEntries(key, []ingressEntry{
					{
						app:  model.App{Config: model.AppConfig{Domain: "stale.example.com"}},
						name: "foo",
					},
				})

				item := unstructured.Unstructured{}
				item.SetNamespace(key.namespace)
				item.SetName(key.name)
				item.SetAnnotations(map[string]string{
					"tinyauth.apps.myapp.config.oauthWhitelist": "[",
				})

				svc.updateFromItem(&item)

				var got *model.App
				svc.getEntry(func(name string, app *model.App) bool {
					got = app
					return true
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
