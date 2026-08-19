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

func mustWatchedResource(resource string) watchedResource {
	for _, res := range watchedResources {
		if res.gvr.Resource == resource {
			return res
		}
	}
	panic("unknown watched resource: " + resource)
}

var (
	testIngressResource   = mustWatchedResource("ingresses")
	testHTTPRouteResource = mustWatchedResource("httproutes")
	testGRPCRouteResource = mustWatchedResource("grpcroutes")
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
				svc.addResourceEntries(resourceKey{
					resource:  "ingresses",
					namespace: "default",
					name:      "my-ingress",
				}, []resourceEntry{
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
			description: "RemoveResource clears domain and app name entries",
			run: func(t *testing.T, svc *KubernetesService) {
				key := resourceKey{
					resource:  "ingresses",
					namespace: "default",
					name:      "my-ingress",
				}

				app := model.App{Config: model.AppConfig{Domain: "foo.example.com"}}
				svc.addResourceEntries(key, []resourceEntry{
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
				svc.removeResource(key)

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
			description: "AddResourceEntries replaces stale entries for the same resource",
			run: func(t *testing.T, svc *KubernetesService) {
				key := resourceKey{
					resource:  "ingresses",
					namespace: "default",
					name:      "my-ingress",
				}

				old := model.App{Config: model.AppConfig{Domain: "old.example.com"}}
				svc.addResourceEntries(key, []resourceEntry{
					{
						app:  old,
						name: "foo",
					},
				})

				updated := model.App{Config: model.AppConfig{Domain: "new.example.com"}}
				svc.addResourceEntries(key, []resourceEntry{
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
			description: "Resources of different kinds with the same name do not clobber each other",
			run: func(t *testing.T, svc *KubernetesService) {
				ingress := unstructured.Unstructured{}
				ingress.SetNamespace("default")
				ingress.SetName("shared")
				ingress.SetAnnotations(map[string]string{
					"tinyauth.apps.ingapp.config.domain": "ingapp.example.com",
				})
				require.NoError(t, unstructured.SetNestedSlice(ingress.Object, []any{
					map[string]any{
						"host": "ingapp.example.com",
					},
				}, "spec", "rules"))

				httpRoute := unstructured.Unstructured{}
				httpRoute.SetNamespace("default")
				httpRoute.SetName("shared")
				httpRoute.SetAnnotations(map[string]string{
					"tinyauth.apps.gwapp.config.domain": "gwapp.example.com",
				})
				require.NoError(t, unstructured.SetNestedStringSlice(httpRoute.Object, []string{
					"gwapp.example.com",
				}, "spec", "hostnames"))

				svc.updateFromItem(testIngressResource, &ingress)
				svc.updateFromItem(testHTTPRouteResource, &httpRoute)

				var got *model.App
				svc.getEntry(func(name string, app *model.App) bool {
					if app.Config.Domain == "ingapp.example.com" {
						got = app
						return true
					}
					return false
				})
				require.NotNil(t, got)

				got = nil
				svc.getEntry(func(name string, app *model.App) bool {
					if app.Config.Domain == "gwapp.example.com" {
						got = app
						return true
					}
					return false
				})
				require.NotNil(t, got)
			},
		},
		{
			description: "GetLabels returns app from cache when connected",
			run: func(t *testing.T, svc *KubernetesService) {
				svc.connected = true

				app := model.App{Config: model.AppConfig{Domain: "hit.example.com"}}
				svc.addResourceEntries(resourceKey{
					resource:  "ingresses",
					namespace: "default",
					name:      "my-ingress",
				}, []resourceEntry{
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
				svc.addResourceEntries(resourceKey{
					resource:  "ingresses",
					namespace: "default",
					name:      "my-ingress",
				}, []resourceEntry{
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
				item.Object["spec"] = map[string]any{
					"rules": []any{
						map[string]any{
							"host": "myapp.example.com",
						},
					},
				}

				svc.updateFromItem(testIngressResource, &item)

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
			description: "Update from item skips annotations with no hosts",
			run: func(t *testing.T, svc *KubernetesService) {
				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("test-ingress")
				item.SetAnnotations(map[string]string{
					"tinyauth.apps.myapp.config.domain": "myapp.example.com",
				})

				svc.updateFromItem(testIngressResource, &item)

				var got *model.App
				svc.getEntry(func(name string, app *model.App) bool {
					if app.Config.Domain == "myapp.example.com" {
						got = app
						return true
					}
					return false
				})
				assert.Nil(t, got)
			},
		},
		{
			description: "UpdateFromItem fails when label parsing fails",
			run: func(t *testing.T, svc *KubernetesService) {
				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("test-ingress")
				item.SetAnnotations(map[string]string{
					"tinyauth.apps.myapp.config.domain": "myapp.example.com",
					"tinyauth.apps.myapp.users.break":   "i-dont-exist",
				})
				item.Object["spec"] = map[string]any{
					"rules": []any{
						map[string]any{
							"host": "myapp.example.com",
						},
					},
				}

				svc.updateFromItem(testIngressResource, &item)

				var got *model.App
				svc.getEntry(func(name string, app *model.App) bool {
					if app.Config.Domain == "myapp.example.com" {
						got = app
						return true
					}
					return false
				})

				require.Nil(t, got)
			},
		},
		{
			description: "UpdateFromItem with no annotations removes existing cache entries",
			run: func(t *testing.T, svc *KubernetesService) {
				app := model.App{Config: model.AppConfig{Domain: "todelete.example.com"}}
				svc.addResourceEntries(resourceKey{
					resource:  "ingresses",
					namespace: "default",
					name:      "my-ingress",
				}, []resourceEntry{
					{
						app:  app,
						name: "foo",
					},
				})

				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("my-ingress")

				svc.updateFromItem(testIngressResource, &item)

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

				hosts, err := svc.extractHosts(testIngressResource, &item)
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

				hosts, err := svc.extractIngressHosts(&item)
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

				hosts, err := svc.extractIngressHosts(&item)
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

				hosts, err := svc.extractIngressHosts(&item)
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

				hosts, err := svc.extractIngressHosts(&item)
				require.Error(t, err)
				assert.Nil(t, hosts)
			},
		},
		{
			description: "ExtractRouteHosts returns the hostnames of a route",
			run: func(t *testing.T, svc *KubernetesService) {
				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("test-httproute")
				require.NoError(t, unstructured.SetNestedStringSlice(item.Object, []string{
					"foo.example.com",
					"",
					"*.bar.example.com",
				}, "spec", "hostnames"))

				hosts, err := svc.extractHosts(testHTTPRouteResource, &item)
				require.NoError(t, err)
				assert.Equal(t, []string{"foo.example.com", "*.bar.example.com"}, hosts)
			},
		},
		{
			description: "ExtractRouteHosts returns nothing when spec.hostnames is missing",
			run: func(t *testing.T, svc *KubernetesService) {
				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("test-httproute")

				hosts, err := svc.extractRouteHosts(testHTTPRouteResource, &item)
				require.NoError(t, err)
				assert.Empty(t, hosts)
			},
		},
		{
			description: "ExtractRouteHosts errors when spec.hostnames is not a string slice",
			run: func(t *testing.T, svc *KubernetesService) {
				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("test-httproute")
				require.NoError(t, unstructured.SetNestedField(item.Object, "invalid", "spec", "hostnames"))

				hosts, err := svc.extractRouteHosts(testHTTPRouteResource, &item)
				require.Error(t, err)
				assert.Nil(t, hosts)
			},
		},
		{
			description: "ExtractRoutePaths treats omitted matches as a catch all",
			run: func(t *testing.T, svc *KubernetesService) {
				paths, catchAll, err := svc.extractRoutePaths(map[string]any{})
				require.NoError(t, err)
				assert.True(t, catchAll)
				assert.Empty(t, paths)
			},
		},
		{
			description: "ExtractRoutePaths applies the default path match",
			run: func(t *testing.T, svc *KubernetesService) {
				paths, catchAll, err := svc.extractRoutePaths(map[string]any{
					"matches": []any{
						map[string]any{
							"path": map[string]any{},
						},
					},
				})
				require.NoError(t, err)
				assert.True(t, catchAll)
				assert.Equal(t, []string{"/"}, paths)
			},
		},
		{
			description: "ExtractRoutePaths reports no catch all for scoped path matches",
			run: func(t *testing.T, svc *KubernetesService) {
				paths, catchAll, err := svc.extractRoutePaths(map[string]any{
					"matches": []any{
						map[string]any{
							"path": map[string]any{
								"type":  "PathPrefix",
								"value": "/api",
							},
						},
						map[string]any{
							"path": map[string]any{
								"type":  "Exact",
								"value": "/",
							},
						},
						"not-a-map",
					},
				})
				require.NoError(t, err)
				assert.False(t, catchAll)
				assert.Equal(t, []string{"/api", "/"}, paths)
			},
		},
		{
			description: "ExtractRoutePaths treats a match without a path as a catch all",
			run: func(t *testing.T, svc *KubernetesService) {
				paths, catchAll, err := svc.extractRoutePaths(map[string]any{
					"matches": []any{
						map[string]any{
							"method": map[string]any{
								"service": "com.example.Service",
							},
						},
					},
				})
				require.NoError(t, err)
				assert.True(t, catchAll)
				assert.Empty(t, paths)
			},
		},
		{
			description: "ExtractRoutePaths errors when matches is not a slice",
			run: func(t *testing.T, svc *KubernetesService) {
				paths, catchAll, err := svc.extractRoutePaths(map[string]any{
					"matches": "invalid",
				})
				require.Error(t, err)
				assert.False(t, catchAll)
				assert.Nil(t, paths)
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
				require.NoError(t, unstructured.SetNestedStringSlice(item.Object, []string{
					"gwapp.example.com",
				}, "spec", "hostnames"))

				svc.updateFromItem(testHTTPRouteResource, &item)

				var got *model.App
				svc.getEntry(func(name string, app *model.App) bool {
					if app.Config.Domain == "gwapp.example.com" {
						got = app
						return true
					}
					return false
				})
				require.NotNil(t, got)
				assert.Equal(t, "gwapp.example.com", got.Config.Domain)
				assert.Equal(t, "bob", got.Users.Allow)
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
				require.NoError(t, unstructured.SetNestedStringSlice(item.Object, []string{
					"grpcapp.example.com",
				}, "spec", "hostnames"))

				svc.updateFromItem(testGRPCRouteResource, &item)

				var got *model.App
				svc.getEntry(func(name string, app *model.App) bool {
					if app.Config.Domain == "grpcapp.example.com" {
						got = app
						return true
					}
					return false
				})
				require.NotNil(t, got)
				assert.Equal(t, "grpcapp.example.com", got.Config.Domain)
				assert.Equal(t, "carol", got.Users.Allow)
			},
		},
		{
			description: "UpdateFromItem skips routes without hostnames",
			run: func(t *testing.T, svc *KubernetesService) {
				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("test-httproute")
				item.SetAnnotations(map[string]string{
					"tinyauth.apps.gwapp.config.domain": "gwapp.example.com",
				})

				svc.updateFromItem(testHTTPRouteResource, &item)

				var got *model.App
				svc.getEntry(func(name string, app *model.App) bool {
					got = app
					return true
				})
				assert.Nil(t, got)
			},
		},
		{
			description: "UpdateFromItem registers an app whose domain is covered by a wildcard hostname",
			run: func(t *testing.T, svc *KubernetesService) {
				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("test-httproute")
				item.SetAnnotations(map[string]string{
					"tinyauth.apps.gwapp.config.domain": "deep.gwapp.example.com",
				})
				require.NoError(t, unstructured.SetNestedStringSlice(item.Object, []string{
					"*.example.com",
				}, "spec", "hostnames"))

				svc.updateFromItem(testHTTPRouteResource, &item)

				var got *model.App
				svc.getEntry(func(name string, app *model.App) bool {
					if name == "gwapp" {
						got = app
						return true
					}
					return false
				})
				require.NotNil(t, got)
				assert.Equal(t, "deep.gwapp.example.com", got.Config.Domain)
			},
		},
		{
			description: "UpdateFromItem registers an app by name under a wildcard hostname",
			run: func(t *testing.T, svc *KubernetesService) {
				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("test-httproute")
				item.SetAnnotations(map[string]string{
					"tinyauth.apps.gwapp.users.allow": "alice",
				})
				require.NoError(t, unstructured.SetNestedStringSlice(item.Object, []string{
					"*.example.com",
				}, "spec", "hostnames"))

				svc.updateFromItem(testHTTPRouteResource, &item)

				var got *model.App
				svc.getEntry(func(name string, app *model.App) bool {
					if name == "gwapp" {
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
			description: "HostMatches honours the gateway api wildcard suffix rule",
			run: func(t *testing.T, svc *KubernetesService) {
				assert.True(t, hostMatches("foo.example.com", "foo.example.com"))
				assert.True(t, hostMatches("Foo.Example.com", "foo.example.com"))
				assert.False(t, hostMatches("bar.example.com", "foo.example.com"))

				// A wildcard is a suffix match over one or more labels
				assert.True(t, hostMatches("*.example.com", "foo.example.com"))
				assert.True(t, hostMatches("*.example.com", "foo.test.example.com"))
				assert.False(t, hostMatches("*.example.com", "example.com"))
				assert.False(t, hostMatches("*.example.com", "foo.example.net"))
			},
		},
		{
			description: "HostCoversName matches app names against a host",
			run: func(t *testing.T, svc *KubernetesService) {
				assert.True(t, hostCoversName("foo.example.com", "foo"))
				assert.True(t, hostCoversName("Foo.example.com", "FOO"))
				assert.False(t, hostCoversName("bar.example.com", "foo"))
				assert.False(t, hostCoversName("example.com", "foo"))

				// A wildcard routes <name>.<suffix> for every name
				assert.True(t, hostCoversName("*.example.com", "foo"))
				assert.True(t, hostCoversName("*.example.com", "bar"))
			},
		},
		{
			description: "UpdateFromItem registers a route that has no catch-all path",
			run: func(t *testing.T, svc *KubernetesService) {
				item := unstructured.Unstructured{}
				item.SetNamespace("default")
				item.SetName("test-httproute")
				item.SetAnnotations(map[string]string{
					"tinyauth.apps.gwapp.config.domain": "gwapp.example.com",
				})
				require.NoError(t, unstructured.SetNestedStringSlice(item.Object, []string{
					"gwapp.example.com",
				}, "spec", "hostnames"))
				require.NoError(t, unstructured.SetNestedSlice(item.Object, []any{
					map[string]any{
						"matches": []any{
							map[string]any{
								"path": map[string]any{
									"type":  "PathPrefix",
									"value": "/api",
								},
							},
						},
					},
				}, "spec", "rules"))

				svc.updateFromItem(testHTTPRouteResource, &item)

				var got *model.App
				svc.getEntry(func(name string, app *model.App) bool {
					if name == "gwapp" {
						got = app
						return true
					}
					return false
				})
				require.NotNil(t, got)
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
				require.NoError(t, unstructured.SetNestedSlice(ingress.Object, []any{
					map[string]any{
						"host": "ingapp.example.com",
					},
				}, "spec", "rules"))

				httpRoute := unstructured.Unstructured{}
				httpRoute.SetNamespace("default")
				httpRoute.SetName("my-httproute")
				httpRoute.SetAnnotations(map[string]string{
					"tinyauth.apps.gwapp.config.domain": "gwapp.example.com",
				})
				require.NoError(t, unstructured.SetNestedStringSlice(httpRoute.Object, []string{
					"gwapp.example.com",
				}, "spec", "hostnames"))

				svc.updateFromItem(testIngressResource, &ingress)
				svc.updateFromItem(testHTTPRouteResource, &httpRoute)

				var got *model.App
				svc.getEntry(func(name string, app *model.App) bool {
					if app.Config.Domain == "ingapp.example.com" {
						got = app
						return true
					}
					return false
				})
				require.NotNil(t, got)
				assert.Equal(t, "ingapp.example.com", got.Config.Domain)

				got = nil
				svc.getEntry(func(name string, app *model.App) bool {
					if app.Config.Domain == "gwapp.example.com" {
						got = app
						return true
					}
					return false
				})
				require.NotNil(t, got)
				assert.Equal(t, "gwapp.example.com", got.Config.Domain)
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

				svc.updateFromItem(testIngressResource, &item)

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

				svc.updateFromItem(testIngressResource, &item)

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

				svc.updateFromItem(testIngressResource, &item)

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

				svc.updateFromItem(testIngressResource, &item)

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
				key := resourceKey{
					resource:  "ingresses",
					namespace: "default",
					name:      "test-ingress",
				}
				svc.addResourceEntries(key, []resourceEntry{
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

				svc.updateFromItem(testIngressResource, &item)

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
				key := resourceKey{
					resource:  "ingresses",
					namespace: "default",
					name:      "test-ingress",
				}
				svc.addResourceEntries(key, []resourceEntry{
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

				svc.updateFromItem(testIngressResource, &item)

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
				resourceEntries: make(map[resourceKey][]resourceEntry),
				log:             log,
			}
			test.run(t, svc)
		})
	}
}
