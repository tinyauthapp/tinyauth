//go:build ignore

package service

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func watchedResourceForTest(t *testing.T, typ ResourceType) watchedResource {
	t.Helper()
	for _, resource := range supportedResources {
		if resource.typ == typ {
			return resource
		}
	}
	t.Fatalf("unsupported resource type %q", typ)
	return watchedResource{}
}

func newKubernetesServiceForTest(log *logger.Logger) *KubernetesService {
	service := &KubernetesService{
		apps: make(map[resourceKey]routedApps),
		log:  log,
	}
	service.extractors.ingress = NewKubernetesIngressExtractor(KubernetesIngressExtractorInput{Log: log})
	return service
}

func testIngress(name string, annotations map[string]string, hosts ...string) *typedItem {
	rules := make([]networking.IngressRule, 0, len(hosts))
	for _, host := range hosts {
		rules = append(rules, networking.IngressRule{Host: host})
	}
	return &typedItem{
		typ: ResourceTypeIngress,
		ingress: &networking.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", Annotations: annotations},
			Spec:       networking.IngressSpec{Rules: rules},
		},
	}
}

func lookupApp(service *KubernetesService, domain string) *model.App {
	var app *model.App
	service.getEntry(domain, func(name string, candidate *model.App) bool {
		if candidate.Config.Domain == domain || strings.HasPrefix(domain, name+".") {
			app = candidate
			return true
		}
		return false
	})
	return app
}

func TestKubernetesServiceUpdateFromItem(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	tests := []struct {
		name             string
		resource         ResourceType
		item             *typedItem
		domain           string
		wantConfigDomain string
		allow            string
	}{
		{
			name:     "Ingress matches a configured domain",
			resource: ResourceTypeIngress,
			item: testIngress("ingress", map[string]string{
				"tinyauth.apps.dashboard.config.domain": "dashboard.example.com",
				"tinyauth.apps.dashboard.users.allow":   "alice",
			}, "dashboard.example.com"),
			domain: "dashboard.example.com", wantConfigDomain: "dashboard.example.com", allow: "alice",
		},
		{
			name:     "Ingress matches an app name case insensitively",
			resource: ResourceTypeIngress,
			item: testIngress("ingress", map[string]string{
				"tinyauth.apps.dashboard.users.allow": "alice",
			}, "Dashboard.example.com"),
			domain: "dashboard.example.com", allow: "alice",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := newKubernetesServiceForTest(log)
			service.updateFromItem(watchedResourceForTest(t, test.resource), test.item)

			app := lookupApp(service, test.domain)
			require.NotNil(t, app)
			assert.Equal(t, test.allow, app.Users.Allow)
			assert.Equal(t, test.wantConfigDomain, app.Config.Domain)
		})
	}
}

func TestKubernetesServiceUpdateFromItemRemovesStaleEntries(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	tests := []struct {
		name     string
		resource ResourceType
		item     *typedItem
	}{
		{"Ingress without annotations", ResourceTypeIngress, testIngress("route", nil, "app.example.com")},
		{"Ingress without hosts", ResourceTypeIngress, testIngress("route", map[string]string{"tinyauth.apps.app.users.allow": "alice"})},
		{"Ingress with invalid annotations", ResourceTypeIngress, testIngress("route", map[string]string{"tinyauth.apps.app.users.break": "invalid"}, "app.example.com")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := newKubernetesServiceForTest(log)
			key := resourceKey{typ: test.resource, namespace: "default", name: "route"}
			service.addResourceEntries(key, []string{"app.example.com"}, []resourceEntry{{
				name: "app",
				app:  model.App{Config: model.AppConfig{Domain: "app.example.com"}},
			}})

			service.updateFromItem(watchedResourceForTest(t, test.resource), test.item)
			assert.Nil(t, lookupApp(service, "app.example.com"))
		})
	}
}

func TestTypedItemFromUnstructured(t *testing.T) {
	tests := []struct {
		name     string
		resource ResourceType
		item     unstructured.Unstructured
		assert   func(t *testing.T, item *typedItem)
	}{
		{
			name:     "Ingress",
			resource: ResourceTypeIngress,
			item: unstructured.Unstructured{Object: map[string]any{
				"metadata": map[string]any{"name": "ingress", "namespace": "default"},
				"spec":     map[string]any{"rules": []any{map[string]any{"host": "app.example.com"}}},
			}},
			assert: func(t *testing.T, item *typedItem) {
				require.NotNil(t, item.ingress)
				assert.Equal(t, "app.example.com", item.ingress.Spec.Rules[0].Host)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			item, err := new(typedItem).fromUnstructured(test.resource, &test.item)
			require.NoError(t, err)
			assert.Equal(t, test.resource, item.typ)
			test.assert(t, item)
		})
	}
}

func TestKubernetesServiceLookup(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()

	tests := []struct {
		name      string
		connected bool
		domain    string
		wantApp   bool
	}{
		{"Returns a matching app when connected", true, "app.example.com", true},
		{"Skips the cache before the service is connected", false, "app.example.com", false},
		{"Skips an invalid domain", true, "app.example.com\xC3\xA9", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := newKubernetesServiceForTest(log)
			service.connected = test.connected
			service.addResourceEntries(resourceKey{typ: ResourceTypeIngress, namespace: "default", name: "route"}, []string{"app.example.com"}, []resourceEntry{{
				name: "app",
				app:  model.App{Config: model.AppConfig{Domain: "app.example.com"}},
			}})

			var app *model.App
			err := service.Lookup(test.domain, func(_ string, candidate *model.App) bool {
				app = candidate
				return true
			})
			require.NoError(t, err)
			assert.Equal(t, test.wantApp, app != nil)
		})
	}
}

func TestKubernetesServiceKeepsResourceTypesSeparate(t *testing.T) {
	log := logger.NewLogger().WithTestConfig()
	log.Init()
	service := newKubernetesServiceForTest(log)

	resources := []struct {
		resource ResourceType
		item     *typedItem
		domain   string
	}{
		{ResourceTypeIngress, testIngress("shared", map[string]string{"tinyauth.apps.ingress.config.domain": "ingress.example.com"}, "ingress.example.com"), "ingress.example.com"},
	}

	for _, resource := range resources {
		service.updateFromItem(watchedResourceForTest(t, resource.resource), resource.item)
	}
	for _, resource := range resources {
		assert.NotNil(t, lookupApp(service, resource.domain))
	}
}

func TestKubernetesHostMatching(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		domain string
		want   bool
	}{
		{"Exact host", "app.example.com", "app.example.com", true},
		{"Case insensitive exact host", "App.Example.com", "app.example.com", true},
		{"Wildcard host", "*.example.com", "deep.app.example.com", true},
		{"Wildcard does not match its apex", "*.example.com", "example.com", false},
		{"Different host", "app.example.com", "other.example.com", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, hostMatchesHostname(test.host, test.domain))
		})
	}
}
