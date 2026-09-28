package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tinyauthapp/tinyauth/internal/model"
	networking "k8s.io/api/networking/v1"
)

func TestKubernetesIngressExtractorExtract(t *testing.T) {
	meta := &ResourceMeta{Typ: ResourceTypeIngress, Name: "route", Namespace: "default"}
	tests := []struct {
		name    string
		ingress *networking.Ingress
		want    ExtractionResult
	}{
		{
			name: "domain, name and wildcard match across hosts",
			ingress: testIngress("route", map[string]string{
				"tinyauth.apps.dashboard.config.domain": "app.example.com",
				"tinyauth.apps.dashboard.users.allow":   "alice",
				"tinyauth.apps.portal.users.allow":      "bob",
				"tinyauth.apps.other.users.allow":       "carol",
			}, "app.example.com", "Portal.example.com"),
			want: ExtractionResult{Meta: meta, Apps: map[string]model.App{
				"dashboard": {Config: model.AppConfig{Domain: "app.example.com"}, Users: model.AppUsers{Allow: "alice"}},
				"portal":    {Users: model.AppUsers{Allow: "bob"}},
			}},
		},
		{
			name: "wildcard matches configured domain",
			ingress: testIngress("route", map[string]string{
				"tinyauth.apps.dashboard.config.domain": "dashboard.example.com",
			}, "*.example.com"),
			want: ExtractionResult{Meta: meta, Apps: map[string]model.App{
				"dashboard": {Config: model.AppConfig{Domain: "dashboard.example.com"}},
			}},
		},
		{
			name:    "hostless rule matches name",
			ingress: testIngress("route", map[string]string{"tinyauth.apps.dashboard.users.allow": "alice"}, ""),
			want: ExtractionResult{Meta: meta, Apps: map[string]model.App{
				"dashboard": {Users: model.AppUsers{Allow: "alice"}},
			}},
		},
		{
			name:    "invalid domain falls back to name",
			ingress: testIngress("route", map[string]string{"tinyauth.apps.dashboard.config.domain": "dömain.example.com"}, "dashboard.example.com"),
			want: ExtractionResult{Meta: meta, Apps: map[string]model.App{
				"dashboard": {Config: model.AppConfig{Domain: "dömain.example.com"}},
			}},
		},
		{
			name:    "unmatched annotations yield empty apps",
			ingress: testIngress("route", map[string]string{"tinyauth.apps.other.users.allow": "alice"}, "dashboard.example.com"),
			want:    ExtractionResult{Meta: meta, Apps: map[string]model.App{}},
		},
		{
			name:    "no annotations yield empty apps",
			ingress: testIngress("route", nil, "dashboard.example.com"),
			want:    ExtractionResult{Meta: meta, Apps: map[string]model.App{}},
		},
		{
			name:    "invalid annotations",
			ingress: testIngress("route", map[string]string{"tinyauth.apps.dashboard.users.invalid": "alice"}, "dashboard.example.com"),
			want:    ExtractionResult{Meta: meta},
		},
		{
			name:    "no rules",
			ingress: testIngress("route", nil),
			want:    ExtractionResult{Meta: meta},
		},
		{
			name:    "missing name",
			ingress: testIngress("", nil, "app.example.com"),
			want:    ExtractionResult{},
		},
		{
			name:    "missing namespace",
			ingress: &networking.Ingress{},
			want:    ExtractionResult{},
		},
	}
	extractor := NewKubernetesIngressExtractor(KubernetesIngressExtractorInput{Log: kubernetesTestLogger()})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractor.Extract(tt.ingress))
		})
	}
}

func TestKubernetesIngressExtractorHostsAndPaths(t *testing.T) {
	extractor := NewKubernetesIngressExtractor(KubernetesIngressExtractorInput{Log: kubernetesTestLogger()})
	for _, tt := range []struct {
		name  string
		rules []networking.IngressRule
		hosts []string
		paths []string
	}{
		{"no rules", nil, nil, nil},
		{"no HTTP paths", []networking.IngressRule{{Host: "app.example.com"}}, []string{"app.example.com"}, nil},
		{"catch-all path", []networking.IngressRule{{Host: "app.example.com", IngressRuleValue: networking.IngressRuleValue{HTTP: &networking.HTTPIngressRuleValue{Paths: []networking.HTTPIngressPath{{Path: "/"}}}}}}, []string{"app.example.com"}, []string{"/"}},
		{"specific paths", []networking.IngressRule{{Host: "app.example.com", IngressRuleValue: networking.IngressRuleValue{HTTP: &networking.HTTPIngressRuleValue{Paths: []networking.HTTPIngressPath{{Path: "/login"}, {Path: "/admin"}}}}}}, []string{"app.example.com"}, []string{"/login", "/admin"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.hosts, extractor.getHosts(tt.rules))
			if len(tt.rules) > 0 {
				assert.Equal(t, tt.paths, extractor.getPaths(tt.rules[0]))
			}
		})
	}
}

func TestKubernetesHostMatching(t *testing.T) {
	for _, tt := range []struct {
		name, host, hostname string
		want                 bool
	}{
		{"exact", "app.example.com", "app.example.com", true},
		{"case insensitive and trailing dot", "App.Example.com.", "app.example.com", true},
		{"wildcard", "*.example.com", "app.example.com", true},
		{"wildcard case insensitive", "*.Example.com", "App.example.com", true},
		{"wildcard excludes apex", "*.example.com", "example.com", false},
		{"wildcard excludes empty label", "*.example.com", ".example.com", false},
		{"wildcard excludes nested labels", "*.example.com", "deep.app.example.com", false},
		{"wildcard excludes other suffix", "*.example.com", "app.other.com", false},
		{"different host", "app.example.com", "other.example.com", false},
		{"empty host", "", "other.example.com", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hostMatchesHostname(tt.host, tt.hostname))
		})
	}
}

func TestKubernetesHostCoversName(t *testing.T) {
	for _, tt := range []struct {
		host, name string
		want       bool
	}{
		{"", "dashboard", true},
		{"dashboard.example.com", "dashboard", true},
		{"Dashboard.example.com", "dashboard", true},
		{"*.example.com", "dashboard", true},
		{"other.example.com", "dashboard", false},
	} {
		t.Run(tt.host+"/"+tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hostCoversName(tt.host, tt.name))
		})
	}
}
