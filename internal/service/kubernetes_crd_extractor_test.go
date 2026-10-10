package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/pkg/apis/tinyauth/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientfake "k8s.io/client-go/kubernetes/fake"
)

func TestKubernetesCRDExtractorExtract(t *testing.T) {
	meta := &ResourceMeta{Typ: ResourceTypeCRD, Name: "dashboard", Namespace: "default"}
	base := testApplication("dashboard", "dashboard.example.com")
	base.Spec.Users.Allow = "alice"
	base.Spec.OAuth.Groups = "admins"
	base.Spec.IP.Allow = []string{"192.0.2.0/24"}
	base.Spec.Path.Block = "/private"
	base.Spec.Response.BasicAuth.Username = "viewer"
	withRef := base.DeepCopy()
	withRef.Spec.Response.BasicAuth.PasswordSecretRef = &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "credentials"}, Key: "password"}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "credentials", Namespace: "default"}, Data: map[string][]byte{"password": []byte("s3cret")}}
	missingKey := secret.DeepCopy()
	missingKey.Data = map[string][]byte{"other": []byte("s3cret")}
	app := model.App{
		Config:   model.AppConfig{Domain: "dashboard.example.com"},
		Users:    model.AppUsers{Allow: "alice"},
		OAuth:    model.AppOAuth{Groups: "admins"},
		IP:       model.AppIP{Allow: []string{"192.0.2.0/24"}},
		Path:     model.AppPath{Block: "/private"},
		Response: model.AppResponse{BasicAuth: model.AppBasicAuth{Username: "viewer"}},
	}
	withPassword := app
	withPassword.Response.BasicAuth.Password = "s3cret"
	tests := []struct {
		name        string
		resource    *corev1.Secret
		application func() *v1alpha1.Application
		want        ExtractionResult
		reads       int
	}{
		{"valid application", nil, func() *v1alpha1.Application { return base.DeepCopy() }, ExtractionResult{Meta: meta, Apps: map[string]model.App{"dashboard": app}}, 0},
		{"password from secret", secret, func() *v1alpha1.Application { return withRef.DeepCopy() }, ExtractionResult{Meta: meta, Apps: map[string]model.App{"dashboard": withPassword}}, 1},
		{"secret not found", nil, func() *v1alpha1.Application { return withRef.DeepCopy() }, ExtractionResult{Meta: meta}, 1},
		{"secret key not found", missingKey, func() *v1alpha1.Application { return withRef.DeepCopy() }, ExtractionResult{Meta: meta}, 1},
		{"missing domain", nil, func() *v1alpha1.Application { a := base.DeepCopy(); a.Spec.Config.Domain = ""; return a }, ExtractionResult{Meta: meta}, 0},
		{"non-ascii domain", nil, func() *v1alpha1.Application {
			a := base.DeepCopy()
			a.Spec.Config.Domain = "dömain.example.com"
			return a
		}, ExtractionResult{Meta: meta}, 0},
		{"missing name", nil, func() *v1alpha1.Application { a := base.DeepCopy(); a.Name = ""; return a }, ExtractionResult{}, 0},
		{"missing namespace", nil, func() *v1alpha1.Application { a := base.DeepCopy(); a.Namespace = ""; return a }, ExtractionResult{}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := clientfake.NewClientset()
			if tt.resource != nil {
				client = clientfake.NewClientset(tt.resource)
			}
			extractor := NewKubernetesCRDExtractor(KubernetesCRDInput{Log: kubernetesTestLogger(), Client: client})
			assert.Equal(t, tt.want, extractor.Extract(tt.application()))
			assert.Len(t, client.Actions(), tt.reads)
		})
	}
}
