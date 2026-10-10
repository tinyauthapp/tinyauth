package service

import (
	"context"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/tinyauthapp/tinyauth/pkg/apis/tinyauth/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type KubernetesCRDInput struct {
	Log    *logger.Logger
	Client kubernetes.Interface
}

type KubernetesCRDExtractor struct {
	log    *logger.Logger
	client kubernetes.Interface
}

func NewKubernetesCRDExtractor(i KubernetesCRDInput) *KubernetesCRDExtractor {
	return &KubernetesCRDExtractor{
		log:    i.Log,
		client: i.Client,
	}
}

func (k *KubernetesCRDExtractor) Extract(app *v1alpha1.Application) ExtractionResult {
	meta := &ResourceMeta{
		Typ:       ResourceTypeCRD,
		Name:      app.GetName(),
		Namespace: app.GetNamespace(),
	}

	if !ensureResourceMeta(meta) {
		k.log.App.Warn().Str("namespace", meta.Namespace).Str("name", meta.Name).Msg("Resource has no namespace or name, skipping")
		return ExtractionResult{}
	}

	if app.Spec.Config.Domain == "" {
		k.log.App.Warn().Str("name", meta.Name).Str("namespace", meta.Namespace).Msg("Application has no domain, skipping")
		return ExtractionResult{
			Meta: meta,
			Apps: nil,
		}
	}

	if !ensureAscii(app.Spec.Config.Domain) {
		k.log.App.Warn().Str("name", meta.Name).Str("namespace", meta.Namespace).Str("domain", app.Spec.Config.Domain).Msg("Domain is invalid, skipping")
		return ExtractionResult{
			Meta: meta,
			Apps: nil,
		}
	}

	// Convert the CRD to the internal representation.
	internalApp := app.Spec.ToInternalApp()
	passwordRef := app.Spec.Response.BasicAuth.PasswordSecretRef
	if passwordRef != nil {
		secret, err := k.client.CoreV1().Secrets(meta.Namespace).Get(context.Background(), passwordRef.Name, metav1.GetOptions{})
		if err != nil {
			k.log.App.Warn().Err(err).Str("namespace", meta.Namespace).Str("name", meta.Name).Str("secret", passwordRef.Name).Str("key", passwordRef.Key).Msg("Failed to read basic auth password Secret, skipping")
			return ExtractionResult{Meta: meta}
		}

		password, ok := secret.Data[passwordRef.Key]
		if !ok {
			k.log.App.Warn().Str("namespace", meta.Namespace).Str("name", meta.Name).Str("secret", passwordRef.Name).Str("key", passwordRef.Key).Msg("Basic auth password Secret key does not exist, skipping")
			return ExtractionResult{Meta: meta}
		}

		internalApp.Response.BasicAuth.Password = string(password)
	}

	return ExtractionResult{
		Meta: meta,
		Apps: map[string]model.App{
			meta.Name: internalApp,
		},
	}
}
