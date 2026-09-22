package service

import (
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/tinyauthapp/tinyauth/pkg/apis/tinyauth/v1alpha1"
)

type KubernetesCRDInput struct {
	Log *logger.Logger
}

type KubernetesCRDExtractor struct {
	log *logger.Logger
}

func NewKubernetesCRDExtractor(i KubernetesCRDInput) *KubernetesCRDExtractor {
	return &KubernetesCRDExtractor{
		log: i.Log,
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

	return ExtractionResult{
		Meta: meta,
		Apps: map[string]model.App{
			// Convert the CRD to the internal representation
			meta.Name: app.Spec.ToInternalApp(),
		},
	}
}
