package service

import (
	"strings"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

type LabelProvider interface {
	GetLabels(appDomain string) (*model.App, error)
}

type AccessControlsService struct {
	log           *logger.Logger
	config        *model.Config
	labelProvider *LabelProvider
}

func NewAccessControlsService(
	deps *ServiceDependencies,
) *AccessControlsService {

	return &AccessControlsService{
		log:           deps.Log,
		config:        deps.StaticConfig,
		labelProvider: &deps.LabelProvider,
	}
}

func (service *AccessControlsService) lookupStaticACLs(domain string) *model.App {
	var nameMatch *model.App

	// First try to find a matching app by domain, then fallback to matching by app name (subdomain)
	for app, config := range service.config.Apps {
		if config.Config.Domain == domain {
			service.log.App.Debug().Str("name", app).Msg("Found matching container by domain")
			return &config
		}
		if strings.SplitN(domain, ".", 2)[0] == app {
			service.log.App.Debug().Str("name", app).Msg("Found matching container by app name")
			nameMatch = &config
		}
	}

	return nameMatch
}

func (service *AccessControlsService) GetAccessControls(domain string) (*model.App, error) {
	// First check in the static config
	app := service.lookupStaticACLs(domain)

	if app != nil {
		service.log.App.Debug().Msg("Using static ACLs for app")
		return app, nil
	}

	// If we have a label provider configured, try to get ACLs from it
	if service.labelProvider != nil && *service.labelProvider != nil {
		return (*service.labelProvider).GetLabels(domain)
	}

	// no labels
	return nil, nil
}
