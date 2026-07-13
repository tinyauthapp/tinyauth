package service

import (
	"strings"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/tinyauthapp/tinyauth/pkg/validators"
	"go.uber.org/dig"
)

type LabelProvider interface {
	GetLabels(appDomain string) (*model.App, error)
}

type AccessControlsService struct {
	log           *logger.Logger
	config        *model.Config
	labelProvider LabelProvider
}

type AccessControlServiceInput struct {
	dig.In

	Log           *logger.Logger
	Config        *model.Config
	LabelProvider LabelProvider `optional:"true"`
}

func NewAccessControlsService(i AccessControlServiceInput) *AccessControlsService {

	return &AccessControlsService{
		log:           i.Log,
		config:        i.Config,
		labelProvider: i.LabelProvider,
	}
}

func (service *AccessControlsService) lookupStaticACLs(domain string) (*model.App, error) {
	var nameMatch *model.App

	v := validators.NewDomainValidator(validators.DomainValidatorOptions{})

	// First try to find a matching app by domain, then fallback to matching by app name (subdomain)
	for app, config := range service.config.Apps {
		err := v.Validate(config.Config.Domain, domain)
		// Maybe not the best way to check if a match succeeded, but expected is only
		// used on match errors and not parsing errors
		if err != nil && !strings.HasPrefix(err.Error(), "expected") {
			return nil, err
		}
		if err == nil {
			service.log.App.Debug().Str("name", app).Msg("Found matching container by domain")
			return &config, nil
		}
		if strings.HasPrefix(domain, app+".") {
			service.log.App.Debug().Str("name", app).Msg("Found matching container by app name")
			nameMatch = &config
		}
	}

	return nameMatch, nil
}

func (service *AccessControlsService) GetAccessControls(domain string) (*model.App, error) {
	// First check in the static config
	app, err := service.lookupStaticACLs(domain)

	if err != nil {
		return nil, err
	}

	if app != nil {
		service.log.App.Debug().Msg("Using static ACLs for app")
		return app, nil
	}

	// If we have a label provider configured, try to get ACLs from it
	if service.labelProvider != nil {
		return service.labelProvider.GetLabels(domain)
	}

	// no labels
	return nil, nil
}
