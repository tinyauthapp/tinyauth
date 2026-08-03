package service

import (
	"errors"
	"strings"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/tinyauthapp/tinyauth/pkg/validators"
	"go.uber.org/dig"
)

type LabelProvider interface {
	Lookup(locator func(name string, app *model.App) bool) error
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

func (service *AccessControlsService) getACLs(domain string, lookup func(locator func(name string, app *model.App) bool) error) (*model.App, error) {
	v := validators.NewDomainValidator(validators.DomainValidatorOptions{})

	var domainMatch *model.App
	var nameMatch *model.App
	var nameMatchedApps []string

	locatorFunc := func(name string, app *model.App) bool {
		if app.Config.Domain != "" {
			err := v.Validate(app.Config.Domain, domain)
			if err == nil {
				service.log.App.Debug().Str("name", name).Msg("Found matching container by domain")
				domainMatch = app
				return true
			} else if !errors.Is(err, validators.ErrHostnameMismatch) {
				service.log.App.Debug().Str("name", name).Err(err).Msg("Domain validation failed")
			}
		}
		if strings.HasPrefix(strings.ToLower(domain), strings.ToLower(name+".")) {
			service.log.App.Debug().Str("name", name).Msg("Found matching container by app name")
			nameMatch = app
			nameMatchedApps = append(nameMatchedApps, name)
		}
		return false
	}

	err := lookup(locatorFunc)
	if err != nil {
		return nil, err
	}

	if domainMatch != nil {
		service.log.App.Debug().Str("domain", domain).Msg("Found matching app by domain")
		return domainMatch, nil
	}

	if nameMatch == nil {
		service.log.App.Debug().Str("domain", domain).Msg("No match found for domain, skipping")
		return nil, nil
	}

	if len(nameMatchedApps) > 1 {
		service.log.App.Warn().Str("domain", domain).Strs("apps", nameMatchedApps).Msg("Multiple apps matched domain by name, app names must be unique, using last match")
	}

	service.log.App.Debug().Str("domain", domain).Msg("Found matching app by app name")
	return nameMatch, nil
}

func (service *AccessControlsService) lookupStaticACLs(domain string) (*model.App, error) {
	return service.getACLs(domain, func(locator func(name string, app *model.App) bool) error {
		for app, config := range service.config.Apps {
			if ok := locator(app, &config); ok {
				return nil
			}
		}
		return nil
	})
}

func (service *AccessControlsService) GetAccessControls(domain string) (*model.App, error) {
	// First check in the static config
	app, err := service.lookupStaticACLs(domain)

	// Will never return an error here, but we need to check it
	if err != nil {
		return nil, err
	}

	if app != nil {
		service.log.App.Debug().Msg("Using static ACLs for app")
		return app, nil
	}

	// If we have a label provider configured, try to get ACLs from it
	if service.labelProvider != nil {
		return service.getACLs(domain, service.labelProvider.Lookup)
	}

	// No labels
	return nil, nil
}
