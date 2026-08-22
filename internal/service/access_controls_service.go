package service

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"unicode"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
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

func (service *AccessControlsService) ensureAscii(str string) bool {
	for i := 0; i < len(str); i++ {
		if str[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func (service *AccessControlsService) normalizeDomain(domain string) string {
	if host, _, err := net.SplitHostPort(domain); err == nil {
		domain = host
	}
	domain = strings.TrimRight(domain, ".")
	return strings.ToLower(domain)
}

func (service *AccessControlsService) getACLs(domain string, lookup func(locator func(name string, app *model.App) bool) error) (*model.App, error) {
	if !service.ensureAscii(domain) {
		return nil, errors.New("domain contains non-ascii characters")
	}

	normalizedDomain := service.normalizeDomain(domain)

	var domainMatch *model.App
	var nameMatch *model.App
	var nameMatchedApps []string

	locatorFunc := func(name string, app *model.App) bool {
		if app.Config.Domain != "" {
			if !service.ensureAscii(app.Config.Domain) {
				service.log.App.Warn().Str("name", name).Str("domain", app.Config.Domain).Msg("Domain contains non-ascii characters, skipping")
				return false
			}
			if normalizedDomain == service.normalizeDomain(app.Config.Domain) {
				service.log.App.Debug().Str("name", name).Msg("Found matching container by domain")
				domainMatch = app
				return true
			}
			return false
		}
		if strings.HasPrefix(normalizedDomain, strings.ToLower(name+".")) {
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
		return nil, fmt.Errorf("multiple apps matched domain by name, app names must be unique")
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
