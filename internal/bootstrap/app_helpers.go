package bootstrap

import (
	"context"
	"errors"
	"fmt"

	"github.com/tinyauthapp/tinyauth/internal/utils"
)

// Not really the best place for the helpers to be but it works because bootstrap app provides
// them with everything they need

func (app *BootstrapApp) getCookieDomain(ctx context.Context, ip string) (string, error) {
	cookieDomain := app.runtime.CookieDomain

	if app.isTailscaleRequest(ctx, ip) {
		if app.services.tailscaleService == nil {
			return "", errors.New("tailscale service is not configured")
		}

		tsCookieDomain, err := utils.GetCookieDomain(fmt.Sprintf("https://%s", app.services.tailscaleService.GetHostname()))

		if err != nil {
			return "", fmt.Errorf("failed to get cookie domain for tailscale user: %w", err)
		}

		cookieDomain = tsCookieDomain
	}

	if app.config.Auth.SubdomainsEnabled {
		cookieDomain = "." + cookieDomain
	}

	return cookieDomain, nil
}

func (app *BootstrapApp) isTailscaleRequest(ctx context.Context, ip string) bool {
	if app.services.tailscaleService == nil {
		return false
	}

	whois, err := app.services.tailscaleService.Whois(ctx, ip)

	if err != nil {
		app.log.App.Error().Err(err).Msgf("Error performing Tailscale whois for IP %s: %v", ip, err)
		return false
	}

	if whois == nil {
		return false
	}

	return true
}
