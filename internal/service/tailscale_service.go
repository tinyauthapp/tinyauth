package service

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/steveiliop56/ding"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/tinyauthapp/tinyauth/pkg/cache"
	"go.uber.org/dig"
)

const tailscaleAPIBaseURL = "https://api.tailscale.com/api/v2"

var (
	tailscaleAPIDeviceList = func(tailnet string) string {
		return tailscaleAPIBaseURL + "/tailnet/" + tailnet + "/devices"
	}
	tailscaleAPIUserList = func(tailnet string) string {
		return tailscaleAPIBaseURL + "/tailnet/" + tailnet + "/users"
	}
)

type tailscaleDevice struct {
	Addresses []string `json:"addresses"`
	User      string   `json:"user"`
	Name      string   `json:"name"`
	Tags      []string `json:"tags"`
}

type tailscaleAPIDevices struct {
	Devices []tailscaleDevice `json:"devices"`
}

type tailscaleUser struct {
	DisplayName string `json:"displayName"`
	LoginName   string `json:"loginName"`
}

type tailscaleAPIUsers struct {
	Users []tailscaleUser `json:"users"`
}

type TailscaleWhoisResponse struct {
	DisplayName string
	LoginName   string
	NodeName    string
}

type TailscaleService struct {
	config *model.Config
	log    *logger.Logger
	client *http.Client
	ctx    context.Context

	apiToken string

	caches struct {
		devices *cache.CacheStore[tailscaleAPIDevices]
		users   *cache.CacheStore[tailscaleAPIUsers]
	}

	urls struct {
		devices string
		users   string
	}
}

type TailscaleServiceInput struct {
	dig.In

	Ding   *ding.Ding
	Config *model.Config
	Log    *logger.Logger
	Ctx    context.Context
}

func NewTailscaleService(i TailscaleServiceInput) (*TailscaleService, error) {
	if !i.Config.Tailscale.Enabled {
		return nil, nil
	}

	if i.Config.Tailscale.Tailnet == "" {
		return nil, fmt.Errorf("tailscale tailnet not set")
	}

	apiToken := utils.GetSecret(i.Config.Tailscale.APIToken, i.Config.Tailscale.APITokenFile)

	if apiToken == "" {
		return nil, fmt.Errorf("tailscale api token not set")
	}

	s := &TailscaleService{
		config:   i.Config,
		log:      i.Log,
		ctx:      i.Ctx,
		apiToken: apiToken,
	}

	devicesCache := cache.NewCacheStore[tailscaleAPIDevices](0)
	usersCache := cache.NewCacheStore[tailscaleAPIUsers](0)

	s.caches.devices = devicesCache
	s.caches.users = usersCache

	i.Ding.Go(func(ctx context.Context) {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.caches.devices.Sweep()
				s.caches.users.Sweep()
			case <-ctx.Done():
				return
			}
		}
	}, ding.RingMinor)

	s.urls.devices = tailscaleAPIDeviceList(i.Config.Tailscale.Tailnet)
	s.urls.users = tailscaleAPIUserList(i.Config.Tailscale.Tailnet)
	s.client = &http.Client{
		Timeout: 10 * time.Second,
	}

	_, _, err := s.getDeviceList()

	if err != nil {
		return nil, fmt.Errorf("failed to get device list: %w", err)
	}

	_, _, err = s.getUsersList()

	if err != nil {
		return nil, fmt.Errorf("failed to get user list: %w", err)
	}

	s.log.App.Info().Msg("Tailscale service initialized")

	return s, nil
}

func (s *TailscaleService) buildAuthorizationHeader() string {
	return "Bearer " + s.apiToken
}

func (s *TailscaleService) getDeviceList() (*tailscaleAPIDevices, bool, error) {
	cached, ok := s.caches.devices.Get("devices")

	if ok {
		return &cached, true, nil
	}

	devices, err := simpleReq[tailscaleAPIDevices](s.client, s.ctx, s.urls.devices, map[string]string{
		"Authorization": s.buildAuthorizationHeader(),
	})

	if err != nil {
		return nil, false, fmt.Errorf("failed to get device list: %w", err)
	}

	s.caches.devices.Set("devices", *devices, time.Duration(s.config.Tailscale.CacheDuration)*time.Second)

	return devices, false, nil
}

func (s *TailscaleService) getUsersList() (*tailscaleAPIUsers, bool, error) {
	cached, ok := s.caches.users.Get("users")

	if ok {
		return &cached, true, nil
	}

	users, err := simpleReq[tailscaleAPIUsers](s.client, s.ctx, s.urls.users, map[string]string{
		"Authorization": s.buildAuthorizationHeader(),
	})

	if err != nil {
		return nil, false, fmt.Errorf("failed to get user list: %w", err)
	}

	s.caches.users.Set("users", *users, time.Duration(s.config.Tailscale.CacheDuration)*time.Second)

	return users, false, nil
}

func (s *TailscaleService) Whois(addr string) (*TailscaleWhoisResponse, error) {
	var device *tailscaleDevice

	devices, dCacheHit, err := s.getDeviceList()

	if err != nil {
		return nil, fmt.Errorf("failed to get device list: %w", err)
	}

	for _, d := range devices.Devices {
		if len(d.Tags) != 0 {
			continue
		}
		for _, a := range d.Addresses {
			if a == addr {
				device = &d
				break
			}
		}
	}

	if device == nil {
		return nil, nil
	}

	s.log.App.Debug().Str("device", device.Name).Bool("cache_hit", dCacheHit).Msg("Tailscale device found")

	var user *tailscaleUser

	users, uCacheHit, err := s.getUsersList()

	if err != nil {
		return nil, fmt.Errorf("failed to get user list: %w", err)
	}

	for _, u := range users.Users {
		if u.LoginName == device.User {
			user = &u
			break
		}
	}

	if user == nil {
		return nil, nil
	}

	s.log.App.Debug().Str("user", user.LoginName).Bool("cache_hit", uCacheHit).Msg("Tailscale user found")

	return &TailscaleWhoisResponse{
		LoginName:   user.LoginName,
		DisplayName: user.DisplayName,
		NodeName:    device.Name,
	}, nil
}
