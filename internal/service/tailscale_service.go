package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/steveiliop56/ding"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"tailscale.com/client/local"
	"tailscale.com/tsnet"
)

type TailscaleWhoisResponse struct {
	UserID      string
	LoginName   string
	DisplayName string
	NodeName    string
}

type TailscaleService struct {
	log    *logger.Logger
	config *model.Config
	ctx    context.Context

	srv *tsnet.Server
	lc  *local.Client
	ln  *net.Listener
	mu  sync.Mutex
}

func NewTailscaleService(
	deps *ServiceDependencies,
) (*TailscaleService, error) {
	if !deps.StaticConfig.Tailscale.Enabled {
		return nil, nil
	}

	srv := new(tsnet.Server)

	// node options
	srv.Dir = deps.StaticConfig.Tailscale.Dir
	srv.Hostname = deps.StaticConfig.Tailscale.Hostname
	srv.AuthKey = deps.StaticConfig.Tailscale.AuthKey
	srv.Ephemeral = deps.StaticConfig.Tailscale.Ephemeral

	// redirect logs to zerolog
	srv.Logf = deps.Log.App.Printf
	srv.UserLogf = deps.Log.App.Printf

	err := srv.Start()

	if err != nil {
		return nil, fmt.Errorf("failed to start tailscale server: %w", err)
	}

	lc, err := srv.LocalClient()

	if err != nil {
		_ = srv.Close()
		return nil, fmt.Errorf("failed to get tailscale local client: %w", err)
	}

	service := &TailscaleService{
		log:    deps.Log,
		config: deps.StaticConfig,
		ctx:    deps.Ctx,
		srv:    srv,
		lc:     lc,
	}

	connectCtx, cancel := context.WithTimeout(deps.Ctx, 2*time.Minute) // large enough timeout to allow for user to manually authenticate with link if needed
	defer cancel()

	err = service.waitForConn(connectCtx)

	if err != nil {
		_ = srv.Close()
		return nil, fmt.Errorf("failed to connect to tailscale network: %w", err)
	}

	deps.Ding.Go(service.watchAndClose, ding.RingMajor)

	return service, nil
}

func (ts *TailscaleService) watchAndClose(ctx context.Context) {
	<-ctx.Done()
	ts.log.App.Debug().Msg("Shutting down Tailscale service")
	ts.mu.Lock()
	srv := ts.srv
	ln := ts.ln
	ts.ln = nil
	ts.srv = nil
	ts.mu.Unlock()
	if ln != nil {
		(*ln).Close()
	}
	if srv != nil {
		srv.Close()
	}
}

func (ts *TailscaleService) Whois(ctx context.Context, addr string) (*TailscaleWhoisResponse, error) {
	who, err := ts.lc.WhoIs(ctx, addr)

	if err != nil {
		if errors.Is(err, local.ErrPeerNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get client whois: %w", err)
	}

	if who.Node.IsTagged() {
		ts.log.App.Debug().Msgf("Skipping whois for tagged node %s", who.Node.Name)
		return nil, nil
	}

	uid := strings.TrimPrefix(who.UserProfile.ID.String(), "userid:")

	res := TailscaleWhoisResponse{
		UserID:      uid,
		LoginName:   who.UserProfile.LoginName,
		DisplayName: who.UserProfile.DisplayName,
		NodeName:    strings.TrimSuffix(who.Node.Name, "."),
	}

	ts.log.App.Debug().Interface("res", res).Msg("tailscale")

	return &res, nil
}

func (ts *TailscaleService) CreateListener() (net.Listener, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.ln != nil {
		return *ts.ln, nil
	}
	ln, err := ts.srv.ListenTLS("tcp", ":443")
	if err != nil {
		return nil, err
	}
	ts.ln = &ln
	return ln, nil
}

func (ts *TailscaleService) GetHostname() string {
	status, err := ts.lc.Status(ts.ctx)

	if err != nil {
		ts.log.App.Error().Err(err).Msg("Failed to get Tailscale status")
		return ""
	}

	return strings.TrimSuffix(status.Self.DNSName, ".")
}

func (ts *TailscaleService) waitForConn(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for tailscale connection")
		default:
			ip4, _ := ts.srv.TailscaleIPs()
			if !ip4.IsValid() {
				time.Sleep(1 * time.Second)
				continue
			}
			return nil
		}
	}
}
