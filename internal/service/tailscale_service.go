package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"tailscale.com/client/local"
	"tailscale.com/tsnet"
)

type TailscaleService struct {
	log    *logger.Logger
	wg     *sync.WaitGroup
	config model.Config
	ctx    context.Context

	srv *tsnet.Server
	lc  *local.Client
	ln  *net.Listener
}

func NewTailscaleService(log *logger.Logger, config model.Config, ctx context.Context, wg *sync.WaitGroup) (*TailscaleService, error) {
	srv := new(tsnet.Server)

	// node options
	srv.Dir = config.Tailscale.Dir
	srv.Hostname = config.Tailscale.Hostname
	srv.AuthKey = config.Tailscale.AuthKey
	srv.Ephemeral = config.Tailscale.Ephemeral

	// redirect logs to zerolog
	srv.Logf = log.App.Printf
	srv.UserLogf = log.App.Printf

	err := srv.Start()

	if err != nil {
		return nil, fmt.Errorf("failed to start tailscale server: %w", err)
	}

	lc, err := srv.LocalClient()

	if err != nil {
		return nil, fmt.Errorf("failed to get tailscale local client: %w", err)
	}

	service := &TailscaleService{
		log:    log,
		wg:     wg,
		config: config,
		ctx:    ctx,
		srv:    srv,
		lc:     lc,
	}

	wg.Go(service.watchAndClose)

	return service, nil
}

func (ts *TailscaleService) watchAndClose() {
	<-ts.ctx.Done()
	ts.log.App.Debug().Msg("Shutting down Tailscale service")
	if ts.ln != nil {
		(*ts.ln).Close()
	}
	if ts.srv != nil {
		ts.srv.Close()
	}
}

func (ts *TailscaleService) Whois(ctx context.Context, addr string) (*model.TailscaleWhoisResponse, error) {
	who, err := ts.lc.WhoIs(ctx, addr)

	if err != nil {
		if errors.Is(err, local.ErrPeerNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get client whois: %w", err)
	}

	res := model.TailscaleWhoisResponse{
		UserID:      who.UserProfile.ID.String(),
		LoginName:   who.UserProfile.LoginName,
		DisplayName: who.UserProfile.DisplayName,
		NodeName:    who.Node.Name,
	}

	return &res, nil
}

func (ts *TailscaleService) CreateListener() (net.Listener, error) {
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
