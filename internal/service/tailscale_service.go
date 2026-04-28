package service

import (
	"context"
	"errors"
	"net"

	"github.com/tinyauthapp/tinyauth/internal/config"
	"github.com/tinyauthapp/tinyauth/internal/utils/tlog"
	"tailscale.com/client/local"
	"tailscale.com/tsnet"
)

type TailscaleServiceConfig struct {
	Dir       string
	Hostname  string
	AuthKey   string
	Ephemeral bool
}

type TailscaleService struct {
	config TailscaleServiceConfig
	srv    *tsnet.Server
	lc     *local.Client
	ln     *net.Listener
}

func NewTailscaleService(config TailscaleServiceConfig) *TailscaleService {
	return &TailscaleService{
		config: config,
	}
}

func (ts *TailscaleService) Init() error {
	srv := new(tsnet.Server)

	// node options
	srv.Dir = ts.config.Dir
	srv.Hostname = ts.config.Hostname
	srv.AuthKey = ts.config.AuthKey
	srv.Ephemeral = ts.config.Ephemeral

	// redirect logs to zerolog
	srv.Logf = tlog.App.Printf
	srv.UserLogf = tlog.App.Printf

	err := srv.Start()

	if err != nil {
		return err
	}

	ts.srv = srv

	lc, err := srv.LocalClient()

	if err != nil {
		return err
	}

	ts.lc = lc
	return nil
}

func (ts *TailscaleService) Destroy() error {
	if ts.ln != nil {
		(*ts.ln).Close()
	}
	if ts.srv != nil {
		return ts.srv.Close()
	}
	ts.ln = nil
	ts.lc = nil
	ts.srv = nil
	return nil
}

func (ts *TailscaleService) Whois(ctx context.Context, addr string) (config.TailscaleWhoisResponse, error) {
	who, err := ts.lc.WhoIs(ctx, addr)

	if err != nil {
		if errors.Is(err, local.ErrPeerNotFound) {
			return config.TailscaleWhoisResponse{}, nil
		}
		return config.TailscaleWhoisResponse{}, err
	}

	res := config.TailscaleWhoisResponse{
		UserID:      who.UserProfile.ID.String(),
		LoginName:   who.UserProfile.LoginName,
		DisplayName: who.UserProfile.DisplayName,
		NodeName:    who.Node.Name,
	}

	return res, nil
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

func (ts *TailscaleService) IsConnfigured() bool {
	return ts.srv != nil
}

func (ts *TailscaleService) GetHostname() string {
	return ts.srv.Hostname
}
