package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tinyauthapp/paerser/cli"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
)

type healthzResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

func healthcheckCmd() *cli.Command {
	return &cli.Command{
		Name:          "healthcheck",
		Description:   "Perform a health check",
		Configuration: nil,
		Resources:     nil,
		AllowArg:      true,
		Run: func(args []string) error {
			log := logger.NewLogger().WithSimpleConfig()
			log.Init()

			appUrl, socketPath := healthcheckTarget(
				os.Getenv("TINYAUTH_SERVER_ADDRESS"),
				os.Getenv("TINYAUTH_SERVER_PORT"),
				os.Getenv("TINYAUTH_SERVER_SOCKETPATH"),
			)

			if len(args) > 0 {
				appUrl = args[0]
				socketPath = ""
			}

			if appUrl == "" {
				return errors.New("Could not determine app URL")
			}

			log.App.Info().Str("app_url", appUrl).Msg("Performing health check")

			client := http.Client{
				Timeout: 30 * time.Second,
			}

			if socketPath != "" {
				log.App.Info().Str("socket_path", socketPath).Msg("Using unix socket")
				transport := http.DefaultTransport.(*http.Transport).Clone()
				transport.Proxy = nil
				transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
				}
				client.Transport = transport
			}

			req, err := http.NewRequest("GET", appUrl+"/api/healthz", nil)

			if err != nil {
				return fmt.Errorf("failed to create request: %w", err)
			}

			resp, err := client.Do(req)

			if err != nil {
				return fmt.Errorf("failed to perform request: %w", err)
			}

			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("service is not healthy, got: %s", resp.Status)
			}

			var healthResp healthzResponse

			body, err := io.ReadAll(resp.Body)

			if err != nil {
				return fmt.Errorf("failed to read response: %w", err)
			}

			err = json.Unmarshal(body, &healthResp)

			if err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			log.App.Info().Interface("response", healthResp).Msg("Tinyauth is healthy")

			return nil
		},
	}
}

// healthcheckTarget returns the URL to probe and, when tinyauth serves on a unix socket, the socket to dial.
// Wildcard listen addresses are probed on IPv4 loopback.
func healthcheckTarget(addr string, port string, socketPath string) (string, string) {
	if socketPath != "" {
		return "http://tinyauth", socketPath
	}

	host := utils.TrimHostBrackets(addr)
	switch host {
	case "", "0.0.0.0":
		// IPv4 wildcard (and the dual-stack :port listener): IPv4 loopback reaches it.
		host = "127.0.0.1"
	case "::":
		// IPv6 wildcard: probe IPv6 loopback. It reaches a [::] listener whether it is
		// dual-stack or IPv6-only, whereas 127.0.0.1 fails on an IPv6-only listener
		// (a platform without IPv4-mapped IPv6, e.g. bindv6only).
		host = "::1"
	}

	if port == "" {
		port = "3000"
	}

	// A link-local address keeps its zone id (fe80::1%eth0); the listener accepts the raw
	// %, but it must be percent-encoded as %25 before it goes into the probe URL host.
	host = strings.ReplaceAll(host, "%", "%25")

	return "http://" + utils.JoinHostPort(host, port), ""
}
