package main

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/tinyauthapp/paerser/cli"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"gopkg.in/yaml.v3"
)

func createOidcClientCmd() *cli.Command {
	return &cli.Command{
		Name:          "create",
		Description:   "Create a new OIDC Client",
		Configuration: nil,
		Resources:     nil,
		AllowArg:      true,
		Run: func(args []string) error {
			colors := getColors()

			if len(args) == 0 {
				return errors.New("client name is required. use tinyauth oidc create <name>")
			}

			clientName := args[0]

			match, err := regexp.MatchString("^[a-zA-Z0-9-]*$", clientName)

			if !match || err != nil {
				return errors.New("client name can only contain alphanumeric characters and hyphens")
			}

			uuid := uuid.New()
			clientId := uuid.String()
			clientSecret := "ta-" + utils.GenerateString(61)

			uclientName := strings.ToUpper(clientName)
			lclientName := strings.ToLower(clientName)

			buf := strings.Builder{}

			// header
			fmt.Fprintf(&buf, "Created '%s' OIDC client.\n\n", clientName)

			// credentials
			fmt.Fprintf(&buf, "Credentials:\n\n")
			fmt.Fprintf(&buf, "Client Name: %s\n", clientName)
			fmt.Fprintf(&buf, "Client ID: %s\n", clientId)
			fmt.Fprintf(&buf, "Client Secret: %s\n\n", clientSecret)

			// end variables
			fmt.Fprintf(&buf, "Environment variables:\n\n")
			renderToBuf(&buf, []kv{
				{
					k: fmt.Sprintf("TINYAUTH_OIDC_CLIENTS_%s_CLIENTID", uclientName),
					v: clientId,
				},
				{
					k: fmt.Sprintf("TINYAUTH_OIDC_CLIENTS_%s_CLIENTSECRET", uclientName),
					v: clientSecret,
				},
				{
					k: fmt.Sprintf("TINYAUTH_OIDC_CLIENTS_%s_NAME", uclientName),
					v: utils.Capitalize(lclientName),
				},
			}, "=")
			fmt.Fprintf(&buf, "\n")

			// cli flags
			fmt.Fprintf(&buf, "CLI flags:\n\n")
			renderToBuf(&buf, []kv{
				{
					k: fmt.Sprintf("--oidc-clients-%s-clientid", lclientName),
					v: clientId,
				},
				{
					k: fmt.Sprintf("--oidc-clients-%s-clientsecret", lclientName),
					v: clientSecret,
				},
				{
					k: fmt.Sprintf("--oidc-clients-%s-name", lclientName),
					v: utils.Capitalize(lclientName),
				},
			}, "=")
			fmt.Fprintf(&buf, "\n")

			// yaml config
			fmt.Fprintf(&buf, "YAML config:\n\n")

			yout, err := yaml.Marshal(&model.OIDCConfig{
				Clients: map[string]model.OIDCClientConfig{
					lclientName: {
						ClientID:     clientId,
						ClientSecret: clientSecret,
						Name:         utils.Capitalize(lclientName),
					},
				},
			})

			if err != nil {
				return fmt.Errorf("failed to marshal yaml: %w", err)
			}

			for l := range strings.SplitSeq(string(yout), "\n") {
				if l == "" {
					continue
				}
				lp := strings.SplitN(l, ":", 2)
				buf.WriteString(colors.red.Render(lp[0]))
				buf.WriteString(colors.gray.Render(":"))
				if len(lp) == 2 {
					buf.WriteString("")
					buf.WriteString(colors.green.Render(lp[1]))
				}
				buf.WriteString("\n")
			}

			buf.WriteString("\n")

			// footer
			fmt.Fprintln(&buf, "You can use any of the above options to configure your OIDC client. Make sure to save these credentials as there is no way to regenerate them.")

			// print
			out := buf.String()
			fmt.Print(out)
			return nil
		},
	}
}
