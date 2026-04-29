package main

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/paerser/cli"
)

func createOidcClientCmd() *cli.Command {
	return &cli.Command{
		Name:          "create",
		Description:   "Create a new OIDC Client",
		Configuration: nil,
		Resources:     nil,
		AllowArg:      true,
		Run: func(args []string) error {
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

			builder := strings.Builder{}

			// header
			fmt.Fprintf(&builder, "Created credentials for client %s\n\n", clientName)

			// credentials
			fmt.Fprintf(&builder, "Client Name: %s\n", clientName)
			fmt.Fprintf(&builder, "Client ID: %s\n", clientId)
			fmt.Fprintf(&builder, "Client Secret: %s\n\n", clientSecret)

			// env variables
			fmt.Fprint(&builder, "Environment variables:\n\n")
			fmt.Fprintf(&builder, "TINYAUTH_OIDC_CLIENTS_%s_CLIENTID=%s\n", uclientName, clientId)
			fmt.Fprintf(&builder, "TINYAUTH_OIDC_CLIENTS_%s_CLIENTSECRET=%s\n", uclientName, clientSecret)
			fmt.Fprintf(&builder, "TINYAUTH_OIDC_CLIENTS_%s_NAME=%s\n\n", uclientName, utils.Capitalize(lclientName))

			// cli flags
			fmt.Fprint(&builder, "CLI flags:\n\n")
			fmt.Fprintf(&builder, "--oidc.clients.%s.clientid=%s\n", lclientName, clientId)
			fmt.Fprintf(&builder, "--oidc.clients.%s.clientsecret=%s\n", lclientName, clientSecret)
			fmt.Fprintf(&builder, "--oidc.clients.%s.name=%s\n\n", lclientName, utils.Capitalize(lclientName))

			// footer
			fmt.Fprintln(&builder, "You can use either option to configure your OIDC client. Make sure to save these credentials as there is no way to regenerate them.")

			// print
			out := builder.String()
			fmt.Print(out)
			return nil
		},
	}
}
