package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/tinyauthapp/tinyauth/internal/utils"

	"charm.land/huh/v2"
	"github.com/mdp/qrterminal/v3"
	"github.com/pquerna/otp/totp"
	"github.com/tinyauthapp/paerser/cli"
)

type GenerateTotpConfig struct {
	Interactive bool   `description:"Generate a TOTP secret interactively."`
	User        string `description:"Your current user (username:hash)."`
}

func NewGenerateTotpConfig() *GenerateTotpConfig {
	return &GenerateTotpConfig{
		Interactive: false,
		User:        "",
	}
}

func generateTotpCmd() *cli.Command {
	tCfg := NewGenerateTotpConfig()

	loaders := []cli.ResourceLoader{
		&cli.FlagLoader{},
	}

	cmd := &cli.Command{
		Name:          "generate",
		Description:   "Generate a TOTP secret",
		Configuration: tCfg,
		Resources:     loaders,
	}

	cmd.Run = func(_ []string) error {
		colors := getColors()

		if tCfg.Interactive {
			form := huh.NewForm(
				huh.NewGroup(
					huh.NewInput().Title("Current user (username:hash)").Value(&tCfg.User).Validate((func(s string) error {
						if s == "" {
							return errors.New("user cannot be empty")
						}
						return nil
					})),
				),
			)

			theme := new(themeBase)
			err := form.WithTheme(theme).Run()

			if err != nil {
				return fmt.Errorf("failed to run interactive prompt: %w", err)
			}
		}

		if tCfg.User == "" {
			cmd.PrintHelp(os.Stdout)
			return fmt.Errorf("user is required")
		}

		user, err := utils.ParseUser(tCfg.User)

		if err != nil {
			return fmt.Errorf("failed to parse user: %w", err)
		}

		docker := false
		if strings.Contains(tCfg.User, "$$") {
			docker = true
		}

		if user.TOTPSecret != "" {
			return fmt.Errorf("user already has a TOTP secret")
		}

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "Tinyauth",
			AccountName: user.Username,
		})

		if err != nil {
			return fmt.Errorf("failed to generate TOTP secret: %w", err)
		}

		secret := key.Secret()

		fmt.Printf("Scan the following QR code with your authenticator app (e.g., Google Authenticator, 2fauth, Microsoft Authenticator):\n\n")

		config := qrterminal.Config{
			Level:     qrterminal.L,
			Writer:    os.Stdout,
			BlackChar: qrterminal.BLACK,
			WhiteChar: qrterminal.WHITE,
			QuietZone: 2,
		}

		qrterminal.GenerateWithConfig(key.URL(), config)

		user.TOTPSecret = secret

		// If using docker escape re-escape it
		if docker {
			user.Password = strings.ReplaceAll(user.Password, "$", "$$")
		}

		userStr := fmt.Sprintf("%s:%s:%s", user.Username, user.Password, user.TOTPSecret)

		fmt.Print("\nOr add the following TOTP secret to your authenticator app: ")
		fmt.Print(colors.green.Render(secret))
		fmt.Print("\n\n")

		fmt.Printf("Finally, add your user '%s' back to your configuration: ", user.Username)
		fmt.Print(colors.green.Render(userStr))
		fmt.Print("\n")

		return nil
	}

	return cmd
}
