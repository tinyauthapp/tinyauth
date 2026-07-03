package main

import (
	"fmt"
	"os"
	"strings"

	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/tinyauthapp/tinyauth/internal/bootstrap"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/loaders"
	"gopkg.in/yaml.v3"

	"github.com/tinyauthapp/paerser/cli"
)

func main() {
	env := model.DetectRuntimeEnv()
	tConfig := model.NewDefaultConfiguration(env)

	loaders := []cli.ResourceLoader{
		&loaders.FileLoader{},
		&loaders.FlagLoader{},
		&loaders.EnvLoader{},
	}

	cmdTinyauth := &cli.Command{
		Name:          "tinyauth",
		Description:   "The simplest way to protect your apps with a login screen",
		Configuration: tConfig,
		Resources:     loaders,
		Run: func(_ []string) error {
			return runCmd(*tConfig)
		},
	}

	cmdUser := &cli.Command{
		Name:        "user",
		Description: "Manage users",
	}

	cmdTotp := &cli.Command{
		Name:        "totp",
		Description: "Manage TOTP users",
	}

	cmdOidc := &cli.Command{
		Name:        "oidc",
		Description: "Manage OIDC clients",
	}

	helpCmd := &cli.Command{
		Name:        "help",
		Description: "Show the help message",
		Run: func(_ []string) error {
			return cmdTinyauth.PrintHelp(os.Stdout)
		},
	}

	err := cmdTinyauth.AddCommand(helpCmd)

	if err != nil {
		fatalf(err, "Failed to add help command")
	}

	err = cmdTinyauth.AddCommand(versionCmd())

	if err != nil {
		fatalf(err, "Failed to add version command")
	}

	err = cmdTinyauth.AddCommand(configCmd(tConfig, loaders))

	if err != nil {
		fatalf(err, "Failed to add config command")
	}

	err = cmdUser.AddCommand(verifyUserCmd())

	if err != nil {
		fatalf(err, "Failed to add user verify command")
	}

	err = cmdTinyauth.AddCommand(healthcheckCmd())

	if err != nil {
		fatalf(err, "Failed to add healthcheck command")
	}

	err = cmdTotp.AddCommand(generateTotpCmd())

	if err != nil {
		fatalf(err, "Failed to add totp generate command")
	}

	err = cmdUser.AddCommand(createUserCmd())

	if err != nil {
		fatalf(err, "Failed to add create user command")
	}

	err = cmdOidc.AddCommand(createOidcClientCmd())

	if err != nil {
		fatalf(err, "Failed to add create oidc client command")
	}

	err = cmdTinyauth.AddCommand(cmdUser)

	if err != nil {
		fatalf(err, "Failed to add user command")
	}

	err = cmdTinyauth.AddCommand(cmdTotp)

	if err != nil {
		fatalf(err, "Failed to add totp command")
	}

	err = cmdTinyauth.AddCommand(cmdOidc)

	if err != nil {
		fatalf(err, "Failed to add oidc command")
	}

	err = cli.Execute(cmdTinyauth)

	if err != nil {
		if strings.Contains(err.Error(), "command not found") {
			fmt.Println("Command not found. Use 'tinyauth help' to see available commands.")
			return
		}
		if strings.Contains(err.Error(), "is not runnable") {
			return
		}
		fatalf(err, "Failed to execute command")
	}
}

func runCmd(cfg model.Config) error {
	app := bootstrap.NewBootstrapApp(cfg)

	err := app.Setup()

	if err != nil {
		return fmt.Errorf("failed to bootstrap app: %w", err)
	}

	return nil
}

type themeBase struct{}

func (t *themeBase) Theme(isDark bool) *huh.Styles {
	return huh.ThemeBase(isDark)
}

type colors struct {
	blue      lipgloss.Style
	gray      lipgloss.Style
	lightGray lipgloss.Style
	green     lipgloss.Style
	yellow    lipgloss.Style
}

func getColors() colors {
	noColor := os.Getenv("NO_COLOR")
	forceColor := os.Getenv("FORCE_COLOR")

	colorOut := colors{
		green:     lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(34)),
		gray:      lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(245)),
		yellow:    lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(214)),
		blue:      lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(75)),
		lightGray: lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(250)),
	}

	noColorOut := colors{
		green:     lipgloss.NewStyle(),
		gray:      lipgloss.NewStyle(),
		yellow:    lipgloss.NewStyle(),
		blue:      lipgloss.NewStyle(),
		lightGray: lipgloss.NewStyle(),
	}

	useColors := true

	if noColor == "true" || noColor == "1" {
		useColors = false
	}

	if forceColor == "true" || forceColor == "1" {
		useColors = true
	}

	if !useColors {
		return noColorOut
	}

	return colorOut
}

func fatalf(err error, msg string) {
	fmt.Printf("%s: %v\n", msg, err)
	os.Exit(1)
}

type kv struct {
	k string
	v string
}

func renderToBuf(buf *strings.Builder, kv []kv, sep string) {
	colors := getColors()
	for _, i := range kv {
		buf.WriteString(colors.blue.Render(i.k))
		buf.WriteString(colors.gray.Render(sep))
		buf.WriteString(colors.lightGray.Render(i.v))
		buf.WriteString("\n")
	}
}

func renderYamlToBuf(buf *strings.Builder, i any) error {
	colors := getColors()

	yout, err := yaml.Marshal(i)

	if err != nil {
		return fmt.Errorf("failed to marshal yaml: %w", err)
	}

	for l := range strings.SplitSeq(string(yout), "\n") {
		if l == "" {
			continue
		}
		if strings.HasPrefix(strings.TrimLeft(l, " "), "- ") {
			buf.WriteString(colors.lightGray.Render(l))
			buf.WriteString("\n")
			continue
		}
		lp := strings.SplitN(l, ":", 2)
		buf.WriteString(colors.blue.Render(lp[0]))
		buf.WriteString(colors.gray.Render(":"))
		if len(lp) == 2 {
			buf.WriteString(colors.lightGray.Render(lp[1]))
		}
		buf.WriteString("\n")
	}

	return nil
}
