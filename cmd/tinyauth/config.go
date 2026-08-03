package main

import (
	"fmt"
	"strings"

	"github.com/tinyauthapp/paerser/cli"
	"github.com/tinyauthapp/tinyauth/internal/model"
)

func configCmd(tconfig *model.Config, loaders []cli.ResourceLoader) *cli.Command {
	return &cli.Command{
		Name:          "config",
		Description:   "Dump the current configuration in YAML format, useful for debugging",
		Configuration: tconfig,
		Resources:     loaders,
		Run: func(_ []string) error {
			buf := strings.Builder{}

			fmt.Fprint(&buf, "Your current configuration in YAML is:\n\n")

			err := renderYamlToBuf(&buf, tconfig)

			if err != nil {
				return fmt.Errorf("failed to render yaml config: %w", err)
			}

			fmt.Print(buf.String())
			return nil
		},
	}
}
