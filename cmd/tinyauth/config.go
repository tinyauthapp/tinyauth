package main

import (
	"fmt"
	"strings"

	"github.com/tinyauthapp/paerser/cli"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"gopkg.in/yaml.v3"
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

			yout, err := yaml.Marshal(&tconfig)

			if err != nil {
				return fmt.Errorf("failed to marshal yaml: %w", err)
			}

			for l := range strings.SplitSeq(string(yout), "\n") {
				if l == "" {
					continue
				}
				if strings.HasPrefix(strings.TrimLeft(l, " "), "- ") {
					buf.WriteString(greenStyle.Render(l))
					buf.WriteString("\n")
					continue
				}
				lp := strings.SplitN(l, ":", 2)
				buf.WriteString(redStyle.Render(lp[0]))
				buf.WriteString(grayStyle.Render(":"))
				if len(lp) == 2 {
					buf.WriteString(greenStyle.Render(lp[1]))
				}
				buf.WriteString("\n")
			}

			fmt.Println(buf.String())
			return nil
		},
	}
}
