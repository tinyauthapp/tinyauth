package main

import (
	"encoding/json"
	"fmt"

	"github.com/tinyauthapp/paerser/cli"
	"github.com/tinyauthapp/tinyauth/internal/model"
)

func configCmd(tconfig *model.Config, loaders []cli.ResourceLoader) *cli.Command {
	return &cli.Command{
		Name:          "config",
		Description:   "Print the configuration of Tinyauth",
		Configuration: tconfig,
		Resources:     loaders,
		Run: func(_ []string) error {
			jsonBytes, err := json.MarshalIndent(tconfig, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal configuration: %w", err)
			}
			fmt.Println(string(jsonBytes))
			return nil
		},
	}
}
