package loaders

import (
	"os"

	"github.com/tinyauthapp/paerser/cli"
	"github.com/tinyauthapp/paerser/file"
	"github.com/tinyauthapp/paerser/flag"
)

type FileLoader struct{}

func (f *FileLoader) Load(args []string, cmd *cli.Command) (bool, error) {
	flags, err := flag.Parse(args, cmd.Configuration)

	if err != nil {
		return false, err
	}

	// I guess we are using traefik as the root name (we can't change it)
	configFileFlag := "traefik.configfile"
	envVar := "TINYAUTH_CONFIGFILE"

	if _, ok := flags[configFileFlag]; !ok {
		if value := os.Getenv(envVar); value != "" {
			flags[configFileFlag] = value
		} else {
			return false, nil
		}
	}

	err = file.Decode(flags[configFileFlag], cmd.Configuration)

	if err != nil {
		return false, err
	}

	return true, nil
}
