package service

import (
	"context"
	"errors"
	"strings"

	"github.com/steveiliop56/ding"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/decoders"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/tinyauthapp/tinyauth/pkg/validators"
	"go.uber.org/dig"

	container "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

type DockerService struct {
	log     *logger.Logger
	client  *client.Client
	context context.Context

	isConnected bool
}

type DockerServiceInput struct {
	dig.In

	Log  *logger.Logger
	Ctx  context.Context
	Ding *ding.Ding
}

func NewDockerService(i DockerServiceInput) (*DockerService, error) {
	client, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, err
	}

	client.NegotiateAPIVersion(i.Ctx)

	_, err = client.Ping(i.Ctx)

	if err != nil {
		i.Log.App.Debug().Err(err).Msg("Docker not connected")
		return nil, nil
	}

	service := &DockerService{
		log:     i.Log,
		client:  client,
		context: i.Ctx,
	}

	service.isConnected = true
	service.log.App.Debug().Msg("Docker connected successfully")

	i.Ding.Go(service.watchAndClose, ding.RingMajor)

	return service, nil
}

func (docker *DockerService) getContainers() ([]container.Summary, error) {
	return docker.client.ContainerList(docker.context, container.ListOptions{})
}

func (docker *DockerService) inspectContainer(containerId string) (container.InspectResponse, error) {
	return docker.client.ContainerInspect(docker.context, containerId)
}

func (docker *DockerService) GetLabels(appDomain string) (*model.App, error) {
	if !docker.isConnected {
		docker.log.App.Debug().Msg("Docker service not connected, returning empty labels")
		return nil, nil
	}

	containers, err := docker.getContainers()
	if err != nil {
		return nil, err
	}

	for _, ctr := range containers {
		inspect, err := docker.inspectContainer(ctr.ID)
		if err != nil {
			return nil, err
		}

		labels, err := decoders.DecodeLabels[model.Apps](inspect.Config.Labels, "apps")
		if err != nil {
			return nil, err
		}

		v := validators.NewDomainValidator(validators.DomainValidatorOptions{})

		// First try to find a matching app by domain, then fallback to matching by app name (subdomain)
		for app, config := range labels.Apps {
			if config.Config.Domain != "" {
				err := v.Validate(config.Config.Domain, appDomain)
				if err == nil {
					docker.log.App.Debug().Str("name", app).Msg("Found matching container by domain")
					return &config, nil
				}
				if !errors.Is(err, validators.ErrHostnameMismatch) {
					docker.log.App.Debug().Str("name", app).Err(err).Msg("Domain validation failed")
				}
			}
			if strings.HasPrefix(strings.ToLower(appDomain), strings.ToLower(app+".")) {
				docker.log.App.Debug().Str("name", app).Msg("Found matching container by app name")
				return &config, nil
			}
		}
	}

	docker.log.App.Debug().Str("domain", appDomain).Msg("No matching container found for domain")
	return nil, nil
}

func (docker *DockerService) watchAndClose(ctx context.Context) {
	<-ctx.Done()
	docker.log.App.Debug().Msg("Closing Docker client")
	if docker.client != nil {
		err := docker.client.Close()
		if err != nil {
			docker.log.App.Error().Err(err).Msg("Error closing Docker client")
		}
	}
}
