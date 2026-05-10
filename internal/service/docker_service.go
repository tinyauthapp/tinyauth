package service

import (
	"context"
	"strings"
	"sync"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/decoders"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"

	container "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

type DockerService struct {
	log     *logger.Logger
	client  *client.Client
	context context.Context

	isConnected bool
}

func NewDockerService(
	log *logger.Logger,
	ctx context.Context,
	wg *sync.WaitGroup,
) (*DockerService, error) {

	client, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, err
	}

	client.NegotiateAPIVersion(ctx)

	_, err = client.Ping(ctx)

	if err != nil {
		log.App.Debug().Err(err).Msg("Docker not connected")
		return nil, nil
	}

	service := &DockerService{
		log:     log,
		client:  client,
		context: ctx,
	}

	service.isConnected = true
	service.log.App.Debug().Msg("Docker connected successfully")

	wg.Go(service.watchAndClose)

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

		for appName, appLabels := range labels.Apps {
			if appLabels.Config.Domain == appDomain {
				docker.log.App.Debug().Str("id", inspect.ID).Str("name", inspect.Name).Msg("Found matching container by domain")
				return &appLabels, nil
			}

			if strings.SplitN(appDomain, ".", 2)[0] == appName {
				docker.log.App.Debug().Str("id", inspect.ID).Str("name", inspect.Name).Msg("Found matching container by app name")
				return &appLabels, nil
			}
		}
	}

	docker.log.App.Debug().Str("domain", appDomain).Msg("No matching container found for domain")
	return nil, nil
}

func (docker *DockerService) watchAndClose() {
	<-docker.context.Done()
	docker.log.App.Debug().Msg("Closing Docker client")
	if docker.client != nil {
		err := docker.client.Close()
		if err != nil {
			docker.log.App.Error().Err(err).Msg("Error closing Docker client")
		}
	}
}
