package service

import (
	"context"
	"fmt"

	"github.com/steveiliop56/ding"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/decoders"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
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

func (docker *DockerService) Lookup(locator func(name string, app *model.App) bool) error {
	if !docker.isConnected {
		docker.log.App.Debug().Msg("Docker service not connected, returning empty labels")
		return nil
	}

	containers, err := docker.getContainers()
	if err != nil {
		return fmt.Errorf("failed to get containers: %w", err)
	}

	for _, ctr := range containers {
		inspect, err := docker.inspectContainer(ctr.ID)
		if err != nil {
			docker.log.App.Error().Err(err).Msgf("Failed to inspect container %s", ctr.ID)
			continue
		}

		labels, err := decoders.DecodeLabels[model.Apps](inspect.Config.Labels, "apps")
		if err != nil {
			docker.log.App.Warn().Err(err).Msgf("Failed to decode labels for container %s", ctr.ID)
			continue
		}

		for app, config := range labels.Apps {
			if ok := locator(app, &config); ok {
				return nil
			}
		}
	}

	return nil
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
