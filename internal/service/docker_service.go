package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/steveiliop56/ding"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/decoders"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"go.uber.org/dig"

	container "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

var (
	ErrPingFailed = fmt.Errorf("failed to ping docker")
)

type DockerService struct {
	log    *logger.Logger
	client *client.Client
	ctx    context.Context

	apps map[string]model.App
	mu   sync.RWMutex
}

type DockerServiceInput struct {
	dig.In

	Log  *logger.Logger
	Ctx  context.Context
	Ding *ding.Ding
}

func NewDockerService(i DockerServiceInput) (*DockerService, error) {
	service := &DockerService{
		log:  i.Log,
		ctx:  i.Ctx,
		apps: make(map[string]model.App),
		mu:   sync.RWMutex{},
	}

	service.log.App.Debug().Msg("Attempting to connect to Docker")

	var cli *client.Client
	var err error

	if os.Getenv("DOCKER_HOST") != "" {
		cli, err = service.connectWithBackoff()
	} else {
		cli, err = service.connect()
	}

	if err != nil {
		if errors.Is(err, ErrPingFailed) {
			service.log.App.Debug().Msg("Docker not connected, skipping")
			return nil, nil
		}
		return nil, fmt.Errorf("failed to connect to docker: %w", err)
	}

	if cli == nil {
		return nil, nil
	}

	service.client = cli

	// initial sync
	err = service.sync()

	if err != nil {
		return nil, fmt.Errorf("failed to do initial sync: %w", err)
	}

	service.log.App.Debug().Msg("Docker connected successfully")

	i.Ding.Go(service.monitor, ding.RingMajor)

	return service, nil
}

func (docker *DockerService) connectWithBackoff() (*client.Client, error) {
	exp := backoff.NewExponentialBackOff()
	exp.InitialInterval = 3 * time.Second
	exp.RandomizationFactor = 0.1
	exp.Multiplier = 1.5
	exp.Reset()

	operation := func() (*client.Client, error) {
		if docker.client != nil {
			_ = docker.client.Close()
		}
		return docker.connect()
	}

	return backoff.Retry(docker.ctx, operation, backoff.WithBackOff(exp), backoff.WithMaxTries(3))
}

func (docker *DockerService) connect() (*client.Client, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())

	if err != nil {
		return nil, err
	}

	_, err = cli.Ping(docker.ctx)

	if err != nil {
		_ = cli.Close()
		return nil, ErrPingFailed
	}

	return cli, nil
}

func (docker *DockerService) getContainers() ([]container.Summary, error) {
	return docker.client.ContainerList(docker.ctx, container.ListOptions{})
}

func (docker *DockerService) inspectContainer(containerId string) (container.InspectResponse, error) {
	return docker.client.ContainerInspect(docker.ctx, containerId)
}

func (docker *DockerService) sync() error {
	containers, err := docker.getContainers()
	if err != nil {
		return fmt.Errorf("failed to get containers: %w", err)
	}

	apps := make(map[string]model.App)

	for _, ctr := range containers {
		labels, err := decoders.DecodeLabels[model.Apps](ctr.Labels, "apps")
		if err != nil {
			docker.log.App.Warn().Err(err).Str("container_id", ctr.ID).Msg("Failed to decode container labels, skipping")
			continue
		}

		for app, config := range labels.Apps {
			apps[app] = config
		}
	}

	docker.mu.Lock()
	docker.apps = apps
	docker.mu.Unlock()

	return nil
}

func (docker *DockerService) syncWithContainer(containerId string) error {
	ctr, err := docker.inspectContainer(containerId)
	if err != nil {
		return fmt.Errorf("failed to inspect container: %w", err)
	}
	labels, err := decoders.DecodeLabels[model.Apps](ctr.Config.Labels, "apps")
	if err != nil {
		return fmt.Errorf("failed to decode container labels: %w", err)
	}
	docker.mu.Lock()
	for app, config := range labels.Apps {
		if !ctr.State.Running {
			delete(docker.apps, app)
			continue
		}
		docker.apps[app] = config
	}
	docker.mu.Unlock()
	return nil
}

func (docker *DockerService) syncFromEvent(event events.Message) {
	switch event.Action {
	case events.ActionStart, events.ActionRestart,
		events.ActionStop, events.ActionKill, events.ActionDie:

		if err := docker.syncWithContainer(event.Actor.ID); err != nil {
			docker.log.App.Warn().Err(err).
				Msg("Failed to sync container, performing full sync")

			if err := docker.sync(); err != nil {
				docker.log.App.Error().Err(err).
					Msg("Failed to resync Docker apps")
			}
		}
	}
}

func (docker *DockerService) buildEventsKV() filters.Args {
	vals := []string{"start", "restart", "stop", "kill", "die"}
	kv := make([]filters.KeyValuePair, len(vals))
	for i, v := range vals {
		kv[i] = filters.KeyValuePair{
			Key:   "event",
			Value: v,
		}
	}
	return filters.NewArgs(kv...)
}

func (docker *DockerService) monitor(ctx context.Context) {
	defer func() {
		if docker.client != nil {
			_ = docker.client.Close()
		}
	}()

	for ctx.Err() == nil {
		streamCtx, cancel := context.WithCancel(ctx)

		stream, chErr := docker.client.Events(streamCtx, events.ListOptions{
			Filters: docker.buildEventsKV(),
		})

		if err := docker.sync(); err != nil {
			docker.log.App.Error().Err(err).Msg("Failed to sync docker apps")
		} else {
		watch:
			for {
				select {
				case <-ctx.Done():
					cancel()
					docker.log.App.Debug().Msg("Shutting down docker monitor")
					return

				case event, ok := <-stream:
					if !ok {
						docker.log.App.Warn().Msg("Docker event stream closed")
						break watch
					}
					docker.syncFromEvent(event)

				case err, ok := <-chErr:
					if ok && err != nil {
						docker.log.App.Error().Err(err).Msg("Docker event stream failed")
					}
					break watch
				}
			}
		}

		cancel()

		for ctx.Err() == nil {
			docker.log.App.Warn().Msg("Attempting to reconnect to docker")

			cli, err := docker.connect()

			if err == nil && cli != nil {
				_ = docker.client.Close()
				docker.client = cli
				docker.log.App.Info().Msg("Docker connection recovered")
				break
			}

			if err != nil {
				docker.log.App.Error().Err(err).Msg("Failed to reconnect to docker")
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}
}

func (docker *DockerService) Lookup(locator func(name string, app *model.App)) error {
	docker.mu.RLock()
	for app, config := range docker.apps {
		locator(app, &config)
	}
	docker.mu.RUnlock()
	return nil
}
