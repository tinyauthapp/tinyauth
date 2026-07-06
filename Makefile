# Go specific stuff
CGO_ENABLED := 0
GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

# Build out
TAG_NAME := $(shell git describe --abbrev=0 --exact-match 2> /dev/null || echo "main")
COMMIT_HASH := $(shell git rev-parse HEAD)
BUILD_TIMESTAMP := $(shell date '+%Y-%m-%dT%H:%M:%S')
BIN_NAME := tinyauth-$(GOARCH)
LDFLAGS := -s -w
# We don't want all of the tailscale feature-set
TAILSCALE_BUILD_TAGS = $(shell go run tailscale.com/cmd/featuretags@v1.100.0 -min -add acme,serve,netstack)
# Whatever 6MB serialization lib Gin is using
GIN_BUILD_TAGS := nomsgpack
BUILD_TAGS = $(GIN_BUILD_TAGS),$(TAILSCALE_BUILD_TAGS)

# Development vars
DEV_COMPOSE := $(shell test -f "docker-compose.test.yml" && echo "docker-compose.test.yml" || echo "docker-compose.dev.yml" )
PROD_COMPOSE := $(shell test -f "docker-compose.test.prod.yml" && echo "docker-compose.test.prod.yml" || echo "docker-compose.example.yml" )

.DEFAULT_GOAL := binary

.PHONY: deps clean-data clean-webui webui binary binary-linux-amd64 binary-linux-arm64 test vet test-race dev dev-infisical prod prod-infisical sql generate docker docker-distroless

# Deps
deps:
	cd frontend && pnpm ci
	go mod download

# Clean data
clean-data:
	rm -rf data/

# Clean web UI build
clean-webui:
	rm -rf internal/assets/dist
	rm -rf frontend/dist

# Build the web UI
webui: clean-webui
	cd frontend && pnpm run build
	cp -r frontend/dist internal/assets

# Build the binary
binary: webui
	CGO_ENABLED=$(CGO_ENABLED) go build -tags "${BUILD_TAGS}" -ldflags "${LDFLAGS} \
	-X github.com/tinyauthapp/tinyauth/internal/model.Version=${TAG_NAME} \
	-X github.com/tinyauthapp/tinyauth/internal/model.CommitHash=${COMMIT_HASH} \
	-X github.com/tinyauthapp/tinyauth/internal/model.BuildTimestamp=${BUILD_TIMESTAMP}" \
	-o ${BIN_NAME} ./cmd/tinyauth

# Build for amd64
binary-linux-amd64:
	export BIN_NAME=tinyauth-amd64
	export GOARCH=amd64
	export GOOS=linux
	$(MAKE) binary

# Build for arm64
binary-linux-arm64:
	export BIN_NAME=tinyauth-arm64
	export GOARCH=arm64
	export GOOS=linux
	$(MAKE) binary

# Go test
test:
	go test -v ./...

# Go vet
vet:
	go vet ./...

# Go race
test-race:
	go test -race ./...

# Development
dev:
	docker compose -f $(DEV_COMPOSE) up --force-recreate --pull=always --remove-orphans --build

# Development - Infisical
dev-infisical:
	infisical run --env=dev -- docker compose -f $(DEV_COMPOSE) up --force-recreate --pull=always --remove-orphans --build

# Production
prod:
	docker compose -f $(PROD_COMPOSE) up --force-recreate --pull=always --remove-orphans

# Production - Infisical
prod-infisical:
	infisical run --env=dev -- docker compose -f $(PROD_COMPOSE) up --force-recreate --pull=always --remove-orphans

# SQL
sql:
	sqlc generate

# Go gen
generate:
	go generate ./...

# Docker image
docker:
	docker buildx build -t tinyauthapp/tinyauth:dev \
		--build-arg=VERSION=$(TAG_NAME) \
		--build-arg=COMMIT_HASH=$(COMMIT_HASH) \
		--build-arg=BUILD_TIMESTAMP=$(BUILD_TIMESTAMP) \
		--build-arg=BUILD_TAGS=$(BUILD_TAGS) \
		-f Dockerfile .

# Docker image distroless
docker-distroless:
	docker buildx build -t tinyauthapp/tinyauth:dev-distroless \
		--build-arg=VERSION=$(TAG_NAME) \
		--build-arg=COMMIT_HASH=$(COMMIT_HASH) \
		--build-arg=BUILD_TIMESTAMP=$(BUILD_TIMESTAMP) \
		--build-arg=BUILD_TAGS=$(BUILD_TAGS) \
		-f Dockerfile.distroless .
