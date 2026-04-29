# Go specific stuff
CGO_ENABLED := 0
GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

# Build out
TAG_NAME := $(shell git describe --abbrev=0 --exact-match 2> /dev/null || echo "main")
COMMIT_HASH := $(shell git rev-parse HEAD)
BUILD_TIMESTAMP := $(shell date '+%Y-%m-%dT%H:%M:%S')
BIN_NAME := tinyauth-$(GOARCH)

# Development vars
DEV_COMPOSE := $(shell test -f "docker-compose.test.yml" && echo "docker-compose.test.yml" || echo "docker-compose.dev.yml" )
PROD_COMPOSE := $(shell test -f "docker-compose.test.prod.yml" && echo "docker-compose.test.prod.yml" || echo "docker-compose.example.yml" )

.DEFAULT_GOAL := binary

# Deps
deps:
	bun install --frozen-lockfile --cwd frontend
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
	bun run --cwd frontend build
	cp -r frontend/dist internal/assets

# Build the binary
binary: webui
	CGO_ENABLED=$(CGO_ENABLED) go build -ldflags "-s -w \
	-X github.com/tinyauthapp/tinyauth/internal/config.Version=${TAG_NAME} \
	-X github.com/tinyauthapp/tinyauth/internal/config.CommitHash=${COMMIT_HASH} \
	-X github.com/tinyauthapp/tinyauth/internal/config.BuildTimestamp=${BUILD_TIMESTAMP}" \
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
.PHONY: test
test:
	go test -v ./...

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
.PHONY: sql
sql:
	sqlc generate

# Go gen
generate:
	go run ./gen
