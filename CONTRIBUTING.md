# Contributing

Contributing to Tinyauth is straightforward. Follow the steps below to set up a development server.

> [!NOTE]
> If you are using large language models to contribute to the project, please ensure that you have read and understood the [AI Policy](AI_POLICY.md).

## Requirements

- Bun
- Golang v1.24.0 or later
- Git
- Docker
- Make

## Cloning the Repository

Start by cloning the repository:

```sh
git clone https://github.com/tinyauthapp/tinyauth
cd tinyauth
```

## Installing Dependencies

While development occurs within Docker, installing the dependencies locally is recommended to avoid import errors. Install the Go dependencies:

```sh
go mod tidy
```

Frontend dependencies can be installed as follows:

```sh
cd frontend/
bun install
```

## Create the `.env` file

Configuration requires an environment file. Copy the `.env.example` file to `.env` and adjust the environment variables as needed.

## Development Workflow

The development workflow is designed to run entirely within Docker, ensuring compatibility with Traefik and eliminating the need for local builds. A recommended setup involves pointing a subdomain to the local machine:

```
*.dev.example.com -> 127.0.0.1
dev.example.com -> 127.0.0.1
```

> [!NOTE]
> A domain from [sslip.io](https://sslip.io) can be used if a custom domain is
  unavailable. For example, set the Tinyauth domain to `tinyauth.127.0.0.1.sslip.io` and the whoami domain to `whoami.127.0.0.1.sslip.io`.

Ensure the domains are correctly configured in the development Docker Compose file, then start the development environment:

```sh
make dev
```

In case you need to build the binary locally, you can run:

```sh
make binary
```

> [!NOTE]
> Copying the example `docker-compose.dev.yml` file to `docker-compose.test.yml`
  is recommended to prevent accidental commits of sensitive information. The make recipe will automatically use `docker-compose.test.yml` as well as `docker-compose.test.prod.yml` (for the `make prod` recipe) if it exists.
