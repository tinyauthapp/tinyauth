# Agents

*This file is written by Humans for Agents.*

## Overview

Tinyauth is a lightweight and open-source authentication server written in Go and TypeScript (React). It acts as either an authentication middleware (forward_auth, ext_authz or auth_request) to protect applications using proxy authentication or as an OpenID Connect provider to offer SSO (Single-Sign-On) to your self-hosted apps. It supports local users with optional 2FA (via TOTP), LDAP, SSO users via OAuth, and access controls (ACLs). Tinyauth can be deployed with Docker, Kubernetes or bare-metal with a binary.

## Considerations

- The repository we are working at is `https://github.com/tinyauthapp/tinyauth`.
- ALWAYS follow the instructions for committing and creating a pull request as mentioned below. 

## Philosophy

Tinyauth is designed to run with simplicity in mind. This is why we try to avoid adding unnecessary persistent storage and configuration options.

Tinyauth can run without persistent storage, and the SQLite database is only used for storing normal or OpenID Connect sessions. You MUST never store data in the database that is required for Tinyauth function.

As for the configuration, we support environment variables, CLI flags and a YAML configuration file. We try to keep the required configuration at a minimal with sane defaults so users can spend the least amount of time configuring Tinyauth.

We NEVER create a breaking change unless absolutely necessary and only if non-breaking changes have been discussed and deemed not ideal.

## Technical Overview

Tinyauth is designed to be as modular as possible. We use a repository-service-controller structure where each service/controller/middleware defines its dependencies in a Dig input struct, and then the main bootstrap entrypoint dynamically injects the dependencies to each method.

All methods share one global static config struct, which contains the user configuration as is, and a runtime config struct that contains dynamically generated values on startup. If a method needs a modified version, it MUST never modify the global configuration struct but rather create a local copy.

We write database migrations by hand. Migrations go in the respective database directory inside the `assets/migrations` directory and follow the `000001_migration_name_in_snake_case.sql` format where the 6-digit number is incremented on each new migration. The repository is automatically generated from SQL queries, SQLC and our own custom generator that unifies each SQLC package into one repository interface. Always ensure that migrations and queries exist for all available database drivers, else our store generation will fail. After adding your migrations and queries, run the SQLC code-gen with `make sql` and update the store code-gen with `make generate`. DO NOT EDIT the automatically generated files from SQLC or our store generator, they are marked.

When updating translations, you should only update the `frontend/src/lib/i18n/locales/en.json` and `frontend/src/lib/i18n/locales/en-US.json` files (they should be exactly the same). Crowdin will handle the generation of the keys for the rest of the available locales. NEVER hard-code plain English in the frontend, instead use the available `i18next` library and the respective translations.

For the REST framework we use Gin. However, functions or methods should avoid using the Gin Context (`gin.Context`) and default to stdlib arguments and outputs. The Gin Context exposes stdlib-compatible structs such as `http.Request` and `http.ResponseWriter` and is compatible with the `context` package.

When you need to log in the backend, use the injected logger, NOT the global zerolog struct.

In case you need toolchain versions, you can find the Node + Go version in the `Dockerfile` and the PNPM version in the `package.json` file inside the `frontend` directory.

Tinyauth uses Semantic Versioning (SemVer) for versions. 

## File structure

Tinyauth is composed of two parts, the React frontend and the Go backend.

A high level of the backend is as follows:

```text
internal 
├── assets # Contains the embedded assets
│   ├── dist # Dist is the compiled frontend
│   └── migrations # Migrations in SQL for all supported databases
│       ├── postgres
│       └── sqlite
├── bootstrap # The main entrypoint that bootstraps and starts Tinyauth, called by the CLI
├── controller # All of the HTTP controllers
├── middleware # The HTTP middlewares
├── model # Configuration schemas
├── repository # Repository holds all of the queries used by the services, each child-repository implements the store interface
│   ├── memory
│   ├── postgres
│   └── sqlite
├── service # The services that handle the underlying logic for the controllers
├── test # Creates any necessary package-wide configurations and helpers used by tests 
└── utils # Small helpers and utils used by the app
    ├── decoders # Wrappers around paerser decoders such as the label decoder
    ├── loaders # The env, cli and YAML wrappers around the paerser loaders
    └── logger # A wrapper around the zerolog logging library
```

Same for the frontend:

```text
frontend/src
├── components # Different components used by the pages
│   ├── auth # Forms used for authentication
│   ├── domain-warning # Domain warning when configured domain and actual domain don't match
│   ├── icons # Hardcoded SVG icons for OAuth providers
│   ├── layout # Main frontend layout
│   ├── providers # Different state providers such as theme
│   ├── quick-actions # The top right quick settings menu
│   └── ui # ShadCN based UI components
├── context # Holds and provides the app and user context
├── lib # Helpers used by the pages
│   ├── hooks # Hooks around the query parameters
│   └── i18n # Holds translation logic
│       └── locales # The raw JSON locales provided by Crowdin
├── pages # The actual app pages
└── schemas # Different schemas, mostly used for fetching data from the backend
```

## Make recipes

Tinyauth uses a Makefile for simplifying development. A reference of the available recipes can be found below:

- `deps` - Install the frontend and backend dependencies.
- `clean-data` - Clean any data created by running Tinyauth.
- `clean-webui` - Clean frontend build output.
- `webui` - Compile the WebUI.
- `binary` - Compile the binary for the current system.
- `binary-linux-amd64` - Compile the binary for Linux amd64.
- `binary-linux-arm64` - Compile the binary for Linux arm64.
- `test` - Test the Go backend.
- `vet` - Vet the Go backend.
- `test-race` - Test the Go backend with the race detector enabled.
- `dev` - Start the Docker-based development server.
- `prod` - Start the Docker-based production deployment (used for testing pre-releases).
- `sql` - Generate the SQLC repositories.
- `generate` - Update Go code-gen.
- `docker` - Build the Docker image for the current system.
- `docker-distroless` - Build the distroless Docker image for the current system.
- `lint-webui` - Lint the frontend with ESLint.
- `fmt` - Format the Go code with the Go `fmt` tool.

## Development lifecycle

Development of Tinyauth happens inside two Docker containers. The backend is built automatically by air using a template build output for the frontend. The frontend is run with PNPM, and then backend requests are routed with the help of Vite's proxy.

When developing, you should default to the `make dev` command to start everything in Docker and avoid platform-specific issues. If you need to test the CLI, use the `make binary` command.

After finishing with the development, test and vet the backend with `make test` and `make vet` respectively. If you believe you need to test for race conditions, use `make test-race`. You can also test specific parts of the code using the normal `go test` command, for example to run the `TestHealthController` test, you can use `go test ./internal/controller/ -run TestHealthController -v`. Finally, format the Go code with `make fmt`.

If you made any changes to the frontend, make sure to lint with  `make lint-webui`.

NEVER run any destructive commands like `make clean-data` or delete any configurations without the user's approval.

## Creating a pull request

When committing, you MUST use the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0) standard for your commit messages. You can add a commit description if you like. You MUST also use your standard no reply Co-Author trailer.

You should work in separate branches unless it's clearly specified to work in the main branch. When working in a separate branch, follow the naming convention below:

```text
[feat/refactor/fix/tests/etc]/[small-change-description-in-kebab-case]
```

For example, if your change was to add OAuth to Tinyauth, the branch would look as follows:

```text
feat/oauth
```

Or:

```text
feat/add-oauth-support
```

Shorter branch names that still describe the general change are preferred.

Finally, when creating the actual pull request and if you have access to the internet/a GitHub tool, you should look if it resolves any open issues and if it does, reference them.
