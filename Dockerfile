# Site builder
FROM oven/bun:1.3.13-alpine AS frontend-builder

WORKDIR /frontend

COPY ./frontend/package.json ./
COPY ./frontend/bun.lock ./

RUN bun install --frozen-lockfile

COPY ./frontend/public ./public
COPY ./frontend/src ./src
COPY ./frontend/eslint.config.js ./
COPY ./frontend/index.html ./
COPY ./frontend/tsconfig.json ./
COPY ./frontend/tsconfig.app.json ./
COPY ./frontend/tsconfig.node.json ./
COPY ./frontend/vite.config.ts ./

RUN bun run build

# Builder
FROM golang:1.26-alpine3.23 AS builder

ARG VERSION
ARG COMMIT_HASH
ARG BUILD_TIMESTAMP

WORKDIR /tinyauth

COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY ./cmd ./cmd
COPY ./internal ./internal
COPY --from=frontend-builder /frontend/dist ./internal/assets/dist

RUN CGO_ENABLED=0 go build -ldflags "-s -w \
    -X github.com/tinyauthapp/tinyauth/internal/config.Version=${VERSION} \
    -X github.com/tinyauthapp/tinyauth/internal/config.CommitHash=${COMMIT_HASH} \
    -X github.com/tinyauthapp/tinyauth/internal/config.BuildTimestamp=${BUILD_TIMESTAMP}" ./cmd/tinyauth

# Runner
FROM alpine:3.23 AS runner

WORKDIR /tinyauth

COPY --from=builder /tinyauth/tinyauth ./

RUN mkdir -p /data

EXPOSE 3000

VOLUME ["/data"]

ENV TINYAUTH_DATABASE_PATH=/data/tinyauth.db

ENV TINYAUTH_RESOURCES_PATH=/data/resources

ENV PATH=$PATH:/tinyauth

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["tinyauth", "healthcheck"]

ENTRYPOINT ["tinyauth"]
