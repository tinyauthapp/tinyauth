-- name: GetOIDCSessionBySub :one
SELECT * FROM "oidc_sessions"
WHERE "sub" = ?;

-- name: GetOIDCSessionByAccessTokenHash :one
SELECT * FROM "oidc_sessions"
WHERE "access_token_hash" = ?;

-- name: GetOIDCSessionByRefreshTokenHash :one
SELECT * FROM "oidc_sessions"
WHERE "refresh_token_hash" = ?;

-- name: CreateOIDCSession :one
INSERT INTO "oidc_sessions" (
    "sub",
    "access_token_hash",
    "refresh_token_hash",
    "scope",
    "client_id",
    "token_expires_at",
    "refresh_token_expires_at",
    "nonce",
    "userinfo_json"
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?
)
RETURNING *;

-- name: DeleteOIDCSessionBySub :exec
DELETE FROM "oidc_sessions"
WHERE "sub" = ?;

-- name: DeleteExpiredOIDCSessions :exec
DELETE FROM "oidc_sessions"
WHERE "token_expires_at" < ? AND "refresh_token_expires_at" < ?;

-- name: UpdateOIDCSession :one
UPDATE "oidc_sessions" SET
    "access_token_hash" = ?,
    "refresh_token_hash" = ?,
    "scope" = ?,
    "client_id" = ?,
    "token_expires_at" = ?,
    "refresh_token_expires_at" = ?,
    "nonce" = ?,
    "userinfo_json" = ?
WHERE "sub" = ?
RETURNING *;

-- name: UpsertOIDCConsent :one
INSERT INTO "oidc_consents" (
    "username",
    "client_id",
    "scope",
    "created_at"
) VALUES (
    ?, ?, ?, ?
)
ON CONFLICT ("username", "client_id")
DO UPDATE SET
    "scope" = excluded.scope,
    "created_at" = excluded.created_at
RETURNING *;

-- name: GetOIDCConsentByUsernameAndClientID :one
SELECT * FROM "oidc_consents"
WHERE "username" = ? AND "client_id" = ?;

-- name: DeleteOIDCConsentByClientID :exec
DELETE FROM "oidc_consents"
WHERE "client_id" = ?;

-- name: ListOIDCConsents :many
SELECT * FROM "oidc_consents";
