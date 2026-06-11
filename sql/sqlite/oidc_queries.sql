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

-- name: CreateOIDCConsent :one
INSERT INTO "oidc_consent" (
    "uuid",
    "client_id",
    "scopes"
) VALUES (
    ?, ?, ?
)
RETURNING *;

-- name: GetOIDCConsentByUUID :one
SELECT * FROM "oidc_consent"
WHERE "uuid" = ?;

-- name: UpdateOIDCConsent :one
UPDATE "oidc_consent" SET
    "scopes" = ?,
    "updated_at" = CURRENT_TIMESTAMP
WHERE "uuid" = ?
RETURNING *;

-- name: DeleteOIDCConsentByUUID :exec
DELETE FROM "oidc_consent"
WHERE "uuid" = ?;
