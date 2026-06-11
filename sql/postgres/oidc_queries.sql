-- name: GetOIDCSessionBySub :one
SELECT * FROM "oidc_sessions"
WHERE "sub" = $1;

-- name: GetOIDCSessionByAccessTokenHash :one
SELECT * FROM "oidc_sessions"
WHERE "access_token_hash" = $1;

-- name: GetOIDCSessionByRefreshTokenHash :one
SELECT * FROM "oidc_sessions"
WHERE "refresh_token_hash" = $1;

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
    $1, $2, $3, $4, $5, $6, $7, $8, $9
)
RETURNING *;

-- name: DeleteOIDCSessionBySub :exec
DELETE FROM "oidc_sessions"
WHERE "sub" = $1;

-- name: DeleteExpiredOIDCSessions :exec
DELETE FROM "oidc_sessions"
WHERE "token_expires_at" < $1 AND "refresh_token_expires_at" < $2;

-- name: UpdateOIDCSession :one
UPDATE "oidc_sessions" SET
    "access_token_hash" = $1,
    "refresh_token_hash" = $2,
    "scope" = $3,
    "client_id" = $4,
    "token_expires_at" = $5,
    "refresh_token_expires_at" = $6,
    "nonce" = $7,
    "userinfo_json" = $8
WHERE "sub" = $9
RETURNING *;

-- name: CreateOIDCConsent :one
INSERT INTO "oidc_consent" (
    "uuid",
    "client_id",
    "scopes"
) VALUES (
    $1, $2, $3
)
RETURNING *;

-- name: GetOIDCConsentByUUID :one
SELECT * FROM "oidc_consent"
WHERE "uuid" = $1;

-- name: UpdateOIDCConsent :one
UPDATE "oidc_consent" SET
    "scopes" = $1,
    "updated_at" = CURRENT_TIMESTAMP
WHERE "uuid" = $2
RETURNING *;

-- name: DeleteOIDCConsentByUUID :exec
DELETE FROM "oidc_consent"
WHERE "uuid" = $1;
