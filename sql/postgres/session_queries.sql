-- name: CreateSession :one
INSERT INTO "sessions" (
    "uuid",
    "username",
    "email",
    "name",
    "provider",
    "totp_pending",
    "oauth_groups",
    "expiry",
    "created_at",
    "oauth_name",
    "oauth_sub",
    "oauth_id_token"
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
)
RETURNING *;

-- name: GetSession :one
SELECT * FROM "sessions"
WHERE "uuid" = $1;

-- name: DeleteSession :exec
DELETE FROM "sessions"
WHERE "uuid" = $1;

-- name: UpdateSession :one
UPDATE "sessions" SET
    "username"     = $1,
    "email"        = $2,
    "name"         = $3,
    "provider"     = $4,
    "totp_pending" = $5,
    "oauth_groups" = $6,
    "expiry"       = $7,
    "oauth_name"   = $8,
    "oauth_sub"    = $9,
    "oauth_id_token" = $10
WHERE "uuid" = $11
RETURNING *;

-- name: DeleteExpiredSessions :exec
DELETE FROM "sessions"
WHERE "expiry" < $1;
