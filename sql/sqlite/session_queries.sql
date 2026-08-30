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
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)
RETURNING *;

-- name: GetSession :one
SELECT * FROM "sessions"
WHERE "uuid" = ?;

-- name: DeleteSession :exec
DELETE FROM "sessions"
WHERE "uuid" = ?;

-- name: UpdateSession :one
UPDATE "sessions" SET
    "username" = ?,
    "email" = ?,
    "name" = ?,
    "provider" = ?,
    "totp_pending" = ?,
    "oauth_groups" = ?,
    "expiry" = ?,
    "oauth_name" = ?,
    "oauth_sub" = ?,
    "oauth_id_token" = ?
WHERE "uuid" = ?
RETURNING *;

-- name: DeleteExpiredSessions :exec
DELETE FROM "sessions"
WHERE "expiry" < ?;
