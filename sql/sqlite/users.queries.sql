-- name: CreateUser :one
INSERT INTO "users" (
    "uuid",
    "username",
    "email",
    "name"
) VALUES (
    ?, ?, ?, ?
)
RETURNING *;

-- name: GetUserByUUID :one
SELECT * FROM "users"
WHERE "uuid" = ?;

-- name: GetUserByUsername :one
SELECT * FROM "users"
WHERE "username" = ?;

-- name: GetUserByEmail :one
SELECT * FROM "users"
WHERE "email" = ?;

-- name: UpdateUser :exec
UPDATE "users" SET
    "username" = ?,
    "email" = ?,
    "name" = ?
WHERE "uuid" = ?;