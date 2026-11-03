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
