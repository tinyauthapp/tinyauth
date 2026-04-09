-- name: CreateOidcCode :one
INSERT INTO "oidc_codes" (
    "sub",
    "code_hash",
    "scope",
    "redirect_uri",
    "client_id",
    "expires_at",
    "nonce",
    "code_challenge"
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?
)
RETURNING *;

-- name: GetOidcCodeUnsafe :one
SELECT * FROM "oidc_codes"
WHERE "code_hash" = ?;

-- name: GetOidcCode :one
DELETE FROM "oidc_codes"
WHERE "code_hash" = ?
RETURNING *;

-- name: GetOidcCodeBySubUnsafe :one
SELECT * FROM "oidc_codes"
WHERE "sub" = ?;

-- name: GetOidcCodeBySub :one
DELETE FROM "oidc_codes"
WHERE "sub" = ?
RETURNING *;

-- name: DeleteOidcCode :exec
DELETE FROM "oidc_codes"
WHERE "code_hash" = ?;

-- name: DeleteOidcCodeBySub :exec
DELETE FROM "oidc_codes"
WHERE "sub" = ?;

-- name: CreateOidcToken :one
INSERT INTO "oidc_tokens" (
    "sub",
    "access_token_hash",
    "refresh_token_hash",
    "scope",
    "client_id",
    "token_expires_at",
    "refresh_token_expires_at",
    "code_hash",
    "nonce"
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?
)
RETURNING *;

-- name: UpdateOidcTokenByRefreshToken :one
UPDATE "oidc_tokens" SET
    "access_token_hash" = ?,
    "refresh_token_hash" = ?,
    "token_expires_at" = ?,
    "refresh_token_expires_at" = ?
WHERE "refresh_token_hash" = ?
RETURNING *;

-- name: GetOidcToken :one
SELECT * FROM "oidc_tokens"
WHERE "access_token_hash" = ?;

-- name: GetOidcTokenByRefreshToken :one
SELECT * FROM "oidc_tokens"
WHERE "refresh_token_hash" = ?;

-- name: GetOidcTokenBySub :one
SELECT * FROM "oidc_tokens"
WHERE "sub" = ?;

-- name: DeleteOidcTokenByCodeHash :exec
DELETE FROM "oidc_tokens"
WHERE "code_hash" = ?;

-- name: DeleteOidcToken :exec
DELETE FROM "oidc_tokens"
WHERE "access_token_hash" = ?;

-- name: DeleteOidcTokenBySub :exec
DELETE FROM "oidc_tokens"
WHERE "sub" = ?;

-- name: CreateOidcUserInfo :one
INSERT INTO "oidc_userinfo" (
    "sub",
    "name",
    "preferred_username",
    "email",
    "groups",
    "updated_at",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "phone_number",
    "phone_number_verified",
    "address"
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)
RETURNING *;

-- name: GetOidcUserInfo :one
SELECT * FROM "oidc_userinfo"
WHERE "sub" = ?;

-- name: DeleteOidcUserInfo :exec
DELETE FROM "oidc_userinfo"
WHERE "sub" = ?;

-- name: DeleteExpiredOidcCodes :many
DELETE FROM "oidc_codes"
WHERE "expires_at" < ?
RETURNING *;

-- name: DeleteExpiredOidcTokens :many
DELETE FROM "oidc_tokens"
WHERE "token_expires_at" < ? AND "refresh_token_expires_at" < ?
RETURNING *;
