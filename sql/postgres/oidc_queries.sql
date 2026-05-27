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
    $1, $2, $3, $4, $5, $6, $7, $8
)
RETURNING *;

-- name: GetOidcCodeUnsafe :one
SELECT * FROM "oidc_codes"
WHERE "code_hash" = $1;

-- name: GetOidcCode :one
DELETE FROM "oidc_codes"
WHERE "code_hash" = $1
RETURNING *;

-- name: GetOidcCodeBySubUnsafe :one
SELECT * FROM "oidc_codes"
WHERE "sub" = $1;

-- name: GetOidcCodeBySub :one
DELETE FROM "oidc_codes"
WHERE "sub" = $1
RETURNING *;

-- name: DeleteOidcCode :exec
DELETE FROM "oidc_codes"
WHERE "code_hash" = $1;

-- name: DeleteOidcCodeBySub :exec
DELETE FROM "oidc_codes"
WHERE "sub" = $1;

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
    $1, $2, $3, $4, $5, $6, $7, $8, $9
)
RETURNING *;

-- name: UpdateOidcTokenByRefreshToken :one
UPDATE "oidc_tokens" SET
    "access_token_hash"        = $1,
    "refresh_token_hash"       = $2,
    "token_expires_at"         = $3,
    "refresh_token_expires_at" = $4
WHERE "refresh_token_hash" = $5
RETURNING *;

-- name: GetOidcToken :one
SELECT * FROM "oidc_tokens"
WHERE "access_token_hash" = $1;

-- name: GetOidcTokenByRefreshToken :one
SELECT * FROM "oidc_tokens"
WHERE "refresh_token_hash" = $1;

-- name: GetOidcTokenBySub :one
SELECT * FROM "oidc_tokens"
WHERE "sub" = $1;

-- name: DeleteOidcTokenByCodeHash :exec
DELETE FROM "oidc_tokens"
WHERE "code_hash" = $1;

-- name: DeleteOidcToken :exec
DELETE FROM "oidc_tokens"
WHERE "access_token_hash" = $1;

-- name: DeleteOidcTokenBySub :exec
DELETE FROM "oidc_tokens"
WHERE "sub" = $1;

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
    "address"
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
)
RETURNING *;

-- name: GetOidcUserInfo :one
SELECT * FROM "oidc_userinfo"
WHERE "sub" = $1;

-- name: DeleteOidcUserInfo :exec
DELETE FROM "oidc_userinfo"
WHERE "sub" = $1;

-- name: DeleteExpiredOidcCodes :many
DELETE FROM "oidc_codes"
WHERE "expires_at" < $1
RETURNING *;

-- name: DeleteExpiredOidcTokens :many
DELETE FROM "oidc_tokens"
WHERE "token_expires_at" < $1 AND "refresh_token_expires_at" < $2
RETURNING *;
