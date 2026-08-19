ALTER TABLE "oidc_codes" ADD COLUMN "nonce" TEXT DEFAULT "";
ALTER TABLE "oidc_tokens" ADD COLUMN "nonce" TEXT DEFAULT "";
