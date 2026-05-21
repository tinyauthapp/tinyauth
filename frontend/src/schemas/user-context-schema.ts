import { z } from "zod";

const authSchema = z.object({
  authenticated: z.boolean(),
  username: z.string(),
  name: z.string(),
  email: z.string(),
  providerId: z.string(),
});

const oauthSchema = z.object({
  active: z.boolean(),
  displayName: z.string(),
});

const totpSchema = z.object({
  pending: z.boolean(),
});

const tailscaleSchema = z.object({
  nodeName: z.string().optional(),
});

export const userContextSchema = z.object({
  auth: authSchema,
  oauth: oauthSchema,
  totp: totpSchema,
  tailscale: tailscaleSchema,
});

export type UserContextSchema = z.infer<typeof userContextSchema>;
