import { z } from "zod";

export const userContextSchema = z.object({
  isLoggedIn: z.boolean(),
  username: z.string(),
  name: z.string(),
  email: z.string(),
  provider: z.string(),
  oauth: z.boolean(),
  totpPending: z.boolean(),
  oauthName: z.string(),
  tailscaleNodeName: z.string(),
});

export type UserContextSchema = z.infer<typeof userContextSchema>;
