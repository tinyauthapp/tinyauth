import { z } from "zod";

export const providerSchema = z.object({
  id: z.string(),
  name: z.string(),
  oauth: z.boolean(),
});

const authSchema = z.object({
  providers: z.array(providerSchema),
});

const oauthSchema = z.object({
  autoRedirect: z.string(),
});

const uiSchema = z.object({
  title: z.string(),
  forgotPasswordMessage: z.string(),
  backgroundImage: z.string(),
  warningsEnabled: z.boolean(),
});

const appSchema = z.object({
  appUrl: z.string(),
  cookieDomain: z.string(),
});

export const appContextSchema = z.object({
  auth: authSchema,
  oauth: oauthSchema,
  ui: uiSchema,
  app: appSchema,
});

export type AppContextSchema = z.infer<typeof appContextSchema>;
