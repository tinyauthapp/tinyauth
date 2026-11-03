import { z } from "zod";

type ScreenParams = {
  login_for?: "oidc" | "app";
  redirect_uri?: string;
  oidc_ticket?: string;
  oidc_scope?: string;
  oidc_name?: string;
  oidc_prompt?: "none" | "login";
  logout_reason?: "oidc";
};

const zodScreenParams = z.object({
  login_for: z.enum(["oidc", "app"]).optional(),
  redirect_uri: z.string().optional(),
  oidc_ticket: z.string().optional(),
  oidc_scope: z.string().optional(),
  oidc_name: z.string().optional(),
  oidc_prompt: z.enum(["none", "login"]).optional(),
  logout_reason: z.enum(["oidc"]).optional(),
});

export function useScreenParams(params: URLSearchParams): ScreenParams {
  const paramsObj = Object.fromEntries(params.entries());
  const parsed = zodScreenParams.safeParse(paramsObj);
  if (!parsed.success) {
    return {};
  }
  return parsed.data;
}

export function searchParamsFromObject(obj: object): URLSearchParams {
  return new URLSearchParams(
    Object.fromEntries(
      Object.entries(obj).filter(([, v]) => v !== undefined),
    ) as Record<string, string>,
  );
}
