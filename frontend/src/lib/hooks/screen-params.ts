import { z } from "zod";

type ScreenParams = {
  login_for?: "oidc" | "app";
  redirect_uri?: string;
  oidc_ticket?: string;
  oidc_scope?: string;
  oidc_name?: string;
};

const zodScreenParams = z.object({
  login_for: z.enum(["oidc", "app"]).optional(),
  redirect_uri: z.string().optional(),
  oidc_ticket: z.string().optional(),
  oidc_scope: z.string().optional(),
  oidc_name: z.string().optional(),
});

export function useScreenParams(params: URLSearchParams): ScreenParams {
  const paramsObj = Object.fromEntries(params.entries());
  const parsed = zodScreenParams.safeParse(paramsObj);
  if (!parsed.success) {
    return {};
  }
  return parsed.data;
}

export function recompileScreenParams(params: ScreenParams): string {
  const p = new URLSearchParams(
    Object.fromEntries(
      Object.entries(params).filter(([, v]) => v !== null),
    ) as Record<string, string>,
  ).toString();

  if (p.length > 0) {
    return "?" + p;
  }

  return "";
}
