import { LoginForm } from "@/components/auth/login-form";
import { GithubIcon } from "@/components/icons/github";
import { GoogleIcon } from "@/components/icons/google";
import { MicrosoftIcon } from "@/components/icons/microsoft";
import { OAuthIcon } from "@/components/icons/oauth";
import { PocketIDIcon } from "@/components/icons/pocket-id";
import { TailscaleIcon } from "@/components/icons/tailscale";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
} from "@/components/ui/card";
import { OAuthButton } from "@/components/ui/oauth-button";
import { SeperatorWithChildren } from "@/components/ui/separator";
import { useAppContext } from "@/context/app-context";
import { useUserContext } from "@/context/user-context";
import { useOIDCParams } from "@/lib/hooks/oidc";
import { LoginSchema } from "@/schemas/login-schema";
import { useMutation } from "@tanstack/react-query";
import axios, { AxiosError } from "axios";
import { useEffect, useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Navigate, useLocation } from "react-router";
import { toast } from "sonner";

const iconMap: Record<string, React.ReactNode> = {
  google: <GoogleIcon />,
  github: <GithubIcon />,
  tailscale: <TailscaleIcon />,
  microsoft: <MicrosoftIcon />,
  pocketid: <PocketIDIcon />,
};

export const LoginPage = () => {
  const { isLoggedIn } = useUserContext();
  const { providers, title, oauthAutoRedirect } = useAppContext();
  const { search } = useLocation();
  const { t } = useTranslation();

  const [showRedirectButton, setShowRedirectButton] = useState(false);

  const hasAutoRedirectedRef = useRef(false);

  const redirectTimer = useRef<number | null>(null);
  const redirectButtonTimer = useRef<number | null>(null);

  const formId = useId();

  const searchParams = new URLSearchParams(search);
  const redirectUri = searchParams.get("redirect_uri") || undefined;
  const oidcParams = useOIDCParams(searchParams);

  const [isOauthAutoRedirect, setIsOauthAutoRedirect] = useState(
    providers.find((provider) => provider.id === oauthAutoRedirect) !==
      undefined && redirectUri !== undefined,
  );

  const oauthProviders = providers.filter(
    (provider) => provider.id !== "local" && provider.id !== "ldap",
  );
  const userAuthConfigured =
    providers.find(
      (provider) => provider.id === "local" || provider.id === "ldap",
    ) !== undefined;

  const {
    mutate: oauthMutate,
    data: oauthData,
    isPending: oauthIsPending,
    variables: oauthVariables,
  } = useMutation({
    mutationFn: (provider: string) => {
      const getParams = function (): string {
        if (oidcParams.isOidc) {
          return `?${oidcParams.compiled}`;
        }
        if (redirectUri) {
          return `?redirect_uri=${encodeURIComponent(redirectUri)}`;
        }
        return "";
      };
      return axios.get(`/api/oauth/url/${provider}${getParams()}`);
    },
    mutationKey: ["oauth"],
    onSuccess: (data) => {
      toast.info(t("loginOauthSuccessTitle"), {
        description: t("loginOauthSuccessSubtitle"),
      });

      redirectTimer.current = window.setTimeout(() => {
        window.location.replace(data.data.url);
      }, 500);

      if (isOauthAutoRedirect) {
        redirectButtonTimer.current = window.setTimeout(() => {
          setShowRedirectButton(true);
        }, 5000);
      }
    },
    onError: () => {
      setIsOauthAutoRedirect(false);
      toast.error(t("loginOauthFailTitle"), {
        description: t("loginOauthFailSubtitle"),
      });
    },
  });

  const { mutate: loginMutate, isPending: loginIsPending } = useMutation({
    mutationFn: (values: LoginSchema) => axios.post("/api/user/login", values),
    mutationKey: ["login"],
    onSuccess: (data) => {
      if (data.data.totpPending) {
        if (oidcParams.isOidc) {
          window.location.replace(`/totp?${oidcParams.compiled}`);
          return;
        }
        window.location.replace(
          `/totp${redirectUri ? `?redirect_uri=${encodeURIComponent(redirectUri)}` : ""}`,
        );
        return;
      }

      toast.success(t("loginSuccessTitle"), {
        description: t("loginSuccessSubtitle"),
      });

      redirectTimer.current = window.setTimeout(() => {
        if (oidcParams.isOidc) {
          window.location.replace(`/authorize?${oidcParams.compiled}`);
          return;
        }
        window.location.replace(
          `/continue${redirectUri ? `?redirect_uri=${encodeURIComponent(redirectUri)}` : ""}`,
        );
      }, 500);
    },
    onError: (error: AxiosError) => {
      toast.error(t("loginFailTitle"), {
        description:
          error.response?.status === 429
            ? t("loginFailRateLimit")
            : t("loginFailSubtitle"),
      });
    },
  });

  useEffect(() => {
    if (
      !isLoggedIn &&
      isOauthAutoRedirect &&
      !hasAutoRedirectedRef.current &&
      redirectUri !== undefined
    ) {
      hasAutoRedirectedRef.current = true;
      oauthMutate(oauthAutoRedirect);
    }
  }, [
    isLoggedIn,
    oauthMutate,
    hasAutoRedirectedRef,
    oauthAutoRedirect,
    isOauthAutoRedirect,
    redirectUri,
  ]);

  useEffect(() => {
    return () => {
      if (redirectTimer.current) {
        clearTimeout(redirectTimer.current);
      }

      if (redirectButtonTimer.current) {
        clearTimeout(redirectButtonTimer.current);
      }
    };
  }, [redirectTimer, redirectButtonTimer]);

  if (isLoggedIn && oidcParams.isOidc) {
    return <Navigate to={`/authorize?${oidcParams.compiled}`} replace />;
  }

  if (isLoggedIn && redirectUri !== undefined) {
    return (
      <Navigate
        to={`/continue${redirectUri ? `?redirect_uri=${encodeURIComponent(redirectUri)}` : ""}`}
        replace
      />
    );
  }

  if (isLoggedIn) {
    return <Navigate to="/logout" replace />;
  }

  if (isOauthAutoRedirect) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-xl">
            {t("loginOauthAutoRedirectTitle")}
          </CardTitle>
          <CardDescription>
            {t("loginOauthAutoRedirectSubtitle")}
          </CardDescription>
        </CardHeader>
        {showRedirectButton && (
          <CardFooter className="flex flex-col items-stretch">
            <Button
              onClick={() => {
                if (oauthData?.data.url) {
                  window.location.replace(oauthData.data.url);
                } else {
                  setIsOauthAutoRedirect(false);
                  toast.error(t("loginOauthFailTitle"), {
                    description: t("loginOauthFailSubtitle"),
                  });
                }
              }}
            >
              {t("loginOauthAutoRedirectButton")}
            </Button>
          </CardFooter>
        )}
      </Card>
    );
  }
  return (
    <Card>
      <CardHeader className="gap-1.5">
        <CardTitle className="text-center text-xl">{title}</CardTitle>
        {providers.length > 0 && (
          <CardDescription className="text-center">
            {oauthProviders.length !== 0
              ? t("loginTitle")
              : t("loginTitleSimple")}
          </CardDescription>
        )}
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {oauthProviders.length !== 0 && (
          <div className="flex flex-col gap-2.5 items-center justify-center">
            {oauthProviders.map((provider) => (
              <OAuthButton
                key={provider.id}
                title={provider.name}
                icon={iconMap[provider.id] ?? <OAuthIcon />}
                className="w-full"
                onClick={() => oauthMutate(provider.id)}
                loading={oauthIsPending && oauthVariables === provider.id}
                disabled={oauthIsPending || loginIsPending}
              />
            ))}
          </div>
        )}
        {userAuthConfigured && oauthProviders.length !== 0 && (
          <SeperatorWithChildren>{t("loginDivider")}</SeperatorWithChildren>
        )}
        {userAuthConfigured && (
          <LoginForm
            onSubmit={(values) => loginMutate(values)}
            loading={loginIsPending || oauthIsPending}
            formId={formId}
            params={(() => {
              const eparams = searchParams.toString();
              return eparams.length > 0 ? `?${eparams}` : "";
            })()}
          />
        )}
        {providers.length == 0 && (
          <pre className="break-normal! text-sm text-red-600">
            {t("failedToFetchProvidersTitle")}
          </pre>
        )}
      </CardContent>
      {userAuthConfigured && (
        <CardFooter>
          <Button
            className="w-full"
            type="submit"
            form={formId}
            loading={loginIsPending || oauthIsPending}
          >
            {t("loginSubmit")}
          </Button>
        </CardFooter>
      )}
    </Card>
  );
};
