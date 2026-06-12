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
import { LoginSchema } from "@/schemas/login-schema";
import { useMutation } from "@tanstack/react-query";
import axios, { AxiosError } from "axios";
import { useEffect, useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Navigate, useLocation } from "react-router";
import { toast } from "sonner";
import {
  recompileScreenParams,
  useScreenParams,
} from "@/lib/hooks/screen-params";
import { useLoginFor } from "@/lib/hooks/login-for";

const iconMap: Record<string, React.ReactNode> = {
  google: <GoogleIcon />,
  github: <GithubIcon />,
  tailscale: <TailscaleIcon />,
  microsoft: <MicrosoftIcon />,
  pocketid: <PocketIDIcon />,
};

export const LoginPage = () => {
  const { auth, tailscale } = useUserContext();
  const {
    ui,
    oauth,
    auth: { providers },
  } = useAppContext();
  const { search } = useLocation();
  const { t } = useTranslation();

  const [showRedirectButton, setShowRedirectButton] = useState(false);
  const [useTailscale, setUseTailscale] = useState(
    tailscale.nodeName !== undefined,
  );

  const hasAutoRedirectedRef = useRef(false);

  const redirectTimer = useRef<number | null>(null);
  const redirectButtonTimer = useRef<number | null>(null);

  const formId = useId();

  const searchParams = new URLSearchParams(search);
  const screenParams = useScreenParams(searchParams);
  const compiledParams = recompileScreenParams(screenParams);
  const loginForUrl = useLoginFor({
    login_for: screenParams.login_for,
    compiledParams,
  });

  const [isOauthAutoRedirect, setIsOauthAutoRedirect] = useState(
    providers.find((provider) => provider.id === oauth.autoRedirect) !==
      undefined && screenParams.redirect_uri !== undefined,
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
      return axios.get(`/api/oauth/url/${provider}${compiledParams}`);
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
        window.location.replace(`/totp${compiledParams}`);
        return;
      }

      toast.success(t("loginSuccessTitle"), {
        description: t("loginSuccessSubtitle"),
      });

      redirectTimer.current = window.setTimeout(() => {
        window.location.replace(loginForUrl);
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

  const { mutate: tailscaleMutate, isPending: tailscaleIsPending } =
    useMutation({
      mutationFn: () => axios.post("/api/user/tailscale"),
      mutationKey: ["tailscale"],
      onSuccess: () => {
        toast.success(t("loginSuccessTitle"), {
          description: t("loginTailscaleSuccess"),
        });

        redirectTimer.current = window.setTimeout(() => {
          window.location.replace(loginForUrl);
        }, 500);
      },
      onError: () => {
        toast.error(t("loginFailTitle"), {
          description: t("loginTailscaleFail"),
        });
      },
    });

  useEffect(() => {
    if (
      !auth.authenticated &&
      isOauthAutoRedirect &&
      !hasAutoRedirectedRef.current &&
      screenParams.redirect_uri &&
      screenParams.login_for
    ) {
      hasAutoRedirectedRef.current = true;
      oauthMutate(oauth.autoRedirect);
    }
  }, [
    auth.authenticated,
    oauthMutate,
    hasAutoRedirectedRef,
    oauth.autoRedirect,
    isOauthAutoRedirect,
    screenParams.login_for,
    screenParams.redirect_uri,
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

  if (auth.authenticated) {
    return <Navigate to={loginForUrl} replace />;
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

  if (useTailscale) {
    return (
      <Card>
        <CardHeader className="gap-3">
          <TailscaleIcon className="mx-auto h-8 w-8" />
          <CardTitle className="text-center text-xl">
            {t("loginTailscaleTitle")}
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="text-muted-foreground text-sm">
            {t("loginTailscaleDescription")}
          </div>
          <div className="text-muted-foreground text-sm">
            {t("loginTailscaleDeviceName")} <code>{tailscale.nodeName}</code>
          </div>
        </CardContent>
        <CardFooter className="flex flex-col items-stretch gap-3">
          <Button
            className="w-full"
            onClick={() => tailscaleMutate()}
            loading={tailscaleIsPending}
          >
            {t("loginTailscaleSubmit")}
          </Button>
          <Button
            className="w-full"
            variant="outline"
            onClick={() => setUseTailscale(false)}
            disabled={tailscaleIsPending}
          >
            {t("loginTailscaleOtherMethod")}
          </Button>
        </CardFooter>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="gap-1.5">
        <CardTitle className="text-center text-xl">{ui.title}</CardTitle>
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
