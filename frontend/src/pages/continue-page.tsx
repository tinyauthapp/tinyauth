import { Button } from "@/components/ui/button";
import {
  Card,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useAppContext } from "@/context/app-context";
import { useUserContext } from "@/context/user-context";
import { Trans, useTranslation } from "react-i18next";
import { Navigate, useLocation, useNavigate } from "react-router";
import { useCallback, useEffect, useRef, useState } from "react";
import { useRedirectUri } from "@/lib/hooks/redirect-uri";
import {
  recompileScreenParams,
  useScreenParams,
} from "@/lib/hooks/screen-params";

export const ContinuePage = () => {
  const { app, ui } = useAppContext();
  const { auth } = useUserContext();
  const { search } = useLocation();
  const { t } = useTranslation();
  const navigate = useNavigate();

  const [isLoading, setIsLoading] = useState(false);
  const [showRedirectButton, setShowRedirectButton] = useState(false);
  const hasRedirected = useRef(false);

  const searchParams = new URLSearchParams(search);
  const screenParams = useScreenParams(searchParams);
  const redirectUri = screenParams.redirect_uri;
  const isAppLogin = screenParams.login_for === "app";
  const recompiledParams = recompileScreenParams(screenParams);

  const { url, valid, trusted, allowedProto, httpsDowngrade } = useRedirectUri(
    redirectUri,
    app.cookieDomain,
    app.appUrl,
    app.subdomainsEnabled,
  );

  const urlHref = url?.href;

  const hasValidRedirect = valid && allowedProto;
  const showUntrustedWarning =
    hasValidRedirect && !trusted && ui.warningsEnabled;
  const showInsecureWarning =
    hasValidRedirect && httpsDowngrade && ui.warningsEnabled;
  const shouldAutoRedirect =
    auth.authenticated &&
    hasValidRedirect &&
    !showUntrustedWarning &&
    !showInsecureWarning &&
    isAppLogin;

  const redirectToTarget = useCallback(() => {
    if (!urlHref || hasRedirected.current) {
      return;
    }

    hasRedirected.current = true;
    window.location.assign(urlHref);
  }, [urlHref]);

  const handleRedirect = useCallback(() => {
    setIsLoading(true);
    redirectToTarget();
  }, [redirectToTarget]);

  useEffect(() => {
    if (!shouldAutoRedirect) {
      return;
    }

    const auto = setTimeout(() => {
      redirectToTarget();
    }, 100);

    const reveal = setTimeout(() => {
      setShowRedirectButton(true);
    }, 5000);

    return () => {
      clearTimeout(auto);
      clearTimeout(reveal);
    };
  }, [shouldAutoRedirect, redirectToTarget]);

  if (!auth.authenticated) {
    return <Navigate to={`/login${recompiledParams}`} replace />;
  }

  if (!hasValidRedirect || !isAppLogin) {
    return <Navigate to="/logout" replace />;
  }

  if (showUntrustedWarning) {
    return (
      <Card role="alert" aria-live="assertive">
        <CardHeader className="gap-1.5">
          <CardTitle className="text-xl">
            {t("continueUntrustedRedirectTitle")}
          </CardTitle>
          <CardDescription>
            <Trans
              i18nKey="continueUntrustedRedirectSubtitle"
              t={t}
              components={{
                code: <code />,
              }}
              values={{
                cookieDomain: app.subdomainsEnabled
                  ? `.${app.cookieDomain}`
                  : app.cookieDomain,
              }}
              shouldUnescape={true}
            />
          </CardDescription>
        </CardHeader>
        <CardFooter className="flex flex-col items-stretch gap-3">
          <Button
            onClick={handleRedirect}
            loading={isLoading}
            variant="destructive"
          >
            {t("continueTitle")}
          </Button>
          <Button
            onClick={() => navigate("/logout")}
            variant="outline"
            disabled={isLoading}
          >
            {t("cancelTitle")}
          </Button>
        </CardFooter>
      </Card>
    );
  }

  if (showInsecureWarning) {
    return (
      <Card role="alert" aria-live="assertive">
        <CardHeader className="gap-1.5">
          <CardTitle className="text-xl">
            {t("continueInsecureRedirectTitle")}
          </CardTitle>
          <CardDescription>
            <Trans
              i18nKey="continueInsecureRedirectSubtitle"
              t={t}
              components={{
                code: <code />,
              }}
            />
          </CardDescription>
        </CardHeader>
        <CardFooter className="flex flex-col items-stretch gap-3">
          <Button
            onClick={handleRedirect}
            loading={isLoading}
            variant="warning"
          >
            {t("continueTitle")}
          </Button>
          <Button
            onClick={() => navigate("/logout")}
            variant="outline"
            disabled={isLoading}
          >
            {t("cancelTitle")}
          </Button>
        </CardFooter>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="gap-1.5">
        <CardTitle className="text-xl">
          {t("continueRedirectingTitle")}
        </CardTitle>
        <CardDescription>{t("continueRedirectingSubtitle")}</CardDescription>
      </CardHeader>
      {showRedirectButton && (
        <CardFooter>
          <Button className="w-full" onClick={handleRedirect}>
            {t("continueRedirectManually")}
          </Button>
        </CardFooter>
      )}
    </Card>
  );
};
