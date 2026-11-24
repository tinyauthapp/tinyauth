import { Button } from "@/components/ui/button";
import {
  Card,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useUserContext } from "@/context/user-context";
import { useMutation } from "@tanstack/react-query";
import axios from "axios";
import { useEffect, useRef, type ReactNode } from "react";
import { Trans, useTranslation } from "react-i18next";
import { Navigate, useLocation, useNavigate } from "react-router";
import { toast } from "sonner";
import {
  searchParamsFromObject,
  useScreenParams,
} from "@/lib/hooks/screen-params";

export const LogoutPage = () => {
  const { auth } = useUserContext();
  const { t } = useTranslation();
  const { search } = useLocation();
  const navigate = useNavigate();

  const { logout_reason, ...loginParams } = useScreenParams(
    new URLSearchParams(search),
  );
  const params = searchParamsFromObject(loginParams).toString();
  const loginUrl = `/login${params ? `?${params}` : ""}`;
  const { mutate, isPending, isSuccess } = useLogout(loginUrl);

  if (!auth.authenticated) {
    return <Navigate to={loginUrl} replace />;
  }

  if (logout_reason === "oidc") {
    return (
      <LogoutCard
        title={t("logoutOidcTitle")}
        isPending={isPending || isSuccess}
        onLogout={mutate}
        onCancel={() => navigate("/", { replace: true })}
      >
        {t("logoutOidcSubtitle")}
      </LogoutCard>
    );
  }

  return (
    <LogoutCard
      title={t("logoutTitle")}
      isPending={isPending || isSuccess}
      onLogout={mutate}
    >
      <LogoutDescription />
    </LogoutCard>
  );
};

function useLogout(loginUrl: string) {
  const { t } = useTranslation();
  const redirectTimer = useRef<number | null>(null);

  const mutation = useMutation({
    mutationFn: () => axios.post("/api/user/logout"),
    mutationKey: ["logout"],
    onSuccess: () => {
      toast.success(t("logoutSuccessTitle"), {
        description: t("logoutSuccessSubtitle"),
      });

      redirectTimer.current = window.setTimeout(() => {
        window.location.replace(loginUrl);
      }, 500);
    },
    onError: () => {
      toast.error(t("logoutFailTitle"), {
        description: t("logoutFailSubtitle"),
      });
    },
  });

  useEffect(() => {
    return () => {
      if (redirectTimer.current !== null) {
        window.clearTimeout(redirectTimer.current);
      }
    };
  }, []);

  return mutation;
}

interface LogoutCardProps {
  title: string;
  children: ReactNode;
  isPending?: boolean;
  onLogout?: () => void;
  onCancel?: () => void;
}

function LogoutCard({
  title,
  children,
  isPending = false,
  onLogout,
  onCancel,
}: LogoutCardProps) {
  const { t } = useTranslation();

  return (
    <Card aria-live="polite">
      <CardHeader className="gap-1.5">
        <CardTitle className="text-xl">{title}</CardTitle>
        <CardDescription>{children}</CardDescription>
      </CardHeader>
      {onLogout && (
        <CardFooter className="flex flex-col items-stretch gap-3">
          <Button
            variant="destructive"
            loading={isPending}
            onClick={onLogout}
          >
            {t("logoutTitle")}
          </Button>
          {onCancel && (
            <Button variant="outline" disabled={isPending} onClick={onCancel}>
              {t("cancelTitle")}
            </Button>
          )}
        </CardFooter>
      )}
    </Card>
  );
}

function LogoutDescription() {
  const { auth, oauth, tailscale } = useUserContext();
  const { t } = useTranslation();
  const subtitle = oauth.active
    ? "logoutOauthSubtitle"
    : auth.providerId === "tailscale"
      ? "logoutTailscaleSubtitle"
      : "logoutUsernameSubtitle";

  return (
    <Trans
      i18nKey={subtitle}
      t={t}
      components={{ code: <code /> }}
      values={{
        username: oauth.active ? auth.email : auth.username,
        provider: oauth.displayName,
        deviceName: tailscale.nodeName,
      }}
      shouldUnescape={true}
    />
  );
}
