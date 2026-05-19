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
import { useEffect, useRef } from "react";
import { Trans, useTranslation } from "react-i18next";
import { Navigate } from "react-router";
import { toast } from "sonner";
import { type UseMutationResult } from "@tanstack/react-query";
import { type AxiosResponse } from "axios";

export const LogoutPage = () => {
  const { auth, oauth, tailscale } = useUserContext();
  const { t } = useTranslation();

  const redirectTimer = useRef<number | null>(null);

  const logoutMutation = useMutation({
    mutationFn: () => axios.post("/api/user/logout"),
    mutationKey: ["logout"],
    onSuccess: () => {
      toast.success(t("logoutSuccessTitle"), {
        description: t("logoutSuccessSubtitle"),
      });

      redirectTimer.current = window.setTimeout(() => {
        window.location.replace("/login");
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
      if (redirectTimer.current) {
        clearTimeout(redirectTimer.current);
      }
    };
  }, [redirectTimer]);

  if (!auth.authenticated) {
    return <Navigate to="/login" replace />;
  }

  if (oauth.active) {
    return (
      <LogoutLayout logoutMutation={logoutMutation}>
        <Trans
          i18nKey="logoutOauthSubtitle"
          t={t}
          components={{
            code: <code />,
          }}
          values={{
            username: auth.email,
            provider: oauth.displayName,
          }}
          shouldUnescape={true}
        />
      </LogoutLayout>
    );
  }

  if (auth.providerId === "tailscale") {
    return (
      <LogoutLayout logoutMutation={logoutMutation}>
        <Trans
          i18nKey="logoutTailscaleSubtitle"
          t={t}
          components={{
            code: <code />,
          }}
          values={{
            deviceName: tailscale.nodeName,
          }}
          shouldUnescape={true}
        />
      </LogoutLayout>
    );
  }

  return (
    <LogoutLayout logoutMutation={logoutMutation}>
      <Trans
        i18nKey="logoutUsernameSubtitle"
        t={t}
        components={{
          code: <code />,
        }}
        values={{
          username: auth.username,
        }}
        shouldUnescape={true}
      />
    </LogoutLayout>
  );
};

interface LogoutLayoutProps {
  children: React.ReactNode;
  logoutMutation: UseMutationResult<
    //eslint-disable-next-line @typescript-eslint/no-explicit-any,@typescript-eslint/no-empty-object-type
    AxiosResponse<any, any, {}>,
    Error,
    void,
    unknown
  >;
}

function LogoutLayout({ children, logoutMutation }: LogoutLayoutProps) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader className="gap-1.5">
        <CardTitle className="text-xl">{t("logoutTitle")}</CardTitle>
        <CardDescription>{children}</CardDescription>
      </CardHeader>
      <CardFooter>
        <Button
          className="w-full"
          variant="outline"
          loading={logoutMutation.isPending}
          onClick={() => logoutMutation.mutate()}
        >
          {t("logoutTitle")}
        </Button>
      </CardFooter>
    </Card>
  );
}
