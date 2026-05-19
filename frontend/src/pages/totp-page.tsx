import { TotpForm } from "@/components/auth/totp-form";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useUserContext } from "@/context/user-context";
import { TotpSchema } from "@/schemas/totp-schema";
import { useMutation } from "@tanstack/react-query";
import axios from "axios";
import { useEffect, useId, useRef } from "react";
import { useTranslation } from "react-i18next";
import { Navigate, useLocation } from "react-router";
import { toast } from "sonner";
import { useOIDCParams } from "@/lib/hooks/oidc";

export const TotpPage = () => {
  const { totp } = useUserContext();
  const { t } = useTranslation();
  const { search } = useLocation();
  const formId = useId();

  const redirectTimer = useRef<number | null>(null);

  const searchParams = new URLSearchParams(search);
  const redirectUri = searchParams.get("redirect_uri") || undefined;
  const oidcParams = useOIDCParams(searchParams);

  const totpMutation = useMutation({
    mutationFn: (values: TotpSchema) => axios.post("/api/user/totp", values),
    mutationKey: ["totp"],
    onSuccess: () => {
      toast.success(t("totpSuccessTitle"), {
        description: t("totpSuccessSubtitle"),
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
    onError: () => {
      toast.error(t("totpFailTitle"), {
        description: t("totpFailSubtitle"),
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

  if (!totp.pending) {
    return <Navigate to="/" replace />;
  }

  return (
    <Card>
      <CardHeader className="gap-1.5">
        <CardTitle className="text-xl">{t("totpTitle")}</CardTitle>
        <CardDescription>{t("totpSubtitle")}</CardDescription>
      </CardHeader>
      <CardContent>
        <TotpForm
          formId={formId}
          onSubmit={(values) => totpMutation.mutate(values)}
        />
      </CardContent>
      <CardFooter>
        <Button
          className="w-full"
          form={formId}
          type="submit"
          loading={totpMutation.isPending}
        >
          {t("continueTitle")}
        </Button>
      </CardFooter>
    </Card>
  );
};
