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
import {
  recompileScreenParams,
  useScreenParams,
} from "@/lib/hooks/screen-params";
import { useLoginFor } from "@/lib/hooks/login-for";

export const TotpPage = () => {
  const { totp, auth } = useUserContext();
  const { t } = useTranslation();
  const { search } = useLocation();
  const formId = useId();

  const redirectTimer = useRef<number | null>(null);

  const searchParams = new URLSearchParams(search);
  const screenParams = useScreenParams(searchParams);
  const compiledParams = recompileScreenParams(screenParams);
  const loginForUrl = useLoginFor({
    login_for: screenParams.login_for,
    compiledParams,
  });

  const totpMutation = useMutation({
    mutationFn: (values: TotpSchema) => axios.post("/api/user/totp", values),
    mutationKey: ["totp"],
    onSuccess: () => {
      toast.success(t("totpSuccessTitle"), {
        description: t("totpSuccessSubtitle"),
      });

      redirectTimer.current = window.setTimeout(() => {
        window.location.replace(loginForUrl);
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
    if (auth.authenticated) {
      return <Navigate to={loginForUrl} replace />;
    }
    return <Navigate to={`/login${compiledParams}`} replace />;
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
