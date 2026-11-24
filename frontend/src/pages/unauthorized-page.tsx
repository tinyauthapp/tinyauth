import { Button } from "@/components/ui/button";
import {
  Card,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { searchParamsFromObject } from "@/lib/hooks/screen-params";
import axios from "axios";
import { useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { Navigate, useLocation, useNavigate } from "react-router";
import { toast } from "sonner";

export const UnauthorizedPage = () => {
  const { search } = useLocation();
  const { t } = useTranslation();
  const navigate = useNavigate();

  const [loading, setLoading] = useState(false);

  const searchParams = new URLSearchParams(search);
  const username = searchParams.get("username");
  const resource = searchParams.get("resource");
  const groupErr = searchParams.get("groupErr");
  const ip = searchParams.get("ip");
  const redirectUri = searchParams.get("redirect_uri");

  const handleRedirect = async () => {
    setLoading(true);

    // The user is signed in but not allowed to access the app. Sign out first
    // so that another user can sign in, then return to the app after login.
    // Skip the automatic OAuth redirect, which could sign the same user in
    // again, so that the user can choose how to sign in.
    if (username && redirectUri) {
      try {
        await axios.post("/api/user/logout");
      } catch {
        setLoading(false);
        toast.error(t("logoutFailTitle"), {
          description: t("logoutFailSubtitle"),
        });
        return;
      }
      const params = searchParamsFromObject({
        redirect_uri: redirectUri,
        login_for: "app",
        skip_auto_redirect: "true",
      });
      window.location.replace(`/login?${params}`);
      return;
    }

    navigate("/login");
  };

  if (!username && !ip) {
    return <Navigate to="/" />;
  }

  let i18nKey = "unauthorizedLoginSubtitle";

  if (resource) {
    i18nKey = "unauthorizedResourceSubtitle";
  }

  if (groupErr === "true") {
    i18nKey = "unauthorizedGroupsSubtitle";
  }

  if (ip) {
    i18nKey = "unauthorizedIpSubtitle";
  }

  return (
    <Card>
      <CardHeader className="gap-1.5">
        <CardTitle className="text-xl">{t("unauthorizedTitle")}</CardTitle>
        <CardDescription>
          <Trans
            i18nKey={i18nKey}
            t={t}
            components={{
              code: <code />,
            }}
            values={{
              username,
              resource,
              ip,
            }}
          />
        </CardDescription>
      </CardHeader>
      <CardFooter>
        <Button
          variant="outline"
          className="w-full"
          onClick={handleRedirect}
          loading={loading}
        >
          {t("unauthorizedButton")}
        </Button>
      </CardFooter>
    </Card>
  );
};
