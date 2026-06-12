import { useUserContext } from "@/context/user-context";
import { useMutation } from "@tanstack/react-query";
import { Navigate, useNavigate } from "react-router";
import { useLocation } from "react-router";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardFooter,
  CardContent,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import axios from "axios";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";
import { TFunction } from "i18next";
import { Mail, MapPin, Phone, Shield, User, Users } from "lucide-react";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  recompileScreenParams,
  useScreenParams,
} from "@/lib/hooks/screen-params";

type Scope = {
  id: string;
  name: string;
  description: string;
  icon: React.ReactNode;
};

const scopeMapIconProps = {
  className: "stroke-muted-foreground stroke-[1.75] h-4",
};

const createScopeMap = (t: TFunction<"translation", undefined>): Scope[] => {
  return [
    {
      id: "openid",
      name: t("openidScopeName"),
      description: t("openidScopeDescription"),
      icon: <Shield {...scopeMapIconProps} />,
    },
    {
      id: "email",
      name: t("emailScopeName"),
      description: t("emailScopeDescription"),
      icon: <Mail {...scopeMapIconProps} />,
    },
    {
      id: "profile",
      name: t("profileScopeName"),
      description: t("profileScopeDescription"),
      icon: <User {...scopeMapIconProps} />,
    },
    {
      id: "groups",
      name: t("groupsScopeName"),
      description: t("groupsScopeDescription"),
      icon: <Users {...scopeMapIconProps} />,
    },
    {
      id: "phone",
      name: t("phoneScopeName"),
      description: t("phoneScopeDescription"),
      icon: <Phone {...scopeMapIconProps} />,
    },
    {
      id: "address",
      name: t("addressScopeName"),
      description: t("addressScopeDescription"),
      icon: <MapPin {...scopeMapIconProps} />,
    },
  ];
};

export const AuthorizePage = () => {
  const { auth } = useUserContext();
  const { search } = useLocation();
  const { t } = useTranslation();
  const navigate = useNavigate();
  const scopeMap = createScopeMap(t);

  const searchParams = new URLSearchParams(search);
  const screenParams = useScreenParams(searchParams);
  const isOidc = screenParams.login_for === "oidc";
  const compiledParams = recompileScreenParams(screenParams);

  const authorizeMutation = useMutation({
    mutationFn: () => {
      return axios.post("/api/oidc/authorize-complete", {
        ticket: screenParams.oidc_ticket,
      });
    },
    mutationKey: ["authorize", screenParams.oidc_ticket],
    onSuccess: (data) => {
      toast.info(t("authorizeSuccessTitle"), {
        description: t("authorizeSuccessSubtitle"),
      });
      window.location.replace(data.data.redirect_uri);
    },
    onError: (error) => {
      window.location.replace(
        `/error?error=${encodeURIComponent(error.message)}`,
      );
    },
  });

  if (!isOidc || !screenParams.oidc_ticket || !screenParams.oidc_scope) {
    return (
      <Navigate
        to={`/error?error=${encodeURIComponent(t("authorizeErrorInvalidParams"))}`}
        replace
      />
    );
  }

  if (!auth.authenticated) {
    return <Navigate to={`/login${compiledParams}`} replace />;
  }

  const scopes =
    screenParams.oidc_scope.split(" ").filter((s) => s.trim() !== "") || [];

  return (
    <Card>
      <CardHeader className="mb-2">
        <div className="flex flex-col gap-3 items-center justify-center text-center">
          <div className="bg-accent-foreground box-content text-muted text-xl font-bold font-sans rounded-lg size-8 p-2 flex items-center justify-center">
            {screenParams.oidc_name ? screenParams.oidc_name.slice(0, 1) : "U"}
          </div>
          <CardTitle className="text-xl">
            {t("authorizeCardTitle", {
              app: screenParams.oidc_name || "Unknown",
            })}
          </CardTitle>
          <CardDescription className="text-sm max-w-sm">
            {scopes.includes("openid")
              ? t("authorizeSubtitle")
              : t("authorizeSubtitleOAuth")}
          </CardDescription>
        </div>
      </CardHeader>
      {scopes.includes("openid") && (
        <CardContent className="mb-2">
          <div className="flex flex-wrap gap-2 items-center justify-center">
            {scopes.map((id) => {
              const scope = scopeMap.find((s) => s.id === id);
              if (!scope) return null;
              return (
                <Tooltip key={scope.id}>
                  <TooltipTrigger className="flex flex-row justify-center items-center gap-1 rounded-full bg-secondary font-light pl-2 pr-4 py-1 border-border border">
                    <div>{scope.icon}</div>
                    <div className="text-sm text-accent-foreground">
                      {scope.name}
                    </div>
                  </TooltipTrigger>
                  <TooltipContent>{scope.description}</TooltipContent>
                </Tooltip>
              );
            })}
          </div>
        </CardContent>
      )}
      <CardFooter className="flex flex-col items-stretch gap-3">
        <Button
          onClick={() => authorizeMutation.mutate()}
          loading={authorizeMutation.isPending}
        >
          {t("authorizeTitle")}
        </Button>
        <Button
          onClick={() => navigate(`/logout${compiledParams}`)}
          disabled={authorizeMutation.isPending}
          variant="outline"
        >
          {t("cancelTitle")}
        </Button>
      </CardFooter>
    </Card>
  );
};
