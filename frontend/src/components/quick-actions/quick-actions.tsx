import { languages, SupportedLanguage } from "@/lib/i18n/locales";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuPortal,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "../ui/dropdown-menu";
import { useState } from "react";
import i18n from "@/lib/i18n/i18n";
import { useUserContext } from "@/context/user-context";
import { ScrollArea } from "../ui/scroll-area";
import { useTheme } from "../providers/theme-provider";
import {
  Check,
  DoorOpenIcon,
  Languages,
  Monitor,
  Moon,
  Palette,
  Settings,
  Sun,
  UserRoundKey,
  X,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import { useLocation } from "react-router";
import { useRef } from "react";
import {
  useScreenParams,
  recompileScreenParams,
} from "@/lib/hooks/screen-params";
import { useMutation } from "@tanstack/react-query";
import axios from "axios";
import { toast } from "sonner";
import { useEffect } from "react";
import { GoogleIcon } from "../icons/google";
import { GithubIcon } from "../icons/github";
import { TailscaleIcon } from "../icons/tailscale";
import { MicrosoftIcon } from "../icons/microsoft";
import { PocketIDIcon } from "../icons/pocket-id";
import { OAuthIcon } from "../icons/oauth";
import { Tooltip, TooltipContent, TooltipTrigger } from "../ui/tooltip";

const iconStyles = "size-4";

const iconMap: Record<string, React.ReactNode> = {
  google: <GoogleIcon className={iconStyles} />,
  github: <GithubIcon className={iconStyles} />,
  tailscale: <TailscaleIcon className={iconStyles} />,
  microsoft: <MicrosoftIcon className={iconStyles} />,
  pocketid: <PocketIDIcon className={iconStyles} />,
};

export const QuickActions = () => {
  const { auth, oauth, tailscale } = useUserContext();
  const { theme, setTheme } = useTheme();
  const { t } = useTranslation();
  const { search } = useLocation();

  const [language, setLanguage] = useState<SupportedLanguage>(
    i18n.language as SupportedLanguage,
  );

  const redirectTimer = useRef<number | null>(null);
  const searchParams = new URLSearchParams(search);
  const screenParams = useScreenParams(searchParams);
  const compiledParams = recompileScreenParams(screenParams);

  const [isOpen, setIsOpen] = useState(false);

  const providerDetails = (():
    | { name: string; icon: React.ReactNode }
    | undefined => {
    if (!auth.authenticated) {
      return undefined;
    }

    if (auth.providerId === "local" || auth.providerId === "ldap") {
      return {
        name: t(
          auth.providerId === "ldap"
            ? "quickActionsProviderLDAP"
            : "quickActionsProviderLocal",
        ),
        icon: (
          <UserRoundKey
            strokeWidth={1.5}
            size={16}
            className="text-muted-foreground ml-0.5"
          />
        ),
      };
    }

    if (oauth.active) {
      return {
        name: t("quickActionsProviderOAuth", { provider: oauth.displayName }),
        icon: iconMap[auth.providerId] || <OAuthIcon className={iconStyles} />,
      };
    }

    if (auth.providerId === "tailscale") {
      return {
        name: `Tailscale (${tailscale.nodeName})`,
        icon: <TailscaleIcon className={iconStyles} />,
      };
    }

    return undefined;
  })();

  const logoutMutation = useMutation({
    mutationFn: () => axios.post("/api/user/logout"),
    mutationKey: ["logout"],
    onSuccess: () => {
      toast.success(t("logoutSuccessTitle"), {
        description: t("logoutSuccessSubtitle"),
      });

      redirectTimer.current = window.setTimeout(() => {
        window.location.replace(`/login${compiledParams}`);
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

  const initial = auth.authenticated
    ? (auth.name[0] || "U").toUpperCase()
    : null;

  const handleSelect = (option: string) => {
    setLanguage(option as SupportedLanguage);
    i18n.changeLanguage(option as SupportedLanguage);
  };

  const themes = [
    { key: "light", label: t("quickActionsThemeLight"), icon: Sun },
    { key: "dark", label: t("quickActionsThemeDark"), icon: Moon },
    { key: "system", label: t("quickActionsThemeSystem"), icon: Monitor },
  ] as const;

  return (
    <DropdownMenu onOpenChange={(open) => setIsOpen(open)} open={isOpen}>
      <DropdownMenuTrigger asChild>
        <button
          aria-label={t("quickActionsTitle")}
          className="rounded-full transition-transform duration-200 will-change-transform hover:scale-105 hover:cursor-pointer focus:ring-0 focus:outline-3 focus:outline-ring/50"
        >
          {auth.authenticated ? (
            <div className="size-10 flex justify-center items-center p-2 rounded-full bg-card border border-border">
              {isOpen ? (
                <X className="size-4 text-primary rotate-0 transition-transform duration-200 starting:rotate-45" />
              ) : (
                <span className="text-sm text-primary rotate-0 transition-transform duration-200 starting:-rotate-45">
                  {initial}
                </span>
              )}
            </div>
          ) : (
            <span className="bg-card text-primary border-border size-10 flex items-center justify-center rounded-full border shadow-lg">
              <Settings
                className={`size-4 transition-transform duration-200 ${
                  isOpen ? "rotate-45" : "rotate-0"
                }`}
              />
            </span>
          )}
        </button>
      </DropdownMenuTrigger>

      <DropdownMenuContent
        align="end"
        sideOffset={8}
        className="rounded-xl p-1"
      >
        {auth.authenticated && (
          <>
            <DropdownMenuLabel className="flex items-center gap-3 p-2">
              <Tooltip>
                <TooltipTrigger className="size-9 rounded-full p-2 bg-muted border-border border flex items-center justify-center">
                  {providerDetails!.icon}
                </TooltipTrigger>
                <TooltipContent>{providerDetails!.name}</TooltipContent>
              </Tooltip>
              <div className="flex min-w-0 flex-col gap-1.5">
                <span className="truncate text-sm font-medium leading-none">
                  {auth.name}
                </span>
                <span className="text-muted-foreground truncate text-xs leading-none">
                  {auth.email}
                </span>
              </div>
            </DropdownMenuLabel>

            <DropdownMenuSeparator />
          </>
        )}

        <DropdownMenuSub>
          <DropdownMenuSubTrigger>
            <Languages className="size-4" />
            {t("quickActionsLanguage")}
          </DropdownMenuSubTrigger>
          <DropdownMenuPortal>
            <DropdownMenuSubContent sideOffset={8} className="rounded-xl p-1">
              <ScrollArea className="h-80">
                {Object.entries(languages).map(([key, value]) => (
                  <DropdownMenuItem
                    key={key}
                    onSelect={() => handleSelect(key)}
                  >
                    {value}
                    {language === key && <Check className="size-4" />}
                  </DropdownMenuItem>
                ))}
              </ScrollArea>
            </DropdownMenuSubContent>
          </DropdownMenuPortal>
        </DropdownMenuSub>

        <DropdownMenuSub>
          <DropdownMenuSubTrigger>
            <Palette className="size-4" />
            {t("quickActionsTheme")}
          </DropdownMenuSubTrigger>
          <DropdownMenuPortal>
            <DropdownMenuSubContent className="rounded-xl p-1" sideOffset={8}>
              {themes.map(({ key, label, icon: Icon }) => (
                <DropdownMenuItem key={key} onClick={() => setTheme(key)}>
                  <span className="flex items-center gap-2">
                    <Icon className="size-4" />
                    {label}
                  </span>
                  {theme === key && <Check className="size-4" />}
                </DropdownMenuItem>
              ))}
            </DropdownMenuSubContent>
          </DropdownMenuPortal>
        </DropdownMenuSub>

        {auth.authenticated && (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onSelect={() => logoutMutation.mutate()}
              className="text-destructive"
            >
              <DoorOpenIcon className="size-4 text-destructive" />
              {t("quickActionsLogout")}
            </DropdownMenuItem>
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
};
