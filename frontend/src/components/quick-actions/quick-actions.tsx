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

function Avatar({ initial }: { initial: string }) {
  return (
    <span className="group relative grid size-10 place-items-center rounded-full">
      <span className="absolute inset-0 overflow-hidden rounded-full bg-linear-to-b from-neutral-50 to-neutral-100 dark:from-neutral-700 dark:to-neutral-950 shadow-lg"></span>
      <span className="relative text-sm font-semibold text-primary">
        {initial}
      </span>
    </span>
  );
}

export const QuickActions = () => {
  const { auth } = useUserContext();
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
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          aria-label={t("quickActionsTitle")}
          className="rounded-full transition-transform duration-200 will-change-transform hover:scale-105 hover:cursor-pointer focus:ring-0 focus:outline-3 focus:outline-ring/50"
        >
          {auth.authenticated ? (
            <Avatar initial={initial!} />
          ) : (
            <span className="bg-card text-primary border-border size-10 flex items-center justify-center rounded-full border shadow-lg">
              <Settings className="size-4" />
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
              <div className="bg-foreground text-background flex size-9 shrink-0 items-center justify-center rounded-full text-sm font-medium">
                {initial}
              </div>
              <div className="flex min-w-0 flex-col">
                <span className="truncate text-sm font-medium">
                  {auth.name}
                </span>
                <span className="text-muted-foreground truncate text-xs font-normal">
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
              <DoorOpenIcon className="size-4" />
              {t("quickActionsLogout")}
            </DropdownMenuItem>
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
};
