import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useTranslation } from "react-i18next";
import { useLocation } from "react-router";

export const ErrorPage = () => {
  const { t } = useTranslation();
  const { search } = useLocation();
  const searchParams = new URLSearchParams(search);
  const error = searchParams.get("error") || "";

  return (
    <Card>
      <CardHeader className="gap-1.5">
        <CardTitle className="text-xl">{t("errorTitle")}</CardTitle>
        <CardDescription className="flex flex-col gap-3">
          {error ? (
            <>
              <p>{t("errorSubtitleInfo")}</p>
              <pre>{error}</pre>
            </>
          ) : (
            <>
              <p>{t("errorSubtitle")}</p>
            </>
          )}
        </CardDescription>
      </CardHeader>
    </Card>
  );
};
