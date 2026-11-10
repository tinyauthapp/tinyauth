import {
  Card,
  CardContent,
  CardFooter,
  CardHeader,
  CardTitle,
} from "../ui/card";
import { Button } from "../ui/button";
import { useTranslation } from "react-i18next";
import { useLocation } from "react-router";

interface Props {
  onClick: () => void;
  appUrl: string;
  currentUrl: string;
}

export const DomainWarning = (props: Props) => {
  const { onClick, appUrl, currentUrl } = props;
  const { t } = useTranslation();
  const { search } = useLocation();

  const searchParams = (new URLSearchParams(search)).toString();

  return (
    <Card role="alert" aria-live="assertive">
      <CardHeader>
        <CardTitle className="text-xl">{t("domainWarningTitle")}</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3 text-sm mb-1.25">
        <p className="text-muted-foreground">{t("domainWarningSubtitle")}</p>
        <pre>
          <span className="text-muted-foreground">
            {t("domainWarningExpected")}&nbsp;
            <span className="text-primary">{appUrl}</span>
          </span>
        </pre>
        <pre>
          <span className="text-muted-foreground">
            {t("domainWarningCurrent")}&nbsp;
            <span className="text-primary">{currentUrl}</span>
          </span>
        </pre>
      </CardContent>
      <CardFooter className="flex flex-col items-stretch gap-3">
        <Button
          onClick={() =>
            window.location.assign(`${appUrl}/login${searchParams ? `?${searchParams}` : ""}`)
          }
          variant="outline"
        >
          {t("goToCorrectDomainTitle")}
        </Button>
        <Button onClick={onClick} variant="warning">
          {t("ignoreTitle")}
        </Button>
      </CardFooter>
    </Card>
  );
};
