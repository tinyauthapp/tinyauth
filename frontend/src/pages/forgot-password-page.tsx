import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useAppContext } from "@/context/app-context";
import { useTranslation } from "react-i18next";
import Markdown from "react-markdown";
import { useLocation } from "react-router";
import {
  recompileScreenParams,
  useScreenParams,
} from "@/lib/hooks/screen-params";

export const ForgotPasswordPage = () => {
  const { ui } = useAppContext();
  const { t } = useTranslation();
  const { search } = useLocation();
  const searchParams = new URLSearchParams(search);
  const screenParams = useScreenParams(searchParams);
  const compiledParams = recompileScreenParams(screenParams);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-xl">{t("forgotPasswordTitle")}</CardTitle>
      </CardHeader>
      <CardContent>
        <CardDescription>
          <Markdown>
            {ui.forgotPasswordMessage !== ""
              ? ui.forgotPasswordMessage
              : t("forgotPasswordMessage")}
          </Markdown>
        </CardDescription>
      </CardContent>
      <CardFooter>
        <Button
          className="w-full"
          variant="outline"
          onClick={() => {
            window.location.replace(`/login${compiledParams}`);
          }}
        >
          {t("backToLoginButton")}
        </Button>
      </CardFooter>
    </Card>
  );
};
