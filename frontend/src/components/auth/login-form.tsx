import { useTranslation } from "react-i18next";
import { Input } from "../ui/input";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "../ui/form";
import { loginSchema, LoginSchema } from "@/schemas/login-schema";
import z from "zod";
import { useState } from "react";
import { Eye, EyeOff } from "lucide-react";

interface Props {
  onSubmit: (data: LoginSchema) => void;
  loading?: boolean;
  formId?: string;
  params?: string;
}

export const LoginForm = (props: Props) => {
  const { onSubmit, loading, formId } = props;
  const { t } = useTranslation();
  const [showPassword, setShowPassword] = useState(false);

  z.config({
    customError: (iss) =>
      iss.input === undefined ? t("fieldRequired") : t("invalidInput"),
  });

  const form = useForm<LoginSchema>({
    resolver: zodResolver(loginSchema),
  });

  return (
    <Form {...form}>
      <form id={formId} onSubmit={form.handleSubmit(onSubmit)}>
        <FormField
          control={form.control}
          name="username"
          render={({ field }) => (
            <FormItem className="mb-4 gap-0">
              <FormLabel className="mb-2">{t("loginUsername")}</FormLabel>
              <FormControl className="mb-1">
                <Input
                  placeholder={t("loginUsername").toLocaleLowerCase()}
                  disabled={loading}
                  autoComplete="username"
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="password"
          render={({ field }) => (
            <FormItem className="gap-0">
              <div className="relative mb-1">
                <FormLabel className="mb-2">{t("loginPassword")}</FormLabel>
                <div className="relative">
                  <FormControl>
                    <Input
                      placeholder={t("loginPassword").toLowerCase()}
                      type={showPassword ? "text" : "password"}
                      disabled={loading}
                      autoComplete="current-password"
                      className="pr-10"
                      {...field}
                    />
                  </FormControl>
                  <button
                    type="button"
                    aria-label={t("loginPasswordToggle")}
                    aria-pressed={showPassword}
                    disabled={loading}
                    onClick={() => setShowPassword(!showPassword)}
                    className="text-muted-foreground absolute right-0 top-0 h-9 px-3 rounded-r-md opacity-50 hover:opacity-100 focus-visible:opacity-100 transition-opacity hover:cursor-pointer disabled:pointer-events-none outline-none focus-visible:ring-ring/50 focus-visible:ring-[3px] [&_svg]:size-4"
                  >
                    {showPassword ? <EyeOff /> : <Eye />}
                  </button>
                </div>
                <a
                  href="/forgot-password"
                  onClick={(e) => {
                    e.preventDefault();
                    window.location.replace(
                      `/forgot-password${props.params ? `${props.params}` : ""}`,
                    );
                  }}
                  className="text-muted-foreground hover:text-muted-foreground/80 text-sm absolute right-0 bottom-[2.565rem] max-w-40 truncate" // 2.565 is *just* perfect
                >
                  {t("forgotPasswordTitle")}
                </a>
              </div>
              <FormMessage />
            </FormItem>
          )}
        />
      </form>
    </Form>
  );
};
