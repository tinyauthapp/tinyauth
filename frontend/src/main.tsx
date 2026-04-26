import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import { Layout } from "./components/layout/layout.tsx";
import { BrowserRouter, Route, Routes } from "react-router";
import { LoginPage } from "./pages/login-page.tsx";
import { App } from "./App.tsx";
import { ErrorPage } from "./pages/error-page.tsx";
import { NotFoundPage } from "./pages/not-found-page.tsx";
import { ContinuePage } from "./pages/continue-page.tsx";
import { TotpPage } from "./pages/totp-page.tsx";
import { ForgotPasswordPage } from "./pages/forgot-password-page.tsx";
import { LogoutPage } from "./pages/logout-page.tsx";
import { UnauthorizedPage } from "./pages/unauthorized-page.tsx";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AppContextProvider } from "./context/app-context.tsx";
import { UserContextProvider } from "./context/user-context.tsx";
import { Toaster } from "@/components/ui/sonner";
import { ThemeProvider } from "./components/providers/theme-provider.tsx";
import { AuthorizePage } from "./pages/authorize-page.tsx";
import { TooltipProvider } from "@/components/ui/tooltip";

const queryClient = new QueryClient();

createRoot(document.getElementById("root")!).render(
  <main>
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <AppContextProvider>
          <UserContextProvider>
            <TooltipProvider>
              <ThemeProvider defaultTheme="system" storageKey="tinyauth-theme">
                <BrowserRouter>
                  <Routes>
                    <Route element={<Layout />} errorElement={<ErrorPage />}>
                      <Route path="/" element={<App />} />
                      <Route path="/login" element={<LoginPage />} />
                      <Route path="/authorize" element={<AuthorizePage />} />
                      <Route path="/logout" element={<LogoutPage />} />
                      <Route path="/continue" element={<ContinuePage />} />
                      <Route path="/totp" element={<TotpPage />} />
                      <Route
                        path="/forgot-password"
                        element={<ForgotPasswordPage />}
                      />
                      <Route
                        path="/unauthorized"
                        element={<UnauthorizedPage />}
                      />
                      <Route path="/error" element={<ErrorPage />} />
                      <Route path="*" element={<NotFoundPage />} />
                    </Route>
                  </Routes>
                </BrowserRouter>
                <Toaster />
              </ThemeProvider>
            </TooltipProvider>
          </UserContextProvider>
        </AppContextProvider>
      </QueryClientProvider>
    </StrictMode>
  </main>,
);
