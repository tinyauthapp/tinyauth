import { useAppContext } from "@/context/app-context";
import { Outlet } from "react-router";
import { useCallback, useEffect, useState } from "react";
import { DomainWarning } from "../domain-warning/domain-warning";
import { QuickActions } from "../quick-actions/quick-actions";

const BaseLayout = ({ children }: { children: React.ReactNode }) => {
  const { ui } = useAppContext();

  useEffect(() => {
    document.title = ui.title;
  }, [ui.title]);

  return (
    <div
      className="flex flex-col justify-center items-center min-h-svh px-4"
      style={{
        backgroundImage: `url(${ui.backgroundImage})`,
        backgroundSize: "cover",
        backgroundPosition: "center",
      }}
    >
      <div className="absolute top-4 right-4">
        <QuickActions />
      </div>
      <div className="max-w-sm md:min-w-sm min-w-xs">{children}</div>
    </div>
  );
};

export const Layout = () => {
  const { app, ui } = useAppContext();
  const [ignoreDomainWarning, setIgnoreDomainWarning] = useState(() => {
    return window.sessionStorage.getItem("ignoreDomainWarning") === "true";
  });
  const currentUrl = window.location.origin;

  const handleIgnore = useCallback(() => {
    window.sessionStorage.setItem("ignoreDomainWarning", "true");
    setIgnoreDomainWarning(true);
  }, [setIgnoreDomainWarning]);

  if (!ignoreDomainWarning && ui.warningsEnabled && currentUrl !== app.appUrl) {
    return (
      <BaseLayout>
        <DomainWarning
          appUrl={app.appUrl}
          currentUrl={currentUrl}
          onClick={() => handleIgnore()}
        />
      </BaseLayout>
    );
  }

  return (
    <BaseLayout>
      <Outlet />
    </BaseLayout>
  );
};
