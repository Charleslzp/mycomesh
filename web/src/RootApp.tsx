import { useEffect } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { AppRoutes } from "./app/index";
import { LandingPage } from "./pages/LandingPage";
import { isAppHostname } from "./protocol/config";

const pageTitles: Record<string, string> = {
  "/app": "Overview",
  "/app/playground": "Playground",
  "/app/access": "Consumer access",
  "/app/funds": "Funds",
  "/app/reservations": "Reservations",
  "/app/activity": "Activity",
  "/app/network": "Network",
  "/app/provider": "Provider",
  "/app/contracts": "Contracts",
};

function NavigationEffects() {
  const location = useLocation();

  useEffect(() => {
    const title = pageTitles[location.pathname];
    document.title = title ? `${title} | MycoMesh` : "MycoMesh | Open AI inference network";
    if (!location.hash) window.scrollTo({ top: 0, behavior: "instant" });
  }, [location.hash, location.pathname]);

  return null;
}

function RootEntry() {
  if (isAppHostname()) return <Navigate replace to="/app" />;
  return <LandingPage />;
}

function UnknownRoute() {
  return <Navigate replace to={isAppHostname() ? "/app" : "/"} />;
}

export function RootApp() {
  return (
    <>
      <NavigationEffects />
      <Routes>
        <Route path="/" element={<RootEntry />} />
        <Route path="/app/*" element={<AppRoutes />} />
        <Route path="*" element={<UnknownRoute />} />
      </Routes>
    </>
  );
}
