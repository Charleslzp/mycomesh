import {
  Activity,
  Boxes,
  Braces,
  CircleDollarSign,
  FileKey2,
  Gauge,
  Menu,
  Network,
  RadioTower,
  Sparkles,
  Waypoints,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import type { LucideIcon } from "lucide-react";
import { isAppHostname, isV3Configured, isV4Configured, runtimeConfig } from "../protocol/config";
import { useV3DeploymentVerification, useV4DeploymentVerification } from "../protocol/deployment";
import { ApiKeyProvider } from "../state/ApiKeyContext";
import { Status } from "./ui";
import { WalletButton } from "./WalletButton";

const navigation: ReadonlyArray<{ to: string; label: string; icon: LucideIcon; end?: boolean }> = [
  { to: "/app", label: "Overview", icon: Gauge, end: true },
  { to: "/app/playground", label: "Playground", icon: Sparkles },
  { to: "/app/access", label: "Access", icon: FileKey2 },
  { to: "/app/funds", label: "Funds", icon: CircleDollarSign },
  { to: "/app/reservations", label: "Reservations", icon: Boxes },
  { to: "/app/activity", label: "Activity", icon: Activity },
  { to: "/app/network", label: "Network", icon: Network },
  { to: "/app/provider", label: "Provider", icon: RadioTower },
  { to: "/app/contracts", label: "Contracts", icon: Braces },
];

function Navigation({ variant }: { variant: "sidebar" | "mobile" }) {
  const [moreOpen, setMoreOpen] = useState(false);
  const location = useLocation();
  const mobileNavRef = useRef<HTMLElement>(null);
  const moreButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    setMoreOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    if (!moreOpen) return;

    function closeOnOutsidePointer(event: PointerEvent) {
      if (!mobileNavRef.current?.contains(event.target as Node)) setMoreOpen(false);
    }

    function closeOnEscape(event: KeyboardEvent) {
      if (event.key !== "Escape") return;
      setMoreOpen(false);
      moreButtonRef.current?.focus();
    }

    document.addEventListener("pointerdown", closeOnOutsidePointer);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("pointerdown", closeOnOutsidePointer);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, [moreOpen]);

  if (variant === "mobile") {
    const primaryPaths = new Set(["/app", "/app/playground", "/app/network", "/app/activity"]);
    const primary = navigation.filter(({ to }) => primaryPaths.has(to));
    const secondary = navigation.filter(({ to }) => !primaryPaths.has(to));
    const moreActive = secondary.some(({ to }) => location.pathname === to);
    return (
      <nav ref={mobileNavRef} className="app-navigation app-navigation--mobile" aria-label="Application">
        {primary.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            className={({ isActive }) => `app-navigation__item${isActive ? " is-active" : ""}`}
            end={end}
            key={to}
            to={to}
          >
            <Icon aria-hidden="true" size={18} />
            <span>{label}</span>
          </NavLink>
        ))}
        <button
          ref={moreButtonRef}
          className={`app-navigation__item${moreActive || moreOpen ? " is-active" : ""}`}
          type="button"
          aria-expanded={moreOpen}
          aria-controls="mobile-more-navigation"
          onClick={() => setMoreOpen((value) => !value)}
        >
          <Menu aria-hidden="true" size={18} />
          <span>More</span>
        </button>
        {moreOpen ? (
          <div className="app-more-menu" id="mobile-more-navigation">
            <strong>More workspaces</strong>
            {secondary.map(({ to, label, icon: Icon }) => (
              <NavLink key={to} to={to} onClick={() => setMoreOpen(false)}>
                <Icon aria-hidden="true" size={17} />
                <span>{label}</span>
              </NavLink>
            ))}
          </div>
        ) : null}
      </nav>
    );
  }

  return (
    <nav className={`app-navigation app-navigation--${variant}`} aria-label="Application">
      {navigation.map(({ to, label, icon: Icon, end }) => (
        <NavLink
          className={({ isActive }) => `app-navigation__item${isActive ? " is-active" : ""}`}
          end={end}
          key={to}
          to={to}
          title={label}
        >
          <Icon aria-hidden="true" size={18} />
          <span>{label}</span>
        </NavLink>
      ))}
    </nav>
  );
}

function AppShellLayout() {
  const deploymentVerification = useV3DeploymentVerification();
  const sessionDeploymentVerification = useV4DeploymentVerification();
  const sessionReady = isV4Configured && sessionDeploymentVerification.verified;
  const siteUrl = runtimeConfig.siteUrl === "/" && isAppHostname()
    ? "https://mycomesh.xyz"
    : runtimeConfig.siteUrl;
  return (
    <div className="app-shell">
      <aside className="app-sidebar">
        <a className="app-brand" href={siteUrl} aria-label="MycoMesh home">
          <span className="app-brand__mark" aria-hidden="true"><Waypoints size={17} /></span>
          <span>MycoMesh</span>
        </a>
        <div className="app-sidebar__network">
          <span>{runtimeConfig.networkName}</span>
          <Status tone={sessionReady || deploymentVerification.verified ? "positive" : "warning"}>
            {isV4Configured
              ? sessionReady ? "V4 session escrow" : "V4 locked"
              : deploymentVerification.verified
                ? "V3 verified"
              : isV3Configured
                ? "V3 locked"
                : "Protocol preview"}
          </Status>
        </div>
        <Navigation variant="sidebar" />
        <div className="app-sidebar__footer">
          <a href={runtimeConfig.docsUrl}>Documentation</a>
          <a href={runtimeConfig.githubUrl} target="_blank" rel="noreferrer">GitHub</a>
        </div>
      </aside>

      <div className="app-workspace">
        <header className="app-topbar">
          <a className="app-brand app-brand--mobile" href={siteUrl} aria-label="MycoMesh home">
            <span className="app-brand__mark" aria-hidden="true"><Waypoints size={17} /></span>
            <span>MycoMesh</span>
          </a>
          <div className="app-topbar__context">
            <span>Consumer console</span>
            <Status tone="neutral">Testnet</Status>
          </div>
          <WalletButton />
        </header>
        <main className="app-content" id="main-content">
          <Outlet />
        </main>
      </div>

      <Navigation variant="mobile" />
    </div>
  );
}

export function AppShell() {
  return (
    <ApiKeyProvider>
      <AppShellLayout />
    </ApiKeyProvider>
  );
}
