import { Navigate, Route, Routes } from "react-router-dom";
import {
  AccessPage,
  ActivityPage,
  ContractsPage,
  FundsPage,
  NetworkPage,
  OverviewPage,
  PlaygroundPage,
  ProviderPage,
  ReservationsPage,
} from "../pages/app";
import { AppShell } from "./AppShell";

export function AppRoutes() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<OverviewPage />} />
        <Route path="playground" element={<PlaygroundPage />} />
        <Route path="access" element={<AccessPage />} />
        <Route path="funds" element={<FundsPage />} />
        <Route path="reservations" element={<ReservationsPage />} />
        <Route path="activity" element={<ActivityPage />} />
        <Route path="network" element={<NetworkPage />} />
        <Route path="provider" element={<ProviderPage />} />
        <Route path="contracts" element={<ContractsPage />} />
        <Route path="*" element={<Navigate replace to="/app" />} />
      </Route>
    </Routes>
  );
}
