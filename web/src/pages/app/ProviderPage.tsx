import { useQuery } from "@tanstack/react-query";
import { Activity, BookOpen, ExternalLink, RadioTower, ShieldAlert, Waypoints } from "lucide-react";
import { PageHeader, Panel, Status, truncateMiddle } from "../../app/ui";
import { protocolApi } from "../../protocol/api";
import { runtimeConfig } from "../../protocol/config";

export function ProviderPage() {
  const peers = useQuery({ queryKey: ["peers"], queryFn: protocolApi.peers, retry: 1 });

  return (
    <div className="app-page app-page--provider">
      <PageHeader
        eyebrow="Operator surface"
        title="Provider"
        description="Inspect public provider advertisements without exposing administrative controls in the browser."
        actions={<Status tone="neutral">Operator managed</Status>}
      />

      <div className="app-provider-summary">
        <RadioTower aria-hidden="true" size={26} />
        <div>
          <strong>{peers.isLoading ? "Reading public peers" : peers.isError ? "Unavailable" : `${peers.data?.length ?? 0} public peers`}</strong>
          <span>{peers.isError ? "Bridge is currently unavailable" : "Reported by the configured bridge"}</span>
        </div>
      </div>

      <div className="app-three-column">
        <Panel title="Serve inference">
          <Waypoints aria-hidden="true" size={20} />
          <p>The provider client announces supported models, capacity, transport, payment address, and a short-lived transport key.</p>
        </Panel>
        <Panel title="Advertise reachability">
          <Activity aria-hidden="true" size={20} />
          <p>The public descriptor must resolve to a URL reachable by consumers. Loopback and private service URLs are not public endpoints.</p>
        </Panel>
        <Panel title="Keep admin local">
          <ShieldAlert aria-hidden="true" size={20} />
          <p>Registration and operator administration remain CLI or server-side tasks. This application intentionally has no admin token input.</p>
        </Panel>
      </div>

      <Panel title="Current advertisements" description="Payment addresses and transport metadata are shown only when the bridge publishes them.">
        {peers.data?.length ? (
          <div className="app-table-wrap">
            <table className="app-table">
              <thead><tr><th>Peer</th><th>Model</th><th>Payment</th><th>Capacity</th><th>Status</th></tr></thead>
              <tbody>
                {peers.data.map((peer) => (
                  <tr key={peer.peer_id}>
                    <td data-label="Peer">{truncateMiddle(peer.peer_id, 9, 5)}</td>
                    <td data-label="Model">{peer.model || "Unavailable"}</td>
                    <td data-label="Payment">{peer.payment_address ? truncateMiddle(peer.payment_address) : "Unavailable"}</td>
                    <td data-label="Capacity">{peer.capacity?.max_concurrency ?? "Unavailable"}</td>
                    <td data-label="Status"><Status tone={peer.status === "online" || peer.status === "active" ? "positive" : "neutral"}>{peer.status || "Advertised"}</Status></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <div className="app-loading-state">{peers.isLoading ? "Reading public peers" : "No public provider advertisement is available"}</div>}
      </Panel>

      <a className="button button--secondary app-provider-docs" href={runtimeConfig.docsUrl}>
        <BookOpen aria-hidden="true" size={17} /> Provider documentation <ExternalLink aria-hidden="true" size={14} />
      </a>
    </div>
  );
}
