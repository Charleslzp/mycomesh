import { useQuery } from "@tanstack/react-query";
import { ExternalLink, RefreshCw, Router, Server, TriangleAlert } from "lucide-react";
import { Metric, Notice, PageHeader, Panel, Status, formatTime, truncateMiddle } from "../../app/ui";
import { protocolApi } from "../../protocol/api";
import { runtimeConfig } from "../../protocol/config";

export function NetworkPage() {
  const health = useQuery({ queryKey: ["proxy-health"], queryFn: protocolApi.health, retry: 1 });
  const discovery = useQuery({ queryKey: ["discovery"], queryFn: protocolApi.discovery, retry: 1 });
  const models = useQuery({ queryKey: ["models"], queryFn: protocolApi.models, retry: 1 });
  const peers = useQuery({ queryKey: ["peers"], queryFn: protocolApi.peers, retry: 1 });
  const refreshing = health.isFetching || discovery.isFetching || models.isFetching || peers.isFetching;

  function refresh() {
    void Promise.all([health.refetch(), discovery.refetch(), models.refetch(), peers.refetch()]);
  }

  return (
    <div className="app-page app-page--network">
      <PageHeader
        eyebrow="Discovery"
        title="Live network"
        description="Public gateway, model, and provider information returned by the configured proxy and bridge."
        actions={
          <button className="button button--secondary" disabled={refreshing} onClick={refresh} type="button">
            <RefreshCw className={refreshing ? "is-spinning" : ""} aria-hidden="true" size={16} />
            Refresh
          </button>
        }
      />

      {(health.isError || discovery.isError || models.isError || peers.isError) ? (
        <Notice icon={TriangleAlert} title="Some public interfaces are unavailable" tone="warning">
          Unreachable data remains marked unavailable; the console does not infer network health from cached or sample records.
        </Notice>
      ) : null}

      <section className="app-metric-grid" aria-label="Network status">
        <Metric label="Consumer proxy" value={health.isLoading ? "Checking" : health.data?.ok ? "Online" : "Unavailable"} detail={health.data?.billing_mode || "Billing mode unavailable"} />
        <Metric label="Providers" value={peers.isLoading ? "Checking" : peers.isError ? "Unavailable" : peers.data?.length ?? 0} detail="Public bridge peers" />
        <Metric label="Models" value={models.isLoading ? "Checking" : models.isError ? "Unavailable" : models.data?.length ?? 0} detail="Proxy model catalog" />
        <Metric label="Chain ID" value={discovery.data?.chain_id ?? runtimeConfig.chainId} detail={discovery.data?.network || runtimeConfig.networkName} />
      </section>

      <div className="app-two-column app-network-layout">
        <Panel title="Gateway discovery" description="Signed routing metadata advertised by the consumer proxy.">
          {discovery.data ? (
            <dl className="app-definition-list">
              <div><dt>Network ID</dt><dd>{discovery.data.network || "Unavailable"}</dd></div>
              <div><dt>Settlement</dt><dd>{discovery.data.settlement ? truncateMiddle(discovery.data.settlement, 8, 6) : "Unavailable"}</dd></div>
              <div><dt>Recommended URL</dt><dd>{discovery.data.recommended_base_url || "Unavailable"}</dd></div>
              <div><dt>Updated</dt><dd>{formatTime(discovery.data.updated_at)}</dd></div>
              <div><dt>Credential scope</dt><dd>{discovery.data.key_registration?.credential_scope || "Unavailable"}</dd></div>
            </dl>
          ) : <div className="app-loading-state">{discovery.isLoading ? "Reading discovery document" : "Discovery unavailable"}</div>}
        </Panel>

        <Panel title="Models" description="Identifiers returned directly by GET /v1/models.">
          {models.data?.length ? (
            <ul className="app-model-list">
              {models.data.map((model) => <li key={model.id}><Server aria-hidden="true" size={16} /><span><strong>{model.id}</strong><small>{model.owned_by || "Owner not advertised"}</small></span></li>)}
            </ul>
          ) : <div className="app-loading-state">{models.isLoading ? "Reading model catalog" : "No model advertised"}</div>}
        </Panel>
      </div>

      <Panel title="Provider peers" description="Only providers visible from the public bridge are shown.">
        {peers.data?.length ? (
          <div className="app-provider-grid">
            {peers.data.map((peer) => (
              <article className="app-provider-record" key={peer.peer_id}>
                <header><Router aria-hidden="true" size={18} /><strong>{truncateMiddle(peer.peer_id, 10, 6)}</strong><Status tone={peer.status === "online" || peer.status === "active" ? "positive" : "neutral"}>{peer.status || "Advertised"}</Status></header>
                <dl>
                  <div><dt>Model</dt><dd>{peer.model || "Unavailable"}</dd></div>
                  <div><dt>Transport</dt><dd>{peer.capacity?.transport || peer.channel || "Unavailable"}</dd></div>
                  <div><dt>Concurrency</dt><dd>{peer.capacity?.max_concurrency ?? "Unavailable"}</dd></div>
                  <div><dt>Reputation</dt><dd>{peer.reputation?.score ?? "Unavailable"}</dd></div>
                  <div><dt>Expires</dt><dd>{formatTime(peer.expires_at)}</dd></div>
                </dl>
              </article>
            ))}
          </div>
        ) : <div className="app-loading-state">{peers.isLoading ? "Reading bridge peers" : "No public provider peer is currently advertised"}</div>}
      </Panel>

      <a className="app-external-row" href={`${runtimeConfig.apiBaseUrl}/.well-known/mycomesh.json`} target="_blank" rel="noreferrer">
        Open raw discovery document <ExternalLink aria-hidden="true" size={15} />
      </a>
    </div>
  );
}
