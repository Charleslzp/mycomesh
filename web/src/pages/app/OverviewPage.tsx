import { useQuery } from "@tanstack/react-query";
import { ArrowRight, CircleAlert, KeyRound, RadioTower, Sparkles, WalletCards } from "lucide-react";
import { Link } from "react-router-dom";
import { useAccount } from "wagmi";
import { useApiKey } from "../../state/ApiKeyContext";
import { Metric, Notice, PageHeader, Panel, Status } from "../../app/ui";
import { protocolApi } from "../../protocol/api";
import { useConsumerAccount } from "../../protocol/queries";
import { isV3Configured, isV4Configured, runtimeConfig } from "../../protocol/config";
import { useV3DeploymentVerification, useV4DeploymentVerification } from "../../protocol/deployment";

export function OverviewPage() {
  const { address, isConnected } = useAccount();
  const { apiKey, hasApiKey } = useApiKey();
  const health = useQuery({ queryKey: ["proxy-health"], queryFn: protocolApi.health, retry: 1 });
  const models = useQuery({ queryKey: ["models"], queryFn: protocolApi.models, retry: 1 });
  const peers = useQuery({ queryKey: ["peers"], queryFn: protocolApi.peers, retry: 1 });
  const account = useConsumerAccount(apiKey);
  const deploymentVerification = useV3DeploymentVerification();
  const sessionDeploymentVerification = useV4DeploymentVerification();
  const sessionReady = isV4Configured && sessionDeploymentVerification.verified;

  return (
    <div className="app-page app-page--overview">
      <PageHeader
        eyebrow="Consumer console"
        title="Protocol overview"
        description="Connect a wallet, establish access, and route a paid inference request through the live MycoMesh gateway."
        actions={<Status tone={health.data?.ok ? "positive" : health.isError ? "negative" : "neutral"}>{health.data?.ok ? "Gateway online" : health.isError ? "Gateway unavailable" : "Checking gateway"}</Status>}
      />

      {isV4Configured && !sessionReady ? (
        <Notice icon={CircleAlert} title="V4 session deployment is not verified" tone="warning">
          {sessionDeploymentVerification.message} {sessionDeploymentVerification.issues[0] ?? "Contract actions remain locked."}
        </Notice>
      ) : !isV4Configured && !isV3Configured ? (
        <Notice icon={CircleAlert} title="V3 deployment is not configured" tone="warning">
          Inference and API-key access can still be inspected. Deposits, withdrawals, and contract-derived
          activity remain disabled until a complete V3 manifest is supplied.
        </Notice>
      ) : !sessionReady && !deploymentVerification.verified ? (
        <Notice icon={CircleAlert} title="V3 deployment is not verified" tone="warning">
          {deploymentVerification.message} {deploymentVerification.issues[0] ?? "Contract actions remain locked."}
        </Notice>
      ) : null}

      <section className="app-metric-grid" aria-label="Network snapshot">
        <Metric
          label="Gateway"
          value={health.isLoading ? "Checking" : health.data?.ok ? "Online" : "Unavailable"}
          detail={health.data?.service || "Consumer proxy"}
        />
        <Metric
          label="Models"
          value={models.isLoading ? "Checking" : models.isError ? "Unavailable" : models.data?.length ?? 0}
          detail="Advertised by the proxy"
        />
        <Metric
          label="Providers"
          value={peers.isLoading ? "Checking" : peers.isError ? "Unavailable" : peers.data?.length ?? 0}
          detail="Visible through the public bridge"
        />
        <Metric
          label="Account balance"
          value={account.isLoading ? "Checking" : account.data ? `${account.data.balance_usdc} USDC` : "Unavailable"}
          detail={hasApiKey ? "Gateway billing account" : "API key required"}
        />
      </section>

      <div className="app-two-column app-overview-actions">
        <Panel title="Get a request through" description="The shortest path from wallet to a verifiable response.">
          <ol className="app-step-list">
            <li className={isConnected ? "is-complete" : ""}>
              <span>1</span>
              <div><strong>Connect your wallet</strong><small>{address ? `Connected as ${address}` : "Use an injected Ethereum wallet."}</small></div>
            </li>
            <li className={hasApiKey ? "is-complete" : ""}>
              <span>2</span>
              <div><strong>Register an API key</strong><small>The secret is created in this browser; only its SHA-256 hash is registered.</small></div>
              <Link to="/app/access" aria-label="Open access setup"><ArrowRight aria-hidden="true" size={17} /></Link>
            </li>
            <li>
              <span>3</span>
              <div><strong>Run an inference</strong><small>Send an OpenAI-compatible request through the consumer proxy.</small></div>
              <Link to="/app/playground" aria-label="Open playground"><ArrowRight aria-hidden="true" size={17} /></Link>
            </li>
          </ol>
        </Panel>

        <Panel title="Workspace" description="Every surface is backed by a public protocol interface.">
          <div className="app-action-list">
            <Link to="/app/playground">
              <Sparkles aria-hidden="true" size={18} />
              <span><strong>Inference playground</strong><small>Run `/v1/responses` and inspect usage and receipt data.</small></span>
              <ArrowRight aria-hidden="true" size={17} />
            </Link>
            <Link to="/app/access">
              <KeyRound aria-hidden="true" size={18} />
              <span><strong>Consumer access</strong><small>Create or rotate a wallet-bound API key.</small></span>
              <ArrowRight aria-hidden="true" size={17} />
            </Link>
            <Link to="/app/funds">
              <WalletCards aria-hidden="true" size={18} />
              <span><strong>Settlement funds</strong><small>Approve, deposit, and withdraw exact token amounts.</small></span>
              <ArrowRight aria-hidden="true" size={17} />
            </Link>
            <Link to="/app/network">
              <RadioTower aria-hidden="true" size={18} />
              <span><strong>Live network</strong><small>Inspect gateway discovery, models, and provider peers.</small></span>
              <ArrowRight aria-hidden="true" size={17} />
            </Link>
          </div>
        </Panel>
      </div>

      <p className="app-data-footnote">
        Live values are read from {runtimeConfig.networkName}. An unavailable value is never replaced with sample data.
      </p>
    </div>
  );
}
