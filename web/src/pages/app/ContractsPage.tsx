import { Braces, ExternalLink, LockKeyhole, ShieldCheck } from "lucide-react";
import { isV3Configured, isV4Configured, runtimeConfig } from "../../protocol/config";
import { useV3DeploymentVerification, useV4DeploymentVerification } from "../../protocol/deployment";
import { Notice, PageHeader, Panel, Status, truncateMiddle } from "../../app/ui";

const contracts = [
  { name: "Settlement V3", key: "settlementAddress" },
  { name: "Stablecoin", key: "stablecoinAddress" },
  { name: "Reward token", key: "tokenAddress" },
  { name: "Treasury", key: "treasuryAddress" },
  { name: "Governance", key: "governanceAddress" },
] as const;

export function ContractsPage() {
  const verification = useV3DeploymentVerification();
  const sessionVerification = useV4DeploymentVerification();
  const sessionReady = isV4Configured && sessionVerification.verified;
  return (
    <div className="app-page app-page--contracts">
      <PageHeader
        eyebrow="Protocol bindings"
        title="Contracts"
        description="The exact deployment manifest compiled into this application."
        actions={<Status tone={sessionReady || verification.verified ? "positive" : "warning"}>{isV4Configured ? sessionReady ? "V4 session escrow" : "V4 locked" : verification.verified ? "Verified on-chain" : verification.status === "checking" ? "Verifying" : "Not verified"}</Status>}
      />

      {!isV4Configured && !isV3Configured ? (
        <Notice icon={LockKeyhole} title="Fail-closed deployment gate" tone="warning">
          Protocol version, all five addresses, and a deployment block must be present together. A partial or legacy
          manifest cannot activate contract reads or writes.
        </Notice>
      ) : isV4Configured ? (
        <Notice icon={sessionReady ? ShieldCheck : LockKeyhole} title={sessionReady ? "V4 session escrow configured" : "V4 session escrow is not verified"} tone={sessionReady ? "positive" : "warning"}>
          {sessionReady ? "The public Playground uses the bounded V4 session path. The legacy V3 manifest below remains available for diagnostics and recovery." : `${sessionVerification.message} ${sessionVerification.issues[0] ?? "Contract actions remain locked."}`}
        </Notice>
      ) : verification.verified ? (
        <Notice icon={ShieldCheck} title="V3 deployment verified" tone="positive">
          Bytecode and protocol bindings match this build. Contract interactions are restricted to chain ID {runtimeConfig.chainId} and the addresses below.
        </Notice>
      ) : (
        <Notice icon={LockKeyhole} title="On-chain verification has not passed" tone="warning">
          {verification.message} {verification.issues[0] ?? "Contract writes remain locked while verification is pending."}
        </Notice>
      )}

      <Panel title="Deployment" description={`${runtimeConfig.networkName} · chain ID ${runtimeConfig.chainId}`}>
        <div className="app-contract-list">
          {contracts.map(({ name, key }) => {
            const address = runtimeConfig.deployment[key];
            return (
              <div className="app-contract-row" key={key}>
                <Braces aria-hidden="true" size={18} />
                <div><strong>{name}</strong><code>{address ? truncateMiddle(address, 12, 10) : "Not configured"}</code></div>
                {address ? <a aria-label={`Open ${name} in explorer`} href={`${runtimeConfig.explorerUrl}/address/${address}`} target="_blank" rel="noreferrer" title={`Open ${name} in explorer`}><ExternalLink aria-hidden="true" size={16} /></a> : <Status tone="neutral">Missing</Status>}
              </div>
            );
          })}
        </div>
      </Panel>

      <Panel title="Session escrow" description="V4 keeps one bounded prepaid session open while individual receipts are relayed off-chain.">
        <div className="app-contract-list">
          <div className="app-contract-row">
            <Braces aria-hidden="true" size={18} />
            <div><strong>Settlement V4</strong><code>{runtimeConfig.sessionDeployment.settlementAddress ? truncateMiddle(runtimeConfig.sessionDeployment.settlementAddress, 12, 10) : "Not configured"}</code></div>
            {runtimeConfig.sessionDeployment.settlementAddress ? <a aria-label="Open Settlement V4 in explorer" href={`${runtimeConfig.explorerUrl}/address/${runtimeConfig.sessionDeployment.settlementAddress}`} target="_blank" rel="noreferrer" title="Open Settlement V4 in explorer"><ExternalLink aria-hidden="true" size={16} /></a> : <Status tone="neutral">Missing</Status>}
          </div>
        </div>
        <dl className="app-definition-list app-deployment-meta">
          <div><dt>Protocol version</dt><dd>{runtimeConfig.sessionDeployment.protocolVersion || "Unavailable"}</dd></div>
          <div><dt>Deployment block</dt><dd>{runtimeConfig.sessionDeployment.deploymentBlock?.toLocaleString() || "Not supplied"}</dd></div>
        </dl>
      </Panel>

      <dl className="app-definition-list app-deployment-meta">
        <div><dt>Protocol version</dt><dd>{runtimeConfig.deployment.protocolVersion || "Unavailable"}</dd></div>
        <div><dt>Deployment block</dt><dd>{runtimeConfig.deployment.deploymentBlock?.toLocaleString() || "Unavailable"}</dd></div>
        <div><dt>Explorer</dt><dd><a href={runtimeConfig.explorerUrl} target="_blank" rel="noreferrer">{runtimeConfig.explorerUrl}<ExternalLink aria-hidden="true" size={13} /></a></dd></div>
      </dl>
    </div>
  );
}
