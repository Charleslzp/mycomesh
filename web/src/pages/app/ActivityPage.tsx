import { Activity, ExternalLink, FileSearch, LockKeyhole } from "lucide-react";
import { EmptyState, Notice, PageHeader, Panel, Status } from "../../app/ui";
import { isV3Configured, runtimeConfig } from "../../protocol/config";

export function ActivityPage() {
  const settlement = runtimeConfig.deployment.settlementAddress;

  return (
    <div className="app-page app-page--activity">
      <PageHeader
        eyebrow="Audit trail"
        title="Activity"
        description="Protocol events and request receipts, with explicit provenance for every displayed record."
        actions={<Status tone="neutral">Indexer not connected</Status>}
      />

      {!isV3Configured ? (
        <Notice icon={LockKeyhole} title="V3 event source unavailable" tone="warning">This build has no verified V3 settlement address or deployment block, so it cannot identify the canonical event stream.</Notice>
      ) : null}

      <div className="app-two-column app-activity-layout">
        <Panel title="On-chain events" description="Deposits, withdrawals, reservations, releases, and settled receipts belong in this timeline.">
          <EmptyState icon={Activity} title="No public event indexer configured">
            <p>A complete wallet history cannot be guaranteed from an arbitrary browser RPC range. No partial timeline is presented as complete.</p>
            {isV3Configured && settlement ? <a href={`${runtimeConfig.explorerUrl}/address/${settlement}#events`} target="_blank" rel="noreferrer">Open canonical contract events <ExternalLink aria-hidden="true" size={14} /></a> : null}
          </EmptyState>
        </Panel>

        <Panel title="Inference receipts" description="The current gateway returns receipt data with an individual /v1/responses result.">
          <EmptyState icon={FileSearch} title="No receipt-history endpoint">
            <p>Run a request in the Playground to inspect that response's receipt envelope. Historical receipts are not exposed by the public API yet.</p>
          </EmptyState>
        </Panel>
      </div>
    </div>
  );
}
