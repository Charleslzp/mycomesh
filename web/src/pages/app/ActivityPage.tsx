import { useQuery } from "@tanstack/react-query";
import { ExternalLink, FileSearch, WalletCards } from "lucide-react";
import { formatUnits } from "viem";
import { useAccount } from "wagmi";
import { EmptyState, Metric, Notice, PageHeader, Panel, Status, formatTime, truncateMiddle } from "../../app/ui";
import { protocolApi } from "../../protocol/api";
import { runtimeConfig } from "../../protocol/config";

export function ActivityPage() {
  const { address, isConnected } = useAccount();
  const history = useQuery({
    queryKey: ["v8-receipts", address],
    queryFn: () => protocolApi.v8Receipts(address as string),
    enabled: isConnected && Boolean(address),
    retry: 1,
  });
  const summary = history.data?.summary;
  const fee = summary
    ? `${formatUnits(BigInt(summary.actual_fee_units), runtimeConfig.stablecoinDecimals)} ${runtimeConfig.stablecoinSymbol}`
    : "Unavailable";

  return (
    <div className="app-page app-page--activity">
      <PageHeader
        eyebrow="Audit trail"
        title="Activity"
        description="Confirmed Settlement V8 receipts for the connected wallet."
        actions={
          <Status tone={history.data ? "positive" : history.isError ? "negative" : "neutral"}>
            {history.data ? "Indexer online" : history.isError ? "Indexer unavailable" : "Waiting for wallet"}
          </Status>
        }
      />

      {history.isError ? (
        <Notice icon={FileSearch} title="Receipt history unavailable" tone="negative">
          {history.error instanceof Error ? history.error.message : "The V8 Indexer could not be reached."}
        </Notice>
      ) : null}

      {history.data ? (
        <section className="app-metric-grid app-metric-grid--compact" aria-label="Wallet receipt totals">
          <Metric label="Settled requests" value={summary?.receipt_count ?? 0} detail="Confirmed V8 receipts" />
          <Metric label="Total spent" value={fee} detail="On-chain actual fee" />
          <Metric label="Input tokens" value={(summary?.input_tokens ?? 0).toLocaleString()} detail="Relay-verified detail" />
          <Metric label="Output tokens" value={(summary?.output_tokens ?? 0).toLocaleString()} detail={`${summary?.enriched_receipt_count ?? 0} enriched receipts`} />
        </section>
      ) : null}

      <Panel title="Inference receipts" description={address ? `Wallet ${truncateMiddle(address, 10, 8)}` : "Connect a wallet to load its public ledger."}>
        {!isConnected ? (
          <EmptyState icon={WalletCards} title="Wallet not connected" />
        ) : history.isLoading ? (
          <EmptyState icon={FileSearch} title="Loading receipts" />
        ) : history.data?.receipts.length ? (
          <div className="app-table-wrap">
            <table className="app-table">
              <thead><tr><th>Time</th><th>Tokens</th><th>Fee</th><th>Provider</th><th>Transaction</th></tr></thead>
              <tbody>
                {history.data.receipts.map((receipt) => (
                  <tr key={receipt.settlement_key}>
                    <td data-label="Time">{formatTime(receipt.block_timestamp)}</td>
                    <td data-label="Tokens">
                      {receipt.enriched ? `${receipt.input_tokens?.toLocaleString()} / ${receipt.output_tokens?.toLocaleString()}` : "Chain only"}
                    </td>
                    <td data-label="Fee">{formatUnits(BigInt(receipt.actual_fee_units), runtimeConfig.stablecoinDecimals)} {runtimeConfig.stablecoinSymbol}</td>
                    <td data-label="Provider">{truncateMiddle(receipt.provider)}</td>
                    <td data-label="Transaction">
                      <a href={`${runtimeConfig.explorerUrl}/tx/${receipt.transaction_hash}`} target="_blank" rel="noreferrer">
                        {truncateMiddle(receipt.transaction_hash)} <ExternalLink aria-hidden="true" size={13} />
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : history.data ? (
          <EmptyState icon={FileSearch} title="No settled receipts" />
        ) : null}
      </Panel>
    </div>
  );
}
