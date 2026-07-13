import { Check, Clipboard, Eye, KeyRound, RotateCw, ShieldCheck, Trash2, Wallet } from "lucide-react";
import { useState } from "react";
import { useAccount, useSignMessage } from "wagmi";
import { useApiKey } from "../../state/ApiKeyContext";
import { FieldError, Metric, Notice, PageHeader, Panel, Status } from "../../app/ui";
import { challengeAudienceFromDiscovery, registerBrowserApiKey } from "../../protocol/access";
import { protocolApi } from "../../protocol/api";
import { runtimeConfig } from "../../protocol/config";
import { redactApiKey } from "../../protocol/crypto";
import { toProtocolError } from "../../protocol/errors";
import { useConsumerAccount } from "../../protocol/queries";

type RegistrationStep = "idle" | "generating" | "challenging" | "signing" | "registering" | "complete";

export function AccessPage() {
  const { address, chainId, isConnected } = useAccount();
  const { signMessageAsync } = useSignMessage();
  const { apiKey, clearApiKey, setApiKey } = useApiKey();
  const [step, setStep] = useState<RegistrationStep>("idle");
  const [error, setError] = useState<string | null>(null);
  const [revealedSecret, setRevealedSecret] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const account = useConsumerAccount(apiKey);
  const wrongChain = isConnected && chainId !== runtimeConfig.chainId;
  const busy = !["idle", "complete"].includes(step);

  async function register(rotate: boolean) {
    if (!address || wrongChain) return;
    setError(null);
    setCopied(false);
    setRevealedSecret(null);
    try {
      const discovery = await protocolApi.discovery();
      const registration = await registerBrowserApiKey({
        wallet: address,
        rotate,
        audience: challengeAudienceFromDiscovery(discovery),
        signMessage: (message) => signMessageAsync({ message }),
        onStage: (stage) => {
          const steps: Record<typeof stage, RegistrationStep> = {
            generating: "generating",
            requesting_challenge: "challenging",
            awaiting_signature: "signing",
            registering: "registering",
          };
          setStep(steps[stage]);
        },
      });
      setApiKey(registration.apiKey, {
        wallet: registration.challenge.wallet,
        fingerprint: registration.challenge.key_fingerprint,
      });
      setRevealedSecret(registration.apiKey);
      setStep("complete");
    } catch (registrationError) {
      setError(toProtocolError(registrationError).message);
      setStep("idle");
    }
  }

  async function copySecret() {
    const value = revealedSecret;
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
    } catch {
      setError("Clipboard access was denied. Select and copy the key manually.");
    }
  }

  return (
    <div className="app-page app-page--access">
      <PageHeader
        eyebrow="Credentials"
        title="Consumer access"
        description="Create a wallet-bound API credential without sending the secret to MycoMesh."
        actions={<Status tone={apiKey ? "positive" : "neutral"}>{apiKey ? "Key in this session" : "No active key"}</Status>}
      />

      <Notice icon={ShieldCheck} title="The secret starts here and stays here" tone="positive">
        This browser generates 256 bits of randomness and registers only its SHA-256 hash. Your wallet signs the
        exact gateway challenge binding that hash to the origin, network, chain, settlement, and nonce.
      </Notice>

      <div className="app-two-column app-access-layout">
        <Panel title="Register access" description="The signature is identity proof. It does not submit a transaction or spend gas.">
          {!isConnected ? (
            <div className="app-gated-action">
              <Wallet aria-hidden="true" size={22} />
              <strong>Connect a wallet to continue</strong>
              <p>The wallet control in the header supports an injected Ethereum wallet.</p>
            </div>
          ) : wrongChain ? (
            <div className="app-gated-action">
              <Wallet aria-hidden="true" size={22} />
              <strong>Switch to {runtimeConfig.networkName}</strong>
              <p>Key challenges are chain-bound and will be rejected on chain ID {chainId}.</p>
            </div>
          ) : (
            <div className="app-registration-flow">
              <dl className="app-definition-list">
                <div><dt>Wallet</dt><dd>{address}</dd></div>
                <div><dt>Chain ID</dt><dd>{runtimeConfig.chainId}</dd></div>
                <div><dt>Signature</dt><dd>personal_sign</dd></div>
                <div><dt>Secret storage</dt><dd>Current browser tab</dd></div>
              </dl>
              <div className="app-button-row">
                <button className="button button--primary" disabled={busy} onClick={() => register(false)} type="button">
                  <KeyRound aria-hidden="true" size={17} />
                  {busy && !apiKey ? "Registering" : "Create API key"}
                </button>
                {apiKey ? (
                  <button className="button button--secondary" disabled={busy} onClick={() => register(true)} type="button">
                    <RotateCw aria-hidden="true" size={17} />
                    Rotate key
                  </button>
                ) : null}
              </div>
              {busy ? <p className="app-progress-message">{step === "signing" ? "Review the exact challenge in your wallet." : "Preparing the bound credential."}</p> : null}
              <FieldError>{error}</FieldError>
            </div>
          )}
        </Panel>

        <Panel title="Session credential" description="MycoMesh cannot recover this client-generated value.">
          {apiKey ? (
            <div className="app-secret">
              {revealedSecret ? (
                <Notice icon={Eye} title="New key created" tone="warning">
                  This is the only time the console reveals this value. Store it now; rotating invalidates the previous key hash.
                </Notice>
              ) : (
                <Notice icon={ShieldCheck} title="Session key active" tone="positive">
                  The key can be used by this tab but is no longer available for display or copying.
                </Notice>
              )}
              <label htmlFor="session-api-key">API key</label>
              <div className="app-secret__value">
                <input
                  id="session-api-key"
                  readOnly
                  type="text"
                  value={revealedSecret || redactApiKey(apiKey)}
                />
                {revealedSecret ? (
                  <button aria-label="Copy API key" onClick={copySecret} title="Copy API key" type="button">
                    {copied ? <Check aria-hidden="true" size={17} /> : <Clipboard aria-hidden="true" size={17} />}
                  </button>
                ) : null}
              </div>
              <button
                className="button button--danger-quiet"
                onClick={() => {
                  clearApiKey();
                  setRevealedSecret(null);
                  setStep("idle");
                }}
                type="button"
              >
                <Trash2 aria-hidden="true" size={16} />
                Remove from this tab
              </button>
            </div>
          ) : (
            <div className="app-empty-credential"><KeyRound aria-hidden="true" size={23} /><p>No API key is stored in this browser tab.</p></div>
          )}
        </Panel>
      </div>

      <section className="app-metric-grid" aria-label="Gateway account">
        <Metric label="Account" value={account.data?.account_id || (account.isLoading ? "Checking" : "Unavailable")} />
        <Metric label="Status" value={account.data?.status || (account.isError ? "Key rejected" : "Unavailable")} />
        <Metric label="Balance" value={account.data ? `${account.data.balance_usdc} USDC` : "Unavailable"} />
        <Metric label="Billing mode" value={account.data?.billing_mode || "Unavailable"} />
      </section>
    </div>
  );
}
