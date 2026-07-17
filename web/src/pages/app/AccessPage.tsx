import {
  Check,
  Clipboard,
  Eye,
  EyeOff,
  Fingerprint,
  KeyRound,
  Link2,
  RotateCw,
  ShieldCheck,
  ShieldX,
  Trash2,
  Wallet,
  X,
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { useAccount, useSignMessage } from "wagmi";
import { useApiKey } from "../../state/ApiKeyContext";
import { FieldError, Metric, Notice, PageHeader, Panel, Status } from "../../app/ui";
import {
  canonicalGatewayBaseUrl,
  challengeAudienceFromDiscovery,
  registerBrowserApiKey,
} from "../../protocol/access";
import { protocolApi } from "../../protocol/api";
import { runtimeConfig } from "../../protocol/config";
import { redactApiKey } from "../../protocol/crypto";
import { toProtocolError } from "../../protocol/errors";
import { useConsumerAccount, useDiscovery } from "../../protocol/queries";
import {
  deleteBrowserConsumerIdentity,
  getOrCreateBrowserConsumerIdentity,
} from "../../protocol/browserConsumerStore";

type RegistrationStep = "idle" | "generating" | "challenging" | "signing" | "registering" | "complete";

export function AccessPage() {
  const { address, chainId, isConnected } = useAccount();
  const { signMessageAsync } = useSignMessage();
  const { apiKey, credential, clearApiKey, setApiKey } = useApiKey();
  const [accessMode, setAccessMode] = useState<"direct" | "gateway">("direct");
  const [step, setStep] = useState<RegistrationStep>("idle");
  const [error, setError] = useState<string | null>(null);
  const [revealedSecret, setRevealedSecret] = useState<string | null>(null);
  const [secretVisible, setSecretVisible] = useState(false);
  const [copied, setCopied] = useState<"key" | "url" | null>(null);
  const [confirmingRevoke, setConfirmingRevoke] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [revokedFingerprint, setRevokedFingerprint] = useState<string | null>(null);
  const [rotatingIdentity, setRotatingIdentity] = useState(false);
  const [confirmingIdentityRotation, setConfirmingIdentityRotation] = useState(false);
  const account = useConsumerAccount(apiKey, accessMode === "gateway");
  const discovery = useDiscovery(accessMode === "gateway");
  const browserIdentity = useQuery({
    queryKey: ["browser-consumer-identity"],
    queryFn: getOrCreateBrowserConsumerIdentity,
    retry: false,
    staleTime: Number.POSITIVE_INFINITY,
    enabled: accessMode === "direct",
  });
  const wrongChain = isConnected && chainId !== runtimeConfig.chainId;
  const busy = !["idle", "complete"].includes(step) || revoking;
  let discoveredBaseUrl: string | null = null;
  try {
    const audience = challengeAudienceFromDiscovery(discovery.data);
    discoveredBaseUrl = canonicalGatewayBaseUrl(
      discovery.data?.recommended_base_url,
      audience.origin,
    );
  } catch {
    // Registration remains disabled by its own fail-closed discovery validation.
  }
  const apiBaseUrl = credential?.baseUrl || discoveredBaseUrl;
  const fingerprint = account.data?.key_fingerprint || credential?.fingerprint || null;

  async function register(rotate: boolean) {
    if (!address || wrongChain) return;
    setError(null);
    setCopied(null);
    setRevealedSecret(null);
    setSecretVisible(false);
    setConfirmingRevoke(false);
    setRevokedFingerprint(null);
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
        baseUrl: registration.baseUrl,
      });
      setRevealedSecret(registration.apiKey);
      setSecretVisible(true);
      setStep("complete");
    } catch (registrationError) {
      setError(toProtocolError(registrationError).message);
      setStep("idle");
    }
  }

  async function copyValue(value: string | null, target: "key" | "url") {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      setCopied(target);
    } catch {
      setError("Clipboard access was denied. Select and copy the value manually.");
    }
  }

  async function revokeKey() {
    if (!apiKey) return;
    setError(null);
    setRevoking(true);
    try {
      const result = await protocolApi.revokeCurrentKey(apiKey);
      if (result.revoked !== true) throw new Error("Gateway did not confirm credential revocation.");
      setRevokedFingerprint(result.key_fingerprint || fingerprint);
      clearApiKey();
      setRevealedSecret(null);
      setSecretVisible(false);
      setConfirmingRevoke(false);
      setStep("idle");
    } catch (revokeError) {
      setError(toProtocolError(revokeError).message);
    } finally {
      setRevoking(false);
    }
  }

  async function rotateBrowserIdentity() {
    setError(null);
    setRotatingIdentity(true);
    try {
      await deleteBrowserConsumerIdentity();
      await browserIdentity.refetch();
      setConfirmingIdentityRotation(false);
    } catch (identityError) {
      setError(toProtocolError(identityError).message);
    } finally {
      setRotatingIdentity(false);
    }
  }

  if (accessMode === "direct") {
    const identity = browserIdentity.data;
    return (
      <div className="app-page app-page--access">
        <PageHeader
          eyebrow="Consumer identity"
          title="Direct access"
          description="This browser owns the request identity used for encrypted Provider sessions."
          actions={
            <Status tone={identity ? "positive" : browserIdentity.isError ? "negative" : "warning"}>
              {identity ? "Local identity ready" : browserIdentity.isError ? "Identity unavailable" : "Creating identity"}
            </Status>
          }
        />

        <div className="app-segmented-control" aria-label="Access mode">
          <button aria-pressed="true" onClick={() => setAccessMode("direct")} type="button">
            Direct network
          </button>
          <button aria-pressed="false" onClick={() => setAccessMode("gateway")} type="button">
            Gateway compatibility
          </button>
        </div>

        <Notice icon={ShieldCheck} title="Non-extractable local signer" tone="positive">
          The Ed25519 private key is a non-extractable WebCrypto key. IndexedDB stores the key handle,
          public key and Peer ID; it never stores plaintext private-key bytes.
        </Notice>

        <div className="app-two-column app-access-layout">
          <Panel title="Browser Consumer" description="Public identity presented to Providers and bound by the wallet authorization.">
            {identity ? (
              <div className="app-secret">
                <label htmlFor="browser-consumer-key"><KeyRound aria-hidden="true" size={14} />Consumer public key</label>
                <div className="app-secret__value">
                  <input id="browser-consumer-key" readOnly type="text" value={identity.publicKey} />
                  <button aria-label="Copy Consumer public key" onClick={() => copyValue(identity.publicKey, "key")} title="Copy Consumer public key" type="button">
                    {copied === "key" ? <Check aria-hidden="true" size={17} /> : <Clipboard aria-hidden="true" size={17} />}
                  </button>
                </div>
                <div className="app-credential-fingerprint">
                  <Fingerprint aria-hidden="true" size={15} />
                  <span>Peer ID</span>
                  <code>{identity.peerId}</code>
                </div>
                {confirmingIdentityRotation ? (
                  <div className="app-revoke-confirmation">
                    <Notice icon={ShieldX} title="Rotate this Consumer identity?" tone="warning">
                      Existing wallet authorizations remain bound to the current public key and cannot be used by the replacement key.
                    </Notice>
                    <div className="app-button-row">
                      <button className="button button--danger" disabled={rotatingIdentity} onClick={rotateBrowserIdentity} type="button">
                        <RotateCw aria-hidden="true" size={17} />
                        {rotatingIdentity ? "Rotating" : "Confirm rotation"}
                      </button>
                      <button className="button button--secondary" disabled={rotatingIdentity} onClick={() => setConfirmingIdentityRotation(false)} type="button">
                        <X aria-hidden="true" size={16} />
                        Cancel
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="app-button-row">
                    <button className="button button--secondary" disabled={rotatingIdentity} onClick={() => setConfirmingIdentityRotation(true)} type="button">
                      <RotateCw aria-hidden="true" size={17} />
                      Rotate identity
                    </button>
                    <Link className="button button--primary" to="/app/playground">
                      <Link2 aria-hidden="true" size={17} />
                      Open Playground
                    </Link>
                  </div>
                )}
              </div>
            ) : (
              <div className="app-empty-credential">
                <KeyRound aria-hidden="true" size={23} />
                <p>{browserIdentity.isError ? "The local signer could not be created." : "Creating the local signer."}</p>
              </div>
            )}
            <FieldError>{error}</FieldError>
          </Panel>

          <Panel title="Network endpoints" description="Public routing information; no Gateway credential is required.">
            <div className="app-credential-field">
              <label htmlFor="consumer-bridge-url"><Link2 aria-hidden="true" size={14} />Bridge fetch URL</label>
              <div className="app-secret__value">
                <input id="consumer-bridge-url" readOnly type="text" value={runtimeConfig.bridgeBaseUrl} />
                <button aria-label="Copy Bridge URL" onClick={() => copyValue(runtimeConfig.bridgeBaseUrl, "url")} title="Copy Bridge URL" type="button">
                  {copied === "url" ? <Check aria-hidden="true" size={17} /> : <Clipboard aria-hidden="true" size={17} />}
                </button>
              </div>
            </div>
            <dl className="app-definition-list">
              <div><dt>Signed audience</dt><dd>{runtimeConfig.bridgeAudienceUrl}</dd></div>
              <div><dt>Local Docker app</dt><dd>http://127.0.0.1:8110/app/playground</dd></div>
              <div><dt>Local API base</dt><dd>http://127.0.0.1:8110/v1</dd></div>
              <div><dt>API secret</dt><dd>Docker volume only</dd></div>
            </dl>
          </Panel>
        </div>

        <section className="app-metric-grid" aria-label="Direct Consumer binding">
          <Metric label="Network" value={runtimeConfig.networkId} />
          <Metric label="Channel" value={runtimeConfig.channelId} />
          <Metric label="Settlement" value="V3" />
          <Metric label="Gateway" value="Optional" />
        </section>
      </div>
    );
  }

  return (
    <div className="app-page app-page--access">
      <PageHeader
        eyebrow="Credentials"
        title="Consumer access"
        description="Create a wallet-bound API credential whose plaintext is never stored by MycoMesh."
        actions={
          <Status tone={account.isError ? "negative" : apiKey ? "positive" : "neutral"}>
            {account.isError ? "Key rejected" : apiKey ? "Key in this session" : "No active key"}
          </Status>
        }
      />

      <div className="app-segmented-control" aria-label="Access mode">
        <button aria-pressed="false" onClick={() => setAccessMode("direct")} type="button">
          Direct network
        </button>
        <button aria-pressed="true" onClick={() => setAccessMode("gateway")} type="button">
          Gateway compatibility
        </button>
      </div>

      <Notice icon={ShieldCheck} title="Generated here, stored only in this session" tone="positive">
        This browser generates 256 bits of randomness and registers only its SHA-256 hash. The plaintext is sent
        over HTTPS only when authenticating a Gateway request; the Gateway does not persist it. Your wallet signs
        the exact challenge binding that hash to the origin, network, chain, settlement, and nonce.
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

        <Panel title="API connection" description="Use this URL and credential with an OpenAI-compatible client.">
          {apiBaseUrl ? (
            <div className="app-credential-field">
              <label htmlFor="consumer-api-url"><Link2 aria-hidden="true" size={14} />API base URL</label>
              <div className="app-secret__value">
                <input id="consumer-api-url" readOnly type="url" value={apiBaseUrl} />
                <button
                  aria-label="Copy API base URL"
                  onClick={() => copyValue(apiBaseUrl, "url")}
                  title="Copy API base URL"
                  type="button"
                >
                  {copied === "url" ? <Check aria-hidden="true" size={17} /> : <Clipboard aria-hidden="true" size={17} />}
                </button>
              </div>
            </div>
          ) : null}
          {apiKey ? (
            <div className="app-secret">
              {revealedSecret ? (
                <Notice icon={Eye} title="New key created" tone="warning">
                  This is the only time the console reveals this value. Store it now; rotating invalidates the previous key hash.
                </Notice>
              ) : (
                <Notice icon={ShieldCheck} title="Session key active" tone="positive">
                  The complete key remains available only in this browser tab. Reveal it only when needed.
                </Notice>
              )}
              <label htmlFor="session-api-key"><KeyRound aria-hidden="true" size={14} />API key</label>
              <div className="app-secret__value">
                <input
                  id="session-api-key"
                  readOnly
                  type="text"
                  value={secretVisible ? apiKey : redactApiKey(apiKey)}
                />
                <button
                  aria-label={secretVisible ? "Hide API key" : "Reveal API key"}
                  onClick={() => setSecretVisible((visible) => !visible)}
                  title={secretVisible ? "Hide API key" : "Reveal API key"}
                  type="button"
                >
                  {secretVisible ? <EyeOff aria-hidden="true" size={17} /> : <Eye aria-hidden="true" size={17} />}
                </button>
                <button
                  aria-label="Copy API key"
                  onClick={() => copyValue(apiKey, "key")}
                  title="Copy API key"
                  type="button"
                >
                  {copied === "key" ? <Check aria-hidden="true" size={17} /> : <Clipboard aria-hidden="true" size={17} />}
                </button>
              </div>
              {fingerprint ? (
                <div className="app-credential-fingerprint">
                  <Fingerprint aria-hidden="true" size={15} />
                  <span>SHA-256 fingerprint</span>
                  <code>{fingerprint}</code>
                </div>
              ) : null}
              {confirmingRevoke ? (
                <div className="app-revoke-confirmation">
                  <Notice icon={ShieldX} title="Revoke this credential?" tone="warning">
                    Requests using this key will be rejected immediately. The account and funds remain intact.
                  </Notice>
                  <div className="app-button-row">
                    <button className="button button--danger" disabled={revoking} onClick={revokeKey} type="button">
                      <ShieldX aria-hidden="true" size={16} />
                      {revoking ? "Revoking" : "Revoke key"}
                    </button>
                    <button className="button button--secondary" disabled={revoking} onClick={() => setConfirmingRevoke(false)} type="button">
                      <X aria-hidden="true" size={16} />
                      Cancel
                    </button>
                  </div>
                </div>
              ) : (
                <div className="app-credential-actions">
                  <button
                    className="button button--danger-quiet"
                    disabled={busy}
                    onClick={() => setConfirmingRevoke(true)}
                    type="button"
                  >
                    <ShieldX aria-hidden="true" size={16} />
                    Revoke key
                  </button>
                  <button
                    className="button button--secondary"
                    disabled={busy}
                    onClick={() => {
                      clearApiKey();
                      setRevealedSecret(null);
                      setSecretVisible(false);
                      setStep("idle");
                    }}
                    type="button"
                  >
                    <Trash2 aria-hidden="true" size={16} />
                    Remove from tab
                  </button>
                </div>
              )}
              <FieldError>{error}</FieldError>
            </div>
          ) : (
            <div className="app-empty-credential">
              {revokedFingerprint ? (
                <><ShieldCheck aria-hidden="true" size={23} /><p>Credential {revokedFingerprint} was revoked.</p></>
              ) : (
                <><KeyRound aria-hidden="true" size={23} /><p>No API key is stored in this browser tab.</p></>
              )}
            </div>
          )}
        </Panel>
      </div>

      <section className="app-metric-grid" aria-label="Gateway account">
        <Metric label="Account" value={account.data?.account_id || (account.isLoading ? "Checking" : "Unavailable")} />
        <Metric label="Status" value={account.data?.status || (account.isError ? "Key rejected" : "Unavailable")} />
        <Metric label="Balance" value={account.data ? `${account.data.balance_usdc} USDC` : "Unavailable"} />
        <Metric label="Key fingerprint" value={fingerprint || "Unavailable"} />
      </section>
    </div>
  );
}
