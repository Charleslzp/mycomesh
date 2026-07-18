import { useQuery } from "@tanstack/react-query";
import {
  ArrowRight,
  Blocks,
  BookOpen,
  Bot,
  Braces,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Code2,
  Cpu,
  ExternalLink,
  KeyRound,
  Menu,
  Network,
  Route,
  Server,
  ShieldCheck,
  Sparkles,
  WalletCards,
  X,
  Zap,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Brand } from "../components/Brand";
import { ProtocolField } from "../components/ProtocolField";
import { protocolApi } from "../protocol/api";
import { appRouteUrl, isV3Configured, isV4Configured, runtimeConfig } from "../protocol/config";

const flow = [
  { label: "Request", icon: Braces, note: "Canonical workload" },
  { label: "Reserve", icon: WalletCards, note: "Bound budget" },
  { label: "Route", icon: Route, note: "Signed discovery" },
  { label: "Infer", icon: Cpu, note: "Private execution" },
  { label: "Accept", icon: CheckCircle2, note: "Usage receipt" },
  { label: "Settle", icon: Blocks, note: "On Ethereum" },
];

const roles = [
  {
    icon: Bot,
    title: "Consumers",
    text: "Call familiar AI APIs, choose providers, and keep spending bounded by each request.",
    link: runtimeConfig.appUrl,
    action: "Open the app",
  },
  {
    icon: Server,
    title: "Providers",
    text: "Serve useful model capacity through signed descriptors and receive verifiable settlement.",
    link: "#developers",
    action: "Run a provider",
  },
  {
    icon: Network,
    title: "Bridges",
    text: "Relay discovery and encrypted traffic without becoming a trusted payment intermediary.",
    link: "#architecture",
    action: "Explore the network",
  },
];

function freshnessLabel(updatedAt?: number) {
  if (!updatedAt) return "Unavailable";
  const timestamp = updatedAt < 10_000_000_000 ? updatedAt * 1_000 : updatedAt;
  const seconds = Math.max(0, Math.round((Date.now() - timestamp) / 1_000));
  return seconds < 60 ? `${seconds}s ago` : `${Math.floor(seconds / 60)}m ago`;
}

function NetworkStrip() {
  const health = useQuery({ queryKey: ["landing", "health"], queryFn: protocolApi.health, retry: 1 });
  const peers = useQuery({ queryKey: ["landing", "peers"], queryFn: protocolApi.peers, retry: 1 });
  const models = useQuery({ queryKey: ["landing", "models"], queryFn: protocolApi.models, retry: 1 });
  const discovery = useQuery({
    queryKey: ["landing", "discovery"],
    queryFn: protocolApi.discovery,
    retry: 1,
  });
  const onlinePeers = peers.data?.filter((peer) => peer.status !== "expired" && peer.status !== "offline").length;

  const items = [
    {
      label: "Gateway",
      value: health.isPending ? "Checking" : health.data?.ok ? "Online" : "Unavailable",
      state: health.data?.ok ? "online" : "neutral",
    },
    { label: "Live providers", value: peers.isPending ? "Checking" : onlinePeers ?? "Unavailable" },
    { label: "Models", value: models.isPending ? "Checking" : models.data?.length ?? "Unavailable" },
    {
      label: "Gateways",
      value: discovery.isPending
        ? "Checking"
        : discovery.isError
          ? "Unavailable"
          : discovery.data?.gateways?.length ?? "Unavailable",
    },
    { label: "Settlement", value: isV4Configured ? "V4 session escrow" : isV3Configured ? "V3 manifest present" : "Manifest pending", state: isV4Configured || isV3Configured ? "online" : "warning" },
    {
      label: "Updated",
      value: discovery.isPending
        ? "Checking"
        : discovery.isError
          ? "Unavailable"
          : freshnessLabel(discovery.data?.updated_at),
    },
  ];

  return (
    <section className="network-strip" aria-label="Live MycoMesh network status">
      <div className="network-strip__inner">
        {items.map((item) => (
          <div className="network-strip__item" key={item.label}>
            <span>{item.label}</span>
            <strong>
              {item.state && <span className={`status-dot status-dot--${item.state}`} aria-hidden="true" />}
              {item.value}
            </strong>
          </div>
        ))}
      </div>
    </section>
  );
}

function LandingHeader() {
  const [open, setOpen] = useState(false);
  const closeRef = useRef<HTMLButtonElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    closeRef.current?.focus();
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setOpen(false);
        triggerRef.current?.focus();
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = Array.from(
        dialogRef.current?.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ) ?? [],
      );
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  return (
    <header className="site-header">
      <div className="site-header__inner">
        <Brand inverted />
        <nav className="site-nav" aria-label="Primary navigation">
          <a href="#protocol">Protocol</a>
          <a href="#network">Network</a>
          <a href="#developers">Developers</a>
          <a href="#security">Security</a>
        </nav>
        <div className="site-header__actions">
          <span className="testnet-label"><span className="status-dot status-dot--warning" />Sepolia</span>
          <a className="button button--light button--small" href={runtimeConfig.appUrl}>
            Launch app <ArrowRight size={16} />
          </a>
          <button
            ref={triggerRef}
            className="icon-button site-header__menu"
            type="button"
            onClick={() => setOpen(true)}
            aria-label="Open navigation"
            aria-expanded={open}
            aria-controls="mobile-site-navigation"
            aria-haspopup="dialog"
          >
            <Menu size={21} />
          </button>
        </div>
      </div>
      {open && (
        <div ref={dialogRef} className="mobile-nav" id="mobile-site-navigation" role="dialog" aria-modal="true" aria-label="Navigation menu">
          <div className="mobile-nav__top">
            <Brand inverted />
            <button
              ref={closeRef}
              className="icon-button icon-button--dark"
              type="button"
              onClick={() => {
                setOpen(false);
                triggerRef.current?.focus();
              }}
              aria-label="Close navigation"
            >
              <X size={22} />
            </button>
          </div>
          <nav aria-label="Mobile navigation" onClick={() => setOpen(false)}>
            <a href="#protocol">Protocol <ChevronRight size={18} /></a>
            <a href="#network">Network <ChevronRight size={18} /></a>
            <a href="#developers">Developers <ChevronRight size={18} /></a>
            <a href="#security">Security <ChevronRight size={18} /></a>
          </nav>
          <a className="button button--primary" href={runtimeConfig.appUrl}>Launch testnet <ArrowRight size={17} /></a>
        </div>
      )}
    </header>
  );
}

export function LandingPage() {
  return (
    <div className="landing-page">
      <LandingHeader />
      <main id="main-content">
        <section className="hero" aria-labelledby="hero-title">
          <ProtocolField />
          <div className="hero__content shell">
            <div className="hero__eyebrow">
              <span className="status-dot status-dot--warning" aria-hidden="true" />
              Sepolia testnet · {isV3Configured ? "V3 manifest present" : "Protocol preview · V3 deployment pending"}
            </div>
            <h1 id="hero-title">MycoMesh</h1>
            <p className="hero__lede">
              OpenAI-compatible AI inference across signed providers, with request-bound settlement on Ethereum.
            </p>
            <div className="hero__actions">
              <a className="button button--primary" href={runtimeConfig.appUrl}>
                Launch testnet <ArrowRight size={18} />
              </a>
              <a className="button button--ghost-light" href="#protocol">
                Read the protocol <BookOpen size={17} />
              </a>
            </div>
            <div className="hero__legend" aria-label="Network visualization key">
              <span><i className="legend-dot legend-dot--provider" />Provider capacity</span>
              <span><i className="legend-dot legend-dot--consumer" />Consumer request</span>
              <span><i className="legend-dot legend-dot--settlement" />Settlement checkpoint</span>
            </div>
          </div>
          <a className="hero__scroll" href="#network" aria-label="Scroll to live network status">
            Live network <ChevronRight size={15} />
          </a>
        </section>

        <div id="network"><NetworkStrip /></div>

        <section className="section section--protocol" id="protocol">
          <div className="shell">
            <div className="section-heading">
              <span className="eyebrow">One bounded request at a time</span>
              <h2>Useful work, with an accountable path to payment.</h2>
              <p>
                Prompts and outputs stay offchain. MycoMesh binds the provider, request commitment, budget,
                usage, and receipt so settlement can be checked without publishing private inference data.
              </p>
            </div>
            <ol className="protocol-flow" aria-label="MycoMesh request lifecycle">
              {flow.map(({ label, icon: Icon, note }, index) => (
                <li key={label}>
                  <div className="protocol-flow__index">0{index + 1}</div>
                  <Icon size={22} aria-hidden="true" />
                  <strong>{label}</strong>
                  <span>{note}</span>
                  {index < flow.length - 1 && <ChevronRight className="protocol-flow__arrow" size={17} />}
                </li>
              ))}
            </ol>
          </div>
        </section>

        <section className="section section--roles">
          <div className="shell">
            <div className="roles-intro">
              <span className="eyebrow">A market with clear roles</span>
              <h2>Open participation. Narrow trust.</h2>
            </div>
            <div className="role-grid">
              {roles.map(({ icon: Icon, title, text, link, action }) => (
                <article className="role-card" key={title}>
                  <Icon size={25} aria-hidden="true" />
                  <h3>{title}</h3>
                  <p>{text}</p>
                  <a href={link}>{action} <ArrowRight size={16} /></a>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="section section--architecture" id="architecture">
          <div className="shell architecture-layout">
            <div className="section-heading section-heading--left">
              <span className="eyebrow">Protocol architecture</span>
              <h2>Not a new chain. A useful-work network anchored to one.</h2>
              <p>
                Discovery, transport, and inference remain fast and private offchain. Ethereum handles the
                commitments and final value transfer that benefit from shared verification.
              </p>
              <a className="text-link" href={runtimeConfig.docsUrl}>Read technical documentation <ExternalLink size={15} /></a>
            </div>
            <div className="architecture-stack" role="img" aria-label="Four protocol layers from Ethereum to provider execution">
              <div><span>04</span><Cpu size={20} /><strong>Provider execution</strong><small>Models · evidence · metering</small></div>
              <div><span>03</span><Network size={20} /><strong>Useful-work mesh</strong><small>Discovery · routing · sealed transport</small></div>
              <div><span>02</span><Blocks size={20} /><strong>Settlement contracts</strong><small>Reservations · receipts · balances</small></div>
              <div><span>01</span><CircleDot size={20} /><strong>Ethereum</strong><small>Sepolia testnet today</small></div>
            </div>
          </div>
        </section>

        <section className="section section--developers" id="developers">
          <div className="shell developer-layout">
            <div className="developer-copy">
              <span className="eyebrow eyebrow--dark">Drop into existing AI tooling</span>
              <h2>One base URL. One user-controlled key.</h2>
              <p>
                The consumer proxy exposes an OpenAI-compatible surface while MycoMesh handles provider
                selection and protocol receipts. Responses are currently buffered, including streaming-mode requests.
              </p>
              <ul className="feature-list">
                <li><KeyRound size={18} />Secret generated in your browser</li>
                <li><ShieldCheck size={18} />Wallet-bound registration challenge</li>
                <li><Zap size={18} />Receipt and price returned with inference</li>
              </ul>
              <a className="button button--primary" href={appRouteUrl("access")}>Create API access <ArrowRight size={17} /></a>
            </div>
            <div className="code-window" aria-label="Python integration example">
              <div className="code-window__bar"><span /><span /><span /><small>client.py</small></div>
              <pre><code>{`from openai import OpenAI

client = OpenAI(
    base_url="https://gateway.mycomesh.xyz/v1",
    api_key=os.environ["MYCOMESH_API_KEY"],
)

response = client.responses.create(
    model="provider/model",
    input="Explain the result.",
    max_output_tokens=512,
)

print(response.output_text)`}</code></pre>
            </div>
          </div>
        </section>

        <section className="section section--security" id="security">
          <div className="shell security-layout">
            <div>
              <span className="eyebrow">Security by explicit boundaries</span>
              <h2>The protocol proves what it can. It labels what it cannot yet.</h2>
            </div>
            <div className="security-grid">
              <div><ShieldCheck size={21} /><strong>Signed discovery</strong><span>Provider identity and expiry are verified before routing.</span></div>
              <div><Sparkles size={21} /><strong>Sealed transport</strong><span>Relay infrastructure does not need plaintext inference traffic.</span></div>
              <div><WalletCards size={21} /><strong>Bound settlement</strong><span>Reservations limit exposure to a specific request and budget.</span></div>
              <div><CircleDot size={21} /><strong>Open-network gates</strong><span>Anti-Sybil, quality disputes, staking, and slashing remain launch gates.</span></div>
            </div>
          </div>
        </section>
      </main>

      <footer className="site-footer">
        <div className="shell site-footer__top">
          <div><Brand inverted /><p>Verifiable markets for useful AI work.</p></div>
          <div className="site-footer__links">
            <a href={runtimeConfig.docsUrl}>Docs</a>
            <a href={runtimeConfig.githubUrl}>GitHub <Code2 size={14} /></a>
            <a href="#security">Security</a>
            <a href={appRouteUrl("contracts")}>Contracts</a>
            <a href={runtimeConfig.explorerUrl}>Sepolia <ExternalLink size={14} /></a>
          </div>
        </div>
        <div className="shell site-footer__bottom">
          <span>© {new Date().getFullYear()} MycoMesh</span>
          <span>Testnet only · tUSDC has no monetary value</span>
          <span>Rewards paused</span>
        </div>
      </footer>
    </div>
  );
}
