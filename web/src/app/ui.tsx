import type { LucideIcon } from "lucide-react";
import type { PropsWithChildren, ReactNode } from "react";

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <header className="app-page-header">
      <div className="app-page-header__copy">
        {eyebrow ? <p className="app-eyebrow">{eyebrow}</p> : null}
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {actions ? <div className="app-page-header__actions">{actions}</div> : null}
    </header>
  );
}

export function Panel({
  title,
  description,
  actions,
  className = "",
  children,
}: PropsWithChildren<{
  title?: string;
  description?: string;
  actions?: ReactNode;
  className?: string;
}>) {
  return (
    <section className={`app-panel ${className}`.trim()}>
      {title || description || actions ? (
        <header className="app-panel__header">
          <div>
            {title ? <h2>{title}</h2> : null}
            {description ? <p>{description}</p> : null}
          </div>
          {actions ? <div className="app-panel__actions">{actions}</div> : null}
        </header>
      ) : null}
      <div className="app-panel__body">{children}</div>
    </section>
  );
}

export function Status({
  tone = "neutral",
  children,
}: PropsWithChildren<{ tone?: "positive" | "warning" | "negative" | "neutral" }>) {
  return <span className={`app-status app-status--${tone}`}>{children}</span>;
}

export function Notice({
  icon: Icon,
  title,
  tone = "neutral",
  children,
}: PropsWithChildren<{
  icon: LucideIcon;
  title: string;
  tone?: "neutral" | "warning" | "negative" | "positive";
}>) {
  return (
    <div className={`app-notice app-notice--${tone}`} role={tone === "negative" ? "alert" : "status"}>
      <Icon aria-hidden="true" size={18} />
      <div>
        <strong>{title}</strong>
        <div>{children}</div>
      </div>
    </div>
  );
}

export function Metric({ label, value, detail }: { label: string; value: ReactNode; detail?: ReactNode }) {
  return (
    <div className="app-metric">
      <span>{label}</span>
      <strong>{value}</strong>
      {detail ? <small>{detail}</small> : null}
    </div>
  );
}

export function EmptyState({
  icon: Icon,
  title,
  children,
}: PropsWithChildren<{ icon: LucideIcon; title: string }>) {
  return (
    <div className="app-empty-state">
      <Icon aria-hidden="true" size={24} />
      <h3>{title}</h3>
      <div>{children}</div>
    </div>
  );
}

export function truncateMiddle(value: string, head = 6, tail = 4): string {
  if (value.length <= head + tail + 3) return value;
  return `${value.slice(0, head)}...${value.slice(-tail)}`;
}

export function formatTime(value?: number): string {
  if (!value) return "Unavailable";
  const milliseconds = value > 10_000_000_000 ? value : value * 1000;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(milliseconds));
}

export function FieldError({ children }: PropsWithChildren) {
  if (!children) return null;
  return <p className="app-field-error" role="alert">{children}</p>;
}
