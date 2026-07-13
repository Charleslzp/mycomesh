import { useQuery } from "@tanstack/react-query";
import { Braces, CircleAlert, Clock3, KeyRound, LoaderCircle, Send, Sparkles } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useApiKey } from "../../state/ApiKeyContext";
import { FieldError, Metric, Notice, PageHeader, Panel, Status } from "../../app/ui";
import { protocolApi, type InferenceResult } from "../../protocol/api";
import { errorMessage } from "./helpers";

export function PlaygroundPage() {
  const { apiKey } = useApiKey();
  const models = useQuery({ queryKey: ["models"], queryFn: protocolApi.models, retry: 1 });
  const [model, setModel] = useState("");
  const [input, setInput] = useState("Explain how request-bound settlement protects an AI inference consumer in three concise points.");
  const [maxOutputTokens, setMaxOutputTokens] = useState(256);
  const [result, setResult] = useState<InferenceResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  useEffect(() => {
    if (!model && models.data?.[0]) setModel(models.data[0].id);
  }, [model, models.data]);

  async function runInference() {
    if (!apiKey || !model || !input.trim()) return;
    setRunning(true);
    setError(null);
    setResult(null);
    try {
      setResult(await protocolApi.infer(apiKey, input.trim(), model, maxOutputTokens));
    } catch (inferenceError) {
      setError(errorMessage(inferenceError));
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="app-page app-page--playground">
      <PageHeader
        eyebrow="Inference"
        title="Playground"
        description="Send one request through the consumer proxy and inspect its returned output, usage, price, and receipt envelope."
        actions={<Status tone={apiKey ? "positive" : "warning"}>{apiKey ? "Credential ready" : "API key required"}</Status>}
      />

      {!apiKey ? (
        <Notice icon={KeyRound} title="Establish consumer access first" tone="warning">
          <Link to="/app/access">Create a wallet-bound API key</Link> before making a billed inference request.
        </Notice>
      ) : null}

      <div className="app-playground-layout">
        <Panel title="Request" description="This form calls POST /v1/responses. Responses are currently returned after completion, not token-streamed.">
          <form className="app-request-form" onSubmit={(event) => { event.preventDefault(); runInference(); }}>
            <label htmlFor="model">Model</label>
            <select id="model" disabled={models.isLoading || models.isError || running} onChange={(event) => setModel(event.target.value)} value={model}>
              {models.data?.map((record) => <option key={record.id} value={record.id}>{record.id}</option>)}
              {!models.data?.length ? <option value="">{models.isLoading ? "Loading models" : "No model advertised"}</option> : null}
            </select>

            <label htmlFor="prompt">Input</label>
            <textarea id="prompt" maxLength={12_000} onChange={(event) => setInput(event.target.value)} rows={9} value={input} />
            <div className="app-form-meta"><span>{input.length.toLocaleString()} / 12,000 characters</span></div>

            <label htmlFor="max-output-tokens">Maximum output tokens</label>
            <div className="app-number-control">
              <input
                id="max-output-tokens"
                max={4096}
                min={16}
                onChange={(event) => setMaxOutputTokens(Math.max(16, Math.min(4096, Number(event.target.value) || 16)))}
                step={16}
                type="number"
                value={maxOutputTokens}
              />
            </div>

            <button className="button button--primary" disabled={!apiKey || !model || !input.trim() || running} type="submit">
              {running ? <LoaderCircle className="is-spinning" aria-hidden="true" size={17} /> : <Send aria-hidden="true" size={17} />}
              {running ? "Routing request" : "Run inference"}
            </button>
            <FieldError>{error}</FieldError>
          </form>
        </Panel>

        <Panel title="Response" description={result?.request_id ? `Request ${result.request_id}` : "The provider output will appear here."}>
          {running ? (
            <div className="app-response-waiting"><LoaderCircle className="is-spinning" aria-hidden="true" size={24} /><strong>Provider inference in progress</strong><p>The gateway buffers the current response until completion.</p></div>
          ) : result ? (
            <div className="app-response-result">
              {result.error ? <Notice icon={CircleAlert} title="Provider returned an error" tone="negative">{result.error}</Notice> : null}
              <div className="app-response-result__output">
                <Sparkles aria-hidden="true" size={18} />
                <p>{result.output_text || "No output text was returned."}</p>
              </div>
              <section className="app-metric-grid app-metric-grid--compact" aria-label="Response metrics">
                <Metric label="Model" value={result.model || model} />
                <Metric label="Provider" value={result.peer || "Unavailable"} />
                <Metric label="Latency" value={result.elapsed_ms !== undefined ? `${result.elapsed_ms} ms` : "Unavailable"} />
                <Metric label="Tokens" value={result.usage?.total_tokens ?? "Unavailable"} />
              </section>
              <details className="app-json-details">
                <summary><Braces aria-hidden="true" size={16} /> Price and receipt envelope</summary>
                <pre>{JSON.stringify({ price: result.mycomesh_price ?? null, receipt: result.mycomesh_receipt ?? null, usage: result.usage ?? null }, null, 2)}</pre>
              </details>
            </div>
          ) : (
            <div className="app-empty-response"><Clock3 aria-hidden="true" size={24} /><p>No inference has been run in this session.</p></div>
          )}
        </Panel>
      </div>
    </div>
  );
}
