// Re-grading Relay probe verdicts (mirrors mycomesh/relay/probes.py and mycomesh/probe_evidence.py).
import { sha256Hex, outputText } from "./protocol.mjs";
import { verifySignedReceipt } from "./eip712.mjs";

export const PROBE_EVIDENCE_SCHEMA = "mycomesh.v11.probe-evidence.v1";
const WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
const numbers = (text) => (text.match(/\d{1,3}(?:[,\s_]\d{3})+(?!\d)|\d+/g) || []).map((match) => match.replace(/[,\s_]/g, ""));

export function buildTask(kind, params) {
  if (kind === "multiply") return { kind, question: `What is ${params.a} multiplied by ${params.b}?`, reference: String(BigInt(params.a) * BigInt(params.b)), numeric: true };
  if (kind === "sum") {
    return { kind, question: `What is the sum of ${params.values.join(", ")}?`, reference: String(params.values.reduce((a, b) => a + Number(b), 0)), numeric: true };
  }
  if (kind === "count") {
    return { kind, question: `How many times does the letter "${params.target}" appear in "${params.letters}"?`,
      reference: String(params.letters.split(params.target).length - 1), numeric: true };
  }
  if (kind === "reverse") return { kind, question: `Write the string "${params.word}" backwards, letter by letter.`, reference: [...params.word].reverse().join(""), numeric: false };
  if (kind === "sort") return { kind, question: `Sort these words alphabetically: ${params.words.join(", ")}.`, reference: [...params.words].sort().join(", "), numeric: false };
  if (kind === "weekday") {
    const day = new Date(`${params.start}T00:00:00Z`);
    day.setUTCDate(day.getUTCDate() + Number(params.offset));
    return { kind, question: `What day of the week is ${params.offset} days after ${params.start}?`, reference: WEEKDAYS[(day.getUTCDay() + 6) % 7], numeric: false };
  }
  throw new Error(`unknown probe kind ${kind}`);
}

export function grade(task, answer) {
  const text = String(answer).trim();
  if (!text) return "unrelated";
  if (task.numeric) {
    const found = numbers(text);
    return found.length ? (found.includes(task.reference) ? "pass" : "wrong") : "unrelated";
  }
  const lower = text.toLowerCase();
  if (task.kind === "reverse") return lower.includes(task.reference) ? "pass" : "wrong";
  if (task.kind === "sort") {
    const positions = task.reference.split(", ").map((word) => lower.indexOf(word));
    if (positions.every((position) => position < 0)) return "unrelated";
    return positions.every((p, i) => p >= 0 && (i === 0 || p >= positions[i - 1])) ? "pass" : "wrong";
  }
  const named = WEEKDAYS.filter((day) => lower.includes(day.toLowerCase()));
  if (!named.length) return "unrelated";
  return named.length === 1 && named[0] === task.reference ? "pass" : "wrong";
}

function* strings(value) {
  if (typeof value === "string") yield value;
  else if (Array.isArray(value)) for (const item of value) yield* strings(item);
  else if (value && typeof value === "object") for (const item of Object.values(value)) yield* strings(item);
}

/** Returns { provider, verdict } after re-grading the Provider's own signed answer; throws otherwise. */
export function verifyProbeEvidence(evidence, deployment) {
  if (evidence?.schema !== PROBE_EVIDENCE_SCHEMA) throw new Error("not probe evidence");
  const signed = evidence.signed_receipt;
  verifySignedReceipt(signed, deployment);
  const request = Buffer.from(evidence.request, "base64");
  const response = Buffer.from(evidence.response, "base64");
  if (sha256Hex(request) !== signed.authorization.request_hash || sha256Hex(response) !== signed.receipt.response_hash) {
    throw new Error("plaintexts do not match the Provider-signed receipt");
  }
  const task = buildTask(evidence.task.kind, evidence.task.params);
  if (![...strings(JSON.parse(request.toString("utf8")))].some((text) => text.includes(task.question))) {
    throw new Error("the request does not ask the stated question");
  }
  const verdict = grade(task, outputText(JSON.parse(response.toString("utf8")).output));
  if (verdict !== evidence.verdict || verdict === "unrelated") throw new Error(`re-grading gives ${verdict}`);
  return { provider: signed.authorization.provider_signer, verdict };
}
