// Re-grading Relay probe verdicts (mirrors mycomesh/relay/probes.py and mycomesh/probe_evidence.py).
import { sha256Hex, outputText } from "./protocol.mjs";
import { verifySignedReceipt } from "./eip712.mjs";

export const PROBE_EVIDENCE_SCHEMA = "mycomesh.v11.probe-evidence.v1";
const WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
const numbers = (text) => (text.match(/[0-9]{1,3}(?:[,\s_][0-9]{3})+(?![0-9])|[0-9]+/g) || []).map((match) => match.replace(/[,\s_]/g, ""));

// ---------------- capability probes (mirrors mycomesh/capability.py) ----------------

export const CAPABILITY_KINDS = ["trace", "crt", "long_multiply", "path", "kth", "letters", "calendar"];
/** Default per-tier pass-rate floors; a manifest tier's capability_floor overrides them. */
export const CAPABILITY_FLOORS = { 1: 0.85 }; // tier 2 (Claude) has none until calibrated

export function ordinal(n) {
  const suffix = n % 100 >= 10 && n % 100 <= 20 ? "th" : ({ 1: "st", 2: "nd", 3: "rd" })[n % 10] || "th";
  return `${n}${suffix}`;
}

const LINE_BREAKS = /\r\n|[\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029]/;
const weekdays = (text) => WEEKDAYS.filter((day) => text.toLowerCase().includes(day.toLowerCase()));

function weekdayAfter(start, offset) {
  const day = new Date(`${start}T00:00:00Z`);
  day.setUTCDate(day.getUTCDate() + Number(offset));
  return WEEKDAYS[(day.getUTCDay() + 6) % 7];
}

function capabilityTask(kind, p) {
  if (kind === "trace") {
    let [x, y] = [Number(p.x), Number(p.y)];
    const [a, m, n] = [Number(p.a), Number(p.m), Number(p.n)];
    const question = `Start with x = ${x} and y = ${y}. Repeat the following ${n} times: first set x to (x * ${a} + y) mod ${m}, `
      + `then set y to (y + 2 * x) mod ${m}. What is x + y at the end?`;
    for (let i = 0; i < n; i += 1) { x = (x * a + y) % m; y = (y + 2 * x) % m; }
    return { question, reference: String(x + y) };
  }
  if (kind === "crt") {
    const moduli = p.moduli.map(Number); const residues = p.residues.map(Number);
    const parts = moduli.map((m, i) => `remainder ${residues[i]} when divided by ${m}`);
    const question = `What is the smallest positive integer that leaves ${parts.slice(0, -1).join(", ")}, and ${parts[parts.length - 1]}?`;
    // Constructive CRT (the moduli are distinct primes): the least positive solution.
    const big = moduli.map(BigInt);
    const product = big.reduce((a, b) => a * b, 1n);
    const power = (base, exponent, m) => { let r = 1n; base %= m; for (; exponent > 0n; exponent >>= 1n, base = base * base % m) if (exponent & 1n) r = r * base % m; return r; };
    const x = big.reduce((sum, m, i) => sum + BigInt(residues[i]) * (product / m) * power(product / m, m - 2n, m), 0n) % product;
    return { question, reference: String(x || product) };
  }
  if (kind === "long_multiply") return { question: `What is ${p.a} times ${p.b}?`, reference: String(BigInt(p.a) * BigInt(p.b)) };
  if (kind === "path") {
    const edges = p.edges.map(([u, v, w]) => [String(u), String(v), Number(w)]);
    const question = `In a road network the two-way roads and their lengths are: ${edges.map(([u, v, w]) => `${u}-${v} ${w}`).join(", ")}. `
      + `What is the length of the shortest route from ${p.start} to ${p.end}?`;
    const distance = new Map([[String(p.start), 0]]); const done = new Set();
    for (;;) {
      const open = [...distance].filter(([node]) => !done.has(node)).sort((a, b) => a[1] - b[1] || (a[0] < b[0] ? -1 : 1));
      if (!open.length) break;
      const [node, d] = open[0];
      done.add(node);
      for (const [u, v, w] of edges) {
        for (const [here, there] of [[u, v], [v, u]]) {
          if (here === node && d + w < (distance.get(there) ?? Infinity)) distance.set(there, d + w);
        }
      }
    }
    return { question, reference: String(distance.get(String(p.end))) };
  }
  if (kind === "kth") {
    const values = p.values.map(Number); const k = Number(p.k);
    return { question: `What is the ${ordinal(k)} smallest number in this list: ${values.join(", ")}?`,
      reference: String([...values].sort((a, b) => a - b)[k - 1]) };
  }
  if (kind === "letters") {
    return { question: `How many times does the letter "${p.letter}" appear in the following text: "${p.text}"?`,
      reference: String(String(p.text).split(String(p.letter)).length - 1) };
  }
  if (kind === "calendar") {
    return { question: `What day of the week will it be ${p.offset} days after ${p.start}?`, reference: weekdayAfter(p.start, p.offset) };
  }
  throw new Error(`unknown capability kind ${kind}`);
}

function gradeCapability(task, answer) {
  // The answer finally stated decides: the last \boxed{...}, else the last line that states a value.
  // A handful of values at most: listing candidates is not answering.
  const text = String(answer);
  const pick = task.kind === "calendar" ? weekdays : numbers;
  const boxed = [...text.matchAll(/\\boxed\{([^{}]*)\}/g)];
  let stated = [];
  if (boxed.length) stated = pick(boxed[boxed.length - 1][1]);
  else for (const line of text.split(LINE_BREAKS).reverse()) { const found = pick(line); if (found.length) { stated = found; break; } }
  return stated.length <= (task.kind === "calendar" ? 1 : 3) && stated.includes(task.reference) ? "pass" : "wrong";
}

/** Upper bound of a pass rate at 99% one-sided confidence (Wilson). */
export function wilsonUpper(passes, total, z = 2.326) {
  if (!total) return 1;
  const p = passes / total;
  const centre = p + (z * z) / (2 * total);
  const spread = z * Math.sqrt((p * (1 - p)) / total + (z * z) / (4 * total * total));
  return Math.min(1, (centre + spread) / (1 + (z * z) / total));
}

/** 99% confident the pass rate is below the floor, after enough probes. */
export const capabilityFlagged = (passes, total, floor, minimum = 20) => total >= minimum && wilsonUpper(passes, total) < floor;

export function buildTask(kind, params) {
  if (CAPABILITY_KINDS.includes(kind)) return { kind, capability: true, ...capabilityTask(kind, params) };
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
  if (task.capability) return gradeCapability(task, answer);
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
  return { provider: signed.authorization.provider_signer, verdict, capability: Boolean(task.capability) };
}
