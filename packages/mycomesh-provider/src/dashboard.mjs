// The Provider's local dashboard: served by this machine to this machine, like a Bitcoin node's GUI.
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { CONTAINER, IMAGE, explain } from "./cli.mjs";

const LOGIN = "mycomesh-provider-login";

const PAGE = new URL("./web/dashboard.html", import.meta.url);
const EARNINGS_CACHE_MS = 20_000;
// After one successful signature the wallet stays unlocked here for a while, so claiming later needs no password.
export const UNLOCK_MS = 15 * 60_000;

export function localRequestAllowed(req, port) {
  const allowed = new Set([`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`]);
  if (!allowed.has(String(req.headers.host || ""))) return false;
  const origin = req.headers.origin;
  return !origin || allowed.has(origin.replace(/^http:\/\//, ""));
}

async function capture(main, args, password) {
  let text = "";
  const previous = process.env.MYCOMESH_KEY_PASSWORD;
  if (password !== undefined) process.env.MYCOMESH_KEY_PASSWORD = String(password);
  try {
    await main(args, { stdout: { write: (chunk) => { text += chunk; } } });
  } finally {
    if (previous === undefined) delete process.env.MYCOMESH_KEY_PASSWORD; else process.env.MYCOMESH_KEY_PASSWORD = previous;
  }
  return text.trim();
}

function docker(args) {
  const result = spawnSync("docker", args, { encoding: "utf8" });
  return result.status === 0 ? result.stdout.trim() : "";
}

export function serveDashboard(main, { home, port = 8120, host = "127.0.0.1" }) {
  const common = home ? ["--home", home] : [];
  let earnings = { at: 0, value: null };
  let unlocked = null; // { password, until }
  const password = (body) => {
    if (body.password) return String(body.password);
    if (unlocked && Date.now() < unlocked.until) return unlocked.password;
    throw new Error("wallet is locked: enter the wallet password");
  };
  /** Run a command that signs with the owner wallet; a password that worked is remembered for UNLOCK_MS. */
  const signing = async (args, body) => {
    const secret = password(body);
    const output = await capture(main, args, secret);
    unlocked = { password: secret, until: Date.now() + UNLOCK_MS };
    return output;
  };
  const routes = {
    "GET /": () => ({ type: "text/html; charset=utf-8", body: readFileSync(PAGE, "utf8") }),
    "GET /api/status": async () => {
      const config = JSON.parse((await capture(main, ["config", ...common])) || "{}");
      const logs = spawnSync("docker", ["logs", "--tail", "40", CONTAINER], { encoding: "utf8" });
      return {
        ...config,
        container: docker(["ps", "-a", "--filter", `name=^${CONTAINER}$`, "--format", "{{.Status}}"]) || "not created",
        logs: `${logs.stdout || ""}${logs.stderr || ""}`.trim(),
        unlocked_until: unlocked && Date.now() < unlocked.until ? unlocked.until : null,
      };
    },
    "GET /api/earnings": async () => {
      if (!earnings.value || Date.now() - earnings.at > EARNINGS_CACHE_MS) {
        earnings = { at: Date.now(), value: JSON.parse(await capture(main, ["earnings", ...common])) };
      }
      return earnings.value;
    },
    "POST /api/claim": async (body) => {
      earnings = { at: 0, value: null };
      if (body.owner_key_file) {
        return JSON.parse(await capture(main, ["claim", "--json", "--owner-key-file", String(body.owner_key_file), ...common]));
      }
      return JSON.parse(await signing(["claim", "--json", ...common], body));
    },
    "POST /api/lock": async () => { unlocked = null; return { locked: true }; },
    // ---- onboarding: every step the command line has, in the browser ----
    "POST /api/init": async () => ({ message: await capture(main, ["init", ...common]) }),
    "POST /api/wallet": async (body) => ({ message: await capture(main, ["wallet", ...common], body.password) }),
    "POST /api/register": async (body) => ({
      message: await signing(["register", ...(body.operator_id ? ["--operator-id", String(body.operator_id)] : []), ...common], body),
    }),
    "POST /api/login": async () => {
      const config = JSON.parse((await capture(main, ["config", ...common])) || "{}");
      spawnSync("docker", ["rm", "-f", LOGIN], { stdio: "ignore" });
      const user = typeof process.getuid === "function" ? ["--user", `${process.getuid()}:${process.getgid()}`, "-e", "HOME=/tmp"] : [];
      docker(["run", "-d", "--name", LOGIN, ...user, "-e", "CODEX_HOME=/codex", "-v", `${config.codex_home}:/codex`,
        "--entrypoint", "codex", config.image || IMAGE, "login", "--device-auth"]);
      return { started: true };
    },
    "GET /api/login": async () => {
      const config = JSON.parse((await capture(main, ["config", ...common])) || "{}");
      if (config.codex_login) {
        spawnSync("docker", ["rm", "-f", LOGIN], { stdio: "ignore" });
        return { done: true };
      }
      const logs = spawnSync("docker", ["logs", LOGIN], { encoding: "utf8" });
      const text = `${logs.stdout || ""}${logs.stderr || ""}`.replace(/\u001b\[[0-9;]*m/g, "");
      const state = docker(["inspect", "-f", "{{.State.Status}}", LOGIN]);
      // The login container ended without a login: the code expired, or it could not reach OpenAI.
      const failed = state === "exited" || state === "dead" || (!state && !text);
      return { done: false, failed, error: failed ? text.trim().split("\n").slice(-3).join(" ").slice(0, 300) || "the login did not start" : null,
        url: text.match(/https:\/\/\S+/)?.[0] || null, code: text.match(/\b[A-Z0-9]{4,}-[A-Z0-9]{4,}\b/)?.[0] || null };
    },
    "POST /api/start": async () => ({ message: await capture(main, ["start", ...common]) }),
    "POST /api/stop": async () => ({ message: await capture(main, ["stop", ...common]) }),
    "POST /api/restart": async () => ({ message: docker(["restart", CONTAINER]) ? "restarted" : "not running" }),
  };
  const server = createServer(async (req, res) => {
    const send = (status, body, type = "application/json") => {
      res.writeHead(status, { "content-type": type, "cache-control": "no-store" });
      res.end(type === "application/json" ? JSON.stringify(body) : body);
    };
    if (!localRequestAllowed(req, server.address().port)) return send(403, { error: "only this machine may use the dashboard" });
    const route = routes[`${req.method} ${new URL(req.url, "http://localhost").pathname}`];
    if (!route) return send(404, { error: "not found" });
    if (req.method === "POST" && !String(req.headers["content-type"] || "").startsWith("application/json")) {
      return send(415, { error: "JSON body required" });
    }
    try {
      let body = {};
      if (req.method === "POST") {
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
      }
      const result = await route(body);
      return result?.type ? send(200, result.body, result.type) : send(200, result);
    } catch (error) {
      return send(400, { error: explain(error.message) });
    }
  });
  return new Promise((resolve) => server.listen(port, host, () => resolve(server)));
}
