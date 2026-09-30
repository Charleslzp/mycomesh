// The Provider's local dashboard: served by this machine to this machine, like a Bitcoin node's GUI.
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { CONTAINER } from "./cli.mjs";

const PAGE = new URL("./web/dashboard.html", import.meta.url);
const EARNINGS_CACHE_MS = 20_000;

export function localRequestAllowed(req, port) {
  const allowed = new Set([`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`]);
  if (!allowed.has(String(req.headers.host || ""))) return false;
  const origin = req.headers.origin;
  return !origin || allowed.has(origin.replace(/^http:\/\//, ""));
}

async function capture(main, args) {
  let text = "";
  await main(args, { stdout: { write: (chunk) => { text += chunk; } } });
  return text.trim();
}

function docker(args) {
  const result = spawnSync("docker", args, { encoding: "utf8" });
  return result.status === 0 ? result.stdout.trim() : "";
}

export function serveDashboard(main, { home, port = 8120, host = "127.0.0.1" }) {
  const common = home ? ["--home", home] : [];
  let earnings = { at: 0, value: null };
  const routes = {
    "GET /": () => ({ type: "text/html; charset=utf-8", body: readFileSync(PAGE, "utf8") }),
    "GET /api/status": async () => {
      const config = JSON.parse((await capture(main, ["config", ...common])) || "{}");
      return {
        ...config,
        container: docker(["ps", "-a", "--filter", `name=^${CONTAINER}$`, "--format", "{{.Status}}"]) || "not created",
        logs: (spawnSync("docker", ["logs", "--tail", "40", CONTAINER], { encoding: "utf8" }).stdout || "").trim(),
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
      return JSON.parse(await capture(main, ["claim", "--owner-key-file", String(body.owner_key_file || ""), ...common]));
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
      return send(400, { error: error.message });
    }
  });
  return new Promise((resolve) => server.listen(port, host, () => resolve(server)));
}
