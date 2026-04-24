/**
 * dashboard/server.js — Claw Safety dashboard server
 *
 * Serves the UI and exposes two API endpoints:
 *   GET  /api/entries  — audit log as JSON array
 *   GET  /api/config   — policy.yaml as JSON
 *   POST /api/config   — write updated policy back to disk
 *
 * Run: node dashboard/server.js
 * Then open: http://localhost:8765
 */

import { createServer }          from "node:http";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join, dirname }         from "node:path";
import { fileURLToPath }         from "node:url";
import { homedir }               from "node:os";
import { load as yamlLoad, dump as yamlDump } from "js-yaml";

const __dir      = dirname(fileURLToPath(import.meta.url));
const PORT       = parseInt(process.env.PORT || "8765");
const HTML_FILE  = join(__dir, "index.html");

// ── Resolve paths without hardcoding ─────────────────────────────────────

function findPolicyPath() {
  const candidates = [
    process.env.SHIELD_CONFIG,
    join(homedir(), ".openclaw", "claw-safety", "policy.yaml"),
    join(__dir, "..", "config", "policy.yaml"),
    join(process.cwd(), "policy.yaml"),
  ].filter(Boolean);

  for (const p of candidates) {
    if (existsSync(p)) return p;
  }
  return join(homedir(), ".openclaw", "claw-safety", "policy.yaml");
}

function findAuditLogPath() {
  const candidates = [
    process.env.SHIELD_AUDIT_LOG,
    join(homedir(), ".openclaw", "logs", "claw-safety-audit.jsonl"),
    join(__dir, "..", "audit.log"),
    join(process.cwd(), "audit.log"),
  ].filter(Boolean);

  for (const p of candidates) {
    if (existsSync(p)) return p;
  }
  return join(homedir(), ".openclaw", "logs", "claw-safety-audit.jsonl");
}

// ── API handlers ──────────────────────────────────────────────────────────

function getEntries() {
  const logPath = findAuditLogPath();
  if (!existsSync(logPath)) return [];

  const raw = readFileSync(logPath, "utf8").trim();
  if (!raw) return [];

  return raw
    .split("\n")
    .filter(Boolean)
    .map(line => {
      try { return JSON.parse(line); }
      catch { return null; }
    })
    .filter(Boolean)
    .reverse(); // newest first
}

function getConfig() {
  const policyPath = findPolicyPath();
  if (!existsSync(policyPath)) {
    return { version: 1, default: "allow", agents: {} };
  }
  return yamlLoad(readFileSync(policyPath, "utf8"));
}

function saveConfig(body) {
  const policyPath = findPolicyPath();
  mkdirSync(dirname(policyPath), { recursive: true });

  // Backup current file
  if (existsSync(policyPath)) {
    writeFileSync(policyPath + ".bak", readFileSync(policyPath));
  }

  const yaml = yamlDump(body, { lineWidth: 120, sortKeys: false });
  writeFileSync(policyPath, yaml, "utf8");
  return policyPath;
}

// ── HTTP server ───────────────────────────────────────────────────────────

function send(res, status, contentType, body) {
  const buf = typeof body === "string" ? Buffer.from(body) : body;
  res.writeHead(status, {
    "Content-Type":  contentType,
    "Content-Length": buf.length,
    "Access-Control-Allow-Origin":  "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  });
  res.end(buf);
}

function sendJSON(res, status, data) {
  send(res, status, "application/json", JSON.stringify(data));
}

const server = createServer((req, res) => {
  const url = req.url.split("?")[0];

  // CORS preflight
  if (req.method === "OPTIONS") {
    send(res, 204, "text/plain", "");
    return;
  }

  // ── GET /api/entries ─────────────────────────────────────────────────
  if (req.method === "GET" && url === "/api/entries") {
    try {
      const entries = getEntries();
      sendJSON(res, 200, entries);
    } catch (err) {
      sendJSON(res, 500, { error: err.message });
    }
    return;
  }

  // ── GET /api/config ──────────────────────────────────────────────────
  if (req.method === "GET" && url === "/api/config") {
    try {
      sendJSON(res, 200, getConfig());
    } catch (err) {
      sendJSON(res, 500, { error: err.message });
    }
    return;
  }

  // ── POST /api/config ─────────────────────────────────────────────────
  if (req.method === "POST" && url === "/api/config") {
    let body = "";
    req.on("data", chunk => body += chunk);
    req.on("end", () => {
      try {
        const data = JSON.parse(body);
        const savedPath = saveConfig(data);
        sendJSON(res, 200, { ok: true, path: savedPath });
      } catch (err) {
        sendJSON(res, 500, { error: err.message });
      }
    });
    return;
  }

  // ── GET / or /index.html ─────────────────────────────────────────────
  if (req.method === "GET" && (url === "/" || url === "/index.html")) {
    try {
      const html = readFileSync(HTML_FILE);
      send(res, 200, "text/html; charset=utf-8", html);
    } catch (err) {
      send(res, 404, "text/plain", "index.html not found — place it in dashboard/");
    }
    return;
  }

  send(res, 404, "text/plain", "Not found");
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`[ClawSafety Dashboard] http://localhost:${PORT}`);
  console.log(`[ClawSafety Dashboard] Policy: ${findPolicyPath()}`);
  console.log(`[ClawSafety Dashboard] Audit log: ${findAuditLogPath()}`);
});
