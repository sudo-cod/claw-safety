/**
 * audit.js — Module C: Audit Trail Logger
 *
 * Emits OpenTelemetry-compatible JSON spans to a JSONL file.
 * One span per tool call lifecycle event or security finding.
 *
 * Span shape (OTel-compatible):
 * {
 *   traceId, spanId, name,
 *   startTime, endTime, duration_ms,
 *   attributes: { ... },
 *   status: { code: "OK" | "ERROR", message? }
 * }
 */

import { appendFileSync, mkdirSync } from "node:fs";
import { dirname, join }             from "node:path";
import { homedir }                   from "node:os";
import { randomBytes }               from "node:crypto";

const DEFAULT_LOG_PATH = join(homedir(), ".openclaw", "logs", "claw-safety-audit.jsonl");

// Session → traceId map so all spans in one session share a traceId
const sessionTraces = new Map();

function traceIdFor(sessionId) {
  if (!sessionTraces.has(sessionId)) {
    sessionTraces.set(sessionId, randomBytes(16).toString("hex"));
  }
  return sessionTraces.get(sessionId);
}

function newSpanId()  { return randomBytes(8).toString("hex"); }
function isoNow()     { return new Date().toISOString(); }
function truncate(v, max = 500) {
  if (v == null) return "";
  const s = typeof v === "string" ? v : JSON.stringify(v);
  return s.length > max ? s.slice(0, max) + "…" : s;
}

/**
 * Create an audit logger bound to a log file path.
 *
 * @param {string} [logPath]   Override the default log path
 * @returns {{ logToolCall, logSecurityEvent, logLLM }}
 */
export function createAuditLogger(logPath) {
  const target = logPath || DEFAULT_LOG_PATH;

  try { mkdirSync(dirname(target), { recursive: true }); } catch { /* already exists */ }

  function write(span) {
    try {
      appendFileSync(target, JSON.stringify(span) + "\n", "utf8");
    } catch (err) {
      console.error(`[ClawSafety] Audit write failed: ${err.message}`);
    }
  }

  /**
   * Log a complete tool call lifecycle event.
   * Call from after_tool_call with the full event + scan metadata.
   */
  function logToolCall({ toolName, params, result, durationMs, error, sessionId, runId, toolCallId, injection }) {
    const sid = sessionId || "unknown";
    write({
      traceId:    traceIdFor(sid),
      spanId:     newSpanId(),
      name:       `tool.${toolName}`,
      startTime:  isoNow(),
      duration_ms: durationMs ?? 0,
      attributes: {
        "shield.module":           "audit",
        "shield.version":          "0.1.0",
        "tool.name":               toolName,
        "tool.call_id":            toolCallId ?? "",
        "tool.params":             truncate(JSON.stringify(params ?? {})),
        "tool.result_length":      String(typeof result === "string" ? result.length : 0),
        "tool.success":            String(!error),
        "tool.error":              error ?? "",
        "session.id":              sid,
        "session.run_id":          runId ?? "",
        "injection.clean":         String(injection?.clean ?? true),
        "injection.hits":          JSON.stringify(injection?.hits?.map(h => h.id) ?? []),
        "injection.action":        injection?.action ?? "none",
      },
      status: error
        ? { code: "ERROR", message: error }
        : { code: "OK" },
    });
  }

  /**
   * Log a security event (permission denied, injection blocked, etc.)
   */
  function logSecurityEvent({ type, toolName, agentId, sessionId, details }) {
    const sid = sessionId || "unknown";
    write({
      traceId:   traceIdFor(sid),
      spanId:    newSpanId(),
      name:      `shield.${type}`,
      startTime: isoNow(),
      attributes: {
        "shield.module":     "security",
        "shield.event_type": type,
        "tool.name":         toolName ?? "",
        "agent.id":          agentId  ?? "",
        "session.id":        sid,
        "shield.details":    JSON.stringify(details ?? {}),
      },
      status: { code: "ERROR", message: type },
    });
  }

  /**
   * Log an LLM output event (model + token usage).
   */
  function logLLM({ model, provider, usage, sessionId }) {
    const sid = sessionId || "unknown";
    write({
      traceId:   traceIdFor(sid),
      spanId:    newSpanId(),
      name:      "llm.api_call",
      startTime: isoNow(),
      attributes: {
        "shield.module":       "audit",
        "llm.model":           model    ?? "",
        "llm.provider":        provider ?? "",
        "llm.tokens.input":    String(usage?.input      ?? 0),
        "llm.tokens.output":   String(usage?.output     ?? 0),
        "llm.tokens.cache_read":  String(usage?.cacheRead  ?? 0),
        "llm.tokens.cache_write": String(usage?.cacheWrite ?? 0),
        "session.id":          sid,
      },
      status: { code: "OK" },
    });
  }

  return { logToolCall, logSecurityEvent, logLLM, logPath: target };
}
