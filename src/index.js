/**
 * index.js — Claw Safety OpenClaw Plugin
 *
 * Wires Module A (injection detector), Module B (permission policy),
 * and Module C (audit logger) into OpenClaw's plugin hook API.
 *
 * No subprocesses. No hardcoded paths. Pure JS.
 *
 * Install:
 *   cd claw-safety
 *   npm install
 *   openclaw plugins install . --dangerously-force-unsafe-install
 *   openclaw gateway restart
 *
 * Config (in ~/.openclaw/openclaw.json):
 *   plugins:
 *     entries:
 *       claw-safety:
 *         enabled: true
 *         config:
 *           policyPath: ~/.openclaw/claw-safety/policy.yaml
 *           auditLogPath: ~/.openclaw/logs/claw-safety-audit.jsonl
 *           injectionMode: block
 *           failOpen: false
 */

import { scanForInjection, applyInjectionPolicy, ShieldInjectionError } from "./detector.js";
import { loadPolicy, checkPolicy, ShieldPermissionError }                from "./policy.js";
import { createAuditLogger }                                             from "./audit.js";

export default {
  id: "claw-safety",

  register(api) {
    const cfg           = api.config ?? {};
    const globalInjectionMode = cfg.injectionMode ?? "block";
    const failOpen      = cfg.failOpen      ?? false;
    const agentId       = cfg.agentId       ?? "main";

    // ── Bootstrap ──────────────────────────────────────────────────────────
    let policy;
    try {
      policy = loadPolicy(cfg.policyPath ?? null);
    } catch (err) {
      console.error(`[ClawSafety] Policy load error: ${err.message}`);
      if (!failOpen) throw err;
      policy = { version: 1, default: "allow", agents: {} };
    }

    const audit = createAuditLogger(cfg.auditLogPath ?? null);

    console.log(
      `[ClawSafety] Loaded — ` +
      `injectionMode=${globalInjectionMode} (global, overridable per agent) ` +
      `failOpen=${failOpen} ` +
      `auditLog=${audit.logPath}`
    );

    // ── Approval cache ────────────────────────────────────────────────────
    // When require_approval fires, we store the (sessionId, subject) pair.
    // If the same subject is retried from the same session after a short
    // minimum delay (user had time to say yes), we allow it through once.
    const APPROVAL_MIN_DELAY_MS = 4_000;  // must wait at least 4s before retry
    const APPROVAL_TTL_MS       = 120_000; // approval window expires after 2 min
    const pendingApprovals = new Map(); // sessionId -> Map<subject, {earliest, expiry}>

    function storePendingApproval(sessionId, subject) {
      if (!pendingApprovals.has(sessionId)) pendingApprovals.set(sessionId, new Map());
      const now = Date.now();
      pendingApprovals.get(sessionId).set(subject, {
        earliest: now + APPROVAL_MIN_DELAY_MS,
        expiry:   now + APPROVAL_TTL_MS,
      });
    }

    function consumePendingApproval(sessionId, subject) {
      const session = pendingApprovals.get(sessionId);
      if (!session) return false;
      const entry = session.get(subject);
      if (!entry) return false;
      const now = Date.now();
      if (now < entry.earliest) return false; // retried too fast — block again
      if (now > entry.expiry)   { session.delete(subject); return false; } // expired
      session.delete(subject);
      return true;
    }

    // ── Module B: Three-Tier Command Firewall (before_tool_call) ─────────
    // Runs BEFORE the tool executes. Returns block to prevent execution.
    // require_approval is surfaced as a block with a message the agent
    // relays to the user through whatever channel they are on.
    api.on("before_tool_call", async (event, ctx) => {
      try {
        const sid     = ctx?.sessionId ?? "unknown";
        const subject = event.params?.command ?? event.params?.path ?? event.toolName;

        // If this is a retry after the user said yes, allow it through once
        if (consumePendingApproval(sid, subject)) return;

        const result = checkPolicy(
          policy,
          agentId,
          event.toolName,
          event.params ?? {}
        );

        if (!result) return; // null = allow

        if (result.type === "block") {
          audit.logSecurityEvent({
            type:      "permission_denied",
            toolName:  event.toolName,
            agentId,
            sessionId: sid,
            details:   { reason: result.reason, params: event.params },
          });
          return { block: true, blockReason: result.reason };
        }

        if (result.type === "require_approval") {
          storePendingApproval(sid, subject);
          audit.logSecurityEvent({
            type:      "approval_required",
            toolName:  event.toolName,
            agentId,
            sessionId: sid,
            details:   { message: result.message },
          });
          return { block: true, blockReason: result.message };
        }

      } catch (err) {
        if (err.code?.startsWith("SHIELD_")) throw err;

        console.error(`[ClawSafety] before_tool_call error: ${err.message}`);
        if (!failOpen) {
          return { block: true, blockReason: `[ClawSafety] Internal error: ${err.message}` };
        }
      }
    });

    // ── Module A + C: Injection Detector & Audit Logger (after_tool_call) ─
    // Runs AFTER the tool executes.
    // Scans result for injection, logs the span.
    api.on("after_tool_call", async (event, ctx) => {
      try {
        const scan = scanForInjection(event.result);

        const injectionMode = policy.agents?.[agentId]?.injection_mode ?? globalInjectionMode;

        // Determine injection action label for the audit span
        const injectionAction = scan.clean
          ? "none"
          : injectionMode === "block"    ? "blocked"
          : injectionMode === "sanitize" ? "sanitized"
          : "warned";

        // Module C — always log every tool call
        audit.logToolCall({
          toolName:   event.toolName,
          params:     event.params,
          result:     event.result,
          durationMs: event.durationMs,
          error:      event.error,
          sessionId:  ctx?.sessionId,
          runId:      ctx?.runId,
          toolCallId: ctx?.toolCallId,
          injection:  { ...scan, action: injectionAction },
        });

        // Module A — apply injection policy (may throw ShieldInjectionError)
        if (!scan.clean) {
          audit.logSecurityEvent({
            type:      "injection_detected",
            toolName:  event.toolName,
            agentId,
            sessionId: ctx?.sessionId,
            details:   { hits: scan.hits, mode: injectionMode },
          });

          applyInjectionPolicy(scan, event.toolName, injectionMode, null);
        }

      } catch (err) {
        if (err.code === "SHIELD_INJECTION_BLOCKED") throw err;

        console.error(`[ClawSafety] after_tool_call error: ${err.message}`);
        if (!failOpen) throw err;
      }
    });

    // ── Module C supplement: LLM token usage (llm_output) ────────────────
    api.on("llm_output", async (event, ctx) => {
      try {
        audit.logLLM({
          model:     event.model,
          provider:  event.provider,
          usage:     event.usage,
          sessionId: ctx?.sessionId ?? event.sessionId,
        });
      } catch (err) {
        // Audit logging must never crash the agent
        console.error(`[ClawSafety] llm_output logging error: ${err.message}`);
      }
    });
  },
};
