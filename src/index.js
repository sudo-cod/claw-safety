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

    // ── Module B: Permission Policy Engine (before_tool_call) ─────────────
    // Runs BEFORE the tool executes — genuine pre-call enforcement.
    // If this throws or returns block, the tool never runs.
    api.on("before_tool_call", async (event, ctx) => {
      try {
        const decision = checkPolicy(
          policy,
          agentId,
          event.toolName,
          event.params ?? {}
        );

        if (!decision) return; // allow — no conditions

        // Log the security event
        if (decision.block) {
          audit.logSecurityEvent({
            type:      "permission_denied",
            toolName:  event.toolName,
            agentId,
            sessionId: ctx?.sessionId,
            details:   { reason: decision.blockReason, params: event.params },
          });
          return { block: true, blockReason: decision.blockReason };
        }

        if (decision.requireApproval) {
          audit.logSecurityEvent({
            type:      "approval_required",
            toolName:  event.toolName,
            agentId,
            sessionId: ctx?.sessionId,
            details:   { title: decision.requireApproval.title },
          });
          return { requireApproval: decision.requireApproval };
        }

      } catch (err) {
        // Re-throw our own errors
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
