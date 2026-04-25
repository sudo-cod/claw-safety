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

import { statSync }                                                      from "node:fs";
import { scanForInjection, applyInjectionPolicy, ShieldInjectionError } from "./detector.js";
import { loadPolicy, findPolicy, checkPolicy, ShieldPermissionError }    from "./policy.js";
import { createAuditLogger }                                             from "./audit.js";

export default {
  id: "claw-safety",

  register(api) {
    const cfg                 = api.config ?? {};
    const globalInjectionMode = cfg.injectionMode ?? "block";
    const failOpen            = cfg.failOpen       ?? false;
    const agentId             = cfg.agentId        ?? "main";

    // ── Bootstrap ──────────────────────────────────────────────────────────
    let policy;
    try {
      policy = loadPolicy(cfg.policyPath ?? null);
    } catch (err) {
      console.error(`[ClawSafety] Policy load error: ${err.message}`);
      if (!failOpen) throw err;
      policy = { version: 2, agents: {} };
    }

    const audit = createAuditLogger(cfg.auditLogPath ?? null);

    // ── Hot-reload ─────────────────────────────────────────────────────────
    // Re-reads policy.yaml on mtime change so dashboard edits take effect
    // immediately without a gateway restart.
    const policyFilePath = findPolicy(cfg.policyPath ?? null);
    let policyMtime = policyFilePath ? statSync(policyFilePath).mtimeMs : 0;

    function maybeReloadPolicy() {
      if (!policyFilePath) return;
      try {
        const mtime = statSync(policyFilePath).mtimeMs;
        if (mtime !== policyMtime) {
          policy      = loadPolicy(cfg.policyPath ?? null);
          policyMtime = mtime;
          console.log("[ClawSafety] Policy hot-reloaded");
        }
      } catch { /* file temporarily unreadable during write — skip */ }
    }

    console.log(
      `[ClawSafety] Loaded — ` +
      `injectionMode=${globalInjectionMode} (global, overridable per agent) ` +
      `failOpen=${failOpen} ` +
      `auditLog=${audit.logPath}`
    );

    // ── Module B: Three-Tier Command Firewall (before_tool_call) ─────────
    api.on("before_tool_call", async (event, ctx) => {
      try {
        maybeReloadPolicy();

        const result = checkPolicy(
          policy,
          agentId,
          event.toolName,
          event.params ?? {}
        );

        if (!result) return; // null = allow silently

        if (result.type === "block") {
          audit.logSecurityEvent({
            type:      "permission_denied",
            toolName:  event.toolName,
            agentId,
            sessionId: ctx?.sessionId,
            details:   { reason: result.reason, params: event.params },
          });
          return { block: true, blockReason: result.reason };
        }

        if (result.type === "require_approval") {
          audit.logSecurityEvent({
            type:      "approval_required",
            toolName:  event.toolName,
            agentId,
            sessionId: ctx?.sessionId,
            details:   { message: result.message, params: event.params },
          });
          // Block with a message the agent relays to the user via chat.
          // Works on Telegram, Discord, and web equally.
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
    api.on("after_tool_call", async (event, ctx) => {
      try {
        const scan = scanForInjection(event.result);

        const injectionMode = policy.agents?.[agentId]?.injection_mode ?? globalInjectionMode;

        const injectionAction = scan.clean
          ? "none"
          : injectionMode === "block"    ? "blocked"
          : injectionMode === "sanitize" ? "sanitized"
          : "warned";

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
        console.error(`[ClawSafety] llm_output logging error: ${err.message}`);
      }
    });
  },
};
