/**
 * policy.js — Module B: Permission Policy Engine
 *
 * Loads policy.yaml and enforces it on every before_tool_call event.
 * Runs synchronously in the hook — no subprocess, no network call.
 *
 * Policy format (policy.yaml):
 * ---
 * version: 1
 * default: allow          # allow | deny — for unlisted tools
 *
 * agents:
 *   main:
 *     allowed_tools:      # empty = all tools allowed
 *       - read
 *       - exec
 *     injection_mode: block
 *     path_constraints:
 *       read:
 *         allowed_paths:
 *           - /tmp/
 *           - /Users/you/workspace/
 *         blocked_paths:
 *           - /etc/
 *       write:
 *         allowed_paths:
 *           - /tmp/
 *     blocked_commands:   # regex patterns for exec-type tools
 *       - "rm\\s+-[a-z]*r[a-z]*f"
 *       - "curl.*\\|\\s*(bash|sh)"
 */

import { readFileSync, existsSync } from "node:fs";
import { resolve, join }            from "node:path";
import { homedir }                  from "node:os";
import { load as yamlLoad }         from "js-yaml";

export class ShieldPermissionError extends Error {
  constructor(message) {
    super(message);
    this.name = "ShieldPermissionError";
    this.code = "SHIELD_PERMISSION_DENIED";
  }
}

// Built-in dangerous command patterns — always enforced regardless of policy
const BUILTIN_BLOCKED_COMMANDS = [
  { re: /rm\s+-[a-z]*r[a-z]*f|rm\s+-[a-z]*f[a-z]*r/i, reason: "recursive delete blocked" },
  { re: /find\s+.*-delete/i,                            reason: "find-delete blocked" },
  { re: /shutil\.rmtree/i,                              reason: "programmatic directory deletion blocked" },
  { re: /curl.*\|\s*(bash|sh|zsh)/i,                   reason: "curl-pipe-to-shell blocked" },
  { re: /wget.*\|\s*(bash|sh|zsh)/i,                   reason: "wget-pipe-to-shell blocked" },
  { re: />\s*\/etc\//,                                  reason: "write to /etc blocked" },
  { re: /chmod\s+777/i,                                 reason: "world-writable chmod blocked" },
  { re: /\bdd\s+if=/i,                                  reason: "disk write blocked" },
  { re: /:\(\)\{.*\|.*&\s*\};/,                         reason: "fork bomb blocked" },
  { re: /mkfs/i,                                        reason: "disk format blocked" },
  // Protect the shield's own files
  { re: /claw-safety/i,                                 reason: "modification of shield files blocked" },
  { re: /openclaw\.json/i,                              reason: "modification of openclaw config blocked" },
];

/**
 * Find policy.yaml without hardcoded paths.
 * Resolution order:
 *   1. Explicit path argument
 *   2. ~/.openclaw/claw-safety/policy.yaml
 *   3. ./policy.yaml (cwd)
 *   4. ./config/policy.yaml
 */
export function findPolicy(explicitPath) {
  if (explicitPath && existsSync(explicitPath)) return explicitPath;

  const candidates = [
    join(homedir(), ".openclaw", "claw-safety", "policy.yaml"),
    join(process.cwd(), "policy.yaml"),
    join(process.cwd(), "config", "policy.yaml"),
  ];

  for (const p of candidates) {
    if (existsSync(p)) return p;
  }
  return null;
}

/**
 * Load and parse a policy file.
 */
export function loadPolicy(policyPath) {
  const target = findPolicy(policyPath);
  if (!target) {
    console.warn("[ClawSafety] No policy.yaml found. Using permissive defaults. " +
      "Create ~/.openclaw/claw-safety/policy.yaml to enforce rules.");
    return { version: 1, default: "allow", agents: {} };
  }

  try {
    const raw = readFileSync(target, "utf8");
    const parsed = yamlLoad(raw);
    console.log(`[ClawSafety] Policy loaded from ${target}`);
    return parsed;
  } catch (err) {
    throw new Error(`[ClawSafety] Failed to load policy from ${target}: ${err.message}`);
  }
}

/**
 * Get the policy rules for a specific agent.
 * Falls back to "default" agent, then to an empty ruleset.
 */
function agentRules(policy, agentId) {
  return policy.agents?.[agentId]
      ?? policy.agents?.default
      ?? {};
}

/**
 * Check a tool call against the policy.
 *
 * @param {object} policy     Loaded policy object
 * @param {string} agentId    e.g. "main"
 * @param {string} toolName   e.g. "exec"
 * @param {object} params     Tool parameters
 * @returns {object|null}     OpenClaw hook result or null (allow)
 */
export function checkPolicy(policy, agentId, toolName, params) {
  const rules       = agentRules(policy, agentId);
  const defaultAct  = policy.default ?? "allow";

  // ── 1. Tool whitelist ───────────────────────────────────────────────────
  const allowedTools = rules.allowed_tools ?? [];
  const hasWhitelist  = allowedTools.length > 0;

  if (hasWhitelist && !allowedTools.includes(toolName)) {
    return {
      block: true,
      blockReason: `[ClawSafety] Tool "${toolName}" is not in the allowed_tools list for agent "${agentId}".`,
    };
  }

  if (!hasWhitelist && defaultAct === "deny") {
    return {
      block: true,
      blockReason: `[ClawSafety] Tool "${toolName}" is not listed in policy and default is "deny".`,
    };
  }

  // ── 2. Built-in dangerous command patterns ──────────────────────────────
  const command = params?.command ?? params?.cmd ?? params?.input ?? "";
  if (command && ["exec", "bash", "shell", "run", "terminal"].includes(toolName)) {
    for (const { re, reason } of BUILTIN_BLOCKED_COMMANDS) {
      if (re.test(command)) {
        return {
          block: true,
          blockReason: `[ClawSafety] ${reason}: ${command.slice(0, 80)}`,
        };
      }
    }
  }

  // ── 3. Policy-level blocked command patterns ────────────────────────────
  const blockedCmds = rules.blocked_commands ?? [];
  if (command && blockedCmds.length) {
    for (const raw of blockedCmds) {
      const re = new RegExp(raw, "i");
      if (re.test(command)) {
        return {
          block: true,
          blockReason: `[ClawSafety] Command matches blocked pattern "${raw}": ${command.slice(0, 80)}`,
        };
      }
    }
  }

  // ── 4. Path constraints ─────────────────────────────────────────────────
  const pathArg = params?.path ?? params?.file ?? params?.filePath ?? "";
  if (pathArg) {
    const constraints  = rules.path_constraints?.[toolName];
    const allowedPaths = constraints?.allowed_paths ?? [];
    const blockedPaths = constraints?.blocked_paths ?? [];

    const normPath = resolve(pathArg) + "/";  // trailing slash prevents prefix collisions

    // Explicit block list (e.g. /etc/, /root/)
    for (const blocked of blockedPaths) {
      if (normPath.startsWith(resolve(blocked) + "/")) {
        return {
          block: true,
          blockReason: `[ClawSafety] Path "${pathArg}" is in the blocked_paths list for tool "${toolName}".`,
        };
      }
    }

    // Allowed list — if specified, path must be inside one of them
    if (allowedPaths.length > 0) {
      const allowed = allowedPaths.some(p => normPath.startsWith(resolve(p) + "/"));
      if (!allowed) {
        return {
          block: true,
          blockReason: `[ClawSafety] Path "${pathArg}" is outside allowed directories for tool "${toolName}". ` +
            `Allowed: ${allowedPaths.join(", ")}`,
        };
      }
    }
  }

  // ── 5. requireApproval ──────────────────────────────────────────────────
  const approval = rules.require_approval?.[toolName];
  if (approval) {
    const safePatterns = approval.safe_commands ?? [];
    const isSafe = command && safePatterns.some(p => new RegExp(p, "i").test(command.trim()));
    if (!isSafe) {
      return {
        requireApproval: {
          title:           approval.title       ?? `Approval required: ${toolName}`,
          description:     approval.description ?? `Tool "${toolName}" requires human approval.`,
          severity:        approval.severity    ?? "warning",
          timeoutMs:       approval.timeout_ms  ?? 120_000,
          timeoutBehavior: "deny",
        },
      };
    }
  }

  return null; // allow
}
