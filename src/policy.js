/**
 * policy.js — Module B: Three-Tier Command Firewall
 *
 * Evaluates every tool call against a strict priority ladder:
 *   1. always_block.commands    — regex on full command → hard block
 *   2. always_block.read_paths  — prefix match on path (read tools) → hard block
 *   3. always_block.write_paths — prefix match on path (write tools) → hard block
 *   4. require_approval.commands    — substring on full command → ask user
 *   5. require_approval.write_paths — prefix match on path (write tools) → ask user
 *   6. always_allow.commands    — substring on full command → allow silently
 *   7. always_allow.read_paths  — prefix match on path (read tools) → allow silently
 *   8. always_allow.write_paths — prefix match on path (write tools) → allow silently
 *   9. default                  — agent's fallback: allow | require_approval | block
 *
 * Policy format v2 (policy.yaml):
 * ---
 * version: 2
 * agents:
 *   main:
 *     default: require_approval
 *     always_allow:
 *       commands: [ls, git status]
 *       read_paths: [/tmp/]
 *       write_paths: []
 *     require_approval:
 *       commands: [pip install, npm install]
 *       write_paths: [~/Documents/]
 *     always_block:
 *       commands:
 *         - "rm\\s+-[a-z]*r[a-z]*f"
 *       read_paths: [~/.openclaw/credentials/]
 *       write_paths: [~/.openclaw/, /etc/]
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

const EXEC_TOOLS  = ["exec", "bash", "shell", "run", "terminal"];
const READ_TOOLS  = ["read", "cat", "list_dir"];
const WRITE_TOOLS = ["write", "create_file", "append_file"];

// ── Path helpers ──────────────────────────────────────────────────────────────

function expandHome(p) {
  if (typeof p !== "string") return String(p);
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return join(homedir(), p.slice(2));
  return p;
}

function normPath(p) {
  return resolve(expandHome(p)) + "/";
}

// ── Policy loading ────────────────────────────────────────────────────────────

export function findPolicy(explicitPath) {
  if (explicitPath && existsSync(explicitPath)) return explicitPath;

  if (process.env.SHIELD_CONFIG && existsSync(process.env.SHIELD_CONFIG)) {
    return process.env.SHIELD_CONFIG;
  }

  const candidates = [
    join(homedir(), ".openclaw", "claw-safety", "policy.yaml"),
    join(process.cwd(), "config", "policy.yaml"),
    join(process.cwd(), "policy.yaml"),
  ];

  for (const p of candidates) {
    if (existsSync(p)) return p;
  }
  return null;
}

export function loadPolicy(policyPath) {
  const target = findPolicy(policyPath);
  if (!target) {
    console.warn("[ClawSafety] No policy.yaml found. Using permissive defaults. " +
      "Create ~/.openclaw/claw-safety/policy.yaml to enforce rules.");
    return { version: 2, agents: {} };
  }

  try {
    const raw    = readFileSync(target, "utf8");
    const parsed = yamlLoad(raw);
    console.log(`[ClawSafety] Policy v${parsed.version ?? "?"} loaded from ${target}`);
    return parsed;
  } catch (err) {
    throw new Error(`[ClawSafety] Failed to load policy from ${target}: ${err.message}`);
  }
}

// ── Agent rules ───────────────────────────────────────────────────────────────

function resolveAgentRules(policy, agentId) {
  return policy.agents?.[agentId] ?? policy.agents?.default ?? {};
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Evaluate a tool call against the policy.
 *
 * @param {object} policy   Loaded policy object
 * @param {string} agentId  e.g. "main"
 * @param {string} toolName e.g. "exec"
 * @param {object} params   Tool parameters
 * @returns {null | { type: "block", reason: string } | { type: "require_approval", message: string }}
 */
export function checkPolicy(policy, agentId, toolName, params) {
  const rules         = resolveAgentRules(policy, agentId);
  const defaultAction = rules.default ?? "require_approval";

  const command = params?.command ?? params?.cmd ?? params?.input ?? "";
  const path    = params?.path    ?? params?.file ?? params?.filePath ?? "";

  const isExec  = EXEC_TOOLS.includes(toolName);
  const isRead  = READ_TOOLS.includes(toolName);
  const isWrite = WRITE_TOOLS.includes(toolName);

  // ── Step 1: always_block.commands (regex, full command string) ────────────
  if (isExec && command) {
    for (const pattern of rules.always_block?.commands ?? []) {
      try {
        if (new RegExp(pattern, "i").test(command)) {
          return {
            type:   "block",
            reason: `[ClawSafety] blocked: matches blocked pattern "${pattern}"`,
          };
        }
      } catch {
        console.warn(`[ClawSafety] Invalid regex in always_block.commands: ${pattern}`);
      }
    }
  }

  // ── Step 2: always_block.read_paths ──────────────────────────────────────
  if (isRead && path) {
    const norm = normPath(path);
    for (const p of rules.always_block?.read_paths ?? []) {
      if (norm.startsWith(normPath(p))) {
        return {
          type:   "block",
          reason: `[ClawSafety] blocked: read from "${path}" is in always_block.read_paths`,
        };
      }
    }
  }

  // ── Step 3: always_block.write_paths ─────────────────────────────────────
  if (isWrite && path) {
    const norm = normPath(path);
    for (const p of rules.always_block?.write_paths ?? []) {
      if (norm.startsWith(normPath(p))) {
        return {
          type:   "block",
          reason: `[ClawSafety] blocked: write to "${path}" is in always_block.write_paths`,
        };
      }
    }
  }

  // ── Step 4: require_approval.read_paths ──────────────────────────────────
  if (isRead && path) {
    const norm = normPath(path);
    for (const p of rules.require_approval?.read_paths ?? []) {
      if (norm.startsWith(normPath(p))) {
        return {
          type:    "require_approval",
          message: `[ClawSafety] "${path}" requires your approval. Reply "yes" to allow or "no" to cancel.`,
        };
      }
    }
  }

  // ── Step 5: require_approval.commands (substring, case-insensitive) ──────
  if (isExec && command) {
    const lower = command.toLowerCase();
    for (const sub of rules.require_approval?.commands ?? []) {
      if (lower.includes(sub.toLowerCase())) {
        return {
          type:    "require_approval",
          message: `[ClawSafety] "${command}" requires your approval. Reply "yes" to allow or "no" to cancel.`,
        };
      }
    }
  }

  // ── Step 6: require_approval.write_paths ─────────────────────────────────
  if (isWrite && path) {
    const norm = normPath(path);
    for (const p of rules.require_approval?.write_paths ?? []) {
      if (norm.startsWith(normPath(p))) {
        return {
          type:    "require_approval",
          message: `[ClawSafety] "${path}" requires your approval. Reply "yes" to allow or "no" to cancel.`,
        };
      }
    }
  }

  // ── Step 7: always_allow.commands (substring, case-insensitive) ──────────
  if (isExec && command) {
    const lower = command.toLowerCase();
    for (const sub of rules.always_allow?.commands ?? []) {
      if (lower.includes(sub.toLowerCase())) {
        return null; // allow silently
      }
    }
  }

  // ── Step 8: always_allow.read_paths ──────────────────────────────────────
  if (isRead && path) {
    const norm = normPath(path);
    for (const p of rules.always_allow?.read_paths ?? []) {
      if (norm.startsWith(normPath(p))) {
        return null; // allow silently
      }
    }
  }

  // ── Step 9: always_allow.write_paths ─────────────────────────────────────
  if (isWrite && path) {
    const norm = normPath(path);
    for (const p of rules.always_allow?.write_paths ?? []) {
      if (norm.startsWith(normPath(p))) {
        return null; // allow silently
      }
    }
  }

  // ── Step 10: default ──────────────────────────────────────────────────────
  if (defaultAction === "allow") return null;

  if (defaultAction === "block") {
    return {
      type:   "block",
      reason: `[ClawSafety] "${command || path || toolName}" is not permitted by default policy.`,
    };
  }

  // require_approval (default)
  return {
    type:    "require_approval",
    message: `[ClawSafety] "${command || path || toolName}" requires your approval. Reply "yes" to allow or "no" to cancel.`,
  };
}
