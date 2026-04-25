/**
 * policy.js — Module B: Three-Tier Command Firewall
 *
 * Evaluates every tool call against a three-tier priority ladder:
 *   1. always_block  — hard block, no approval possible (regex match)
 *   2. require_approval — block and ask user (substring match)
 *   3. always_allow  — pass through silently (substring match)
 *   4. default       — agent-level fallback: allow | require_approval | block
 *
 * Policy format v2 (policy.yaml):
 * ---
 * version: 2
 * agents:
 *   main:
 *     default: require_approval
 *     always_allow:
 *       commands: [ls, pwd, cat]
 *       read_paths: [/tmp/]
 *       write_paths: []
 *     require_approval:
 *       commands: [pip install, npm install]
 *       write_paths: [~/Documents/]
 *     always_block:
 *       commands:
 *         - "rm\\s+-[a-z]*r[a-z]*f"
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

// ── Tier matching ─────────────────────────────────────────────────────────────

/**
 * Match a command string through the three tiers.
 * Returns null (allow), { type: "block" }, { type: "require_approval" }, or "default".
 */
// Split a command on shell separators into individual segments.
// Strips cd-only segments (e.g. "cd /some/path") since they carry no intent —
// the real command is what follows.
function segments(command) {
  return command
    .split(/\|{1,2}|&&|;/)
    .map(s => s.trim())
    .filter(s => s && !/^cd(\s+\S+)?$/.test(s));
}

function matchCommand(rules, command) {
  // Tier 1 — always_block: regex against the full command string, case-insensitive.
  // Checked first and wins unconditionally.
  for (const pattern of rules.always_block?.commands ?? []) {
    try {
      if (new RegExp(pattern, "i").test(command)) {
        return { type: "block", reason: `matches blocked pattern "${pattern}"` };
      }
    } catch {
      console.warn(`[ClawSafety] Invalid regex in always_block.commands: ${pattern}`);
    }
  }

  // For tiers 2 & 3, check each meaningful segment independently and take
  // the most restrictive result across all segments.
  // This lets "cd /path && git status" match always_allow via the git status segment,
  // while "cd /path && pip install X" correctly requires approval via the pip segment.
  const segs = segments(command);
  let mostRestrictive = "default"; // default < allow < require_approval

  for (const seg of segs) {
    const segLower = seg.toLowerCase();

    // Tier 2 — require_approval: substring match
    for (const sub of rules.require_approval?.commands ?? []) {
      if (segLower.includes(sub.toLowerCase())) {
        return { type: "require_approval" }; // require_approval is the worst non-block outcome
      }
    }

    // Tier 3 — always_allow: substring match
    for (const sub of rules.always_allow?.commands ?? []) {
      if (segLower.includes(sub.toLowerCase())) {
        mostRestrictive = "allow";
        break;
      }
    }
  }

  return mostRestrictive === "allow" ? null : "default";
}

/**
 * Match a path through the three tiers for a given operation ("read" | "write").
 * Returns null (allow), { type: "block" }, { type: "require_approval" }, or "default".
 */
function matchPath(rules, path, operation) {
  const norm = normPath(path);

  if (operation === "write") {
    // Tier 1 — always_block.write_paths
    for (const p of rules.always_block?.write_paths ?? []) {
      if (norm.startsWith(normPath(p))) {
        return { type: "block", reason: `write to "${path}" is in always_block.write_paths` };
      }
    }

    // Tier 2 — require_approval.write_paths
    for (const p of rules.require_approval?.write_paths ?? []) {
      if (norm.startsWith(normPath(p))) {
        return { type: "require_approval" };
      }
    }

    // Tier 3 — always_allow.write_paths
    for (const p of rules.always_allow?.write_paths ?? []) {
      if (norm.startsWith(normPath(p))) {
        return null; // allow
      }
    }
  } else {
    // read — only always_allow.read_paths applies
    for (const p of rules.always_allow?.read_paths ?? []) {
      if (norm.startsWith(normPath(p))) {
        return null; // allow
      }
    }
  }

  return "default";
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

  let match = "default";

  if (EXEC_TOOLS.includes(toolName) && command) {
    match = matchCommand(rules, command);
  } else if (WRITE_TOOLS.includes(toolName) && path) {
    match = matchPath(rules, path, "write");
  } else if (READ_TOOLS.includes(toolName) && path) {
    match = matchPath(rules, path, "read");
  }
  // Other tools (web_fetch, browser_navigate, search) skip to default

  // Explicit tier match
  if (match === null) return null; // always_allow

  if (match !== "default") {
    if (match.type === "block") {
      return {
        type:   "block",
        reason: `[ClawSafety] blocked: ${match.reason}. This action is not permitted.`,
      };
    }
    if (match.type === "require_approval") {
      return {
        type:    "require_approval",
        message: `[ClawSafety] "${command || path || toolName}" requires your approval before running. Reply "yes" to allow it or "no" to cancel.`,
      };
    }
  }

  // Default fallback
  if (defaultAction === "allow") return null;

  if (defaultAction === "block") {
    return {
      type:   "block",
      reason: `[ClawSafety] "${toolName}" is not permitted by default policy.`,
    };
  }

  // require_approval (default)
  return {
    type:    "require_approval",
    message: `[ClawSafety] "${command || path || toolName}" requires your approval before running. Reply "yes" to allow it or "no" to cancel.`,
  };
}
