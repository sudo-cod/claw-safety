/**
 * detector.js — Module A: Injection Detector
 *
 * Scans tool return values for prompt injection patterns before
 * they re-enter the LLM context.
 *
 * Three response modes:
 *   warn     — log the finding, return result unchanged
 *   sanitize — redact matched segments, return cleaned result
 *   block    — throw ShieldInjectionError, result is discarded
 */

export class ShieldInjectionError extends Error {
  constructor(message) {
    super(message);
    this.name = "ShieldInjectionError";
    this.code = "SHIELD_INJECTION_BLOCKED";
  }
}

// ── Pattern library ────────────────────────────────────────────────────────
// Each entry: { id, re (RegExp), severity }
export const INJECTION_PATTERNS = [
  // Role / instruction override
  { id: "role_override",        re: /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/gi,                    severity: "high" },
  { id: "you_are_now",          re: /\byou\s+are\s+now\b/gi,                                                        severity: "high" },
  { id: "act_as",               re: /\bact\s+as\s+(a\s+|an\s+)(?!assistant)/gi,                                     severity: "high" },
  { id: "disregard",            re: /\bdisregard\s+(your\s+|all\s+)?(previous|prior|system)\s+/gi,                  severity: "high" },
  { id: "forget_instructions",  re: /\bforget\s+(all\s+|your\s+|previous\s+)?instructions\b/gi,                     severity: "high" },
  { id: "new_prompt",           re: /\bnew\s+(system(-level)?\s+)?prompt\b/gi,                                      severity: "high" },

  // Jailbreaks
  { id: "jailbreak_dan",        re: /\bDAN\b|\bdo\s+anything\s+now\b/gi,                                            severity: "high" },
  { id: "unrestricted_mode",    re: /unrestricted\s+mode|developer\s+mode|admin\s+mode/gi,                          severity: "high" },

  // Permission / authority forgery
  { id: "permission_grant",     re: /\b(you\s+have\s+been\s+granted|elevated\s+privileges?|root\s+access)\b/gi,     severity: "high" },
  { id: "system_tag",           re: /\[(SYSTEM|ADMIN|OVERRIDE|INST)\]|<(system|assistant|user)\s*>/gi,              severity: "high" },

  // Command injection
  { id: "execute_command",      re: /\bexecute\s+(the\s+following|this\s+command)\b/gi,                             severity: "high" },
  { id: "shell_destructive",    re: /\brm\s+-rf\b|\bdrop\s+table\b|\bdelete\s+from\b/gi,                            severity: "high" },

  // Exfiltration
  { id: "exfil_credentials",    re: /print\s+(your\s+)?(api[_\s]?key|secret|token|password|credentials)/gi,         severity: "high" },
  { id: "exfil_prompt",         re: /repeat\s+(the\s+)?(system\s+prompt|instructions?|context)\s+(verbatim|exactly)/gi, severity: "medium" },

  // Token / format injection
  { id: "token_injection",      re: /<\|.*?\|>/gs,                                                                  severity: "medium" },
  { id: "script_injection",     re: /<\s*script[^>]*>|javascript\s*:/gi,                                            severity: "medium" },
];

/**
 * Normalise text to collapse unicode lookalikes and zero-width chars
 * that attackers use to evade regex matching.
 */
function normalise(text) {
  // Remove zero-width / invisible characters
  text = text.replace(/[\u200b\u200c\u200d\ufeff\u00ad\u2060]/g, "");
  // Try to decode base64 segments and append decoded version for scanning
  const b64 = text.match(/[A-Za-z0-9+/]{30,}={0,2}/g) ?? [];
  for (const candidate of b64) {
    try {
      const decoded = Buffer.from(candidate, "base64").toString("utf8");
      if (/[a-z ]{5,}/i.test(decoded)) text += " " + decoded;
    } catch { /* not valid base64 */ }
  }
  return text;
}

/**
 * Scan content for injection patterns.
 *
 * @param {string|any} content   Tool result to scan
 * @returns {{ clean, hits, sanitized }}
 */
export function scanForInjection(content) {
  const text = typeof content === "string" ? content : JSON.stringify(content ?? "");
  const normalised = normalise(text);
  const hits = [];
  let sanitized = text;

  for (const { id, re, severity } of INJECTION_PATTERNS) {
    re.lastIndex = 0;
    if (re.test(normalised)) {
      hits.push({ id, severity });
      re.lastIndex = 0;
      sanitized = sanitized.replace(re, `[REDACTED:${id}]`);
    }
  }

  return { clean: hits.length === 0, hits, sanitized };
}

/**
 * Apply injection scan result based on configured mode.
 *
 * @param {object} scanResult   Result from scanForInjection()
 * @param {string} toolName     For error messages
 * @param {string} mode         warn | sanitize | block
 * @param {Function} logFn      Audit logger
 * @returns {string|undefined}  Sanitized content if mode=sanitize, else undefined
 */
export function applyInjectionPolicy(scanResult, toolName, mode, logFn) {
  if (scanResult.clean) return undefined;

  const hitIds = scanResult.hits.map(h => h.id);

  if (logFn) logFn({ type: "injection_detected", tool: toolName, hits: hitIds, mode });

  if (mode === "warn") {
    console.warn(`[ClawSafety] Injection detected in "${toolName}" result — mode=warn, passing through. Patterns: ${hitIds}`);
    return undefined;
  }

  if (mode === "sanitize") {
    console.warn(`[ClawSafety] Injection detected in "${toolName}" result — sanitizing. Patterns: ${hitIds}`);
    return scanResult.sanitized;
  }

  // block
  throw new ShieldInjectionError(
    `[ClawSafety] Injection blocked in tool "${toolName}". Patterns matched: ${hitIds.join(", ")}`
  );
}
