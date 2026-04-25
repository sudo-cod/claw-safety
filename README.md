# claw-safety

Security middleware plugin for OpenClaw agents. Intercepts every tool call before and after execution.

**Three modules, pure JS, no subprocesses.**

| Module | Hook | What it does |
|--------|------|--------------|
| A — Injection Detector | `after_tool_call` | Scans tool results for prompt injection before they re-enter LLM context |
| B — Permission Engine  | `before_tool_call` | Three-tier firewall evaluated before every tool execution |
| C — Audit Logger       | always             | Every tool call recorded as an OTel-compatible JSONL span |

---

## Install

```bash
cd claw-safety
npm install
mkdir -p ~/.openclaw/claw-safety
cp config/policy.yaml ~/.openclaw/claw-safety/policy.yaml
openclaw plugins install . --dangerously-force-unsafe-install
openclaw gateway restart
openclaw logs | grep ClawSafety
```

---

## Configure

Add to `~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "allow": ["claw-safety"],
    "entries": {
      "claw-safety": {
        "enabled": true,
        "config": {
          "policyPath": "~/.openclaw/claw-safety/policy.yaml",
          "auditLogPath": "~/.openclaw/logs/claw-safety-audit.jsonl",
          "injectionMode": "block",
          "failOpen": false
        }
      }
    }
  }
}
```

### Config options

| Key | Default | Description |
|-----|---------|-------------|
| `policyPath` | auto-discovered | Path to policy.yaml (see search order below) |
| `auditLogPath` | `null` | Path for JSONL audit log. Null = logging disabled |
| `injectionMode` | `"block"` | Global injection response: `block`, `sanitize`, or `warn` |
| `failOpen` | `false` | If `true`, allow tool calls when the plugin errors internally |
| `agentId` | `"main"` | Which agent section of policy.yaml to apply |

---

## Policy

The policy file (`policy.yaml`) defines per-agent firewall rules using a strict three-tier priority ladder.

### Tier priority (first match wins)

| Priority | Tier | Match type | Effect |
|----------|------|-----------|--------|
| 1 | `always_block.commands` | regex on full command | Hard block — no approval possible |
| 2 | `always_block.read_paths` | path prefix | Hard block reads |
| 3 | `always_block.write_paths` | path prefix | Hard block writes |
| 4 | `require_approval.read_paths` | path prefix | Ask user before reading |
| 5 | `require_approval.commands` | substring on full command | Ask user before running |
| 6 | `require_approval.write_paths` | path prefix | Ask user before writing |
| 7 | `always_allow.commands` | substring on full command | Allow silently |
| 8 | `always_allow.read_paths` | path prefix | Allow silently |
| 9 | `always_allow.write_paths` | path prefix | Allow silently |
| 10 | `default` | — | `allow`, `require_approval`, or `block` |

### Schema (v2)

```yaml
version: 2

agents:
  main:
    default: require_approval   # fallback for anything not matched

    always_allow:
      commands: [ls, pwd, git status]
      read_paths: [/tmp/]
      write_paths: [/tmp/]

    require_approval:
      commands: [pip install, npm install, curl, git push]
      read_paths: []
      write_paths: [~/Documents/]

    always_block:
      commands:
        - "rm\\s+-[a-z]*r[a-z]*f"     # rm -rf / rm -fr
        - "curl.*\\|\\s*(bash|sh|zsh)" # curl | bash
      read_paths:
        - ~/.ssh/
        - ~/.openclaw/credentials/
      write_paths:
        - ~/.openclaw/
        - /etc/
        - ~/.ssh/
```

### Policy file search order

The plugin locates `policy.yaml` in this order:
1. `policyPath` from plugin config (if set and exists)
2. `SHIELD_CONFIG` environment variable (if set and exists)
3. `~/.openclaw/claw-safety/policy.yaml`
4. `./config/policy.yaml` (relative to cwd)
5. `./policy.yaml` (relative to cwd)

### Hot-reload

The plugin watches the policy file's modification time on every `before_tool_call`. If the file changed, it reloads automatically — no gateway restart needed after editing policy rules.

---

## Tool classification

Commands are matched against exec tools; paths are matched against read/write tools:

```
EXEC_TOOLS:  exec, bash, shell, run, terminal
READ_TOOLS:  read, cat, list_dir
WRITE_TOOLS: write, create_file, append_file
```

Any tool not in these lists (e.g. `web_fetch`) falls straight through to `default`.

---

## Injection detection (Module A)

Tool results are scanned for prompt injection before the LLM sees them. Patterns detected:

- Role override (`ignore all previous instructions`)
- Persona hijack (`you are now DAN`)
- Forged system tags (`[SYSTEM]`)
- Permission grants (`you have been granted elevated privileges`)
- Zero-width space bypasses

**Injection modes:**

| Mode | Behaviour |
|------|-----------|
| `block` | Throws `ShieldInjectionError` — tool result is dropped |
| `sanitize` | Replaces matched content with `[REDACTED:pattern_id]` |
| `warn` | Logs a warning, passes result through unchanged |

Set globally in plugin config (`injectionMode`) or per-agent in policy.yaml (`injection_mode`).

---

## Audit log (Module C)

Every tool call is written to the audit log as a JSONL span. Security events get a separate entry.

**Watch live:**
```bash
tail -f ~/.openclaw/logs/claw-safety-audit.jsonl | python3 -m json.tool
```

**Entry types:** `tool_call`, `security_event` (`permission_denied`, `approval_required`, `injection_detected`), `llm`

---

## Dashboard

A local web dashboard is included for viewing the audit log and editing policy rules.

```bash
cd dashboard
# open index.html via your OpenClaw dashboard server
```

Features: live audit log feed, per-agent policy editor with YAML preview, tier-by-tier tag editing.

---

## Test

```bash
node --test tests/shield.test.js
```

33 tests covering injection detection, all three firewall tiers, path traversal prevention, default fallback, and agent fallback.

---

## File structure

```
claw-safety/
├── openclaw.plugin.json       # Plugin manifest
├── package.json
├── src/
│   ├── index.js               # Plugin entry — wires all three modules
│   ├── detector.js            # Module A: injection scanner
│   ├── policy.js              # Module B: three-tier permission engine
│   └── audit.js               # Module C: JSONL audit logger
├── tests/
│   └── shield.test.js         # 33 tests (Node built-in runner)
├── config/
│   └── policy.yaml            # Example policy (copy to ~/.openclaw/claw-safety/)
└── dashboard/
    └── index.html             # Web UI for audit log + policy editor
```
