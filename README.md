# claw-safety

Non-intrusive security middleware for OpenClaw agents.

**Three modules, pure JS, no subprocesses.**

| Module | Hook | What it does |
|--------|------|-------------|
| A — Injection Detector | `after_tool_call` | Scans tool return values for prompt injection before they re-enter LLM context |
| B — Permission Engine  | `before_tool_call` | Blocks tools or paths outside the agent's declared whitelist — pre-execution |
| C — Audit Logger       | always | Every tool call recorded as an OTel-compatible JSON span with full params + injection result |

## Install

```bash
cd claw-safety
npm install
openclaw plugins install . --dangerously-force-unsafe-install
openclaw gateway restart
```

## Configure

Copy the example policy:
```bash
mkdir -p ~/.openclaw/claw-safety
cp config/policy.yaml ~/.openclaw/claw-safety/policy.yaml
```

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

## Test

```bash
node --test tests/shield.test.js
```

## Watch the audit log live

```bash
tail -f ~/.openclaw/logs/claw-safety-audit.jsonl | python3 -m json.tool
```

## File structure

```
claw-safety/
├── openclaw.plugin.json   # Plugin manifest
├── package.json
├── src/
│   ├── index.js           # Plugin entry — wires all modules
│   ├── detector.js        # Module A: injection detection
│   ├── policy.js          # Module B: permission policy engine
│   └── audit.js           # Module C: audit trail logger
├── tests/
│   └── shield.test.js     # Node built-in test runner
└── config/
    └── policy.yaml        # Example policy
```
