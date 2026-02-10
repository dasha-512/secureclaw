# SecureClaw — OpenClaw Security Hardening Plugin

## Product Description for Claude Code Development

**One prompt. One install. Complete OpenClaw hardening.**

---

## Mission

SecureClaw is an OpenClaw plugin that transforms the platform's "security dumpster fire" (Laurie Voss, npm CTO) into a defensible deployment. It automates every hardening step documented by Cisco, Palo Alto Networks, Koi Security, ZeroPath, JFrog, Vectra AI, and the OpenClaw security docs — as a single `openclaw plugins install secureclaw` command.

---

## Context: Why This Plugin Must Exist

OpenClaw (formerly Clawdbot/Moltbot) has 170,000+ GitHub stars, 42,000+ publicly exposed instances, and 8 distinct vulnerability classes:

1. **Remote Code Execution** — CVE-2026-25253 (CVSS 8.8), SSH command injection, Docker PATH injection, browser relay credential theft
2. **Prompt Injection** — unsolved industry-wide; email, web, Moltbook, memory poisoning vectors
3. **Supply Chain Attacks** — 341/2,857 ClawHub skills (11.9%) found malicious (ClawHavoc campaign)
4. **Exposed Control Interfaces** — 21,639+ instances on Shodan/Censys with no auth, reverse proxy bypass
5. **Plaintext Credential Storage** — `~/.openclaw/.env`, credentials/, auth-profiles.json all unencrypted, targeted by Redline/Lumma/Vidar infostealers
6. **Memory Poisoning** — persistent memory files (SOUL.md, MEMORY.md) enable time-shifted prompt injection "logic bombs"
7. **Uncontrolled API Cost Exposure** — $20 overnight burns, $750/month heartbeat projections
8. **Scams & Impersonation** — fake extensions, crypto scams, domain squatting from rename confusion

The project has no bug bounty, no security budget, no dedicated security team. Users need an automated solution.

---

## Architecture Overview

```
~/.openclaw/
├── extensions/
│   └── secureclaw/                ← Plugin root
│       ├── package.json
│       ├── dist/
│       │   └── index.js          ← Plugin entrypoint (compiled)
│       ├── src/
│       │   ├── index.ts          ← Plugin registration & lifecycle hooks
│       │   ├── auditor.ts        ← Deep security audit engine
│       │   ├── hardener.ts       ← Automated fix/hardening engine
│       │   ├── monitors/
│       │   │   ├── credential-monitor.ts    ← Watches credential files
│       │   │   ├── memory-integrity.ts      ← SOUL.md/MEMORY.md tamper detection
│       │   │   ├── network-monitor.ts       ← Port/connection monitoring
│       │   │   ├── skill-scanner.ts         ← ClawHub skill vetting
│       │   │   └── cost-monitor.ts          ← API spend tracking & circuit breaker
│       │   ├── hardening/
│       │   │   ├── gateway-hardening.ts     ← Gateway WebSocket + auth hardening
│       │   │   ├── docker-hardening.ts      ← Docker sandbox configuration
│       │   │   ├── credential-hardening.ts  ← File permissions + encryption at rest
│       │   │   ├── network-hardening.ts     ← Bind restrictions + firewall rules
│       │   │   └── config-hardening.ts      ← Approval mode, DM policy, sandbox
│       │   ├── reporters/
│       │   │   ├── console-reporter.ts      ← CLI output formatter
│       │   │   └── json-reporter.ts         ← Machine-readable findings
│       │   └── utils/
│       │       ├── crypto.ts                ← Credential encryption helpers
│       │       ├── hash.ts                  ← File integrity hashing
│       │       └── ioc-db.ts                ← Known bad IPs/domains/hashes
│       ├── ioc/
│       │   └── indicators.json              ← IOC database (C2 IPs, malicious skill hashes)
│       ├── templates/
│       │   └── secure-baseline.json         ← Hardened config template
│       ├── SKILL.md                         ← Skill definition for agent awareness
│       └── tools.md                         ← Tool declarations for agent
```

---

## Technical Specification

### 1. Plugin Registration (src/index.ts)

The plugin hooks into the OpenClaw plugin SDK lifecycle. It must:

```typescript
// Register as an OpenClaw extension plugin
// Entry: dist/index.js (compiled from src/index.ts)
// SDK: import from 'openclaw/plugin-sdk' (resolved via jiti alias at runtime)

export default {
  name: 'secureclaw',
  version: '1.0.0',
  description: 'Automated security hardening for OpenClaw',

  // Lifecycle hooks
  onGatewayStart: async (gateway) => {
    // Run audit on every gateway start
    // Apply hardening fixes if --auto-fix is enabled
    // Start background monitors
  },

  onGatewayStop: async () => {
    // Clean shutdown of monitors
  },

  // Register CLI subcommands
  commands: {
    'secureclaw audit': auditCommand,
    'secureclaw harden': hardenCommand,
    'secureclaw status': statusCommand,
    'secureclaw scan-skill': scanSkillCommand,
    'secureclaw cost-report': costReportCommand,
  },

  // Register agent tools
  tools: [
    'security_audit',
    'security_status',
    'skill_scan',
    'cost_report',
  ],
};
```

**Plugin package.json:**
```json
{
  "name": "@openclaw/secureclaw",
  "version": "1.0.0",
  "description": "Automated security hardening plugin for OpenClaw",
  "main": "dist/index.js",
  "scripts": {
    "build": "tsdown src/index.ts --outDir dist",
    "dev": "tsdown src/index.ts --outDir dist --watch"
  },
  "dependencies": {
    "chokidar": "^4.0.0",
    "node-forge": "^1.3.1"
  },
  "peerDependencies": {
    "openclaw": "*"
  },
  "devDependencies": {
    "openclaw": "*",
    "tsdown": "^0.4.0",
    "typescript": "^5.7.0",
    "vitest": "^3.0.0"
  },
  "openclaw": {
    "type": "extension"
  }
}
```

### 2. Security Audit Engine (src/auditor.ts)

The auditor performs a comprehensive check based on all 8 vulnerability classes. It extends the built-in `openclaw security audit` with deeper, threat-intelligence-informed checks.

**Audit checks to implement (each returns a finding with severity CRITICAL/HIGH/MEDIUM/LOW/INFO):**

#### 2a. Gateway & Network Exposure Checks
- [ ] Gateway bind mode: FAIL if not `loopback` (checks `gateway.bind` in config)
- [ ] Gateway auth: FAIL if `gateway.auth.mode` is not `password` or `token` 
- [ ] Gateway auth token length: WARN if `authToken` < 32 characters
- [ ] Gateway port 18789 accessible from non-localhost: active probe using `net.createConnection()`
- [ ] Browser relay port 17892 accessible: check if listening and from where
- [ ] TLS enabled on gateway: check for `gateway.tls` configuration
- [ ] mDNS/Bonjour enabled in full mode: WARN if broadcasting sensitive fields (check `gateway.mdns.mode !== 'minimal'`)
- [ ] Reverse proxy without `trustedProxies`: CRITICAL (authentication bypass — all connections appear localhost)
- [ ] Control UI `dangerouslyDisableDeviceAuth`: CRITICAL if enabled
- [ ] Control UI `allowInsecureAuth`: WARN if enabled

#### 2b. Credential Storage Checks
- [ ] `~/.openclaw/` directory permissions: FAIL if not `700`
- [ ] Config file permissions: FAIL if not `600`
- [ ] `.env` file exists with plaintext API keys: WARN + offer encryption
- [ ] `credentials/*.json` permissions: FAIL if group/world readable
- [ ] `agents/*/agent/auth-profiles.json` permissions: FAIL if readable
- [ ] OAuth tokens in plaintext: detect and WARN
- [ ] API keys present in `soul.md` or memory files: CRITICAL (credential leak to LLM context)
- [ ] Scan for API key patterns (regex: `sk-ant-`, `sk-proj-`, `sk-`, `xoxb-`, `xoxp-`) in all `.md` and `.json` files under `~/.openclaw/`

#### 2c. Execution & Sandbox Checks
- [ ] `exec.approvals` set to `"off"`: CRITICAL
- [ ] `tools.exec.host` set to `"gateway"` (host execution, not sandbox): HIGH
- [ ] Sandbox mode: WARN if not enabled (`sandbox.mode !== "all"`)
- [ ] Docker `--read-only` flag: check docker-compose.yml or Dockerfile.sandbox config
- [ ] Docker `--cap-drop=ALL`: check container capabilities
- [ ] Docker `--security-opt=no-new-privileges`: verify
- [ ] Docker network mode: FAIL if `host` network

#### 2d. DM & Access Control Checks
- [ ] Any channel with `dmPolicy: "open"`: HIGH (public DMs)
- [ ] Any channel with `groupPolicy: "open"`: HIGH
- [ ] Allowlist contains `"*"` wildcard: WARN
- [ ] Pairing disabled without allowlist: HIGH
- [ ] `session.dmScope` not `"per-channel-peer"` with multiple users: WARN (cross-user context leakage)

#### 2e. Supply Chain / Skill Checks
- [ ] Installed skills count and source audit
- [ ] Check each installed skill directory for:
  - Outbound network calls (`curl`, `wget`, `fetch`, `http`, `https://`, `webhook.site`)
  - Shell execution (`exec`, `spawn`, `child_process`, `system()`)
  - File reads targeting credential paths (`~/.openclaw`, `.env`, `creds.json`)
  - Obfuscated code (base64-encoded strings > 50 chars, `eval()`, `Function()`)
  - Known malicious hashes from IOC database
- [ ] Check skill metadata: GitHub account age < 7 days: WARN
- [ ] Check for ClawHavoc-pattern typosquats in skill names

#### 2f. Memory Integrity Checks
- [ ] Generate SHA-256 hashes of `soul.md`, `MEMORY.md`, and all memory store files
- [ ] Compare against stored baseline (first run = generate baseline)
- [ ] Detect unexpected modifications (tamper detection)
- [ ] Scan memory files for prompt injection patterns:
  - "ignore previous instructions"
  - "you are now"
  - "new system prompt"
  - "forward to", "send to", "exfiltrate"
  - Base64 encoded blocks
  - URLs to non-whitelisted domains
- [ ] Memory file permissions check

#### 2g. API Cost Exposure Checks
- [ ] Check if LLM provider spending limits are configured (environment variables)
- [ ] Estimate token usage from recent session logs
- [ ] Check cron jobs for high-frequency agent invocations (heartbeat cost problem)
- [ ] WARN if estimated daily cost > configurable threshold (default: $5)

#### 2h. IOC (Indicators of Compromise) Checks
- [ ] Check outbound connection logs against known C2 IPs (e.g., `91.92.242.30` from ClawHavoc)
- [ ] Check installed skill URLs against known malicious domains
- [ ] Check for known malicious file hashes in skill directories
- [ ] Check for Atomic Stealer (AMOS) artifacts on macOS
- [ ] Check for Redline/Lumma/Vidar infostealer artifacts targeting `~/.openclaw/`

**Output format:**
```typescript
interface AuditFinding {
  id: string;                    // e.g., "HS-GW-001"
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  category: string;              // e.g., "gateway", "credentials", "execution", "supply-chain"
  title: string;                 // e.g., "Gateway authentication disabled"
  description: string;           // Human-readable explanation
  evidence: string;              // What was found (file path, config value, etc.)
  remediation: string;           // How to fix it
  autoFixable: boolean;          // Can secureclaw --fix handle this?
  references: string[];          // CVE numbers, advisory URLs
  owaspAsi: string;              // OWASP ASI mapping (e.g., "ASI03")
}

interface AuditReport {
  timestamp: string;
  openclawVersion: string;
  secureclawVersion: string;
  platform: string;              // "darwin-arm64", "linux-x64", etc.
  deploymentMode: string;        // "docker", "native", "nix"
  score: number;                 // 0-100 security score
  findings: AuditFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    autoFixable: number;
  };
}
```

### 3. Automated Hardening Engine (src/hardener.ts)

When invoked via `openclaw secureclaw harden` or `openclaw secureclaw audit --fix`, applies fixes automatically. Each fix must be **idempotent** and **reversible** (creates backups before modifying).

**Hardening actions (in priority order):**

#### 3a. Gateway Hardening (gateway-hardening.ts)
```typescript
// 1. Enforce loopback bind
setConfig('gateway.bind', 'loopback');

// 2. Generate strong auth token if none exists or if weak
if (!config.gateway.auth?.token || config.gateway.auth.token.length < 32) {
  const token = crypto.randomBytes(32).toString('hex');
  setConfig('gateway.auth.mode', 'password');
  setConfig('gateway.auth.password', token);
  // Store token securely and display to user once
}

// 3. Disable dangerous Control UI flags
setConfig('gateway.controlUi.dangerouslyDisableDeviceAuth', false);
setConfig('gateway.controlUi.allowInsecureAuth', false);

// 4. Set mDNS to minimal mode
setConfig('gateway.mdns.mode', 'minimal');

// 5. If reverse proxy detected, set trustedProxies
if (detectReverseProxy()) {
  setConfig('gateway.trustedProxies', ['127.0.0.1']);
}
```

#### 3b. Credential Hardening (credential-hardening.ts)
```typescript
// 1. Lock file permissions
chmod('~/.openclaw/', 0o700);
chmod('~/.openclaw/openclaw.json', 0o600);
chmodRecursive('~/.openclaw/credentials/', 0o600);
chmodRecursive('~/.openclaw/agents/*/agent/auth-profiles.json', 0o600);

// 2. Encrypt sensitive files at rest using node-forge
// Generate a machine-local encryption key derived from:
//   - Machine ID (from /etc/machine-id or IOPlatformUUID on macOS)
//   - OpenClaw state dir path
// Store wrapped key in ~/.openclaw/.secureclaw-keystore (permissions 0o400)
// Encrypt: .env, credentials/*.json, auth-profiles.json
// Decrypt transparently when OpenClaw reads them (via plugin hook)

// 3. Remove API keys from memory/soul files if found
scanAndRedactKeys('~/.openclaw/agents/*/soul.md');
scanAndRedactKeys('~/.openclaw/agents/*/memory/*.md');
```

#### 3c. Execution Hardening (config-hardening.ts)
```typescript
// 1. Enable approval mode
setConfig('exec.approvals', 'always');

// 2. Force sandbox execution
setConfig('sandbox.mode', 'all');
setConfig('tools.exec.host', 'sandbox');

// 3. Disable auto-approval for high-risk commands
setConfig('exec.autoApprove', []);  // Empty = nothing auto-approved
```

#### 3d. Docker Hardening (docker-hardening.ts)
```typescript
// Generate or patch docker-compose.yml with hardened settings
const hardenedDockerConfig = {
  services: {
    'openclaw-gateway': {
      read_only: true,
      cap_drop: ['ALL'],
      security_opt: ['no-new-privileges:true'],
      networks: ['restricted-net'],
      // Only allow outbound to known LLM API endpoints
      // Mount data volume as the only writable path
      volumes: ['openclaw-data:/app/data'],
      // Resource limits to prevent cost spirals
      deploy: {
        resources: {
          limits: {
            memory: '2G',
            cpus: '2.0'
          }
        }
      }
    }
  },
  networks: {
    'restricted-net': {
      driver: 'bridge',
      internal: false  // Needs outbound for LLM APIs
    }
  }
};
```

#### 3e. Access Control Hardening (config-hardening.ts)
```typescript
// 1. Set DM policy to pairing (default, but enforce)
for (const channel of getAllChannels()) {
  if (getChannelConfig(channel, 'dmPolicy') === 'open') {
    setChannelConfig(channel, 'dmPolicy', 'pairing');
  }
  if (getChannelConfig(channel, 'groupPolicy') === 'open') {
    setChannelConfig(channel, 'groupPolicy', 'allowlist');
  }
}

// 2. Enable DM session isolation
setConfig('session.dmScope', 'per-channel-peer');

// 3. Enable sensitive log redaction
setConfig('logging.redactSensitive', 'tools');
```

#### 3f. Network Hardening (network-hardening.ts)
```typescript
// 1. Generate egress allowlist for LLM API endpoints only
const egressAllowlist = [
  'api.anthropic.com',
  'api.openai.com',
  'generativelanguage.googleapis.com',
  'api.together.xyz',
  'openrouter.ai',
];
// Write iptables/nftables rules (Linux) or pf rules (macOS) as suggestion
// Don't auto-apply firewall rules — output as a script the user can review

// 2. Block known C2 infrastructure
const blocklist = loadIOCDatabase().ips;
// Generate blocklist rule file
```

### 4. Background Monitors (src/monitors/)

These run as lightweight watchers during gateway operation.

#### 4a. Credential Monitor (credential-monitor.ts)
- Watch `~/.openclaw/credentials/` and `.env` with chokidar
- Alert if permissions change to group/world readable
- Alert if new credential files appear unexpectedly
- Alert if credential files are accessed by unexpected processes (Linux: inotify; macOS: FSEvents)

#### 4b. Memory Integrity Monitor (memory-integrity.ts)
- Hash all memory files on gateway start → store as baseline
- Watch for modifications via chokidar
- On modification: re-scan for prompt injection patterns
- Alert on suspicious content insertion
- Provide `secureclaw memory quarantine` command to isolate suspicious memories

#### 4c. Skill Scanner (skill-scanner.ts)
- Hook into skill installation lifecycle
- Before any skill is installed: scan for malicious patterns
- Check against IOC hash database
- Static analysis for dangerous patterns:
  ```typescript
  const DANGEROUS_PATTERNS = [
    /child_process/,
    /\.exec\s*\(/,
    /\.spawn\s*\(/,
    /eval\s*\(/,
    /Function\s*\(/,
    /webhook\.site/,
    /reverse.shell/,
    /base64.*decode/i,
    /curl\s+.*\|.*sh/,
    /wget\s+.*\|.*sh/,
    /~\/\.openclaw/,
    /~\/\.clawdbot/,
    /creds\.json/,
    /\.env/,
    /auth-profiles/,
    /LD_PRELOAD/,
    /DYLD_INSERT/,
    /NODE_OPTIONS/,
  ];
  ```
- Block installation if critical patterns found, WARN for medium patterns
- Optional: query Koi Security Clawdex API for known-bad skills

#### 4d. Cost Monitor (cost-monitor.ts)
- Track API token usage from session logs
- Configurable spending limits per hour/day/month
- Circuit breaker: if hourly spend exceeds threshold, pause agent sessions
- Alert on unusual cost spikes (> 3x normal hourly rate)
- Generate daily/weekly cost reports

### 5. IOC Database (ioc/indicators.json)

Bundled threat intelligence from publicly documented incidents:

```json
{
  "version": "2026.02.07",
  "last_updated": "2026-02-07T00:00:00Z",
  "c2_ips": [
    "91.92.242.30"
  ],
  "malicious_domains": [
    "webhook.site"
  ],
  "malicious_skill_hashes": {
    "sha256_of_known_bad_skill_file": "campaign_name"
  },
  "typosquat_patterns": [
    "clawhub", "clawhub1", "clawhubb", "cllawhub",
    "clawdhub", "moltbot", "clawdbot"
  ],
  "dangerous_prerequisite_patterns": [
    "curl.*\\|.*bash",
    "password.*protected.*zip",
    "download.*prerequisite"
  ],
  "infostealer_artifacts": {
    "macos": [
      "/tmp/.*amos",
      "~/Library/Application Support/.*stealer"
    ],
    "linux": [
      "/tmp/.*redline",
      "/tmp/.*lumma"
    ]
  }
}
```

### 6. Secure Baseline Template (templates/secure-baseline.json)

This is the "gold standard" config. Applied via `openclaw secureclaw harden --full`:

```json
{
  "gateway": {
    "bind": "loopback",
    "port": 18789,
    "auth": {
      "mode": "password"
    },
    "mdns": {
      "mode": "minimal"
    },
    "controlUi": {
      "dangerouslyDisableDeviceAuth": false,
      "allowInsecureAuth": false
    },
    "trustedProxies": []
  },
  "exec": {
    "approvals": "always"
  },
  "sandbox": {
    "mode": "all",
    "scope": "agent",
    "workspaceAccess": "readwrite"
  },
  "tools": {
    "exec": {
      "host": "sandbox"
    }
  },
  "session": {
    "dmScope": "per-channel-peer"
  },
  "logging": {
    "redactSensitive": "tools"
  },
  "secureclaw": {
    "monitors": {
      "credentials": true,
      "memory": true,
      "skills": true,
      "cost": true
    },
    "cost": {
      "hourlyLimitUsd": 2,
      "dailyLimitUsd": 10,
      "monthlyLimitUsd": 100,
      "circuitBreakerEnabled": true
    },
    "memory": {
      "integrityChecks": true,
      "promptInjectionScan": true,
      "quarantineEnabled": true
    },
    "skills": {
      "blockUnaudited": false,
      "scanOnInstall": true,
      "iocCheckEnabled": true
    },
    "network": {
      "egressAllowlistEnabled": false,
      "egressAllowlist": [
        "api.anthropic.com",
        "api.openai.com",
        "generativelanguage.googleapis.com"
      ]
    }
  }
}
```

### 7. SKILL.md (Agent-Facing Skill Definition)

```markdown
---
name: secureclaw
description: Security hardening toolkit for OpenClaw. Run audits, apply fixes, scan skills, monitor costs and memory integrity.
metadata:
  clawdbot:
    config:
      stateDirs: [".secureclaw"]
---

# SecureClaw — Security Hardening

## Tools

### security_audit
Run a comprehensive security audit of this OpenClaw instance.
Returns findings with severity, description, and remediation steps.
Use when the user asks about security status or hardening.

### security_status
Get current security posture: score, active monitors, recent alerts.

### skill_scan
Scan a ClawHub skill for malicious patterns before installation.
Required parameter: skill name or URL.

### cost_report
Show API cost tracking data: current spend, projections, and alerts.
```

### 8. CLI Commands

```
openclaw secureclaw audit              # Full security audit (console output)
openclaw secureclaw audit --json       # Machine-readable JSON output
openclaw secureclaw audit --deep       # Include live network probes
openclaw secureclaw audit --fix        # Audit + auto-apply safe fixes

openclaw secureclaw harden             # Apply standard hardening (interactive)
openclaw secureclaw harden --full      # Apply full secure baseline (non-interactive)
openclaw secureclaw harden --rollback  # Revert to pre-hardening config backup

openclaw secureclaw status             # Show current security score + monitor status

openclaw secureclaw scan-skill <name>  # Scan a skill before installing

openclaw secureclaw cost-report        # Show API cost data
openclaw secureclaw cost-report --set-limit hourly=2 daily=10 monthly=100

openclaw secureclaw memory check       # Run memory integrity check now
openclaw secureclaw memory baseline    # Regenerate integrity baseline
openclaw secureclaw memory quarantine  # Isolate suspicious memory entries

openclaw secureclaw update-ioc         # Update IOC database (from bundled + optional remote)
```

---

## Implementation Constraints

### OpenClaw Plugin SDK Compatibility
- Entry point must be `dist/index.js` (compiled TypeScript)
- Runtime dependencies must be in `dependencies` (not `devDependencies`)
- Avoid `workspace:*` in dependencies — use `devDependencies` or `peerDependencies` for openclaw
- Plugin installs via `npm install --omit=dev` in plugin directory
- Lifecycle scripts run during install — keep install-time side effects minimal
- Plugin runs **in-process** with the Gateway (Node.js ≥22)
- Use `openclaw/plugin-sdk` for config access, event hooks, and tool registration (resolved via jiti alias)

### File Paths
- State dir: `~/.openclaw/` (or `$OPENCLAW_STATE_DIR`)
- Plugin data: `~/.openclaw/extensions/secureclaw/`
- Plugin state: `~/.openclaw/.secureclaw/` (baselines, keystore, backups)
- Config: `~/.openclaw/openclaw.json` (the main config file)
- Credentials: `~/.openclaw/credentials/`
- Agent data: `~/.openclaw/agents/<agentId>/`
- Session logs: `~/.openclaw/agents/<agentId>/sessions/*.jsonl`

### Config Access
- Read config via the OpenClaw plugin SDK config accessor
- Write config by patching `~/.openclaw/openclaw.json`
- Always create a backup at `~/.openclaw/.secureclaw/backup/openclaw.json.<timestamp>` before modifying
- Config merging: plugin settings go under `secureclaw` key in main config

### Testing
- Framework: Vitest (aligned with OpenClaw's test setup)
- Coverage thresholds: 70% lines/branches/functions/statements
- Test files: colocated `*.test.ts`
- Mock filesystem and config for unit tests
- Use temp directories for integration tests

---

## Development Instructions for Claude Code

### Step 1: Initialize the project

```bash
mkdir -p ~/.openclaw/extensions/secureclaw
cd ~/.openclaw/extensions/secureclaw
npm init -y
# Install dependencies
npm install chokidar node-forge
npm install -D typescript tsdown vitest @types/node
```

### Step 2: Implement in this order

1. **`src/utils/`** — crypto helpers (key derivation, encrypt/decrypt), hash utilities (SHA-256 of files), IOC database loader
2. **`src/auditor.ts`** — the audit engine with all checks from Section 2 above. Each check is a function returning `AuditFinding[]`. Run checks in parallel where possible.
3. **`src/reporters/`** — console reporter (colored, severity-grouped) and JSON reporter
4. **`src/hardening/`** — each hardening module from Section 3. Every module: reads current state → backs up → applies fix → verifies fix worked
5. **`src/hardener.ts`** — orchestrator that runs hardening modules in priority order
6. **`src/monitors/`** — background watchers from Section 4. Each monitor exports `start()`, `stop()`, `status()`
7. **`src/index.ts`** — plugin registration, lifecycle hooks, CLI command wiring, tool registration
8. **`SKILL.md`** and **`tools.md`** — agent-facing documentation
9. **`ioc/indicators.json`** — initial IOC database
10. **`templates/secure-baseline.json`** — gold standard config

### Step 3: Build and test

```bash
npx tsdown src/index.ts --outDir dist
npx vitest run
```

### Step 4: Install into OpenClaw

```bash
# The plugin is already in the extensions directory
# Restart the gateway to pick it up
openclaw gateway restart
```

---

## Quality Requirements

- **Zero false positives on CRITICAL findings** — every CRITICAL finding must represent a real, exploitable vulnerability
- **Idempotent hardening** — running `harden` twice produces the same result
- **Non-destructive** — all changes are reversible via `--rollback`
- **Minimal dependencies** — only `chokidar` (file watching) and `node-forge` (crypto) as runtime deps
- **Fast audits** — full audit completes in < 5 seconds on typical installations
- **No network calls without explicit opt-in** — IOC database is bundled; remote updates are optional
- **Graceful degradation** — if a check fails (e.g., Docker not installed), skip it with INFO finding, don't crash
- **Cross-platform** — works on macOS (primary), Linux, and Windows/WSL2

---

## OWASP ASI Mapping

Every audit finding maps to the OWASP Top 10 for Agentic Applications:

| SecureClaw Check Category | OWASP ASI | OpenClaw Manifestation |
|---|---|---|
| Gateway & Network | ASI03, ASI05 | CVE-2026-25253, exposed instances, reverse proxy bypass |
| Credentials | ASI03 | Plaintext storage, infostealer targeting |
| Execution & Sandbox | ASI02, ASI05 | Shell execution without approval, Docker escape |
| Access Control | ASI01, ASI09 | Open DMs, prompt injection via messages |
| Supply Chain / Skills | ASI04 | ClawHavoc, malicious skills, typosquatting |
| Memory Integrity | ASI06, ASI10 | Memory poisoning, time-shifted prompt injection |
| Cost Exposure | ASI08 | Runaway API costs, cascading failures |
| IOC Detection | ASI04, ASI10 | Known C2 infrastructure, rogue agents |

---

## Success Criteria

After running `openclaw secureclaw harden --full`, the deployment should:

1. ✅ Score ≥ 85/100 on `openclaw secureclaw audit`
2. ✅ Gateway bound to loopback only with strong auth
3. ✅ All credential files encrypted at rest with 600 permissions
4. ✅ Sandbox mode enabled, approval mode set to "always"
5. ✅ DM policy set to "pairing" on all channels
6. ✅ Session isolation enabled (per-channel-peer)
7. ✅ Memory integrity baseline established
8. ✅ All background monitors running
9. ✅ Cost circuit breaker configured
10. ✅ No CRITICAL or HIGH findings remaining

---

*This spec is designed to be implemented by Claude Code in a single session. All architectural decisions are pre-made. All file paths, interfaces, config keys, and check logic are specified. Build it.*
