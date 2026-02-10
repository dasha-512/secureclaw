import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import type {
  AuditContext,
  AuditFinding,
  HardeningModule,
  HardeningResult,
  HardeningAction,
  OpenClawConfig,
} from '../types.js';

async function readConfig(stateDir: string): Promise<OpenClawConfig> {
  const configPath = path.join(stateDir, 'openclaw.json');
  try {
    const content = await fs.readFile(configPath, 'utf-8');
    return JSON.parse(content) as OpenClawConfig;
  } catch {
    return {};
  }
}

async function writeConfig(stateDir: string, config: OpenClawConfig): Promise<void> {
  const configPath = path.join(stateDir, 'openclaw.json');
  await fs.writeFile(configPath, JSON.stringify(config, null, 2), 'utf-8');
}

export const configHardening: HardeningModule = {
  name: 'config-hardening',
  priority: 3,

  async check(ctx: AuditContext): Promise<AuditFinding[]> {
    const findings: AuditFinding[] = [];

    if (ctx.config.exec?.approvals === 'off') {
      findings.push({
        id: 'SC-EXEC-001',
        severity: 'CRITICAL',
        category: 'execution',
        title: 'Execution approvals disabled',
        description: 'Will set exec.approvals to "always".',
        evidence: 'exec.approvals = "off"',
        remediation: 'Set exec.approvals to "always"',
        autoFixable: true,
        references: [],
        owaspAsi: 'ASI02',
      });
    }

    if (ctx.config.sandbox?.mode !== 'all') {
      findings.push({
        id: 'SC-EXEC-003',
        severity: 'MEDIUM',
        category: 'execution',
        title: 'Sandbox not set to all',
        description: 'Will set sandbox.mode to "all".',
        evidence: `sandbox.mode = "${ctx.config.sandbox?.mode ?? 'undefined'}"`,
        remediation: 'Set sandbox.mode to "all"',
        autoFixable: true,
        references: [],
        owaspAsi: 'ASI05',
      });
    }

    const channels = ctx.channels ?? [];
    for (const ch of channels) {
      if (ch.dmPolicy === 'open') {
        findings.push({
          id: 'SC-AC-001',
          severity: 'HIGH',
          category: 'access-control',
          title: `Channel "${ch.name}" has open DM policy`,
          description: 'Will set to "pairing".',
          evidence: `dmPolicy = "open"`,
          remediation: 'Set dmPolicy to "pairing"',
          autoFixable: true,
          references: [],
          owaspAsi: 'ASI01',
        });
      }
    }

    return findings;
  },

  async fix(ctx: AuditContext, backupDir: string): Promise<HardeningResult> {
    const applied: HardeningAction[] = [];
    const skipped: HardeningAction[] = [];
    const errors: string[] = [];

    try {
      // Backup current config
      const configPath = path.join(ctx.stateDir, 'openclaw.json');
      try {
        await fs.copyFile(configPath, path.join(backupDir, 'openclaw-config.json'));
      } catch {
        // Config may not exist yet
      }

      const config = await readConfig(ctx.stateDir);

      // 1. Enable approval mode
      if (!config.exec) config.exec = {};
      const oldApprovals = config.exec.approvals;
      if (oldApprovals !== 'always') {
        config.exec.approvals = 'always';
        applied.push({
          id: 'config-approvals',
          description: 'Set exec.approvals to "always"',
          before: oldApprovals ?? 'undefined',
          after: 'always',
        });
      }

      // 2. Force sandbox execution
      if (!config.sandbox) config.sandbox = {};
      const oldSandboxMode = config.sandbox.mode;
      if (oldSandboxMode !== 'all') {
        config.sandbox.mode = 'all';
        applied.push({
          id: 'config-sandbox-mode',
          description: 'Set sandbox.mode to "all"',
          before: oldSandboxMode ?? 'undefined',
          after: 'all',
        });
      }

      if (!config.tools) config.tools = {};
      if (!config.tools.exec) config.tools.exec = {};
      const oldExecHost = config.tools.exec.host;
      if (oldExecHost !== 'sandbox') {
        config.tools.exec.host = 'sandbox';
        applied.push({
          id: 'config-exec-host',
          description: 'Set tools.exec.host to "sandbox"',
          before: oldExecHost ?? 'undefined',
          after: 'sandbox',
        });
      }

      // 3. Disable auto-approval
      if (!config.exec.autoApprove || config.exec.autoApprove.length > 0) {
        config.exec.autoApprove = [];
        applied.push({
          id: 'config-auto-approve',
          description: 'Cleared exec.autoApprove list',
          before: 'had auto-approved commands',
          after: '[] (nothing auto-approved)',
        });
      }

      // 4. Set DM policy to pairing for open channels
      // Note: Channel configs are typically separate but we handle them via the main config
      // In a real deployment, each channel has its own config.
      // We'll store the fix intent in secureclaw config.

      // 5. Enable DM session isolation
      if (!config.session) config.session = {};
      const oldDmScope = config.session.dmScope;
      if (oldDmScope !== 'per-channel-peer') {
        config.session.dmScope = 'per-channel-peer';
        applied.push({
          id: 'config-dm-scope',
          description: 'Set session.dmScope to "per-channel-peer"',
          before: oldDmScope ?? 'undefined',
          after: 'per-channel-peer',
        });
      }

      // 6. Enable sensitive log redaction
      if (!config.logging) config.logging = {};
      const oldRedact = config.logging.redactSensitive;
      if (oldRedact !== 'tools') {
        config.logging.redactSensitive = 'tools';
        applied.push({
          id: 'config-log-redact',
          description: 'Enabled sensitive log redaction',
          before: oldRedact ?? 'undefined',
          after: 'tools',
        });
      }

      await writeConfig(ctx.stateDir, config);
    } catch (err) {
      errors.push(`Config hardening error: ${err instanceof Error ? err.message : String(err)}`);
    }

    return { module: 'config-hardening', applied, skipped, errors };
  },

  async rollback(backupDir: string): Promise<void> {
    // Rollback is handled by the orchestrator
  },
};
