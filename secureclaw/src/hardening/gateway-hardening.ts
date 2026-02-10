import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { generateToken } from '../utils/crypto.js';
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

export const gatewayHardening: HardeningModule = {
  name: 'gateway-hardening',
  priority: 1,

  async check(ctx: AuditContext): Promise<AuditFinding[]> {
    const findings: AuditFinding[] = [];
    const gw = ctx.config.gateway;

    if (gw?.bind !== 'loopback') {
      findings.push({
        id: 'SC-GW-001',
        severity: 'CRITICAL',
        category: 'gateway',
        title: 'Gateway not bound to loopback',
        description: 'Gateway needs to be bound to loopback.',
        evidence: `gateway.bind = "${gw?.bind ?? 'undefined'}"`,
        remediation: 'Will set gateway.bind to "loopback"',
        autoFixable: true,
        references: [],
        owaspAsi: 'ASI03',
      });
    }

    const authMode = gw?.auth?.mode;
    if (authMode !== 'password' && authMode !== 'token') {
      findings.push({
        id: 'SC-GW-002',
        severity: 'CRITICAL',
        category: 'gateway',
        title: 'Gateway authentication disabled',
        description: 'Will enable password authentication with a strong token.',
        evidence: `gateway.auth.mode = "${authMode ?? 'none'}"`,
        remediation: 'Will set gateway.auth.mode to "password" and generate a token',
        autoFixable: true,
        references: [],
        owaspAsi: 'ASI03',
      });
    }

    const token = gw?.auth?.token ?? gw?.auth?.password ?? '';
    if ((authMode === 'token' || authMode === 'password') && token.length > 0 && token.length < 32) {
      findings.push({
        id: 'SC-GW-003',
        severity: 'MEDIUM',
        category: 'gateway',
        title: 'Weak gateway auth token',
        description: 'Will regenerate a strong 64-character token.',
        evidence: `Token length: ${token.length}`,
        remediation: 'Will generate a 32-byte (64-char hex) token',
        autoFixable: true,
        references: [],
        owaspAsi: 'ASI03',
      });
    }

    if (gw?.controlUi?.dangerouslyDisableDeviceAuth === true) {
      findings.push({
        id: 'SC-GW-009',
        severity: 'CRITICAL',
        category: 'gateway',
        title: 'Device auth disabled',
        description: 'Will re-enable device authentication.',
        evidence: 'dangerouslyDisableDeviceAuth = true',
        remediation: 'Will set to false',
        autoFixable: true,
        references: [],
        owaspAsi: 'ASI03',
      });
    }

    if (gw?.controlUi?.allowInsecureAuth === true) {
      findings.push({
        id: 'SC-GW-010',
        severity: 'MEDIUM',
        category: 'gateway',
        title: 'Insecure auth allowed',
        description: 'Will disable insecure auth.',
        evidence: 'allowInsecureAuth = true',
        remediation: 'Will set to false',
        autoFixable: true,
        references: [],
        owaspAsi: 'ASI03',
      });
    }

    if (gw?.mdns && gw.mdns.mode !== 'minimal') {
      findings.push({
        id: 'SC-GW-007',
        severity: 'MEDIUM',
        category: 'gateway',
        title: 'mDNS in full mode',
        description: 'Will set mDNS to minimal mode.',
        evidence: `mdns.mode = "${gw.mdns.mode}"`,
        remediation: 'Will set to "minimal"',
        autoFixable: true,
        references: [],
        owaspAsi: 'ASI05',
      });
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
        await fs.copyFile(configPath, path.join(backupDir, 'openclaw.json'));
      } catch {
        // Config may not exist yet
      }

      const config = await readConfig(ctx.stateDir);

      // 1. Enforce loopback bind
      if (!config.gateway) config.gateway = {};
      const oldBind = config.gateway.bind;
      if (oldBind !== 'loopback') {
        config.gateway.bind = 'loopback';
        applied.push({
          id: 'gw-bind',
          description: 'Set gateway bind to loopback',
          before: oldBind ?? 'undefined',
          after: 'loopback',
        });
      }

      // 2. Generate strong auth token
      if (!config.gateway.auth) config.gateway.auth = {};
      const oldAuthMode = config.gateway.auth.mode;
      const oldPassword = config.gateway.auth.password;
      if (oldAuthMode !== 'password' && oldAuthMode !== 'token') {
        const token = generateToken(32);
        config.gateway.auth.mode = 'password';
        config.gateway.auth.password = token;
        applied.push({
          id: 'gw-auth',
          description: 'Enabled password authentication with strong token',
          before: `mode=${oldAuthMode ?? 'none'}`,
          after: `mode=password, token=${token.substring(0, 8)}...`,
        });
      } else if (
        (oldPassword ?? config.gateway.auth.token ?? '').length > 0 &&
        (oldPassword ?? config.gateway.auth.token ?? '').length < 32
      ) {
        const token = generateToken(32);
        config.gateway.auth.password = token;
        applied.push({
          id: 'gw-token-strength',
          description: 'Regenerated stronger auth token',
          before: `length=${(oldPassword ?? config.gateway.auth.token ?? '').length}`,
          after: `length=${token.length}`,
        });
      }

      // 3. Disable dangerous flags
      if (!config.gateway.controlUi) config.gateway.controlUi = {};
      if (config.gateway.controlUi.dangerouslyDisableDeviceAuth === true) {
        config.gateway.controlUi.dangerouslyDisableDeviceAuth = false;
        applied.push({
          id: 'gw-device-auth',
          description: 'Re-enabled device authentication',
          before: 'true',
          after: 'false',
        });
      }
      if (config.gateway.controlUi.allowInsecureAuth === true) {
        config.gateway.controlUi.allowInsecureAuth = false;
        applied.push({
          id: 'gw-insecure-auth',
          description: 'Disabled insecure authentication',
          before: 'true',
          after: 'false',
        });
      }

      // 4. Set mDNS to minimal
      if (!config.gateway.mdns) config.gateway.mdns = {};
      const oldMdns = config.gateway.mdns.mode;
      if (oldMdns !== 'minimal') {
        config.gateway.mdns.mode = 'minimal';
        applied.push({
          id: 'gw-mdns',
          description: 'Set mDNS to minimal mode',
          before: oldMdns ?? 'undefined',
          after: 'minimal',
        });
      }

      // 5. Set trustedProxies if binding to non-loopback
      if (!config.gateway.trustedProxies) {
        config.gateway.trustedProxies = [];
      }

      await writeConfig(ctx.stateDir, config);
    } catch (err) {
      errors.push(`Gateway hardening error: ${err instanceof Error ? err.message : String(err)}`);
    }

    return { module: 'gateway-hardening', applied, skipped, errors };
  },

  async rollback(backupDir: string): Promise<void> {
    // Rollback is handled by the orchestrator restoring the full config backup
  },
};
