import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { configHardening } from './config-hardening.js';
import type { AuditContext, OpenClawConfig } from '../types.js';

describe('config-hardening', () => {
  let tmpDir: string;
  let backupDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'sc-cfg-test-'));
    backupDir = path.join(tmpDir, 'backup');
    await fs.mkdir(backupDir, { recursive: true });
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  function makeCtx(config: OpenClawConfig = {}): AuditContext {
    return {
      stateDir: tmpDir,
      config,
      platform: 'darwin-arm64',
      deploymentMode: 'native',
      openclawVersion: '2026.2.0',
      channels: [],
      async fileInfo(p) { return { path: p, exists: true }; },
      async readFile(p) {
        try { return await fs.readFile(p, 'utf-8'); } catch { return null; }
      },
      async listDir(p) { return fs.readdir(p); },
      async fileExists(p) {
        try { await fs.access(p); return true; } catch { return false; }
      },
      async getFilePermissions(p) {
        try { const s = await fs.stat(p); return s.mode & 0o777; } catch { return null; }
      },
    };
  }

  it('sets exec.approvals to always', async () => {
    const configPath = path.join(tmpDir, 'openclaw.json');
    await fs.writeFile(configPath, JSON.stringify({ exec: { approvals: 'off' } }), 'utf-8');

    const ctx = makeCtx({ exec: { approvals: 'off' } });
    await configHardening.fix(ctx, backupDir);

    const updated = JSON.parse(await fs.readFile(configPath, 'utf-8'));
    expect(updated.exec.approvals).toBe('always');
  });

  it('sets sandbox.mode to all', async () => {
    const configPath = path.join(tmpDir, 'openclaw.json');
    await fs.writeFile(configPath, JSON.stringify({ sandbox: { mode: 'off' } }), 'utf-8');

    const ctx = makeCtx({ sandbox: { mode: 'off' } });
    await configHardening.fix(ctx, backupDir);

    const updated = JSON.parse(await fs.readFile(configPath, 'utf-8'));
    expect(updated.sandbox.mode).toBe('all');
  });

  it('sets tools.exec.host to sandbox', async () => {
    const configPath = path.join(tmpDir, 'openclaw.json');
    await fs.writeFile(configPath, JSON.stringify({ tools: { exec: { host: 'gateway' } } }), 'utf-8');

    const ctx = makeCtx({ tools: { exec: { host: 'gateway' } } });
    await configHardening.fix(ctx, backupDir);

    const updated = JSON.parse(await fs.readFile(configPath, 'utf-8'));
    expect(updated.tools.exec.host).toBe('sandbox');
  });

  it('sets session.dmScope to per-channel-peer', async () => {
    const configPath = path.join(tmpDir, 'openclaw.json');
    await fs.writeFile(configPath, JSON.stringify({ session: { dmScope: 'global' } }), 'utf-8');

    const ctx = makeCtx({ session: { dmScope: 'global' } });
    await configHardening.fix(ctx, backupDir);

    const updated = JSON.parse(await fs.readFile(configPath, 'utf-8'));
    expect(updated.session.dmScope).toBe('per-channel-peer');
  });

  it('enables log redaction', async () => {
    const configPath = path.join(tmpDir, 'openclaw.json');
    await fs.writeFile(configPath, JSON.stringify({}), 'utf-8');

    const ctx = makeCtx({});
    await configHardening.fix(ctx, backupDir);

    const updated = JSON.parse(await fs.readFile(configPath, 'utf-8'));
    expect(updated.logging.redactSensitive).toBe('tools');
  });

  it('clears autoApprove list', async () => {
    const configPath = path.join(tmpDir, 'openclaw.json');
    await fs.writeFile(configPath, JSON.stringify({ exec: { autoApprove: ['ls', 'cat'] } }), 'utf-8');

    const ctx = makeCtx({ exec: { autoApprove: ['ls', 'cat'] } });
    await configHardening.fix(ctx, backupDir);

    const updated = JSON.parse(await fs.readFile(configPath, 'utf-8'));
    expect(updated.exec.autoApprove).toEqual([]);
  });

  it('creates backup before changes', async () => {
    const configPath = path.join(tmpDir, 'openclaw.json');
    await fs.writeFile(configPath, JSON.stringify({ exec: { approvals: 'off' } }), 'utf-8');

    const ctx = makeCtx({ exec: { approvals: 'off' } });
    await configHardening.fix(ctx, backupDir);

    const backupExists = await fs.access(path.join(backupDir, 'openclaw-config.json')).then(() => true).catch(() => false);
    expect(backupExists).toBe(true);
  });
});
