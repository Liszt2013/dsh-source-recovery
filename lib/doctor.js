/** Runtime and backend diagnostics. Never prints environment dumps or home paths. */
import { promises as fsp } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { detectTools } from './backends.js';
import { describeConfig } from './config.js';
import { redactPaths } from './util.js';

async function tempCheck() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'dsh-source-recovery-'));
  try {
    const file = path.join(dir, 'probe.txt');
    await fsp.writeFile(file, 'ok', { mode: 0o600 });
    return { writable: true, note: 'temporary workspace is writable' };
  } catch (error) {
    return { writable: false, note: redactPaths(error instanceof Error ? error.message : 'temporary workspace is not writable') };
  } finally {
    await fsp.rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

/** Build a diagnostic report with redacted paths. */
export async function buildDoctorReport({ config, configSource, configWarnings, roots, pluginVersion, refresh = false }) {
  const tools = await detectTools({ refresh });
  const temp = await tempCheck();
  const safeTools = Object.fromEntries(Object.entries(tools).map(([id, tool]) => [id, {
    ...tool,
    path: typeof tool.path === 'string' ? redactPaths(tool.path) : tool.path,
    version: typeof tool.version === 'string' ? redactPaths(tool.version) : tool.version,
  }]));
  return {
    core: {
      node: process.version,
      openssl: process.versions.openssl,
      platform: process.platform,
      arch: process.arch,
      pluginVersion,
    },
    configuration: {
      source: configSource === null ? null : redactPaths(configSource),
      allowedRootCount: Array.isArray(roots) ? roots.length : 0,
      allowedRoots: Array.isArray(roots) ? roots.map((root) => redactPaths(root)) : [],
      ...describeConfig(config),
    },
    backends: safeTools,
    temporaryDirectory: temp,
    warnings: [
      ...(configWarnings ?? []),
      ...(temp.writable ? [] : ['temporary workspace is not writable']),
      ...(tools.rea?.available === true ? ['REA MCP detected: use mcp__rea__* tools for native/managed/APK deep analysis'] : ['REA MCP not detected: local built-in and CLI backends only']),
    ],
  };
}
