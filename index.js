/**
 * dsh-source-recovery — host plugin.
 *
 * One recovery core (lib/) backs eight model tools named reverse_*, one runtime
 * skill, and four read-only loopback routes for the sidebar workbench.
 */
import { promises as fsp } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as api from './lib/api.js';
import { asRecoveryError } from './lib/errors.js';
import { redactPaths } from './lib/util.js';

const PACKAGE_ROOT = path.dirname(fileURLToPath(import.meta.url));
const PLUGIN_VERSION = '0.2.0';
const ROUTE_PREFIX = '/plugins/dsh-source-recovery';

export const name = 'dsh-source-recovery';
export const inject = ['tools', 'skills'];

function renderEnvelope(value) {
  let text;
  try { text = JSON.stringify(value); } catch { text = '{"ok":false,"code":"E_INTERNAL"}'; }
  if (text.length > 120_000) text = `${text.slice(0, 119_000)}\n… rendered text truncated; canonical value remains programmatic`;
  return [{ type: 'text', text }];
}

const ENVELOPE_OUTPUT = {
  schema: {
    type: 'object',
    additionalProperties: true,
    required: ['ok', 'code', 'message', 'formatVersion', 'backend', 'warnings'],
    properties: {
      ok: { type: 'boolean' },
      code: { type: 'string' },
      message: { type: 'string' },
      formatVersion: { type: 'string' },
      backend: { type: 'string' },
      warnings: { type: 'array', items: { type: 'string' } },
    },
  },
  render: (_args, value) => renderEnvelope(value),
};

async function invoke(operation, options, roots) {
  try {
    return await operation({ ...options, roots });
  } catch (error) {
    return api.failure(asRecoveryError(error));
  }
}

function sessionRoots(exec) {
  try {
    const cwd = exec?.agent?.session?.meta?.cwd;
    if (typeof cwd === 'string' && path.isAbsolute(cwd)) return [cwd];
  } catch { /* fall back to configured roots */ }
  return undefined;
}

function resolveToolRoots(exec, config) {
  const roots = [];
  if (Array.isArray(config?.allowedRoots)) {
    for (const root of config.allowedRoots) if (typeof root === 'string' && path.isAbsolute(root)) roots.push(root);
  }
  const fromSession = sessionRoots(exec);
  if (fromSession !== undefined) roots.push(...fromSession);
  return roots.length > 0 ? roots : undefined;
}

function tool(name, description, parameters, execute) {
  const required = Object.entries(parameters).filter(([, schema]) => schema.required === true).map(([key]) => key);
  const properties = Object.fromEntries(Object.entries(parameters).map(([key, schema]) => {
    const copy = { ...schema };
    delete copy.required;
    return [key, copy];
  }));
  return {
    name,
    description,
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties,
      ...(required.length > 0 ? { required } : {}),
    },
    output: { ...ENVELOPE_OUTPUT, render: (_args, value) => renderEnvelope(value) },
    execute,
  };
}

const INPUT = { type: 'string', required: true, description: 'Absolute path to the authorized target file.' };
const OUTPUT_DIR = { type: 'string', required: true, description: 'New or empty absolute output directory inside an allowed root.' };
const AUTHORIZED = { type: 'boolean', required: true, description: 'Must be true only when you are authorized to analyze this target.' };
const NOTE = { type: 'string', description: 'Optional authorization/reason note recorded in the result.' };

export function buildToolDefinitions(toolRoots) {
  const run = (operation, options, exec) => invoke(operation, { ...options, signal: exec?.signal }, toolRoots(exec));
  return [
    tool('reverse_capabilities',
      'List supported target families, honest recovery levels (S0 exact source … S4 behavior-only), local backends and REA MCP presence. Read-only; no target needed.',
      { refresh: { type: 'boolean', description: 'Refresh backend detection instead of using the 60s cache.' } },
      (args, exec) => run(api.capabilities, args, exec)),
    tool('reverse_doctor',
      'Diagnose installed reverse-engineering toolchains (jadx, apktool, objdump, strings, ilspycmd, binwalk, unblob, ghidra), REA MCP presence, config and temporary-directory health. Paths are redacted.',
      { refresh: { type: 'boolean', description: 'Refresh backend detection.' } },
      (args, exec) => run(api.doctor, { ...args, pluginVersion: PLUGIN_VERSION }, exec)),
    tool('reverse_identify',
      'Fingerprint a target without executing it: size, SHA-256, magic, format family, architecture, entropy, strings statistics, container members, recovery plan and gaps.',
      { input: INPUT },
      (args, exec) => run(api.identify, args, exec)),
    tool('reverse_extract',
      'Safely extract an authorized archive/APK/JAR/ASAR/GZIP into a new directory with traversal, symlink, encryption, size, ratio and overwrite protections. Extraction is not decompilation.',
      {
        input: INPUT,
        outputDir: OUTPUT_DIR,
        authorized: AUTHORIZED,
        note: NOTE,
        kind: { type: 'string', enum: ['apk', 'jar', 'zip', 'asar', 'gzip', 'tar'], description: 'Override the detected container kind.' },
      },
      (args, exec) => run(api.extract, args, exec)),
    tool('reverse_decompile',
      'Recover source-form artifacts toward the highest honest level: JADX/apktool for APK, ILSpy for .NET when installed, disassembly for native, ASAR/source-map recovery for Electron, strings for firmware. Never executes the target.',
      {
        input: INPUT,
        outputDir: OUTPUT_DIR,
        authorized: AUTHORIZED,
        note: NOTE,
        resources: { type: 'boolean', description: 'Also run apktool for APK resources/smali (default true).' },
      },
      (args, exec) => run(api.decompile, args, exec)),
    tool('reverse_sourcemap',
      'Recover original source files from a JavaScript source map (S0 when sourcesContent exists). Accepts a .map file or a JS file with an inline/external sourceMappingURL.',
      {
        outputDir: OUTPUT_DIR,
        authorized: AUTHORIZED,
        note: NOTE,
        map: { type: 'string', description: 'Absolute path to a .map file.' },
        js: { type: 'string', description: 'Absolute path to a JS file that references a source map.' },
      },
      (args, exec) => run(api.sourcemap, args, exec)),
    tool('reverse_report',
      'Write an evidence report (Markdown + JSON) for an authorized target: hash, family, recovery ceiling, plan, backend gaps, evidence tags and unknowns. Does not decompile.',
      {
        input: INPUT,
        output: { type: 'string', required: true, description: 'Absolute .md report path; a sibling .json is written.' },
        authorized: AUTHORIZED,
        note: NOTE,
        overwrite: { type: 'boolean', description: 'Allow replacing an existing report file.' },
      },
      (args, exec) => run(api.report, args, exec)),
    tool('reverse_bundle',
      'Create a portable evidence bundle (ZIP): hash-verified manifest, report.md/report.json, tool versions, recovery level/gaps, and optionally an artifacts directory. Suitable for handoff and independent verification.',
      {
        input: INPUT,
        output: { type: 'string', required: true, description: 'Absolute output .zip path.' },
        authorized: AUTHORIZED,
        note: NOTE,
        artifactsDir: { type: 'string', description: 'Optional real directory inside an allowed root to include under artifacts/.' },
        overwrite: { type: 'boolean', description: 'Allow replacing an existing bundle file.' },
      },
      (args, exec) => run(api.bundle, args, exec)),
    tool('reverse_verify',
      'Verify every declared hash and the bundle digest of a dsh-source-recovery evidence bundle. Read-only; reports missing, size, hash, digest and undeclared-artifact mismatches.',
      { bundle: { type: 'string', required: true, description: 'Absolute path to a bundle .zip.' } },
      (args, exec) => run(api.verifyBundle, args, exec)),
    tool('reverse_selftest',
      'Run the deterministic recovery self-test (fixtures only, no target): identify, extraction, traversal rejection, ASAR, source maps, authorization gate and policy facts.',
      {},
      (args, exec) => run(api.selftest, args, exec)),
  ];
}

export async function apply(ctx, config = {}) {
  const toolRoots = (exec) => resolveToolRoots(exec, config);
  const registered = [];
  for (const definition of buildToolDefinitions(toolRoots)) registered.push(ctx.tools.register(definition));
  ctx.effect(() => () => {
    for (const dispose of registered) { try { dispose(); } catch { /* disposed with fiber */ } }
  }, 'dsh-source-recovery: tools');

  await registerSkill(ctx);
  registerWorkbenchRoutes(ctx);
}

async function registerSkill(ctx) {
  const skillDir = path.join(PACKAGE_ROOT, 'skills', 'dsh-source-recovery');
  const skillFile = path.join(skillDir, 'SKILL.md');
  let markdown;
  try { markdown = await fsp.readFile(skillFile, 'utf8'); } catch {
    ctx.logger?.warn?.('dsh-source-recovery: SKILL.md missing; tools remain available');
    return;
  }
  const { description, content } = parseSkillMarkdown(markdown);
  const dispose = ctx.skills.register({
    name: 'dsh-source-recovery',
    description,
    content,
    // DSH's skill registry requires a string `source` on every definition it
    // later loads. Without it, `skill load dsh-source-recovery` fails with
    // "loaded skill ... source must be a string". This is a bundled runtime skill.
    source: 'bundled',
    path: skillFile,
    resourceBase: { kind: 'directory', path: skillDir },
    invocation: { modelInvocable: true, userInvocable: true },
    provider: 'dsh-source-recovery',
    metadata: { version: PLUGIN_VERSION, domain: 'reverse-engineering' },
  });
  ctx.effect(() => dispose, 'dsh-source-recovery: skill');
}

export function parseSkillMarkdown(markdown) {
  const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(markdown);
  let description = 'Recover source-level artifacts from authorized targets with honest levels and evidence.';
  let body = markdown;
  if (match !== null) {
    body = markdown.slice(match[0].length);
    for (const line of match[1].split(/\r?\n/)) {
      const field = /^(name|description):\s*(.+)$/.exec(line.trim());
      if (field !== null && field[1] === 'description') description = field[2].trim().replace(/^["']|["']$/g, '');
    }
  }
  return { description, content: body.trim() };
}

function isLoopbackAddress(address) {
  return address === '::1' || address === '127.0.0.1' || address.startsWith('127.') || address === '::ffff:127.0.0.1';
}

function isTrustedLoopbackRequest(req) {
  if (!isLoopbackAddress(req.socket?.remoteAddress ?? '')) return false;
  const host = String(req.headers?.host ?? '').toLowerCase();
  const hostname = host.startsWith('[') ? host.slice(1, host.indexOf(']')) : host.split(':')[0];
  if (!['127.0.0.1', 'localhost', '::1'].includes(hostname)) return false;
  const origin = req.headers?.origin;
  if (typeof origin === 'string' && origin.length > 0) {
    try {
      const parsed = new URL(origin);
      if (!['127.0.0.1', 'localhost', '::1'].includes(parsed.hostname.toLowerCase())) return false;
    } catch { return false; }
  }
  return true;
}

function registerWorkbenchRoutes(ctx) {
  const webServer = ctx.get('webServer');
  if (webServer === undefined || typeof webServer.register !== 'function') return;
  const routes = [
    ['/capabilities', async () => api.capabilities()],
    ['/doctor', async () => api.doctor({ pluginVersion: PLUGIN_VERSION })],
    ['/selftest', async () => api.selftest()],
    ['/health', async () => api.success({
      pluginVersion: PLUGIN_VERSION,
      toolCount: 10,
      formatVersion: 'source-recovery/1',
      authorizationRequired: true,
      executesTargets: false,
      network: false,
    })],
  ];
  ctx.effect(() => {
    const disposers = [];
    for (const [suffix, handler] of routes) {
      disposers.push(webServer.register({
        kind: 'exact',
        path: `${ROUTE_PREFIX}/api${suffix}`,
        handler: async (req, res) => {
          const method = req.method ?? 'GET';
          if (method !== 'GET' && method !== 'HEAD') {
            res.writeHead(405, { 'content-type': 'application/json; charset=utf-8', allow: 'GET, HEAD' });
            res.end(JSON.stringify({ ok: false, code: 'E_USAGE', message: 'only GET and HEAD are supported' }));
            return;
          }
          if (!isTrustedLoopbackRequest(req)) {
            res.writeHead(403, { 'content-type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ ok: false, code: 'E_USAGE', message: 'loopback same-origin clients only' }));
            return;
          }
          let payload;
          try { payload = await handler(req); } catch (error) {
            res.writeHead(500, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
            res.end(JSON.stringify(api.failure(asRecoveryError(error))));
            return;
          }
          const text = JSON.stringify(payload);
          res.writeHead(200, {
            'content-type': 'application/json; charset=utf-8',
            'cache-control': 'no-store',
            'x-content-type-options': 'nosniff',
            'content-length': Buffer.byteLength(text),
          });
          if (method === 'HEAD') res.end(); else res.end(text);
        },
      }));
    }
    return () => { for (const dispose of disposers) { try { dispose(); } catch { /* removed */ } } };
  }, 'dsh-source-recovery: workbench routes');
  ctx.logger?.debug?.(`dsh-source-recovery: workbench routes at ${redactPaths(ROUTE_PREFIX)}`);
}

export { PACKAGE_ROOT, PLUGIN_VERSION, ROUTE_PREFIX };
