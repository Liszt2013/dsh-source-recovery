/** Shared implementation for tools, CLI, workbench routes and tests. */
import { promises as fsp } from 'node:fs';
import path from 'node:path';
import { RecoveryError, asRecoveryError, envelope } from './errors.js';
import { loadConfig, ROOTS_ENV } from './config.js';
import { assertInputFile, assertOutputFile, isInside, resolveRoots } from './policy.js';
import { assertOutputDirectory, extractByKind } from './archive.js';
import { buildDoctorReport } from './doctor.js';
import { detectTools } from './backends.js';
import { identifyFile } from './identify.js';
import { LEVELS, RECOVERY_POLICY, TARGET_FAMILIES } from './levels.js';
import { buildPlan, recover } from './recovery.js';
import { buildReport, writeReport } from './report.js';
import { recoverSources } from './sourcemap.js';
import { runSelfTest } from './selftest.js';
import { createEvidenceBundle, verifyEvidenceBundle } from './bundle.js';
import { withOutputLock } from './lock.js';
import { nowIso, redactPaths } from './util.js';

export { RecoveryError, asRecoveryError };

export function success(payload, warnings = []) {
  return envelope({ warnings, generatedAt: nowIso(), ...payload });
}

export function failure(error, warnings = []) {
  const normalized = asRecoveryError(error);
  return {
    ok: false,
    code: normalized.code,
    message: normalized.message,
    formatVersion: 'source-recovery/1',
    backend: 'node',
    warnings,
    generatedAt: nowIso(),
    ...(normalized.details === undefined ? {} : { details: normalized.details }),
  };
}

/** Merge explicit roots, configured roots and environment roots. */
export async function operationContext(options = {}) {
  const loaded = await loadConfig({ path: options.configPath });
  const fromEnv = typeof process.env[ROOTS_ENV] === 'string' && process.env[ROOTS_ENV].trim() !== ''
    ? process.env[ROOTS_ENV].split(path.delimiter).filter((entry) => entry.trim() !== '')
    : [];
  const merged = [];
  if (Array.isArray(options.roots)) merged.push(...options.roots);
  merged.push(...loaded.config.allowedRoots, ...fromEnv);
  const roots = await resolveRoots(merged.length > 0 ? merged : undefined, { cwd: options.cwd });
  return { ...loaded, roots };
}

function requireAuthorization(options) {
  if (options.authorized !== true) {
    throw new RecoveryError('E_AUTHZ_REQUIRED', 'explicit authorization is required: pass authorized=true only for targets you are allowed to analyze', { exitCode: 2 });
  }
}

async function checkedInput(input, ctx) {
  if (typeof input !== 'string') throw new RecoveryError('E_ARGS', 'input path is required');
  const checked = await assertInputFile(input, { roots: ctx.roots, maxBytes: ctx.config.maxInputBytes, label: 'target file' });
  return checked.path;
}

/** Capability matrix: target families, recovery levels and backend availability. */
export async function capabilities(options = {}) {
  const ctx = await operationContext(options);
  const tools = await detectTools({ refresh: options.refresh === true });
  const backends = Object.fromEntries(Object.entries(tools).map(([id, tool]) => [id, {
    available: tool.available === true,
    version: tool.version ? redactPaths(tool.version) : null,
    role: tool.role ?? tool.note ?? null,
  }]));
  return success({
    levels: LEVELS,
    families: TARGET_FAMILIES.map((family) => ({
      ...family,
      availableLevel: family.id === 'apk'
        ? ((backends.jadx?.available === true || backends.apktool?.available === true) ? 'S1' : 'S3')
        : family.id === 'native'
          ? (backends.objdump?.available === true ? 'S3' : 'S4')
          : family.id === 'electron' ? 'S3' : family.bestLocal,
      backendState: family.backends.map((id) => ({
        id,
        available: id.startsWith('builtin-') || id === 'static-only'
          ? true
          : id === 'rea-managed' || id === 'rea-native'
            ? tools.rea?.available === true
            : backends[id]?.available === true,
      })),
    })),
    backends,
    rea: tools.rea,
    policy: RECOVERY_POLICY,
    warnings: ctx.warnings,
  }, ctx.warnings);
}

export async function doctor(options = {}) {
  const ctx = await operationContext(options);
  const report = await buildDoctorReport({
    config: ctx.config,
    configSource: ctx.source,
    configWarnings: ctx.warnings,
    roots: ctx.roots,
    pluginVersion: options.pluginVersion ?? '0.2.0',
    refresh: options.refresh === true,
  });
  return success(report, report.warnings);
}

export async function identify(options) {
  const ctx = await operationContext(options);
  const input = await checkedInput(options.input, ctx);
  const identification = await identifyFile(input, { maxInputBytes: ctx.config.maxInputBytes });
  const tools = await detectTools();
  const plan = await buildPlan(identification, tools);
  return success({ ...identification, plan }, ctx.warnings);
}

export async function extract(options) {
  const ctx = await operationContext(options);
  requireAuthorization(options);
  const input = await checkedInput(options.input, ctx);
  const identification = await identifyFile(input, { maxInputBytes: ctx.config.maxInputBytes });
  let kind = typeof options.kind === 'string' ? options.kind : identification.kind;
  if (kind === 'unknown') {
    const head = Buffer.alloc(4);
    const handle = await fsp.open(input, 'r');
    try { await handle.read(head, 0, 4, 0); } finally { await handle.close(); }
    if (head.readUInt32LE(0) === 0x04034b50) kind = 'zip';
  }
  if (typeof options.outputDir !== 'string') throw new RecoveryError('E_ARGS', 'outputDir is required');
  return withOutputLock(options.outputDir, async () => {
    const created = await assertOutputDirectory(options.outputDir, ctx.roots, ctx.config.overwrite === true);
    try {
      const result = await extractByKind(input, kind, created.path, {
        maxEntries: ctx.config.maxEntries,
        maxExtractedBytes: ctx.config.maxExtractedBytes,
        maxEntryBytes: ctx.config.maxEntryBytes,
      });
      return success({
        input,
        sha256: identification.sha256,
        family: identification.family,
        kind,
        authorizationNote: options.authorizationNote ?? '',
        outputDir: created.path,
        ...result,
      }, ctx.warnings);
    } catch (error) {
      const entries = await fsp.readdir(created.path).catch(() => []);
      if (entries.length === 0) await fsp.rm(created.path, { recursive: true, force: true }).catch(() => {});
      throw error;
    }
  });
}

export async function decompile(options) {
  const ctx = await operationContext(options);
  requireAuthorization(options);
  const input = await checkedInput(options.input, ctx);
  if (typeof options.outputDir !== 'string') throw new RecoveryError('E_ARGS', 'outputDir is required');
  const result = await withOutputLock(options.outputDir, () => recover({
    input,
    outputDir: options.outputDir,
    roots: ctx.roots,
    config: ctx.config,
    authorized: true,
    authorizationNote: options.authorizationNote ?? '',
    signal: options.signal,
    resources: options.resources,
  }));
  return success({ ...result, warnings: [...ctx.warnings, ...result.warnings] }, [...ctx.warnings, ...result.warnings]);
}

export async function sourcemap(options) {
  const ctx = await operationContext(options);
  requireAuthorization(options);
  if (typeof options.outputDir !== 'string') throw new RecoveryError('E_ARGS', 'outputDir is required');
  let mapPath;
  let jsPath;
  if (typeof options.map === 'string') mapPath = (await assertInputFile(options.map, { roots: ctx.roots, maxBytes: 64 * 1024 * 1024, label: 'source map' })).path;
  if (typeof options.js === 'string') jsPath = (await assertInputFile(options.js, { roots: ctx.roots, maxBytes: ctx.config.maxInputBytes, label: 'JavaScript file' })).path;
  if (mapPath === undefined && jsPath === undefined) throw new RecoveryError('E_ARGS', 'provide --map or --js');
  return withOutputLock(options.outputDir, async () => {
    const created = await assertOutputDirectory(options.outputDir, ctx.roots, ctx.config.overwrite === true);
    try {
      const result = await recoverSources({ mapPath, jsPath, outputDir: created.path, allowedRoots: ctx.roots });
      return success({
        authorizationNote: options.authorizationNote ?? '',
        outputDir: created.path,
        ...result,
      }, ctx.warnings);
    } catch (error) {
      const entries = await fsp.readdir(created.path).catch(() => []);
      if (entries.length === 0) await fsp.rm(created.path, { recursive: true, force: true }).catch(() => {});
      throw error;
    }
  });
}

export async function report(options) {
  const ctx = await operationContext(options);
  requireAuthorization(options);
  const input = await checkedInput(options.input, ctx);
  if (typeof options.output !== 'string') throw new RecoveryError('E_ARGS', 'output report file path is required');
  const result = await writeReport({
    input,
    output: options.output,
    roots: ctx.roots,
    overwrite: options.overwrite === true || ctx.config.overwrite === true,
    authorizationNote: options.authorizationNote ?? '',
  });
  return success({ ...result, warnings: ctx.warnings }, ctx.warnings);
}

export async function selftest(options = {}) {
  const result = await runSelfTest(options);
  return success({ ...result, warnings: [] });
}

/** Create a portable evidence bundle (report + manifest + optional artifacts). */
export async function bundle(options) {
  const ctx = await operationContext(options);
  requireAuthorization(options);
  const input = await checkedInput(options.input, ctx);
  if (typeof options.output !== 'string') throw new RecoveryError('E_ARGS', 'output bundle path is required');
  let artifactsDir;
  if (typeof options.artifactsDir === 'string') {
    const resolved = path.resolve(options.artifactsDir);
    const real = await fsp.realpath(resolved).catch(() => undefined);
    if (real === undefined) throw new RecoveryError('E_IO', 'artifactsDir does not exist');
    const stat = await fsp.lstat(real);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new RecoveryError('E_PATH_UNSAFE', 'artifactsDir must be a real directory');
    if (!ctx.roots.some((root) => isInside(root, real))) throw new RecoveryError('E_PATH_OUTSIDE_ROOT', 'artifactsDir is outside the allowed roots');
    artifactsDir = real;
  }
  const result = await withOutputLock(options.output, () => createEvidenceBundle({
    input,
    output: options.output,
    artifactsDir,
    roots: ctx.roots,
    overwrite: options.overwrite === true || ctx.config.overwrite === true,
    authorizationNote: options.authorizationNote ?? '',
    pluginVersion: options.pluginVersion,
    achievedLevel: options.achievedLevel,
    maxInputBytes: ctx.config.maxInputBytes,
  }));
  return success({ ...result, warnings: ctx.warnings }, ctx.warnings);
}

/** Verify an evidence bundle without trusting its declared contents. */
export async function verifyBundle(options) {
  const ctx = await operationContext(options);
  if (typeof options.bundle !== 'string') throw new RecoveryError('E_ARGS', 'bundle path is required');
  const checked = await assertInputFile(options.bundle, {
    roots: ctx.roots,
    maxBytes: 2 * 1024 * 1024 * 1024,
    label: 'evidence bundle',
  });
  const result = await verifyEvidenceBundle({ bundle: checked.path });
  if (result.ok !== true) {
    return {
      ...failure(new RecoveryError('E_BUNDLE_INVALID', 'evidence bundle failed verification', { exitCode: 3 }), ctx.warnings),
      ...result,
    };
  }
  return success({ ...result, warnings: ctx.warnings }, ctx.warnings);
}

/** Exported for tests: build a report object without writes. */
export { buildReport };
