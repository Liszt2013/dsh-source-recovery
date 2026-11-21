import { promises as fsp } from 'node:fs';
import path from 'node:path';
import { RecoveryError } from './errors.js';

export const CONFIG_FILE = 'dsh-source-recovery.json';
export const ROOTS_ENV = 'DSH_SOURCE_RECOVERY_ROOTS';
export const CONFIG_ENV = 'DSH_SOURCE_RECOVERY_JSON';

const KNOWN_KEYS = new Set([
  'allowedRoots', 'maxInputBytes', 'maxEntries', 'maxExtractedBytes', 'maxEntryBytes',
  'overwrite', 'backendTimeoutMs', 'backendOutputLimitBytes',
]);

export function defaultConfig() {
  return {
    allowedRoots: [],
    maxInputBytes: 4 * 1024 * 1024 * 1024,
    maxEntries: 100_000,
    maxExtractedBytes: 2 * 1024 * 1024 * 1024,
    maxEntryBytes: 512 * 1024 * 1024,
    overwrite: false,
    backendTimeoutMs: 120_000,
    backendOutputLimitBytes: 1024 * 1024,
  };
}

function positiveInteger(value, key) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new RecoveryError('E_ARGS', `${key} must be a positive safe integer`, { exitCode: 2 });
  }
  return value;
}

/** Load optional JSON config; unknown keys warn, invalid values fail closed. */
export async function loadConfig(options = {}) {
  const warnings = [];
  const filePath = options.path ?? process.env[CONFIG_ENV] ?? null;
  const config = defaultConfig();
  if (typeof filePath !== 'string' || filePath.length === 0) return { config, warnings, source: null };
  const absolute = path.resolve(filePath);
  let raw;
  try {
    const stat = await fsp.lstat(absolute);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new RecoveryError('E_CONFIG', 'config path must be a regular file');
    raw = JSON.parse(await fsp.readFile(absolute, 'utf8'));
  } catch (error) {
    if (error instanceof RecoveryError) throw error;
    throw new RecoveryError('E_CONFIG', `cannot read config: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new RecoveryError('E_CONFIG', 'config must be a JSON object');
  }
  for (const key of Object.keys(raw)) if (!KNOWN_KEYS.has(key)) warnings.push(`unknown configuration key ignored: ${key}`);
  if (raw.allowedRoots !== undefined) {
    if (!Array.isArray(raw.allowedRoots) || raw.allowedRoots.some((entry) => typeof entry !== 'string' || entry.length === 0)) {
      throw new RecoveryError('E_CONFIG', 'allowedRoots must be an array of non-empty strings');
    }
    config.allowedRoots = raw.allowedRoots.map((entry) => path.resolve(entry));
  }
  for (const key of ['maxInputBytes', 'maxEntries', 'maxExtractedBytes', 'maxEntryBytes', 'backendTimeoutMs', 'backendOutputLimitBytes']) {
    if (raw[key] !== undefined) config[key] = positiveInteger(raw[key], key);
  }
  if (raw.overwrite !== undefined) {
    if (typeof raw.overwrite !== 'boolean') throw new RecoveryError('E_CONFIG', 'overwrite must be a boolean');
    config.overwrite = raw.overwrite;
  }
  return { config, warnings, source: absolute };
}

export function describeConfig(config) {
  return {
    maxInputBytes: config.maxInputBytes,
    maxEntries: config.maxEntries,
    maxExtractedBytes: config.maxExtractedBytes,
    maxEntryBytes: config.maxEntryBytes,
    overwrite: config.overwrite,
    backendTimeoutMs: config.backendTimeoutMs,
    backendOutputLimitBytes: config.backendOutputLimitBytes,
  };
}
