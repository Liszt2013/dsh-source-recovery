/** Trusted external-toolchain detection and bounded invocation. */
import { promises as fsp } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { RecoveryError } from './errors.js';
import { runProcess } from './proc.js';
import { redactPaths } from './util.js';

/** Toolchain specs. Detection and version probes never execute a target. */
export const TOOL_SPECS = Object.freeze({
  jadx: { commands: ['jadx', 'jadx.bat'], versionArgs: ['--version'], role: 'APK/DEX → Java/Kotlin source (S1)' },
  apktool: { commands: ['apktool', 'apktool.bat'], versionArgs: ['--version'], role: 'APK → smali + decoded resources (S1)' },
  ilspycmd: { commands: ['ilspycmd'], versionArgs: ['--version'], role: '.NET → C# near-source (S1)' },
  dotnet: { commands: ['dotnet'], versionArgs: ['--version'], role: '.NET runtime (tool host)' },
  objdump: { commands: ['objdump'], versionArgs: ['--version'], role: 'native disassembly (S3)' },
  readelf: { commands: ['readelf'], versionArgs: ['--version'], role: 'ELF headers/sections (S3)' },
  strings: { commands: ['strings'], versionArgs: ['--version'], role: 'printable strings (S3)' },
  ghidra: { commands: ['analyzeHeadless', 'analyzeHeadless.bat'], versionArgs: [], role: 'native decompilation to pseudo-C (S2)' },
  binwalk: { commands: ['binwalk'], versionArgs: ['--version'], role: 'firmware signature extraction (S3)' },
  unblob: { commands: ['unblob'], versionArgs: ['--version'], role: 'firmware extraction (S3)' },
  java: { commands: ['java'], versionArgs: ['-version'], role: 'JVM runtime for JADX/apktool' },
  python: { commands: ['python', 'python3'], versionArgs: ['--version'], role: 'helper scripting runtime' },
  node: { commands: ['node'], versionArgs: ['--version'], role: 'built-in JS/ASAR/source-map handlers' },
});

const EXTENSIONS = (process.env.PATHEXT ?? '.EXE;.CMD;.BAT;.COM').split(';').filter(Boolean);

/** Resolve an executable through PATH without invoking it. */
export async function which(command) {
  if (path.isAbsolute(command)) {
    const stat = await fsp.lstat(command).catch(() => null);
    return stat !== null && stat.isFile() ? command : null;
  }
  const dirs = (process.env.PATH ?? process.env.Path ?? '').split(path.delimiter).filter(Boolean);
  for (const dir of dirs) {
    for (const extension of process.platform === 'win32' ? EXTENSIONS : ['']) {
      const candidate = path.join(dir, `${command}${extension}`);
      try {
        const stat = await fsp.lstat(candidate);
        if (stat.isFile()) return candidate;
      } catch { /* keep searching */ }
    }
  }
  return null;
}

let cache = { at: 0, tools: null };
const CACHE_MS = 60_000;

/** Detect toolchains and versions. Paths are redacted in the result. */
export async function detectTools(options = {}) {
  if (options.refresh !== true && cache.tools !== null && Date.now() - cache.at < CACHE_MS) return cache.tools;
  const tools = {};
  for (const [id, spec] of Object.entries(TOOL_SPECS)) {
    let foundPath = null;
    for (const command of spec.commands) {
      foundPath = await which(command);
      if (foundPath !== null) break;
    }
    if (foundPath === null) {
      tools[id] = { id, available: false, path: null, version: null, role: spec.role };
      continue;
    }
    let version = null;
    if (spec.versionArgs.length > 0) {
      const launch = buildLaunch(foundPath, spec.versionArgs);
      const result = await runProcess(launch.command, launch.args, { timeoutMs: 8000, maxOutputBytes: 16 * 1024, verbatim: launch.verbatim });
      const text = `${result.stdout}\n${result.stderr}`.trim().split(/\r?\n/).find((line) => line.trim() !== '') ?? '';
      version = text.replace(/\s+/g, ' ').slice(0, 200);
    }
    tools[id] = { id, available: true, path: redactPaths(foundPath), version, role: spec.role };
  }
  tools.rea = await detectRea();
  cache = { at: Date.now(), tools };
  return tools;
}

/** Detect the installed dsh-rea/REA MCP bundle without contacting it. */
export async function detectRea() {
  const homes = [];
  if (typeof process.env.DSH_HOME === 'string' && process.env.DSH_HOME !== '') homes.push(process.env.DSH_HOME);
  homes.push(path.join(os.homedir(), '.dsh'));
  for (const home of homes) {
    const profilesDir = path.join(home, 'profiles');
    let profiles;
    try { profiles = await fsp.readdir(profilesDir, { withFileTypes: true }); } catch { continue; }
    for (const profile of profiles) {
      if (!profile.isDirectory()) continue;
      const packagePath = path.join(profilesDir, profile.name, 'node_modules', 'dsh-rea', 'package.json');
      try {
        const pkg = JSON.parse(await fsp.readFile(packagePath, 'utf8'));
        return {
          id: 'rea',
          available: true,
          version: typeof pkg.version === 'string' ? pkg.version : null,
          profile: profile.name,
          note: 'REA MCP is model-invoked (mcp__rea__*); this plugin detects it but does not call MCP tools from host code',
        };
      } catch { /* not installed in this profile */ }
    }
  }
  return { id: 'rea', available: false, version: null, profile: null, note: 'dsh-rea/REA MCP not detected in known DSH profiles' };
}

/** Build a launch plan; .bat/.cmd cannot be spawned directly on Windows. */
export function buildLaunch(command, args = []) {
  if (process.platform === 'win32' && /\.(bat|cmd)$/i.test(command)) {
    const quote = (value) => (/[\s"]/.test(value) ? `"${String(value).replace(/"/g, '\\"')}"` : String(value));
    const line = `"${command}" ${args.map(quote).join(' ')}`;
    return {
      command: process.env.ComSpec ?? 'cmd.exe',
      args: ['/d', '/s', '/c', `"${line}"`],
      verbatim: true,
    };
  }
  return { command, args, verbatim: false };
}

/** Run one trusted backend with structured argv, bounded output and no shell. */
export async function runTool(id, args, options = {}) {
  const tools = await detectTools();
  const tool = tools[id];
  if (tool === undefined || tool.available !== true) {
    throw new RecoveryError('E_BACKEND_UNAVAILABLE', `required backend is not installed: ${id}`, { exitCode: 4 });
  }
  // Re-resolve the real path for execution (display path is redacted).
  let executable = null;
  for (const command of TOOL_SPECS[id].commands) {
    executable = await which(command);
    if (executable !== null) break;
  }
  if (executable === null) throw new RecoveryError('E_BACKEND_UNAVAILABLE', `required backend disappeared: ${id}`, { exitCode: 4 });
  const launch = buildLaunch(executable, args);
  const result = await runProcess(launch.command, launch.args, {
    cwd: options.cwd,
    timeoutMs: options.timeoutMs ?? 120_000,
    maxOutputBytes: options.maxOutputBytes ?? 1024 * 1024,
    signal: options.signal,
    verbatim: launch.verbatim,
  });
  const sanitize = (text) => redactPaths(String(text ?? ''));
  const stderr = sanitize(result.stderr);
  return {
    id,
    code: result.code,
    timedOut: result.timedOut === true,
    truncated: result.truncated === true,
    durationMs: result.durationMs,
    stdout: sanitize(result.stdout),
    stdoutTail: sanitize(result.stdout).slice(-4000),
    stderrTail: stderr.slice(-4000),
    spawnError: result.spawnError ?? null,
  };
}

/** Clear the detection cache (tests / explicit refresh). */
export function clearToolCache() {
  cache = { at: 0, tools: null };
}
