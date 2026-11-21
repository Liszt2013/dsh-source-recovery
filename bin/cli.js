#!/usr/bin/env node
/** dsh-source-recovery CLI. All operations share lib/api.js with the DSH tools. */
import path from 'node:path';
import * as api from '../lib/api.js';
import { RecoveryError, asRecoveryError } from '../lib/errors.js';

const COMMANDS = {
  capabilities: { refresh: false, json: false },
  doctor: { refresh: false, json: false },
  selftest: { json: false },
  identify: { in: true, input: true, json: false },
  recover: { target: true, out: true, output: true, outputDir: true, authorized: false, note: true, report: true, json: false },
  extract: { in: true, input: true, out: true, outputDir: true, kind: true, authorized: false, note: true, json: false },
  decompile: { in: true, input: true, out: true, outputDir: true, authorized: false, note: true, json: false },
  sourcemap: { map: true, js: true, out: true, outputDir: true, authorized: false, note: true, json: false },
  report: { in: true, input: true, out: true, output: true, authorized: false, note: true, overwrite: false, json: false },
  bundle: { in: true, input: true, out: true, output: true, artifacts: true, artifactsDir: true, authorized: false, note: true, achieved: true, overwrite: false, json: false },
  'verify-bundle': { in: true, input: true, bundle: true, json: false },
};
const VERSION = '0.2.0';

function parse(argv) {
  const command = argv[0];
  if (command === undefined || command === '--help' || command === '-h' || command === 'help') return { command: 'help', flags: {} };
  const spec = COMMANDS[command];
  if (spec === undefined) throw new RecoveryError('E_USAGE', `unknown command: ${command}`, { exitCode: 2 });
  const flags = {};
  for (let index = 1; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) throw new RecoveryError('E_USAGE', `unexpected argument: ${token}`, { exitCode: 2 });
    const key = token.slice(2);
    if (!(key in spec)) throw new RecoveryError('E_USAGE', `unknown flag --${key}`, { exitCode: 2 });
    if (spec[key] === true) {
      const value = argv[index + 1];
      if (value === undefined) throw new RecoveryError('E_USAGE', `--${key} requires a value`, { exitCode: 2 });
      flags[key] = value;
      index += 1;
    } else {
      flags[key] = true;
    }
  }
  return { command, flags };
}

function pathFlag(flags, ...keys) {
  for (const key of keys) {
    if (typeof flags[key] === 'string') return path.resolve(flags[key]);
  }
  return undefined;
}

function help() {
  return [
    'dsh-source-recovery — reverse everything toward source (authorized targets only)',
    '',
    'Usage:',
    '  dsh-source-recovery <target> --output <new-dir> --authorized [--report report.md]',
    '  dsh-source-recovery <command> [flags]',
    '',
    'Minimal form (P0):',
    '  dsh-source-recovery ./app.apk --output ./out --authorized',
    '  dsh-source-recovery ./app.asar --output ./out --authorized --report ./report.md',
    '',
    'Commands:',
    '  capabilities [--refresh] [--json]',
    '  doctor [--refresh] [--json]',
    '  selftest [--json]',
    '  identify --in <file> [--json]',
    '  recover --target <file> --out <new-dir> --authorized [--report <md>] [--json]',
    '  extract --in <file> --out <new-dir> --authorized [--kind apk|jar|zip|asar|gzip|tar] [--json]',
    '  decompile --in <file> --out <new-dir> --authorized [--json]',
    '  sourcemap (--map <file> | --js <file>) --out <new-dir> --authorized [--json]',
    '  report --in <file> --out <report.md> --authorized [--overwrite] [--json]',
    '  bundle --in <file> --out <bundle.zip> --authorized [--artifacts <dir>] [--overwrite] [--json]',
    '  verify-bundle --in <bundle.zip> [--json]',
    '  version | --version',
    '',
    'Authorization: recovery/write commands require --authorized. Targets are never executed.',
    'Recovery levels: S0 exact source, S1 near-source, S2 pseudo-source, S3 assembly/metadata, S4 behavior-only.',
  ].join('\n');
}

function render(command, result, flags) {
  if (flags.json === true || !process.stdout.isTTY) {
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return;
  }
  if (result.ok !== true) {
    process.stdout.write(`${result.code}: ${result.message}\n`);
    return;
  }
  if (command === 'capabilities') {
    process.stdout.write(`families: ${result.families.length}\n`);
    for (const family of result.families) process.stdout.write(`- ${family.id}: local ceiling ${family.bestLocal}, with REA ${family.bestWithRea}\n`);
    for (const line of ['backends:']) process.stdout.write(`${line}\n`);
    for (const [id, backend] of Object.entries(result.backends)) process.stdout.write(`- ${id}: ${backend.available ? 'available' : 'missing'}${backend.version ? ` (${backend.version})` : ''}\n`);
    return;
  }
  if (command === 'doctor') {
    process.stdout.write(`node ${result.core.node} | plugin ${result.core.pluginVersion}\n`);
    for (const [id, backend] of Object.entries(result.backends)) process.stdout.write(`- ${id}: ${backend.available ? 'available' : 'missing'}\n`);
    return;
  }
  if (command === 'identify') {
    process.stdout.write(`${result.name}: ${result.family}/${result.kind} ${result.size} bytes\nsha256 ${result.sha256}\nplan ceiling ${result.plan.bestLevel}\n`);
    return;
  }
  if (command === 'extract') {
    process.stdout.write(`extracted ${result.files.length} files (${result.bytes} bytes) to ${result.outputDir}\n`);
    return;
  }
  if (command === 'recover') {
    process.stdout.write(`${result.identify?.family ?? '?'}/${result.identify?.kind ?? '?'} → level ${result.level} (${result.levelName})\n`);
    process.stdout.write(`output ${result.outputDir}\n${result.reason ?? ''}\n`);
    if (result.report?.markdownPath) process.stdout.write(`report ${result.report.markdownPath}\n`);
    for (const warning of result.warnings ?? []) process.stdout.write(`warning: ${warning}\n`);
    return;
  }
  if (command === 'decompile') {
    process.stdout.write(`level ${result.level} (${result.levelName}) → ${result.outputDir}\n${result.reason}\n`);
    for (const warning of result.warnings ?? []) process.stdout.write(`warning: ${warning}\n`);
    return;
  }
  if (command === 'sourcemap') {
    process.stdout.write(`recovered ${result.recovered}/${result.sources} sources (${result.level}) to ${result.outputDir}\n`);
    return;
  }
  if (command === 'report') {
    process.stdout.write(`report ${result.markdownPath}\njson ${result.jsonPath}\nceiling ${result.recoveryCeiling.level}\n`);
    return;
  }
  if (command === 'bundle') {
    process.stdout.write(`evidence bundle ${result.output} (${result.bytes} bytes, ${result.artifactCount} artifacts)\n`);
    process.stdout.write(`sha256 ${result.sha256}\nbundleDigest ${result.bundleDigest}\n`);
    return;
  }
  if (command === 'verify-bundle') {
    process.stdout.write(`${result.ok ? 'VERIFIED' : 'FAILED'}: ${result.note}\n`);
    for (const mismatch of result.mismatches ?? []) process.stdout.write(`- ${mismatch.path}: ${mismatch.problem}\n`);
    return;
  }
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

async function main() {
  let argv = process.argv.slice(2);
  if (argv[0] === 'version' || argv[0] === '--version' || argv[0] === '-V') {
    process.stdout.write(`dsh-source-recovery ${VERSION}\n`);
    return 0;
  }
  // Minimal P0 form: `<target> --output <dir> --authorized` maps to recover.
  if (typeof argv[0] === 'string' && !argv[0].startsWith('-') && COMMANDS[argv[0]] === undefined) {
    argv = ['recover', '--target', path.resolve(argv[0]), ...argv.slice(1)];
  }
  let parsed;
  try {
    parsed = parse(argv);
  } catch (error) {
    const normalized = asRecoveryError(error);
    process.stdout.write(`${JSON.stringify(api.failure(normalized))}\n`);
    return normalized.exitCode;
  }
  if (parsed.command === 'help') {
    process.stdout.write(`${help()}\n`);
    return 0;
  }
  const { command, flags } = parsed;
  const controller = new AbortController();
  process.once('SIGINT', () => controller.abort());
  try {
    let result;
    if (command === 'capabilities') result = await api.capabilities({ refresh: flags.refresh === true });
    else if (command === 'doctor') result = await api.doctor({ refresh: flags.refresh === true });
    else if (command === 'selftest') result = await api.selftest();
    else if (command === 'identify') result = await api.identify({ input: pathFlag(flags, 'in', 'input') });
    else if (command === 'recover') {
      const target = path.resolve(flags.target);
      const outputDir = pathFlag(flags, 'out', 'output', 'outputDir');
      if (outputDir === undefined) throw new RecoveryError('E_USAGE', '--output <new-dir> is required', { exitCode: 2 });
      const identified = await api.identify({ input: target });
      if (identified.ok !== true) result = identified;
      else {
        const recovered = await api.decompile({
          input: target, outputDir, authorized: flags.authorized === true, authorizationNote: flags.note, signal: controller.signal,
        });
        result = { ...recovered, identify: { family: identified.family, kind: identified.kind, sha256: identified.sha256, plan: identified.plan } };
        if (recovered.ok === true && typeof flags.report === 'string') {
          const report = await api.report({
            input: target, output: path.resolve(flags.report), authorized: flags.authorized === true,
            authorizationNote: flags.note, overwrite: true,
          });
          result = { ...result, report: report.ok === true ? report : { ok: false, code: report.code, message: report.message } };
        }
      }
    }
    else if (command === 'extract') result = await api.extract({
      input: pathFlag(flags, 'in', 'input'), outputDir: pathFlag(flags, 'out', 'outputDir'),
      kind: flags.kind, authorized: flags.authorized === true, authorizationNote: flags.note,
    });
    else if (command === 'decompile') result = await api.decompile({
      input: pathFlag(flags, 'in', 'input'), outputDir: pathFlag(flags, 'out', 'outputDir'),
      authorized: flags.authorized === true, authorizationNote: flags.note, signal: controller.signal,
    });
    else if (command === 'sourcemap') result = await api.sourcemap({
      map: pathFlag(flags, 'map'), js: pathFlag(flags, 'js'), outputDir: pathFlag(flags, 'out', 'outputDir'),
      authorized: flags.authorized === true, authorizationNote: flags.note,
    });
    else if (command === 'report') result = await api.report({
      input: pathFlag(flags, 'in', 'input'), output: pathFlag(flags, 'out', 'output'),
      authorized: flags.authorized === true, authorizationNote: flags.note, overwrite: flags.overwrite === true,
    });
    else if (command === 'bundle') result = await api.bundle({
      input: pathFlag(flags, 'in', 'input'), output: pathFlag(flags, 'out', 'output'),
      artifactsDir: pathFlag(flags, 'artifacts', 'artifactsDir'),
      authorized: flags.authorized === true, authorizationNote: flags.note, achievedLevel: flags.achieved, overwrite: flags.overwrite === true,
    });
    else if (command === 'verify-bundle') result = await api.verifyBundle({
      bundle: pathFlag(flags, 'in', 'input', 'bundle'),
    });
    else throw new RecoveryError('E_USAGE', 'unsupported command', { exitCode: 2 });
    render(command, result, flags);
    return result.ok === true ? 0 : (result.code === 'E_AUTHZ_REQUIRED' ? 2 : 1);
  } catch (error) {
    const normalized = asRecoveryError(error);
    const result = api.failure(normalized);
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return normalized.exitCode;
  }
}

process.exitCode = await main();
