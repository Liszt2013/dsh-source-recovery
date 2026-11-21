/**
 * Build the installable tarball with `npm pack`, inspect its contents, scan it
 * for secret patterns, and write reports/npm-pack.json.
 */
import { createHash } from 'node:crypto';
import { promises as fsp } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REPORT_DIR = path.join(ROOT, 'reports');

const REQUIRED = [
  'package/index.js',
  'package/client.js',
  'package/cordis.patch.yml',
  'package/dsh.plugin.json',
  'package/package.json',
  'package/LICENSE',
  'package/README.md',
  'package/README.en.md',
  'package/THIRD-PARTY-NOTICES.md',
  'package/THREAT-MODEL.md',
  'package/SECURITY.md',
  'package/COMPATIBILITY.md',
  'package/KNOWN-LIMITATIONS.md',
  'package/bin/cli.js',
];
const REQUIRED_PREFIXES = ['package/lib/', 'package/skills/', 'package/schemas/', 'package/examples/', 'package/locale/'];
const FORBIDDEN = [/^package\/node_modules\//, /^package\/test\//, /^package\/scripts\//, /^package\/reports\//, /^package\/\.git\//, /\.tgz$/, /__pycache__/, /\.pyc$/];

function npmCli() {
  if (process.env.npm_execpath) return { command: process.execPath, args: [process.env.npm_execpath] };
  const candidate = path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js');
  return { command: process.execPath, args: [candidate] };
}

async function main() {
  await fsp.mkdir(REPORT_DIR, { recursive: true });
  const npm = npmCli();
  const pack = spawnSync(npm.command, [...npm.args, 'pack', '--json'], {
    cwd: ROOT, encoding: 'utf8', timeout: 180000, windowsHide: true, shell: false,
  });
  if (pack.status !== 0) {
    console.error(pack.stdout, pack.stderr);
    throw new Error('npm pack failed');
  }
  const jsonStart = pack.stdout.indexOf('[');
  const packed = JSON.parse(pack.stdout.slice(jsonStart));
  const filename = packed[0].filename;
  const tarball = path.join(ROOT, filename);
  const bytes = await fsp.readFile(tarball);
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  const listing = spawnSync('tar', ['-tzf', tarball], { encoding: 'utf8', timeout: 60000, windowsHide: true });
  if (listing.status !== 0) throw new Error(`tar listing failed: ${listing.stderr}`);
  const entries = listing.stdout.split(/\r?\n/).filter(Boolean).sort();
  const missing = [
    ...REQUIRED.filter((entry) => !entries.includes(entry)),
    ...REQUIRED_PREFIXES.filter((prefix) => !entries.some((entry) => entry.startsWith(prefix))),
  ];
  const forbidden = entries.filter((entry) => FORBIDDEN.some((pattern) => pattern.test(entry)));
  const extractDir = await fsp.mkdtemp(path.join(tmpdir(), 'dspc-pack-'));
  const extract = spawnSync('tar', ['-xzf', tarball, '-C', extractDir], { encoding: 'utf8', timeout: 60000, windowsHide: true });
  if (extract.status !== 0) throw new Error(`tar extraction failed: ${extract.stderr}`);
  const findings = [];
  let textFiles = 0;
  const walk = async (dir) => {
    for (const entry of await fsp.readdir(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) { await walk(full); continue; }
      const stat = await fsp.stat(full);
      if (stat.size > 4 * 1024 * 1024) continue;
      const text = await fsp.readFile(full, 'utf8').catch(() => '');
      if (text === '') continue;
      textFiles += 1;
      const relative = path.relative(extractDir, full);
      if (/-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(text)) findings.push(`${relative}: private key block`);
      if (/\bAKIA[0-9A-Z]{16}\b/.test(text)) findings.push(`${relative}: AWS key pattern`);
      if (/sk-[A-Za-z0-9]{24,}/.test(text)) findings.push(`${relative}: API key pattern`);
    }
  };
  await walk(extractDir);
  await fsp.rm(extractDir, { recursive: true, force: true });
  const report = {
    generatedAt: new Date().toISOString(),
    filename,
    tarball,
    bytes: bytes.length,
    sha256,
    entries: entries.length,
    textFilesScanned: textFiles,
    required: { expected: REQUIRED.length + REQUIRED_PREFIXES.length, missing },
    forbidden,
    findings,
    sample: entries.slice(0, 80),
    ok: missing.length === 0 && forbidden.length === 0 && findings.length === 0,
  };
  await fsp.writeFile(path.join(REPORT_DIR, 'npm-pack.json'), `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify({ ok: report.ok, filename, bytes: report.bytes, entries: entries.length, missing, forbidden, findings }, null, 2));
  if (!report.ok) process.exitCode = 1;
}

await main();
