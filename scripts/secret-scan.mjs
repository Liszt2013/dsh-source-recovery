/**
 * Repository secret-pattern scan. This is a guardrail, not a substitute for a
 * dedicated scanner; it looks for private keys and common credential formats.
 */
import { promises as fsp } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REPORT_DIR = path.join(ROOT, 'reports');
const SKIP_DIRS = new Set(['node_modules', '.git', 'work']);
const PATTERNS = [
  { id: 'private-key-block', regex: /-----BEGIN (RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/ },
  { id: 'aws-access-key', regex: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: 'generic-api-key', regex: /\bsk-[A-Za-z0-9]{24,}\b/ },
  { id: 'github-token', regex: /\bghp_[A-Za-z0-9]{30,}\b/ },
  { id: 'slack-token', regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { id: 'inline-passphrase', regex: /(?:passphrase|password)\s*[:=]\s*["'][A-Za-z0-9!@#$%^&*()_+\-]{16,}["']/i },
];

const findings = [];
let scanned = 0;
async function walk(dir) {
  for (const entry of await fsp.readdir(dir, { withFileTypes: true })) {
    if (entry.name.startsWith('.') && entry.name !== '.github') {
      if (SKIP_DIRS.has(entry.name)) continue;
    }
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) { await walk(full); continue; }
    if (entry.name.endsWith('.tgz') || entry.name.endsWith('.png') || entry.name.endsWith('.jpg')) continue;
    const stat = await fsp.stat(full);
    if (stat.size > 2 * 1024 * 1024) continue;
    const text = await fsp.readFile(full, 'utf8').catch(() => '');
    if (text === '') continue;
    scanned += 1;
    for (const pattern of PATTERNS) {
      if (pattern.regex.test(text)) findings.push({ file: path.relative(ROOT, full), pattern: pattern.id });
    }
  }
}
await walk(ROOT);
await fsp.mkdir(REPORT_DIR, { recursive: true });
const report = { generatedAt: new Date().toISOString(), scannedFiles: scanned, patterns: PATTERNS.map((pattern) => pattern.id), findings, ok: findings.length === 0 };
await fsp.writeFile(path.join(REPORT_DIR, 'secret-scan.json'), `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify(report, null, 2));
if (!report.ok) process.exitCode = 1;
