/**
 * Test runner with an explicit four-way taxonomy.
 *
 *   passed | failed | skipped | unavailable
 *
 * "unavailable" is for an implemented capability whose runtime is absent on this
 * host; it is never converted into a pass. The machine-readable report is
 * reports/tests.json; the console summary prints the same counts.
 */
import { promises as fsp } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TEST_DIR = path.join(ROOT, 'test');
const REPORT_DIR = path.join(ROOT, 'reports');

/** @type {Array<{name:string, fn:Function, meta:any}>} */
const tests = [];

function register(name, fn, meta = {}) {
  tests.push({ name, fn, meta });
}

async function main() {
  const files = (await fsp.readdir(TEST_DIR)).filter((name) => name.endsWith('.test.mjs')).sort();
  for (const file of files) {
    const module = await import(pathToFileURL(path.join(TEST_DIR, file)).href);
    if (typeof module.default !== 'function') throw new Error(`${file} must default-export a registration function`);
    module.default((name, fn, meta) => register(`${file.replace(/\.test\.mjs$/, '')} :: ${name}`, fn, meta));
  }
  const results = [];
  for (const test of tests) {
    const started = Date.now();
    let status = 'passed';
    let detail = '';
    try {
      if (typeof test.meta.gate === 'function') {
        const gate = await test.meta.gate();
        if (gate && gate.available === false) {
          status = 'unavailable';
          detail = gate.reason ?? 'runtime unavailable';
        }
      }
      if (status === 'passed' && test.meta.skip === true) {
        status = 'skipped';
        detail = test.meta.reason ?? 'skipped by declaration';
      }
      if (status === 'passed') {
        const outcome = await test.fn();
        if (outcome && typeof outcome === 'object' && outcome.skipped === true) {
          status = outcome.unavailable === true ? 'unavailable' : 'skipped';
          detail = outcome.reason ?? '';
        } else if (typeof outcome === 'string') {
          detail = outcome;
        }
      }
    } catch (error) {
      status = 'failed';
      detail = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
    }
    results.push({ name: test.name, status, detail: detail.slice(0, 500), durationMs: Date.now() - started });
    const marker = status === 'passed' ? 'ok' : status === 'failed' ? 'FAIL' : status.toUpperCase();
    process.stdout.write(`${marker.padEnd(12)} ${test.name}${detail ? ` — ${detail}` : ''}\n`);
  }
  const counts = {
    total: results.length,
    passed: results.filter((row) => row.status === 'passed').length,
    failed: results.filter((row) => row.status === 'failed').length,
    skipped: results.filter((row) => row.status === 'skipped').length,
    unavailable: results.filter((row) => row.status === 'unavailable').length,
  };
  const report = {
    generatedAt: new Date().toISOString(),
    platform: process.platform,
    arch: process.arch,
    node: process.version,
    counts,
    results,
    note: 'unavailable means the adapter/capability is implemented but its runtime is absent on this host; it is not a pass',
  };
  await fsp.mkdir(REPORT_DIR, { recursive: true });
  await fsp.writeFile(path.join(REPORT_DIR, 'tests.json'), `${JSON.stringify(report, null, 2)}\n`);
  process.stdout.write(`\n${JSON.stringify(counts)}\nreport: reports/tests.json\n`);
  if (counts.failed > 0) process.exitCode = 1;
}

await main();
