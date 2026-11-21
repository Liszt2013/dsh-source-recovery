/**
 * Fresh-profile acceptance: pack, install into an isolated DSH_HOME, boot Web,
 * verify plugin/table/client graph/routes/CLI, then uninstall and prove clean.
 */
import { createHash } from 'node:crypto';
import { promises as fsp } from 'node:fs';
import { createServer } from 'node:net';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REPORT_DIR = path.join(ROOT, 'reports');
const WORKSPACE_ROOT = path.resolve(ROOT, '..');
const PROFILE = 'web';
const PLUGIN = 'dsh-source-recovery';
const steps = [];
const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const DSH_HOME = path.join(WORKSPACE_ROOT, '.dsh-verify', `source-recovery-${stamp}`);
const SERVER_WORKSPACE = path.join(DSH_HOME, 'workspace');

function record(id, status, detail, extra = {}) {
  steps.push({ id, status, detail: String(detail ?? '').slice(0, 1200), ...extra });
  console.log(`${status.toUpperCase().padEnd(11)} ${id} — ${String(detail ?? '').slice(0, 280)}`);
}

function sha256(buffer) { return createHash('sha256').update(buffer).digest('hex'); }

function sanitizeDeep(value) {
  if (typeof value === 'string') return value.replace(/token(?:=|%3D)[^\s&"'<>]+/gi, 'token=REDACTED');
  if (Array.isArray(value)) return value.map((entry) => sanitizeDeep(entry));
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, sanitizeDeep(entry)]));
  return value;
}

function dshCli() {
  if (process.env.DSH_CLI) return process.env.DSH_CLI;
  if (process.platform === 'win32') return 'C:\\Users\\XPS\\AppData\\Local\\Programs\\DeepSeek Harness\\resources\\runtime\\cli\\bin\\dsh.cmd';
  return 'dsh';
}

function runDsh(args, { timeout = 300000, cwd = ROOT } = {}) {
  const env = { ...process.env, DSH_HOME };
  if (process.platform === 'win32') {
    const quote = (value) => (/[\s"]/.test(value) ? `"${value.replace(/"/g, '\\"')}"` : value);
    const commandLine = `${quote(dshCli())} ${args.map(quote).join(' ')}`;
    return spawnSync(process.env.ComSpec ?? 'cmd.exe', ['/d', '/s', '/c', `"${commandLine}"`], {
      cwd, env, encoding: 'utf8', timeout, windowsHide: true, windowsVerbatimArguments: true, maxBuffer: 16 * 1024 * 1024,
    });
  }
  return spawnSync(dshCli(), args, { cwd, env, encoding: 'utf8', timeout, windowsHide: true, maxBuffer: 16 * 1024 * 1024 });
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.listen(0, '127.0.0.1', () => { const { port } = server.address(); server.close(() => resolve(port)); });
    server.on('error', reject);
  });
}

async function waitFor(predicate, timeoutMs, intervalMs = 500) {
  const deadline = Date.now() + timeoutMs;
  let lastError = 'timeout';
  while (Date.now() < deadline) {
    try { const value = await predicate(); if (value) return value; } catch (error) { lastError = error instanceof Error ? error.message : String(error); }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error(`condition not met within ${timeoutMs}ms: ${lastError}`);
}

async function fetchText(url) {
  const response = await fetch(url, { headers: { accept: 'application/json' } });
  return { status: response.status, text: await response.text() };
}

function killTree(child) {
  if (!child || child.pid === undefined) return;
  if (process.platform === 'win32') spawnSync('taskkill', ['/pid', String(child.pid), '/T', '/F'], { windowsHide: true, timeout: 30000 });
  else { try { process.kill(-child.pid, 'SIGKILL'); } catch { try { child.kill('SIGKILL'); } catch { /* gone */ } } }
}

async function snapshotProfile() {
  const dir = path.join(DSH_HOME, 'profiles', PROFILE);
  const snapshot = {};
  for (const file of ['package.json', 'cordis.yml', 'cordis.patch.yml']) {
    try {
      const bytes = await fsp.readFile(path.join(dir, file));
      snapshot[file] = { sha256: sha256(bytes), text: bytes.toString('utf8') };
    } catch { snapshot[file] = null; }
  }
  return snapshot;
}

async function main() {
  await fsp.mkdir(REPORT_DIR, { recursive: true });
  await fsp.mkdir(SERVER_WORKSPACE, { recursive: true });
  const report = { generatedAt: new Date().toISOString(), dshHome: DSH_HOME, profile: PROFILE, steps };
  let server;
  let serverOutput = '';
  try {
    const version = runDsh(['--version'], { timeout: 60000 });
    if (version.status !== 0) throw new Error(`dsh --version failed: ${version.stderr}`);
    report.dshVersion = version.stdout.trim();
    record('toolchain', 'passed', `dsh ${report.dshVersion}; node ${process.version}`);

    const npmCli = process.env.npm_execpath ?? path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js');
    const pack = spawnSync(process.execPath, [npmCli, 'pack', '--json'], { cwd: ROOT, encoding: 'utf8', timeout: 180000, windowsHide: true });
    if (pack.status !== 0) throw new Error(`npm pack failed: ${pack.stderr}`);
    const tarball = path.join(ROOT, JSON.parse(pack.stdout.slice(pack.stdout.indexOf('[')))[0].filename);
    report.tarball = { path: tarball, bytes: (await fsp.stat(tarball)).size, sha256: sha256(await fsp.readFile(tarball)) };
    record('pack', 'passed', `${path.basename(tarball)} sha256=${report.tarball.sha256.slice(0, 16)}…`);

    const install = runDsh(['plugin', '--profile', PROFILE, 'add', tarball]);
    report.install = { status: install.status, stdoutTail: install.stdout?.slice(-1500), stderrTail: install.stderr?.slice(-1500) };
    if (install.status !== 0) throw new Error(`plugin install failed: ${install.stderr?.slice(-700)}`);
    record('install', 'passed', 'tarball installed into isolated DSH_HOME');

    const dump = runDsh(['--profile', PROFILE, '--dump-config'], { timeout: 120000 });
    report.dumpConfig = { status: dump.status, length: dump.stdout?.length ?? 0 };
    if (dump.status !== 0) throw new Error(`dump-config failed: ${dump.stderr?.slice(-700)}`);
    if (!dump.stdout.includes(PLUGIN)) throw new Error('composed profile does not list the plugin');
    record('compose', 'passed', 'plugin present in composed profile');

    const installedPackage = path.join(DSH_HOME, 'profiles', PROFILE, 'node_modules', PLUGIN);
    const clientBytes = await fsp.readFile(path.join(installedPackage, 'client.js'));
    if (!clientBytes.toString('utf8').includes('__ModuleLoader__.load')) throw new Error('client bundle is not a ModuleLoader module');
    record('client-bundle', 'passed', `client.js ${clientBytes.length} bytes`);

    // Load the packaged skill through DSH's own SkillRegistry. This reproduces
    // the historical "source must be a string" failure if the registration is
    // missing `source`.
    if (process.platform === 'win32') {
      const electron = 'C:\\Users\\XPS\\AppData\\Local\\Programs\\DeepSeek Harness\\DeepSeek Harness.exe';
      const resources = 'C:\\Users\\XPS\\AppData\\Local\\Programs\\DeepSeek Harness\\resources';
      const probe = spawnSync(electron, ['--expose-internals', path.join(ROOT, 'scripts', 'skill-load-probe.mjs')], {
        cwd: ROOT,
        env: { ...process.env, ELECTRON_RUN_AS_NODE: '1', DSH_PLUGIN_ROOT: installedPackage, DSH_RESOURCES: resources },
        encoding: 'utf8', timeout: 120000, windowsHide: true,
      });
      if (probe.status !== 0) throw new Error(`skill load failed: ${(probe.stderr || probe.stdout).slice(-700)}`);
      report.skillLoad = JSON.parse(probe.stdout.trim());
      if (report.skillLoad.ok !== true || report.skillLoad.source !== 'bundled') throw new Error('skill load returned an unexpected definition');
      record('skill-load', 'passed', `DSH SkillRegistry loaded "${report.skillLoad.name}" (source=${report.skillLoad.source}, ${report.skillLoad.contentBytes} bytes)`);
    }

    const port = await freePort();
    const appArgs = ['--profile', PROFILE, '--no-open', '--port', String(port)];
    const serverEnv = { ...process.env, DSH_HOME };
    let command = dshCli();
    let args = appArgs.slice();
    if (process.platform === 'win32') {
      const resources = 'C:\\Users\\XPS\\AppData\\Local\\Programs\\DeepSeek Harness\\resources';
      command = 'C:\\Users\\XPS\\AppData\\Local\\Programs\\DeepSeek Harness\\DeepSeek Harness.exe';
      args = ['--expose-internals', `${resources}\\app.asar\\dsh\\node_modules\\@deepseek-ai\\dsh-desktop-host\\lib\\cli.js`, ...appArgs];
      serverEnv.ELECTRON_RUN_AS_NODE = '1';
    }
    server = spawn(command, args, { cwd: SERVER_WORKSPACE, env: serverEnv, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    server.stdout?.on('data', (chunk) => { serverOutput += chunk.toString(); });
    server.stderr?.on('data', (chunk) => { serverOutput += chunk.toString(); });
    report.serverCommand = { command, args, pid: server.pid };
    const base = `http://127.0.0.1:${port}`;
    const health = await waitFor(async () => {
      const response = await fetchText(`${base}/plugins/${PLUGIN}/api/health`);
      if (response.status !== 200) throw new Error(`HTTP ${response.status}`);
      return JSON.parse(response.text);
    }, 120000);
    report.health = health;
    if (health.ok !== true || health.pluginVersion !== '0.2.0' || health.toolCount !== 10) throw new Error(`unexpected health: ${JSON.stringify(health)}`);
    record('boot', 'passed', `web profile booted on ${base}`);
    record('http-health', 'passed', `plugin ${health.pluginVersion}, toolCount=${health.toolCount}`);

    const routes = {};
    for (const name of ['capabilities', 'doctor', 'selftest']) {
      const response = await fetchText(`${base}/plugins/${PLUGIN}/api/${name}`);
      await fsp.mkdir(path.join(REPORT_DIR, 'acceptance-http'), { recursive: true });
      await fsp.writeFile(path.join(REPORT_DIR, 'acceptance-http', `${name}.json`), response.text);
      if (response.status !== 200) throw new Error(`route ${name} returned ${response.status}`);
      const payload = JSON.parse(response.text);
      if (payload.ok !== true) throw new Error(`route ${name} not ok: ${payload.code} ${payload.message}`);
      routes[name] = { status: response.status, bytes: response.text.length };
      if (name === 'capabilities') routes.capabilities.families = payload.families.length;
      if (name === 'selftest') routes.selftest.counts = payload.counts;
    }
    report.routes = routes;
    record('http-routes', 'passed', JSON.stringify(routes));

    const startupUrl = await waitFor(async () => {
      const match = /dsh web:\s+(http:\/\/\S+)/.exec(serverOutput);
      if (match === null) throw new Error('startup URL not printed yet');
      return match[1];
    }, 30000);
    const startup = new URL(startupUrl);
    const token = startup.searchParams.get('token') ?? '';
    report.startup = { origin: startup.origin, tokenPresent: token.length > 0 };
    const htmlEntry = await fetch(`${startup.origin}/?token=${encodeURIComponent(token)}`, { headers: { accept: 'text/html' }, redirect: 'manual' });
    const cookie = (htmlEntry.headers.getSetCookie?.() ?? []).map((entry) => entry.split(';')[0]).join('; ');
    let htmlResponse = htmlEntry;
    if (htmlResponse.status >= 300 && htmlResponse.status < 400) {
      const location = htmlResponse.headers.get('location');
      if (location === null) throw new Error(`boot HTML redirect without location (${htmlResponse.status})`);
      htmlResponse = await fetch(new URL(location, startup.origin).href, { headers: { accept: 'text/html', ...(cookie === '' ? {} : { cookie }) }, redirect: 'manual' });
    }
    if (htmlResponse.status !== 200) throw new Error(`boot HTML returned ${htmlResponse.status}`);
    const html = await htmlResponse.text();
    await fsp.mkdir(path.join(REPORT_DIR, 'acceptance-http'), { recursive: true });
    await fsp.writeFile(path.join(REPORT_DIR, 'acceptance-http', 'boot.html'), html);
    report.bootHtml = { bytes: html.length, hasPluginGraph: html.includes(PLUGIN) };
    if (!html.includes(PLUGIN)) throw new Error('boot HTML does not include the plugin in the client graph');
    const match = /(?:^|["'])(plugins\/\?\?[^"'\s]*dsh-source-recovery\/client\.js[^"'\s]*)/.exec(html);
    if (match === null) throw new Error('boot HTML advertises no client bundle URL');
    const clientUrl = new URL(match[1].replace(/&amp;/g, '&'), `${startup.origin}/`).href;
    const clientResponse = await fetch(clientUrl);
    if (clientResponse.status !== 200) throw new Error(`client bundle returned ${clientResponse.status}`);
    const clientText = await clientResponse.text();
    if (!clientText.includes('sidebar.panellist') || !clientText.includes("label: 'Reverse'")) throw new Error('served client bundle lacks the Reverse sidebar entry');
    report.clientRoute = { status: clientResponse.status, bytes: clientText.length };
    record('http-client', 'passed', `client bundle served (${clientText.length} bytes); Reverse entry in boot graph`);

    const cliPath = path.join(installedPackage, 'bin', 'cli.js');
    const cliWork = path.join(DSH_HOME, 'cli-work');
    await fsp.mkdir(cliWork, { recursive: true });
    const cliEnv = { ...process.env, DSH_SOURCE_RECOVERY_ROOTS: cliWork };
    const selftest = spawnSync(process.execPath, [cliPath, 'selftest', '--json'], { cwd: cliWork, env: cliEnv, encoding: 'utf8', timeout: 180000, windowsHide: true });
    const selftestPayload = JSON.parse(selftest.stdout.trim().split(/\r?\n/).filter(Boolean).pop());
    if (selftest.status !== 0 || selftestPayload.ok !== true) throw new Error('installed CLI self-test failed');
    const target = path.join(cliWork, 'sample.js');
    await fsp.writeFile(target, 'export const answer = 42;\n');
    const identify = spawnSync(process.execPath, [cliPath, 'identify', '--in', target, '--json'], { cwd: cliWork, env: cliEnv, encoding: 'utf8', timeout: 120000, windowsHide: true });
    const identifyPayload = JSON.parse(identify.stdout.trim().split(/\r?\n/).filter(Boolean).pop());
    if (identify.status !== 0 || identifyPayload.ok !== true || identifyPayload.family !== 'electron') throw new Error('installed CLI identify failed');
    const reportPath = path.join(cliWork, 'evidence.md');
    const reportRun = spawnSync(process.execPath, [cliPath, 'report', '--in', target, '--out', reportPath, '--authorized', '--json'], { cwd: cliWork, env: cliEnv, encoding: 'utf8', timeout: 120000, windowsHide: true });
    if (reportRun.status !== 0) throw new Error(`installed CLI report failed: ${reportRun.stderr}`);
    if (!(await fsp.readFile(reportPath, 'utf8')).includes('Recovery ceiling')) throw new Error('report markdown missing recovery ceiling');
    const bundleArtifacts = path.join(cliWork, 'bundle-artifacts');
    await fsp.mkdir(bundleArtifacts, { recursive: true });
    await fsp.writeFile(path.join(bundleArtifacts, 'note.txt'), 'evidence artifact\n');
    const bundlePath = path.join(cliWork, 'evidence.zip');
    const bundleRun = spawnSync(process.execPath, [cliPath, 'bundle', '--in', target, '--out', bundlePath, '--artifacts', bundleArtifacts, '--authorized', '--json'], { cwd: cliWork, env: cliEnv, encoding: 'utf8', timeout: 120000, windowsHide: true });
    if (bundleRun.status !== 0) throw new Error(`installed CLI bundle failed: ${bundleRun.stderr}`);
    const bundlePayload = JSON.parse(bundleRun.stdout.trim().split(/\r?\n/).filter(Boolean).pop());
    if (bundlePayload.ok !== true || bundlePayload.artifactCount !== 1) throw new Error(`unexpected bundle payload: ${bundleRun.stdout.slice(0, 500)}`);
    const verifyRun = spawnSync(process.execPath, [cliPath, 'verify-bundle', '--in', bundlePath, '--json'], { cwd: cliWork, env: cliEnv, encoding: 'utf8', timeout: 120000, windowsHide: true });
    if (verifyRun.status !== 0) throw new Error(`installed CLI verify-bundle failed: ${verifyRun.stderr}`);
    const verifyPayload = JSON.parse(verifyRun.stdout.trim().split(/\r?\n/).filter(Boolean).pop());
    if (verifyPayload.ok !== true || verifyPayload.mismatches.length !== 0) throw new Error(`bundle verification failed: ${verifyRun.stdout.slice(0, 500)}`);
    report.installedCli = {
      selftest: selftestPayload.counts,
      identifyFamily: identifyPayload.family,
      report: true,
      bundle: { artifactCount: bundlePayload.artifactCount, sha256: bundlePayload.sha256, verified: verifyPayload.verifiedFiles },
    };
    record('installed-cli', 'passed', `self-test ${JSON.stringify(selftestPayload.counts)}; identify ${identifyPayload.family}; report and hash-verified evidence bundle`);

    killTree(server);
    server = undefined;
    await new Promise((resolve) => setTimeout(resolve, 1200));
    report.serverOutputTail = serverOutput.slice(-2500);

    const before = await snapshotProfile();
    const removal = runDsh(['plugin', '--profile', PROFILE, 'remove', PLUGIN]);
    report.uninstall = { status: removal.status, stdoutTail: removal.stdout?.slice(-1200), stderrTail: removal.stderr?.slice(-1200) };
    if (removal.status !== 0) throw new Error(`plugin remove failed: ${removal.stderr?.slice(-700)}`);
    const after = await snapshotProfile();
    const dumpAfter = runDsh(['--profile', PROFILE, '--dump-config'], { timeout: 120000 });
    if (dumpAfter.status !== 0) throw new Error('dump-config after uninstall failed');
    if (dumpAfter.stdout.includes(PLUGIN)) throw new Error('composed profile still lists the plugin after uninstall');
    const pkgAfter = JSON.parse(after['package.json']?.text ?? '{}');
    const residue = Object.keys(pkgAfter.dependencies ?? {}).filter((name) => name.includes(PLUGIN));
    if (residue.length > 0) throw new Error(`profile package.json still depends on ${residue.join(', ')}`);
    if (await fsp.lstat(installedPackage).then(() => true).catch(() => false)) throw new Error('installed package directory remains after uninstall');
    report.uninstall.clean = true;
    report.uninstall.profileBefore = before;
    record('uninstall', 'passed', 'plugin removed; composed profile and package.json are clean');

    report.ok = steps.every((step) => step.status === 'passed');
  } catch (error) {
    report.ok = false;
    record('failure', 'failed', error instanceof Error ? error.message : String(error));
    report.serverOutputTail = serverOutput.slice(-2500);
  } finally {
    if (server !== undefined) killTree(server);
    report.summary = { passed: steps.filter((step) => step.status === 'passed').length, failed: steps.filter((step) => step.status === 'failed').length, total: steps.length };
    await fsp.mkdir(REPORT_DIR, { recursive: true });
    await fsp.writeFile(path.join(REPORT_DIR, 'acceptance.json'), `${JSON.stringify(sanitizeDeep(report), null, 2)}\n`);
    console.log(`\nacceptance ${report.ok ? 'PASSED' : 'FAILED'}: ${JSON.stringify(report.summary)}`);
    console.log(`report: reports/acceptance.json\nDSH_HOME: ${DSH_HOME}`);
    if (!report.ok) process.exitCode = 1;
  }
}

await main();
