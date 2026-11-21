/** Portable, hash-verified evidence bundle (ZIP + manifest) for handoff. */
import { promises as fsp } from 'node:fs';
import path from 'node:path';
import { RecoveryError } from './errors.js';
import { assertOutputFile, createTempFile, isInside, publishTempFile, removeTempFile } from './policy.js';
import { readZipEntry, scanZip } from './archive.js';
import { detectTools } from './backends.js';
import { identifyFile } from './identify.js';
import { LEVELS, RECOVERY_POLICY } from './levels.js';
import { buildPlan } from './recovery.js';
import { buildReport, renderMarkdown } from './report.js';
import { sha256, nowIso } from './util.js';

const digestHex = (data) => sha256(data).toString('hex');
import { makeStoredZip } from './zipwrite.js';

const MAX_ARTIFACT_FILES = 500;
const MAX_ARTIFACT_BYTES = 256 * 1024 * 1024;
const MAX_ARTIFACT_FILE_BYTES = 64 * 1024 * 1024;

async function collectArtifacts(root, limits = {}) {
  const resolved = path.resolve(root);
  const artifacts = [];
  let total = 0;
  const walk = async (dir) => {
    for (const entry of await fsp.readdir(dir, { withFileTypes: true })) {
      if (artifacts.length >= MAX_ARTIFACT_FILES) throw new RecoveryError('E_LIMIT', 'artifact tree exceeds the file-count limit');
      const full = path.join(dir, entry.name);
      const stat = await fsp.lstat(full);
      if (stat.isSymbolicLink()) throw new RecoveryError('E_PATH_UNSAFE', `artifact tree contains a symlink: ${path.relative(resolved, full)}`);
      if (stat.isDirectory()) { await walk(full); continue; }
      if (!stat.isFile()) throw new RecoveryError('E_PATH_UNSAFE', `artifact tree contains a special file: ${path.relative(resolved, full)}`);
      if (stat.size > MAX_ARTIFACT_FILE_BYTES) throw new RecoveryError('E_LIMIT', `artifact exceeds the per-file limit: ${path.relative(resolved, full)}`);
      if (total + stat.size > MAX_ARTIFACT_BYTES) throw new RecoveryError('E_LIMIT', 'artifact tree exceeds the total size limit');
      const relative = path.relative(resolved, full).split(path.sep).join('/');
      const data = await fsp.readFile(full);
      artifacts.push({ path: relative, bytes: data.length, sha256: digestHex(data) });
      total += data.length;
      if (artifacts.length > MAX_ARTIFACT_FILES) throw new RecoveryError('E_LIMIT', 'artifact tree exceeds the file-count limit');
    }
  };
  await walk(resolved);
  artifacts.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return { artifacts, total, root: resolved };
}

/** Build an evidence bundle from a target and optional artifact directory. */
export async function createEvidenceBundle(options) {
  const identification = await identifyFile(options.input, { maxInputBytes: options.maxInputBytes });
  const tools = await detectTools();
  const plan = await buildPlan(identification, tools);
  const report = await buildReport(options.input);
  const reportMarkdown = renderMarkdown(report);
  const reportJson = `${JSON.stringify(report, null, 2)}\n`;
  const artifactSet = options.artifactsDir === undefined
    ? { artifacts: [], total: 0, root: null }
    : await collectArtifacts(options.artifactsDir);
  const generatedAt = nowIso();
  const manifestBase = {
    schema: 'dsh-source-recovery/evidence/1',
    bundleVersion: 1,
    generatedAt,
    pluginVersion: options.pluginVersion ?? '0.2.0',
    target: {
      name: identification.name,
      size: identification.size,
      sha256: identification.sha256,
      family: identification.family,
      kind: identification.kind,
    },
    recovery: {
      ceiling: {
        level: plan.bestLevel,
        name: LEVELS[plan.bestLevel].name,
        description: LEVELS[plan.bestLevel].description,
      },
      achieved: options.achievedLevel ?? null,
      note: options.achievedLevel === undefined ? 'bundle was created without running recovery; achieved level is unknown' : 'achieved level supplied by the caller',
      plan: plan.steps,
      gaps: plan.gaps,
    },
    tools: Object.fromEntries(Object.entries(tools).map(([id, tool]) => [id, {
      available: tool.available === true,
      version: tool.version ?? null,
    }])),
    policy: RECOVERY_POLICY,
    authorizationNote: options.authorizationNote ?? '',
    artifacts: artifactSet.artifacts,
    report: {
      markdownSha256: digestHex(reportMarkdown),
      jsonSha256: digestHex(reportJson),
    },
    artifactsRoot: artifactSet.root === null ? null : path.basename(artifactSet.root),
  };
  const bundleDigest = digestHex(JSON.stringify(manifestBase));
  const manifest = { ...manifestBase, bundleDigest };
  const entries = [
    { name: 'manifest.json', data: `${JSON.stringify(manifest, null, 2)}\n` },
    { name: 'report.md', data: reportMarkdown },
    { name: 'report.json', data: reportJson },
  ];
  for (const artifact of artifactSet.artifacts) {
    const absolute = path.join(artifactSet.root, ...artifact.path.split('/'));
    const data = await fsp.readFile(absolute);
    if (digestHex(data) !== artifact.sha256) throw new RecoveryError('E_IO', `artifact changed while bundling: ${artifact.path}`);
    entries.push({ name: `artifacts/${artifact.path}`, data });
  }
  const zip = makeStoredZip(entries);
  const checked = await assertOutputFile(options.output, {
    roots: options.roots,
    overwrite: options.overwrite === true,
    label: 'evidence bundle output',
  });
  const temp = await createTempFile(path.dirname(checked.path), 'bundle');
  try {
    await temp.handle.writeFile(zip);
    await temp.handle.sync();
    await temp.handle.close();
    await publishTempFile(temp.path, checked.path, options.overwrite === true);
  } catch (error) {
    await temp.handle.close().catch(() => {});
    await removeTempFile(temp.path);
    throw new RecoveryError('E_IO', 'failed to publish the evidence bundle', { cause: error });
  }
  return {
    output: checked.path,
    bytes: zip.length,
    sha256: digestHex(zip),
    bundleDigest,
    manifest,
    artifactCount: artifactSet.artifacts.length,
    artifactBytes: artifactSet.total,
  };
}

/** Verify every declared hash inside an evidence bundle. */
export async function verifyEvidenceBundle(options) {
  const { entries } = await scanZip(options.bundle);
  const byName = new Map(entries.map((entry) => [entry.name, entry]));
  const manifestEntry = byName.get('manifest.json');
  if (manifestEntry === undefined) throw new RecoveryError('E_BUNDLE_INVALID', 'bundle has no manifest.json');
  let manifest;
  try {
    manifest = JSON.parse((await readZipEntry(options.bundle, manifestEntry)).toString('utf8'));
  } catch {
    throw new RecoveryError('E_BUNDLE_INVALID', 'manifest.json is not valid JSON');
  }
  if (manifest?.schema !== 'dsh-source-recovery/evidence/1') throw new RecoveryError('E_BUNDLE_INVALID', 'unsupported evidence bundle schema');
  const mismatches = [];
  let verified = 0;
  const checkEntry = async (name, expected, size) => {
    const entry = byName.get(name);
    if (entry === undefined) { mismatches.push({ path: name, problem: 'missing' }); return; }
    const content = await readZipEntry(options.bundle, entry);
    if (content.length !== size) mismatches.push({ path: name, problem: 'size', expected: size, actual: content.length });
    if (digestHex(content) !== expected) mismatches.push({ path: name, problem: 'sha256' });
    verified += 1;
  };
  for (const artifact of Array.isArray(manifest.artifacts) ? manifest.artifacts : []) {
    await checkEntry(`artifacts/${artifact.path}`, artifact.sha256, artifact.bytes);
  }
  const reportMd = byName.get('report.md');
  if (reportMd === undefined) mismatches.push({ path: 'report.md', problem: 'missing' });
  else {
    const content = await readZipEntry(options.bundle, reportMd);
    if (digestHex(content) !== manifest.report?.markdownSha256) mismatches.push({ path: 'report.md', problem: 'sha256' });
    else verified += 1;
  }
  const reportJson = byName.get('report.json');
  if (reportJson === undefined) mismatches.push({ path: 'report.json', problem: 'missing' });
  else {
    const content = await readZipEntry(options.bundle, reportJson);
    if (digestHex(content) !== manifest.report?.jsonSha256) mismatches.push({ path: 'report.json', problem: 'sha256' });
    else verified += 1;
  }
  const { bundleDigest: ignoredDigest, ...manifestWithoutDigest } = manifest;
  void ignoredDigest;
  const expectedDigest = digestHex(JSON.stringify(manifestWithoutDigest));
  if (expectedDigest !== manifest.bundleDigest) mismatches.push({ path: 'manifest.json', problem: 'bundle-digest' });
  const declared = new Set((manifest.artifacts ?? []).map((artifact) => `artifacts/${artifact.path}`));
  const allowed = new Set(['manifest.json', 'report.md', 'report.json', ...declared]);
  const extras = entries.filter((entry) => !allowed.has(entry.name)).map((entry) => entry.name);
  for (const extra of extras) mismatches.push({ path: extra, problem: 'undeclared-entry' });
  return {
    ok: mismatches.length === 0,
    schema: manifest.schema,
    target: manifest.target,
    generatedAt: manifest.generatedAt,
    artifactCount: Array.isArray(manifest.artifacts) ? manifest.artifacts.length : 0,
    verifiedFiles: verified,
    mismatches,
    undeclaredArtifacts: extras,
    checkedEntries: entries.length,
    note: mismatches.length === 0
      ? 'all declared hashes and the bundle digest match'
      : 'bundle is NOT evidence-safe; do not rely on unverified files',
  };
}

export { collectArtifacts };
