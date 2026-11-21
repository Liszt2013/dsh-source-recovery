/** Evidence report writer (Markdown + JSON) for a source-recovery engagement. */
import { promises as fsp } from 'node:fs';
import path from 'node:path';
import { assertOutputFile } from './policy.js';
import { detectTools } from './backends.js';
import { identifyFile } from './identify.js';
import { buildPlan } from './recovery.js';
import { LEVELS, RECOVERY_POLICY } from './levels.js';
import { nowIso, sha256 } from './util.js';

function table(rows, columns) {
  const header = `| ${columns.join(' | ')} |`;
  const divider = `| ${columns.map(() => '---').join(' | ')} |`;
  return [header, divider, ...rows.map((row) => `| ${row.join(' | ')} |`)].join('\n');
}

/** Build the report object without writing it. */
export async function buildReport(input) {
  const identification = await identifyFile(input);
  const tools = await detectTools();
  const plan = await buildPlan(identification, tools);
  return {
    schema: 'dsh-source-recovery/report/1',
    generatedAt: nowIso(),
    target: {
      path: input,
      name: identification.name,
      size: identification.size,
      sha256: identification.sha256,
      family: identification.family,
      kind: identification.kind,
      entropy: identification.entropy,
    },
    recoveryCeiling: {
      level: plan.bestLevel,
      name: LEVELS[plan.bestLevel].name,
      description: LEVELS[plan.bestLevel].description,
    },
    plan: plan.steps,
    gaps: plan.gaps,
    policy: RECOVERY_POLICY,
    evidence: identification.evidence,
    backends: Object.fromEntries(Object.entries(tools).map(([id, tool]) => [id, {
      available: tool.available,
      version: tool.version ?? null,
      role: tool.role ?? tool.note ?? null,
    }])),
    unknowns: [
      'original source code was not necessarily recovered',
      'runtime behavior requires a separately authorized dynamic step',
      'build flags, symbols and comments may be lost',
    ],
  };
}

/** Render a report as Markdown. */
export function renderMarkdown(report) {
  const lines = [
    '# Source recovery report',
    '',
    `Generated: ${report.generatedAt}`,
    '',
    '## Target',
    '',
    table([
      ['Path', `\`${report.target.path}\``],
      ['Size', String(report.target.size)],
      ['SHA-256', `\`${report.target.sha256}\``],
      ['Family', report.target.family],
      ['Kind', report.target.kind],
      ['Entropy (sample)', String(report.target.entropy)],
    ], ['Field', 'Value']),
    '',
    '## Recovery ceiling',
    '',
    `**${report.recoveryCeiling.level} — ${report.recoveryCeiling.name}.** ${report.recoveryCeiling.description}`,
    '',
    '## Plan',
    '',
    table(report.plan.map((step) => [step.step, step.backend, step.level, step.available ? 'available' : 'gap']), ['Step', 'Backend', 'Level', 'State']),
    '',
    '## Gaps',
    '',
    report.gaps.length === 0 ? 'No backend gaps for the available path.' : table(report.gaps.map((gap) => [gap.missing, gap.step, gap.alternatives]), ['Missing', 'Step', 'Alternatives']),
    '',
    '## Policy and evidence',
    '',
    '- Authorization is required; the plugin never executes the target and never accesses the network.',
    '- Evidence is tagged observed / inferred / unknown. A lower recovery level is never presented as recovered source.',
    '- Same-process DSH plugins are not isolated from each other by tool approvals.',
    '',
    '## Unknowns',
    '',
    ...report.unknowns.map((entry) => `- ${entry}`),
    '',
  ];
  return lines.join('\n');
}

/** Write `<output>.md` and `<output>.json` through the output policy. */
export async function writeReport({ input, output, roots, overwrite = false, authorizationNote = '' }) {
  const report = await buildReport(input);
  report.authorizationNote = authorizationNote;
  const mdPath = path.resolve(output);
  const jsonPath = mdPath.replace(/\.[^./\\]+$/, '') + '.json';
  const md = await assertOutputFile(mdPath, { roots, overwrite, label: 'report output' });
  const json = jsonPath === mdPath
    ? { path: `${mdPath}.json` }
    : await assertOutputFile(jsonPath, { roots, overwrite, label: 'report JSON output' });
  const mdText = renderMarkdown(report);
  const jsonText = `${JSON.stringify(report, null, 2)}\n`;
  await fsp.writeFile(md.path, mdText, { flag: 'wx', mode: 0o600 });
  await fsp.writeFile(json.path, jsonText, { flag: 'wx', mode: 0o600 });
  return {
    markdownPath: md.path,
    jsonPath: json.path,
    markdownSha256: sha256(mdText),
    jsonSha256: sha256(jsonText),
    targetSha256: report.target.sha256,
    recoveryCeiling: report.recoveryCeiling,
    gaps: report.gaps,
  };
}
