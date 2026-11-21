/**
 * Verify the packaged skill can be registered and then LOADED by DSH's own
 * skill registry. This reproduces the historical failure:
 *   loaded skill "..." source must be a string
 *
 * Run with the installed Electron runtime (ELECTRON_RUN_AS_NODE=1), because the
 * DSH packages live inside resources/app.asar. The script is diagnostic only.
 */
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const resources = process.env.DSH_RESOURCES
  ?? 'C:\\Users\\XPS\\AppData\\Local\\Programs\\DeepSeek Harness\\resources';
const modules = path.join(resources, 'app.asar', 'dsh', 'node_modules', '@deepseek-ai');
const project = process.env.DSH_PLUGIN_ROOT ?? path.resolve(process.cwd());

const { Context } = await import(pathToFileURL(path.join(modules, 'cordis', 'lib', 'index.js')).href);
const { SkillRegistry } = await import(pathToFileURL(path.join(modules, 'dsh-skill', 'lib', 'index.js')).href);

const ctx = new Context();
await ctx.plugin(SkillRegistry);
const registry = ctx.skills ?? ctx.get('skills');
if (registry === undefined) throw new Error('DSH skill registry service did not start');

const plugin = await import(pathToFileURL(path.join(project, 'index.js')).href);
const fake = {
  tools: { register: () => () => {} },
  skills: registry,
  effect: (callback) => callback(),
  get: () => undefined,
  logger: { debug() {}, warn() {}, error() {} },
};
await plugin.apply(fake, {});

const summaries = await registry.list({});
const summary = summaries.find((entry) => entry.name === 'dsh-source-recovery');
if (summary === undefined) throw new Error('skill was not advertised by the registry');
const loaded = await registry.get('dsh-source-recovery', {});
if (loaded === undefined) throw new Error('skill registry returned no definition');
if (typeof loaded.source !== 'string' || loaded.source.length === 0) throw new Error('loaded skill source is not a non-empty string');
if (typeof loaded.content !== 'string' || loaded.content.length === 0) throw new Error('loaded skill content is empty');
process.stdout.write(`${JSON.stringify({
  ok: true,
  name: loaded.name,
  source: loaded.source,
  provider: loaded.provider,
  contentBytes: Buffer.byteLength(loaded.content),
  summaryCount: summaries.length,
}, null, 2)}\n`);
