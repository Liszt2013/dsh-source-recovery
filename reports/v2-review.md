# dsh-source-recovery v0.2.0 — independent adversarial review

Reviewer: v2-reviewer (read-only adversarial review)
Target: `C:\Users\XPS\Documents\deepseek-harness\default-workspace\dsh-source-recovery` (snapshot 2026-11-21 15:28 local)
Package: `dsh-source-recovery@0.2.0` (private, DSH bundle + host plugin + client + skill + CLI + tests)

## Scope, method and ground truth

- Static read of every runtime file (`index.js`, `client.js`, `bin/cli.js`, all of `lib/`, `test/`, `scripts/`, docs, schemas, reports).
- Contract checks against the installed DSH `0.2.2-rc.5` packages (`@deepseek-ai/dsh-tools`, `dsh-skill`, `dsh-client-ui-layout`, `dsh-client-ui-sidebar`, `dsh-agent-preset` dsh-doc) read through the ASAR-aware file tool.
- Targeted, isolated experiments under `%TEMP%\dsh-okfsn4\v2review` (scratch only; **no project source was modified**). Only this report was added to the project.
- No network, no installs, no target execution, no pushes.
- Snapshot hashes of reviewed runtime files (SHA-256, first 12 hex): index `8BF3EB5C5495`, api `BE23E64150D3`, archive `A77DACE9FE0A`, bundle `C517BED83512`, dotnet `46B53AE0FDC4`, firmware `F6661DF0B7D4`, lock `17C50A3E9680`, recovery `8F302CDF2620`, sourcemap `B09520269B93`, identify `73D41F4D5178`, levels `271ED2BD8F35`, policy `913296BEE671`, proc `35CF6CCE272B`, backends `B116ABF0FBFD`, cli `9510E12E282D`.
- The workspace was being touched by other processes during this review: `dsh-source-recovery-0.2.0.tgz` was re-packed at 15:18:39 local (`68310` bytes, `6a86ef8a…`) and `reports/tests.json` was regenerated at 15:18:26. Rows below describe the source snapshot above; report-line findings are called out explicitly.

## Verdict

**No Critical finding.** Archive member names cannot escape the output directory via traversal/absolute/drive/NUL names, there is no shell invocation, no target execution, and no network in the runtime path. That part of the security boundary is real.

**Six High findings**, however, defeat three headline claims: hostile ZIP/bundle input can exhaust the host process (H1); evidence bundles are not tamper-evident even at the level the product advertises (H2, H6); recovery-level honesty breaks on realistic input (H3); Windows `.bat` toolchains are dispatched incorrectly (H5); and the "one writer per output path" lock claim does not hold for most write paths (H4). v0.2.0 should not be described as "world-class" / "tamper detection fails" / "honest levels S0–S4" until H1–H6 are fixed. It is usable today only for single-user, local, read-mostly triage with a warning that bundles and reported levels are advisory.

Counts: **Critical 0 · High 6 · Medium 12.** (Below-threshold observations are listed separately and not counted.)

---

## High

### H1 — ZIP caps are bypassable: forged central-directory sizes defeat the bomb limits (host OOM / DoS)
- `lib/archive.js:135-145` (`checkZipEntry`) enforces `maxEntryBytes`, the total-extraction budget and the >100:1 ratio cap purely from the **central-directory-declared** `uncompressedSize`.
- `lib/archive.js:168-176` then reads the compressed bytes and calls `zlib.inflateRawSync(compressed)` **without `maxOutputLength`**; only afterwards does it compare `content.length` to the declared size and exit `E_ARCHIVE_INVALID`.
- `lib/archive.js:193-216` (`readZipEntry`) has the same unbounded inflate. It is the reader used by `reverse_verify` (`lib/bundle.js:145,155,166,173`), which requires **no `authorized` flag** and accepts bundles up to 2 GiB (`lib/api.js:239-248`).
- Verified: a 203,842-byte deflate stream of 200 MiB of zeros with a central directory claiming 1,024 uncompressed bytes passed all checks; the process inflated 209,715,200 bytes (peak RSS delta **+348,568 KiB**) before failing with `E_ARCHIVE_INVALID: size mismatch`, despite configured `maxEntryBytes=1 MiB` / `maxExtractedBytes=4 MiB`. At the default 2 GiB extraction budget / 4 GiB input budget a small crafted archive can allocate multi-GiB in the DSH host process (Electron main), crashing the session.
- Related defaults: `extractGzip` uses `maxOutputLength: limits.maxExtractedBytes` (`lib/archive.js:349`, default 2 GiB) and `reverse_extract` of a `tar` reads the whole input into memory (`lib/api.js:417-420`), so even the "protected" paths can allocate the full configured budget.
- Fix: pass `maxOutputLength: Math.min(limits.maxEntryBytes, limits.maxExtractedBytes - total.bytes) + 1` to both `inflateRawSync` calls, map `ERR_BUFFER_TOO_LARGE`/`RangeError` to `E_ARCHIVE_BOMB`, and keep a hard per-archive ceiling. Give `readZipEntry` a fixed independent cap (e.g. 64 MiB) because bundle verification must not trust the archive's own entry sizes. Enforce the budget while streaming and lower the default `maxExtractedBytes` (2 GiB is larger than the host can safely allocate). Add a forged-size fixture test (the existing suite has none).

### H2 — Evidence-bundle verification does not detect realistic tampering; advertised tamper-detection is false
- The bundle digest covers only four things: `target.sha256`, `artifacts`, `report` hashes and `generatedAt` (`lib/bundle.js:91-96`, recomputed at `lib/bundle.js:177-183`). It does **not** cover `recovery.level` / `plan` / `gaps`, `tools`, `policy`, `target.name/size/family/kind`, `authorizationNote`, `pluginVersion`, `artifactsRoot` or `bundleVersion`.
- The verifier never compares `report.json`'s target/recovery fields with the manifest, never validates the manifest against `schemas/evidence.schema.json`, and only flags *undeclared artifacts* whose name starts with `artifacts/` (`lib/bundle.js:184-185`).
- Verified with three rewritten bundles built from a legitimate `reverse_bundle` output (all returned `ok:true`, `mismatches:[]`, note "all declared hashes and the bundle digest match"):
  1. manifest `recovery.level` changed from `S3` to `S0`, `recovery.description` replaced with "FORGED: original source bytes recovered", `target.name` and `authorizationNote` replaced — **digest untouched, verification passes**.
  2. extra top-level `dropped-payload.exe` added to the ZIP — verification passes, `undeclaredArtifacts:[]`.
  3. `report.md` content replaced and report hash + digest recomputed offline (no secret is involved) — verification passes (this part is documented as "integrity, not authenticity").
- Claims contradicted: `README.md:63` "发现篡改即失败", `examples/README.md:72-75` "If any byte is changed, verification fails", `lib/bundle.js:196-198` note text; `KNOWN-LIMITATIONS.md:15-17` / `THREAT-MODEL.md:41` do admit unsigned bundles, but even the narrower integrity guarantee is incomplete.
- Fix: compute `bundleDigest` over the **complete** canonical manifest without the digest field (stable key ordering), verify `report.json` content against the manifest, validate the manifest schema, reject every ZIP entry outside `{manifest.json, report.md, report.json, declared artifacts/**}`, and reject duplicate/local-vs-central name ambiguity (see M6). Either sign the digest (Ed25519 key + pinned public key) or rename/document the property as "consistency check against accidental corruption", not tamper detection. Add negative tests for manifest-metadata edits and extra top-level files (the current tamper test only flips one byte inside `report.md`, which the ZIP CRC catches — `test/core.test.mjs:181-188`).

### H3 — Large source maps are misidentified as plain text; `reverse_decompile` then claims S0 while recovering nothing
- `lib/identify.js:53-58` decodes only the first **64 KiB** of text (`decodeText`); `textKind` (`lib/identify.js:118-134`) runs `JSON.parse` on that truncated string, so any source map larger than 64 KiB fails to parse and is classified `json`.
- Resulting pipeline: family `text`, kind `json` → `lib/recovery.js:271-277` copies the `.map` file and sets **level `S0`, reason "the target is already text/source-like; it was copied, not decompiled"**. `buildPlan` has no `text` branch (`lib/recovery.js:89-95`), so `reverse_report` for the same target says ceiling **S4**.
- Verified on a realistic 970,098-byte map with `sourcesContent` (1,500 modules): `reverse_identify` → `family=text kind=json`; `reverse_report` ceiling `S4`; `reverse_decompile` → **level `S0`**, output contains only `bundle.js.map`, `recovered=null`; `reverse_sourcemap` on the same file correctly recovers 1,500 files at S0.
- This violates the plugin's central promise ("never present a lower level as recovered source" is inverted here: it presents no recovery as exact source), and the report and decompile tools contradict each other for the same target.
- Fix: detect source maps by parsing the complete map (bounded by `maxInputBytes`, not 64 KiB) or at least by checking `"version": 3` + `"mappings"` in the head, and route kind `sourcemap` to `recoverSources`; never map a bare text/JSON/QoS file to S0 merely because it was copied — require actual shipped-source extensions/content or return S3 with `"copied, not decompiled"`. Add `text`/`malware` to `TARGET_FAMILIES`/`buildPlan` so report and decompile agree. Regression test: >64 KiB map through `reverse_decompile`.

### H4 — Output-lock claim is mostly unimplemented, and concurrent extraction corrupts output while reporting success
- `withOutputLock` (`lib/lock.js:14-46`) is used **only** by `decompile` (`lib/api.js:147-163`). `extract` (`lib/api.js:117-145`), `sourcemap` (`lib/api.js:165-187`) and the builtin write paths take no lock; extract also force-deletes the whole output directory on any failure (`lib/archive.js:183-185`), including a directory another writer is using.
- Verified: two concurrent `api.extract` calls targeting the same new output directory with a 4,000-member ZIP produced `["err:EEXIST","ok:4000"]`; the successful call reported 4,000 files while the final tree contained 4,048 entries (50 dirs + 3,998 files) — two files silently missing — and the failing call's cleanup recursively deleted the winner's files mid-write.
- `SECURITY.md:35-37` ("one writer per output path"), `README.md:64` ("输出目录跨进程锁") and `COMPATIBILITY.md:47-49` are therefore not true for the write paths users actually hit.
- Fix: take the lock in every mutating operation (extract, sourcemap, decompile, report, bundle, firmware), key it on the canonical output path, return `E_BUSY` for contention, and only remove the created directory when this call actually created it and no other writer holds the lock. Prefer building into a private temp dir under the root and atomically renaming on success. Add concurrent tests for `extract`/`sourcemap` (the current concurrency test only covers `decompile` — `test/core.test.mjs:225-240`).

### H5 — On Windows, `.bat` toolchains are detected as available but can never run (APK "dual backend" fails silently)
- `lib/backends.js:11-12` lists `jadx.bat` and `apktool.bat` as candidate commands and `which()` (`lib/backends.js:29-45`) accepts any file on `PATH`; `lib/proc.js:84-92` spawns with `shell:false`. Node on Windows refuses to spawn `.bat`/`.cmd` without a shell — verified in isolation: `spawnSync(<temp>.bat, ['--version'], { shell:false })` → `EINVAL`.
- Detection ignores that failure (`lib/backends.js:64-70` only builds a version string, never checks `spawnError`) and still sets `available:true`; `reverse_doctor`/`capabilities` then report JADX/apktool as installed. At recovery time `run.code` is `null`, warnings say "did not produce source files", no raw-extraction fallback runs because `ran > 0` (`lib/recovery.js:128-159`), and the result is S4 with an empty/removed output dir.
- The test suite passes only because this host has Chocolatey `.exe` shims (`C:\ProgramData\chocolatey\bin\jadx.exe`, `apktool.exe`); a normal zip-install of JADX/apktool (the documented `jadx.bat`/`apktool.bat` layout) is broken on the declared Windows platform. The skip-based backend tests (`test/integration.test.mjs:212-243`) cannot catch this.
- Fix: launch `.bat`/`.cmd` through `%ComSpec% /d /s /c` with individually quoted arguments (or restrict TOOL_SPECS to `.exe` shims and mark `.bat` candidates unsupported), and only report `available:true` after a successful version probe (`code === 0`, no `spawnError`). Add a Windows test with a fake `.bat` tool.

### H6 — Evidence bundles record a *ceiling* as the achieved recovery level; Electron/JS bundles are always stamped S0
- `createEvidenceBundle` never runs recovery: it calls `buildReport`/`buildPlan` and writes `manifest.recovery.level = plan.bestLevel` (`lib/bundle.js:48-77`).
- `buildPlan` treats the source-map step as always available for any Electron/JS target (`lib/recovery.js:82-84`, `available() === true`), so `bestLevel` for every `.js`/ASAR target is **S0**. For APK it is S1 whenever JADX/apktool are installed, again regardless of what was recovered.
- Verified: `reverse_bundle` on a plain `sample.js` (no source map, no recovery run) produced `manifest.recovery.level = "S0"`. A handoff consumer reading `recovery.level` reasonably concludes exact source was recovered.
- `reverse_report` labels the same value `recoveryCeiling` (correct); the bundle schema (`schemas/evidence.schema.json:24-34`) also requires `recovery.level`, so the misleading name is load-bearing.
- Fix: rename the field to `recovery.ceiling` and add `recovery.achieved: null | S0..S4` that is filled only when recovery actually ran; compute S0 availability for Electron only when a parseable source map with `sourcesContent` exists; or run `recover()` before bundling and record its result. Update the evidence schema and the tool description ("recovery level/gaps" is currently false).

---

## Medium

### M1 — Output-directory containment is textual only; a symlink/junction ancestor writes outside the allowed root
- `assertOutputDirectory` (`lib/archive.js:60-83`) resolves the path and checks `isInside(root, path.dirname(resolved))` **without `realpath`**, unlike `assertOutputFile` (`lib/policy.js:105-131`, which realpaths the parent). Any symlink/junction component inside an allowed root redirects the write outside it.
- Verified: with `root\linked` a junction to `outside`, `reverse_extract` with `outputDir = root\linked\out`, `roots=[root]` returned `ok:true` and wrote `outside\out\escaped.txt`; the report shows `outputDir` inside the root, the bytes outside.
- Impact: a target-controlled archive (or a concurrent same-user process) can place extracted files outside the operator's declared root if a reparse point exists in the path; the plugin's own extractor rejects symlink members, so exploitation needs a pre-existing/racing link (e.g. `node_modules` junctions in a workspace root).
- Fix: `realpath` the parent and the created directory, re-check containment against canonical roots, and reject any component whose `lstat` is a symlink/other special file (on Windows also reject `FILE_ATTRIBUTE_REPARSE_POINT`, i.e. junctions). Repeat the check in `safeJoin` for the final target's parent.

### M2 — `sourceMappingURL` resolution reads files outside the allowed roots (path-policy bypass)
- `lib/sourcemap.js:37-43` takes the URL found inside an untrusted JS file, resolves it relative to the JS directory, and `fsp.readFile`s it with no root/symlink check (and no `assertInputFile`). `recoverSources` is called both by `reverse_sourcemap` and by `reverse_decompile` on ASAR-extracted bundles.
- Impact: an attacker-supplied JS file can direct the reader at an arbitrary local path (absolute, `C:\…`, `../…`) and have its content parsed as a source map; if it parses (`version:3`, `sources` array), `sourcesContent` is written into the output tree and becomes model-visible/actionable. The read is bounded by map JSON validation, but it is still a read outside the configured roots and a policy/doc violation.
- Fix: resolve the referenced map only through `assertInputFile` semantics (inside allowed roots, regular file, size cap) or restrict it to the same directory tree as the JS file; reject absolute/URL/drive-qualified references. Add tests for `../../` and absolute map URLs.

### M3 — .NET metadata row widths are hardcoded, so large real assemblies get mislabeled type→method mappings
- `lib/dotnet.js:162-208` computes correct table sizes (`tableSizes` uses `tbl(4)`/`tbl(6)`/`tbl(8)` at lines 114-121), but the row parsers bypass that: `lib/dotnet.js:240` computes the TypeDef `MethodList` offset with a hardcoded `+ 2` for the preceding `FieldList` column (should be `tbl(4)`), and `lib/dotnet.js:241-242` / `lib/dotnet.js:227` read `MethodList`/`ParamList` as 2 bytes regardless of `tbl(6)`/`tbl(8)` (4-byte when the table has ≥ 0x10000 rows).
- Impact: on assemblies with ≥65,536 fields/methods/params (large managed apps, generated code) `methodListOffset` is wrong by 2 bytes and the width is wrong, so type→method lists are wrong/misplaced; on corrupt input reads can throw raw `RangeError` (surfaced as `E_INTERNAL`). No local .NET 6.0 runtime assembly currently exceeds the threshold, so this is latent — it is still a real-assembly correctness bug and the code already knows the right widths.
- Fix: use one width helper from `tableSizes` for every column access in `parseTables` (FieldList `tbl(4)`, MethodList `tbl(6)`, ParamList `tbl(8)`), add bounds checks against the `#~` stream, and add a synthetic large-table fixture test.

### M4 — ASAR with multiple JS bundles silently loses all source recovery after the first bundle, still reporting S0
- `recoverEmbeddedSources` (`lib/recovery.js:50-59`) loops over up to 200 JS files into **the same** `outputDir` and swallows every error. `recoverSources` writes `sourcemap-manifest.json` with flag `wx` (`lib/sourcemap.js:105`), so the second bundle always fails at manifest write; identical source paths across bundles also fail at `writeFile(..., 'wx')` (`lib/sourcemap.js:93`). Failures are never surfaced as warnings.
- Verified: a two-bundle ASAR (each with an inline map) produced level `S0`, `recoveredBundles` listing only `bundle-a.js`, `src/shared.ts` containing only bundle-A's text, and a manifest describing only bundle A. No warning mentions bundle B.
- Real Electron apps routinely contain many bundles, so the headline "recover original sources from source maps" path is effectively single-bundle.
- Fix: merge/document manifests per bundle (or one aggregate manifest), allow per-source-path collision handling (`<bundle>/<path>` roots or index prefixes), accumulate failures into `warnings`, and count exactly what was recovered. Add a two-bundle ASAR test.

### M5 — Stale-lock handling is unsafe: a *live* lock older than 1 h is deleted, and waiters can delete each other's fresh lock
- `lib/lock.js:26-38`: `stale = !alive || Date.now() - stat.mtimeMs > 60*60*1000`. A live process holding a lock longer than an hour loses it; `process.kill(pid,0)` failures of any kind (e.g. `EPERM`) are treated as dead; a lock file read while still empty (window between `open('wx')` and `writeFile` at lines 21 and 40) fails `JSON.parse` and is classified stale; two waiters can both decide stale, both `rm`, and the second `rm` can delete the first's newly created lock before re-opening.
- `COMPATIBILITY.md:48` describes "stale locks from a dead PID older than one hour", which is the opposite of what the code does.
- Fix: never treat age alone as death; only reclaim when the recorded PID is confirmed dead, use a token/inode check before unlink (unlink only if the lock still contains the token observed), or replace with an atomic `flock`/`O_EXCL` + heartbeat scheme. Treat unparsable/empty content as "busy until grace expires", not as stale.

### M6 — ZIP ambiguity accepted: duplicate member names and local-vs-central name mismatches
- `scanZip` (`lib/archive.js:110-128`) accepts duplicate names; `verifyEvidenceBundle` builds `byName` from a `Map` (`lib/bundle.js:140`), so the **last** duplicate wins while other extractors (and this plugin's own `extractZip`, which fails with `EEXIST`) use a different entry.
- `extractZip`/`readZipEntry` read local header lengths and data at the central-directory `localOffset` but never compare the local header's name to the central name (`lib/archive.js:162-168`, `197-202`), so a bundle can present one name in the index and a different one in the local header. Overlapping member ranges are not rejected either.
- Impact: a bundle can verify `ok:true` here while a different tool extracts different bytes/names; this undermines the "verified" claim and is the classic ZIP-confusion primitive for a verifier.
- Fix: reject duplicate names (case-insensitively on Windows), require local name == central name and non-overlapping data ranges, and fail verification on any such ambiguity. Add hostile-ZIP fixtures.

### M7 — Delivered reports are stale/inconsistent, so the advertised test/acceptance evidence does not describe the shipped artifact
- `reports/tests.md` (generated 06:41Z) shows **16 passed**, 8 tools, while `reports/tests.json` (07:18Z) shows **21/21 passed**; `README.md:100` claims "21/21 passed" plus "12/12 acceptance".
- `reports/acceptance.md` is a **0.1.0** artifact (tarball `dsh-source-recovery-0.1.0.tgz`, sha `4a3b…`, `toolCount=8`) while `reports/acceptance.json` is 0.2.0 (12/12, tarball sha `0a88ed5d…`, 68,415 bytes). The tarball now on disk is `6a86ef8a…`, 68,310 bytes (re-packed 15:18:39 local, matching `npm-pack.json`), i.e. **the acceptance run was performed against a different tarball than the one present**, and the 12/12 evidence does not cover the current package.
- `README.md:63` / `examples/README.md:72-75` overclaim tamper detection (see H2); `COMPATIBILITY.md:48` misstates lock staleness (M5); `README.md:64` overclaims locking (H4).
- Fix: regenerate `tests.md`, `acceptance.md` and the HTTP captures from a single run and record the exact tarball digest in every report; add a CI assertion that `reports/*.md` and `reports/*.json` agree and that `acceptance.json.tarball.sha256` equals the packed file; align the claims above with the documented limitations.

### M8 — Capability matrix and recovery plan advertise levels/backends the orchestrator never reaches
- `lib/api.js:78` sets `availableLevel: family.bestLocal` regardless of what is installed (a host with no APK tooling still reports `apk.availableLevel = S1`); `lib/levels.js:43-46` gives `dotnet.bestLocal = S2` although no local S2 backend exists (ilspycmd = S1, builtin metadata = S3), and `dotnet.bestWithRea` is S1 while the levels table claims REA managed gives S1 — the ceiling numbers are internally inconsistent.
- `buildPlan` adds "decompile pseudo-C, ghidra/REA, S2, available when ghidra is installed" (`lib/recovery.js:81`) and `readelf`/`binwalk`/`unblob` steps; `recovery.js` never invokes `ghidra`, `readelf`, `binwalk` or `unblob` (only `jadx`, `apktool`, `ilspycmd`, `objdump`, `strings`; verified by grep and by reading the dispatch blocks). So on a Ghidra-equipped host `report.recoveryCeiling`/bundle level becomes **S2** while `reverse_decompile` still only reaches S3 via objdump. `levelFor` (`lib/levels.js:98-107`) is dead code that perpetuates the same claims.
- `RECOVERY_POLICY.externalToolInvocation` lists ghidra/binwalk/unblob/dotnet as tools the plugin runs with timeouts, which it does not.
- Fix: derive `availableLevel` from detected backends and from steps the orchestrator actually implements; remove or implement the Ghidra/binwalk/unblob steps (and the `Recovery policy` wording accordingly); delete or wire `levelFor`; add a test with a fake `ghidra` on PATH asserting the reported ceiling matches what `recover()` can produce.

### M9 — apktool smali/resources are labeled S1, contradicting the level taxonomy
- The taxonomy defines S1 as "Decompiled source (Java/Kotlin, C#, JS/TS-like)" and S3 as "Disassembly, strings, resources, manifests, metadata … no source form" (`lib/levels.js:8-22`). Smali is DEX disassembly and decoded resources/manifests are S3 artifacts.
- Yet `lib/recovery.js:146-148` sets level `S1` for apktool-only runs (reason even says "(not Java source)"), `lib/levels.js:102` does the same, and `README.md:15`, `SKILL.md:15`, `references/levels.md:6` classify apktool smali as S1.
- Impact: an APK decompiled with only apktool is presented as near-source, exactly the class of overclaim the plugin promises not to make. It also makes S1 non-comparable across families.
- Fix: return S3 when only apktool ran; keep S1 only for JADX Java/Kotlin, ILSpy C#, or an actual JS decompiler; update tables and tests; optionally add a separate "smali" artifact tag under S3.

### M10 — Cancellation and timeout propagation are incomplete; a hung child can hang the tool call forever
- `lib/proc.js:100-143`: timeout/abort only sets a flag and calls best-effort `killProcessTree`; the promise settles only on the child's `'close'` event. If the kill fails (permission, taskkill unavailable, unkillable child) the tool never returns — there is no forced `E_TIMEOUT`, no stdio destroy, no second deadline. `options.signal.aborted` is not checked before spawning, so an already-aborted call still starts the backend.
- `bin/cli.js:168-170` installs a SIGINT handler for every command but only forwards the signal to `recover`/`decompile` (`bin/cli.js:184,202`); `extract`, `sourcemap`, `report`, `bundle` swallow Ctrl-C (the listener suppresses the default exit) and keep working. Builtin archive/firmware/sourcemap/dotnet loops never observe a signal, and no tool declares `timeoutMs`, while the DSH tool contract requires `execute` to observe or forward `exec.signal` (`@deepseek-ai/dsh-tools/src/contracts.ts:31-39`).
- Fix: settle on deadline with a forced-abort result (`E_TIMEOUT`/`ABORTED`) and destroy pipes, check `signal?.aborted` before spawn and between files/entries; forward the signal from CLI for all write commands; declare `timeoutMs` only after the forwarding guarantee is real. Add a test with a child that ignores termination (e.g. a Node `--eval` loop) and assert bounded completion.

### M11 — Tests can pass while the features above are broken
Concrete gaps (all confirmed against `test/`):
- The "detects tampering" bundle test flips one byte inside `report.md` (`test/core.test.mjs:181-188`), which the ZIP CRC catches; it never edits manifest metadata or appends a top-level file (H2 reproduces both as passes).
- The concurrency test only covers `decompile` (`test/core.test.mjs:225-240`); `extract`/`sourcemap` have no concurrency test though they are the broken paths (H4 reproduces silent corruption).
- Real-backend tests return `{skipped:true, unavailable:true}` when tools are missing and the runner records them as `unavailable`, so "21/21 passed" is host-dependent (`scripts/run-tests.mjs:45-57`); on this host the Chocolatey `.exe` shims mask the `.bat` dispatch bug (H5). There is no test that simulates a `.bat` tool.
- No test covers: >64 KiB source maps through `reverse_decompile` (H3), two-bundle ASAR (M4), forged central-directory sizes (H1), hostile/duplicate-name bundles (H2/M6), symlinked ancestors (M1), `sourceMappingURL` escaping the roots (M2), .NET tables ≥ 65,536 rows (M3), Ghidra-present plan overclaim (M8), cancellation of a hung backend (M10).
- The acceptance suite proves registration/boot/routes/CLI and string-matches the client bundle (`scripts/acceptance.mjs:188-218`) but never invokes a `reverse_*` tool through the real DSH agent pipeline, and never renders the panel (`KNOWN-LIMITATIONS.md:20-23` admits the latter). Tool `execute` semantics, argument schema enforcement, `output.render`, and `exec.agent.session.meta.cwd` root resolution are therefore unverified end-to-end.
- Fix: add the regression tests named in each finding, make the four-way taxonomy report `passed` only for actually-exercised capability paths (or clearly separate "backend absent" from "passed"), and add one end-to-end DSH tool-call test (agent step calling `reverse_identify`/`reverse_decompile`) plus a client smoke test.

### M12 — Container parsers fail on common real-world layouts (ASAR `unpacked`, CPIO/tar hardlinks)
- ASAR: `flattenAsar` (`lib/archive.js:241-258`) ignores the `unpacked` property entirely, and `extractAsar` computes `unpacked: entries.filter(entry => entry.offset === undefined).length` (`lib/archive.js:293`), which is always 0 because every flattened entry has an `offset`. Unpacked members are then read from the `.asar` byte stream at the in-archive offset (wrong bytes or out-of-bounds → whole extraction aborts), contradicting the comment "unpacked entries are reported, not read". Typical Electron apps with native modules have `app.asar.unpacked` entries.
- CPIO: `extractCpioBuffer` (`lib/archive.js:363-410`) writes every regular member with flag `wx`; newc hardlinks (common for BusyBox applets) appear as a zero-length first member plus a later data member with the same name, so the whole CPIO extraction fails with `EEXIST` and firmware carving silently records no finding (`lib/firmware.js:99-110` swallows per-candidate errors).
- tar: only type `'0'`/`'\0'` and `'5'` are handled (`lib/archive.js:321-335`); hardlink (`'1'`) and symlink (`'2'`) entries are silently skipped, so extracted trees from firmware/tar archives can be incomplete without warnings.
- Fix: skip `node.unpacked` members with an explicit `skipped:'unpacked'` record; for CPIO treat duplicate regular names as hardlinks (write once / copy) and report them; for tar skip link entries explicitly in the result. Add fixtures for unpacked ASAR, CPIO hardlinks and a tar with hardlinks.

---

## Below threshold (not counted; noted for completeness)

- `lib/firmware.js:48-50` throws for inputs > 256 MiB, so the `limited: stat.size > MAX_SCAN_BYTES` field at line 135 is always false (misleading); `MAX_FINDINGS = 20` caps candidate offsets per magic, so 20 early false positives can crowd out later real payloads (false negatives, not false positives).
- `skills/.../references/tools.md:1` contains literal `\n` escapes in a code span (rendering bug). The plugin's locale keys are `plugin.title`/`panel.*` instead of the DSH-documented `meta.title`/`meta.description` (`@deepseek-ai/dsh-agent-preset` dsh-doc `references/host-plugin.md:31-43`), package.json has no `./icon` export/top-level `icon`, and `client.js` hardcodes all UI strings instead of the Client locale service — Plugin Manager metadata/icon/i18n therefore fall back or do not apply.
- `bin/cli.js:188-191`: minimal-form `--report` always passes `overwrite:true`, silently replacing an existing report file.
- `lib/sourcemap.js:46-58` + `lib/archive.js:47-50`: Windows drive-qualified source paths (`C:\src\a.ts`, `file:///C:/…`) make the whole map fail with `E_ARCHIVE_UNSAFE` instead of being sanitized.
- `lib/recovery.js:187-197`: with JADX installed, a resource-only JAR is fed to JADX and gets no builtin extraction fallback (S4 vs the S3 extraction that a tool-less host would perform).
- `reverse_identify` returns up to 100 target member names (`lib/identify.js:198`), i.e. target file names enter model context while `SKILL.md:45` says not to put target contents into prompts; `reverse_decompile` also returns JADX/apktool `stdout` blobs in `actions` (`lib/recovery.js:129-149` via `lib/backends.js:126-136`), though these are logs, not decompiled source.
- `index.js:24` truncates the rendered envelope at 120,000 characters while the canonical value is unbounded — a large `actions` payload is silently truncated in the model-visible text (documented in the string, acceptable, but worth bounding at the source).

---

## Verified good (evidence-backed)

1. **Archive name containment is sound**: `safeSegments` rejects NUL, `.`/`..`, drive-letter segments and absolute/traversal paths; `safeJoin` re-checks containment (`lib/archive.js:42-58`); ZIP symlink members (Unix mode), encrypted members, ZIP64/multi-disk and unsupported methods are rejected (`lib/archive.js:103-145`); CRC and size are verified after inflate; files are written `0600` with exclusive create and the output dir must be new/empty.
2. **No shell and no target execution anywhere in runtime code**: only `lib/proc.js` spawns (`spawn('taskkill'…)` and `spawn(command,args,{shell:false})`); the CLI has no `shell:true`; the analyzed target is never spawned; no installers/scripts are executed. The integration test asserting this (`test/integration.test.mjs:477-481`) matches the code.
3. **No network in the runtime path**: grep over all `.js` finds no `node:http(s)`, `node:net`, `node:dns`, `WebSocket` or external `fetch`; the only `fetch` calls are the client workbench hitting its own loopback routes (`client.js:82-103`). `RECOVERY_POLICY.networkAccess=false` is true.
4. **Authorization gate is real and early**: `reverse_extract`/`decompile`/`sourcemap`/`report`/`bundle` throw `E_AUTHZ_REQUIRED` before any backend or write (`lib/api.js:53-57,119,149,167,191,212`; `lib/recovery.js:108-110`), and the CLI maps it to exit code 2.
5. **Skill `source` field is correct for this DSH version**: `'bundled'` is a documented `SkillSource` in the installed `@deepseek-ai/dsh-skill` (`src/index.ts:40`), and the loaded definition requires/keeps a string `source` (`src/index.ts:724-726,748-767`); the acceptance probe loads the skill through the real `SkillRegistry` and reports `source=bundled` (`reports/acceptance.json:82-89,32-35`). The historical "source must be a string" bug is fixed.
6. **Client slot contract matches the installed UI**: `'main'` is a `keyed` root slot keyed by panel id (`dsh-client-ui-layout/src/client/index.ts:74-75,197`, `retainMainPanels` reads `options.key` at 181-189) and `'sidebar.panellist'` is a `list` root slot whose entries are `{id, order, label}` (`dsh-client-ui-sidebar/src/client/index.ts:58-62,89-92`); `client.js` registers `{name:'main', key:'source-recovery'}` and `{name:'sidebar.panellist', id:'source-recovery', order:42, label:'Reverse'}` in the same shape. The host client bundle is served and appears in the boot graph (acceptance).
7. **Host tool registration contract is satisfied**: ten tools each declare `output {schema, render}` (required by `@deepseek-ai/dsh-tools/src/index.ts:128-136`), strict `parameters` with `additionalProperties:false`, and an `execute(args, exec)` that forwards `exec.signal` (decompile/recover); the plugin's `inject=['tools','skills']` matches available services and the bundle booted successfully in the isolated acceptance profile.
8. **Web workbench routes are loopback+same-origin gated, read-only, GET/HEAD only, no-store** (`index.js:226-297`), and the acceptance run got 200s for capabilities/doctor/selftest/health with no target path leakage beyond redacted toolchain paths (doctor redacts home/workspace).
9. **Loopback route handlers do not accept input and cannot write**; only `capabilities`, `doctor`, `selftest`, `health` are exposed. No SSRF/CSRF surface beyond local GET; Host-header and Origin checks block DNS-rebinding style access.
10. **.NET overall table layout is correct for ECMA-335 tables 0–44** (verified column-by-column against the spec, including the Assembly/AssemblyRef/Module name offsets and the `#US`/`#Strings`/`#GUID` indexing); real `System.Console.dll` recovery works and reports S3 names/metadata honestly (`reports/tests.json` .NET test passes on a real runtime assembly).
11. **Source maps: the dedicated tool is honest** — S0 only when at least one non-empty `sourcesContent` entry was written; otherwise S3 with a clear note (`lib/sourcemap.js:87-113`); recovered source names are sanitized against traversal and drive/URL prefixes before `safeJoin`; inline and relative maps are supported.
12. **ASAR header reading is bounded and validating** (64 MiB header cap, size/offset checks, UTF-8 JSON object with `files`), and traversal names are rejected through `safeSegments`; firmware carving bounds gunzip output to 64 MiB and validates ZIP/tar/CPIO candidates in isolated subdirectories (`lib/firmware.js:63-123`).
13. **No silent overwrite of bundle/report outputs**: report and bundle use `assertOutputFile` + exclusive temp file + hard-link publish with an explicit overwrite opt-in (`lib/policy.js:139-178`), and bundle creation re-hashes artifacts before writing to detect mid-operation change (`lib/bundle.js:103-107`).
14. **Reports do not embed target file contents** (hashes, sizes, entropy, plan, gaps, backend versions only — `lib/report.js:18-98`); bundle artifacts are opt-in and hashed; doctor and runTool redact home/workspace paths from diagnostics.

---

## Unverified / out of scope for this review

- Live rendering of the Reverse panel in the DSH Web GUI (no browser control in this session; client contract verified by source, not pixels) — matches `KNOWN-LIMITATIONS.md:20-23`.
- End-to-end model tool invocation through the real DSH agent pipeline (acceptance only boots the plugin, calls routes and the installed CLI). The `execute`/`output.render`/`exec.agent.session.meta.cwd` behaviour is inferred from contracts and unit fakes.
- The ASAR `unpacked` failure mode (M12) is inferred from code and the platform format; no local Electron app with `app.asar.unpacked` was available to reproduce it. It should be confirmed with a fixture.
- Hardlink CPIO (M12) inferred from newc semantics; no real BusyBox firmware was tested.
- Linux/macOS behaviour (only Windows was exercised locally; `COMPATIBILITY.md:24-25` agrees). The `.bat` failure is Windows-only; `killProcessTree`/`detached` behaviour is untested on POSIX.
- REA MCP tool behaviour (`mcp__rea__*`) was not exercised; the plugin only detects REA, it does not call it.

---

## Recommended fix order before any release/acceptance claim

1. H1 (bounds on every inflate + verify hardening) and H2 (whole-manifest digest + undeclared-entry/duplicate rejection + claim wording).
2. H3 and H6 (truthful S0/level semantics in decompile and evidence bundles) and M9 (smali S3).
3. H5 (Windows `.bat` launch + detection-of-failure) and H4/M5 (real lock coverage, safe staleness, no destructive cleanup of a shared output dir).
4. M1/M2 (realpath/root enforcement) and M3/M4/M12 (real-world parser fixes) before calling the families "supported".
5. Regenerate `reports/` from the fixed, single tarball (M7); add the regression tests from M11.

Counts: **Critical 0 · High 6 · Medium 12 · verified-good 14 items.**

Report path: `C:\Users\XPS\Documents\deepseek-harness\default-workspace\dsh-source-recovery\reports\v2-review.md`
