# v0.2.0 adversarial review resolutions

Independent review: `reports/v2-review.md` (0 Critical, 6 High, 12 Medium).
This file records what changed after that review. Final state: tests 22/22,
acceptance 12/12 (isolated DSH profile, including DSH SkillRegistry load and
evidence-bundle verification).

## High findings

| ID | Finding | Resolution | Verification |
|---|---|---|---|
| H1 | ZIP bomb caps could be bypassed because inflation was unbounded | `extractZip` and `readZipEntry` now call `zlib.inflateRawSync(..., { maxOutputLength: min(declaredSize, limit) + 1 })`; a lying central-directory size throws before allocating the payload. Duplicate member names and local/central name mismatches fail closed. | New core tests for deflate bomb, duplicate names, and header mismatch |
| H2 | Bundle digest did not cover all manifest fields; undeclared entries were ignored | Bundle digest now hashes the **complete** manifest (ceiling, achieved, tools, policy, artifacts, reports, timestamps); verification rejects any entry outside `manifest.json`/`report.*`/declared artifacts. `reverse_verify` returns a failure envelope (`E_BUNDLE_INVALID`) instead of `ok:true`. | Forged `recovery.ceiling.level` and extra `dropped-payload.exe` tests both fail |
| H3 | Large source maps (>64 KiB) mislabeled as text/S0 | `.map` extension + JSON prefix is classified as `sourcemap` regardless of the identification read window; text/config copies are S3, only recognized source extensions are S0. | New >64 KiB map test reaches S0 with 2 recovered sources |
| H4 | Output locks covered decompile only | `extract`, `sourcemap`, and `bundle` now use the same cross-process output lock; losers get `E_BUSY` and cannot delete the winner's output. Stale locks are re-quarantined by rename rather than blindly deleted. | Concurrency test for decompile; lock path shared by all writers |
| H5 | `.bat`/`.cmd` toolchains detected but spawn failed with EINVAL | `buildLaunch()` launches `.bat`/`.cmd` through `cmd.exe /d /s /c` with verbatim argv; version probes and real runs both use it. | Windows launcher unit test |
| H6 | Bundle recorded an available ceiling as the achieved level | Manifest now separates `recovery.ceiling` from `recovery.achieved`; bundle creation without recovery sets `achieved: null` with an explanatory note. CLI accepts `--achieved` when the caller knows the result. | Bundle test/verification + schema update |

## Medium findings addressed

- Output directory parents are realpath-canonicalized before containment checks; symlinked ancestors cannot redirect writes.
- `sourceMappingURL` references are resolved with realpath and must stay inside allowed roots.
- .NET table index widths use actual row-count widths instead of hardcoded 2 bytes.
- Plan/capability honesty: dotnet local ceiling is S3 (metadata), native S2 is marked delegated (not executed), Electron S0 is only "available" for detected source maps, apktool-only output is S2 (smali is not Java source).
- Local/central ZIP name mismatch rejected; duplicate names rejected case-insensitively.
- Stale reports are regenerated from the final tarball; acceptance report matches the shipped artifact.
- Evidence claims now state the digest is unkeyed: it detects modification but does not prove authenticity; sign bundles externally.
- S2/Ghidra delegation is explicit (`delegatedTo`) and never claimed as an executed step.

## Remaining accepted limitations

- Multi-header ASAR archives are parsed as a single header; unusual Electron packaging may need external extraction.
- Output locks are advisory to this plugin; they are not OS mandatory locks.
- Cancellation is delivered to trusted child processes and bounded by timeouts, but a wedged non-cooperative process can still delay teardown until the kill signal is processed.
- Evidence bundles are unsigned; self-consistent rewrite remains possible without an external signature.
- .NET S1 and Ghidra S2 require external tooling or REA MCP; the plugin reports this as a gap.
- Only Windows was executed locally.
