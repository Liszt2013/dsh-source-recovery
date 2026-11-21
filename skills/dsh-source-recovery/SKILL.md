---
name: dsh-source-recovery
description: Recover source-form artifacts from authorized targets (APK, JS/Electron, .NET, native, firmware, archives) with honest levels S0–S4, safe extraction, evidence reports, and no target execution.
---

# Source Recovery

You turn opaque authorized artifacts into the highest **honest** source level. Never call a lower-level artifact "source code".

## Recovery ladder

| Level | Meaning | Typical source |
|---|---|---|
| S0 | exact source | source maps with `sourcesContent`; shipped source/text |
| S1 | near-source | JADX Java/Kotlin, apktool smali/resources, ILSpy C#, decompiled JS bundle |
| S2 | pseudo-source | Ghidra/REA pseudo-C for native code |
| S3 | assembly/metadata | disassembly, strings, resources, manifests, archive contents |
| S4 | behavior-only | observed behavior; internals unknown |

Say which level was reached and why. A missing backend is **unavailable**, not a failed target.

## Workflow

1. **Authorize and scope**: confirm you may analyze the target. Recovery tools require `authorized: true`; never set it for unknown or third-party samples.
2. **Identify before acting**: `reverse_identify` (hash, family, container, arch, entropy, strings, plan). This never executes the target.
3. **Check backends**: `reverse_capabilities` / `reverse_doctor`. If a backend is missing, say so and offer the REA MCP path (`mcp__rea__*`) instead of pretending.
4. **Extract safely** if useful: `reverse_extract` (traversal/symlink/encryption/bomb/overwrite protections). Extraction is not decompilation.
5. **Recover source**: `reverse_decompile` for the family, or `reverse_sourcemap` when a JS map exists. Use REA MCP tools for deep native/managed/APK work when available.
6. **Package evidence**: `reverse_bundle` creates a hash-verified ZIP (manifest + report + artifact hashes). `reverse_verify` checks every declared hash and the bundle digest; never rely on an unverified bundle.
7. **Report evidence**: `reverse_report` writes Markdown + JSON with hash, ceiling, plan, gaps, evidence tags and unknowns.

## Family shortcuts

- **APK/DEX**: JADX → S1 Java; apktool → S1 smali/resources. No JADX/apktool → raw extraction S3 + state the gap.
- **JS/Electron/ASAR**: extract ASAR, then source maps; only `sourcesContent` gives S0.
- **.NET**: ILSpy-class decompiler gives S1; local `ilspycmd` is optional. Otherwise use REA managed tools.
- **Native PE/ELF/Mach-O**: local `objdump` gives S3; pseudo-C (S2) needs Ghidra/REA. Never promise original native source.
- **Firmware**: extraction (binwalk/unblob) gives S3 artifacts; source recovery is usually impossible.
- **Malware/forensics**: static only. Never execute the target, never contact C2, never upload samples.

## Security red lines

- Authorized data only; no bypassing licenses/DRM/authentication, no credential theft, no "cracking".
- Never execute the analyzed target or any downloaded script; no `curl | sh`; no remote install.
- Do not put target contents, keys, credentials or personal data into prompts, reports or logs.
- Extracted files are untrusted: do not run them, do not import them into tooling that executes macros.
- The plugin runs inside the DSH host process; approvals do not isolate same-process plugins.
- External toolchains (jadx, apktool, ILSpy, Ghidra) run as trusted local processes; a replaced binary on `PATH` is outside this plugin's boundary.

## References

- [workflow.md](references/workflow.md) — decision tree and commands
- [levels.md](references/levels.md) — evidence ladder and honest claims
- [tools.md](references/tools.md) — installed toolchains, install hints, REA delegation
- [security.md](references/security.md) — authorization, sample handling, boundaries
- [troubleshooting.md](references/troubleshooting.md) — common failures and exits
