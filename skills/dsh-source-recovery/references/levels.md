# Recovery levels and evidence ladder

| Level | Recovered form | Can it compile? | Typical source |
|---|---|---|---|
| S0 | original source files/text | often yes | source maps with `sourcesContent`; shipped source |
| S1 | decompiled source | sometimes, with fixes | JADX Java/Kotlin, apktool smali, ILSpy C# |
| S2 | pseudo-code | no | Ghidra/REA pseudo-C |
| S3 | assembly/metadata/resources | no | objdump, readelf, strings, ZIP/ASAR contents, .NET CLI metadata, carved firmware payloads |
| S4 | behavior only | no | dynamic observations |

## Evidence tags

- **observed** — bytes, hashes, container names, command output.
- **derived** — family, architecture, plan, level.
- **inferred** — likely original language/build system.
- **unknown** — symbols removed, build flags, original comments, runtime behavior.

## Honesty rules

- Never label S1/S2/S3 output as "the original source".
- Optimized native binaries usually cannot be converted back to source.
- A source map without `sourcesContent` gives mappings, not source.
- Missing tooling is `unavailable` with a reason and an alternative, never "passed".
- A successful extraction is not decompilation.
