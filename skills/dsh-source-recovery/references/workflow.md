# Workflow

```
authorized target
      │
      ├─ reverse_identify ── hash / family / container / arch / entropy / plan
      │
      ├─ reverse_doctor ─── which backends exist? (REA MCP? jadx? apktool? objdump? ilspycmd? ghidra?)
      │
      ├─ reverse_extract ── only when raw contents/resources are useful
      │
      ├─ reverse_decompile ─ family dispatch:
      │     APK      → jadx (S1) | apktool (S1) | raw zip (S3)
      │     Electron → asar + source maps (S3 | S0)
      │     .NET     → ilspycmd (S1) | REA managed (S1) | metadata (S3)
      │     native   → objdump (S3) | REA/Ghidra (S2)
      │     firmware → binwalk/unblob (S3) | strings (S3)
      │     archive  → extraction (S3)
      │
      ├─ reverse_report ─── Markdown + JSON evidence, gaps, unknowns`n      └─ reverse_bundle → reverse_verify ── hash-verified handoff ZIP
```

## Commands

```text
dsh-source-recovery identify --in target --json
dsh-source-recovery extract --in target --out out-dir --authorized
dsh-source-recovery decompile --in target --out out-dir --authorized
dsh-source-recovery sourcemap --js bundle.js --out sources --authorized
dsh-source-recovery report --in target --out report.md --authorized
```

## Rules

1. Identify first; do not decompile blind.
2. Record the achieved level in every answer.
3. State missing-backend gaps explicitly with the REA alternative.
4. Keep raw artifacts; the report references hashes, not huge contents.
5. If the target is malware, work on an offline copy and never execute it.
