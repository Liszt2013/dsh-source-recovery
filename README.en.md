# dsh-source-recovery (English)

Reverse everything toward source — with honest recovery levels. A DeepSeek
Harness plugin with a left-sidebar **Reverse** workbench, eight `reverse_*`
tools, a runtime skill, safe extraction and evidence reports.

- Recovers exact source only when it exists (S0: source maps with
  `sourcesContent`, shipped source). APK/JAR via JADX/apktool, .NET via ILSpy,
  native via disassembly, Electron via ASAR/source maps, firmware via strings.
- Never executes the target, never uses the network, never uploads samples, and
  never presents decompiled/pseudo output as original source.
- Authorized targets only: mutating recovery commands require `authorized: true`.

## Install

```sh
npm pack
DSH_HOME=/tmp/dsh-source-recovery-accept dsh plugin --profile web add ./dsh-source-recovery-0.2.0.tgz
DSH_HOME=/tmp/dsh-source-recovery-accept dsh --profile web --no-open --port 8080
```

## Verify

```sh
npm test
node scripts/build.mjs
node scripts/pack-check.mjs
node scripts/acceptance.mjs
```

MIT. No runtime npm dependencies. See `README.md` (Chinese) and the skill at
`skills/dsh-source-recovery/SKILL.md` for the full workflow and boundaries.
