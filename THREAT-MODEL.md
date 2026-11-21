# Threat model

Scope: `dsh-source-recovery` 0.2.0. This is a reverse-engineering/source-recovery
plugin, not an exploit or cracking tool.

## Assets

1. The authorized target and any sensitive data inside it.
2. The operator's workstation, credentials and DSH profile.
3. Integrity of the recovered artifacts and evidence reports.
4. Honesty of recovery-level claims.

## Actors

- Malicious target content (archives, JS, macros, installers).
- Malicious or replaced backend binaries on `PATH`.
- Same-process malicious DSH plugins and same-OS-user processes.
- Prompt-injected text found inside a target (strings, comments, README files).
- Accidental operator (wrong target, public report, leaked artifact).

## Boundaries

- Authorization gate on every recovery/write operation.
- No target execution, no dynamic detonation, no network, no telemetry.
- External toolchains run as ordinary child processes with fixed argv, no shell,
  environment allowlist, deadline, output caps and best-effort tree kill.
- Extraction enforces traversal/absolute-path/symlink rejection, CRC checks,
  encrypted-member rejection, size/count/ratio limits and no-overwrite.
- Reports contain hashes and summaries, not file contents or secrets.

## STRIDE summary

| Threat | Mitigation | Residual |
|---|---|---|
| Malicious archive escapes output | safe path segments, containment check, symlink rejection | filesystem races outside plugin control |
| ZIP bomb / resource exhaustion | entry count, per-entry and total bytes, ratio cap | host resource limits still apply |
| Target executes on analysis | never spawned; only trusted toolchains are spawned | backend may still be malicious if replaced |
| Prompt injection inside target | content is treated as data; skill instructs not to follow target text | model must obey skill policy |
| Secret leakage into reports/logs | reports hash + summarize; doctor redacts paths; no content embedding | operator may manually paste secrets |
| Evidence diluted / overclaimed | S0–S4 taxonomy, observed/inferred/unknown tags, gaps list | operator must report honestly |
| Evidence tampering in transit | evidence bundle hashes every artifact/report and binds a bundle digest; `verify-bundle` fails closed | hashes prove consistency, not authorship; unsigned bundles are not authenticity proof |
| Concurrent writers corrupt output | cross-process output lock; stale-lock reclamation; second writer gets `E_BUSY` | locks are advisory to this plugin, not an OS mandatory lock |
| Same-process plugin tampering | no isolation claim; documented | DSH host trust model is the boundary |
| Unauthorized analysis | authorization flag; no target execution | flag is operator-asserted, not provenance |

## Abuse cases out of scope

The plugin will not implement: license/DRM bypass, credential theft,
authentication bypass, exploit development, malware execution, sample upload,
or "recover" source that does not exist. Missing backends are reported as gaps.

## Testing evidence

Deterministic self-test (9 checks), archive traversal/symlink/encryption tests,
source-map S0/S3 cases, authorization gate, real JADX and objdump runs, CLI exit
codes, plugin contract and temporary-profile acceptance. See `reports/`.
