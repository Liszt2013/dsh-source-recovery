# Security policy

## Reporting

Report privately to the maintainer. Include plugin/DSH versions, platform, a
minimal reproduction, and whether real samples/secrets were involved. Never send
live malware or real credentials.

## Supported

| Version | Status |
|---|---|
| 0.1.x | current |

## Rules enforced by the plugin

- **Authorization required** for extract/decompile/sourcemap/report; absent flag
  fails with `E_AUTHZ_REQUIRED` before any backend runs.
- **No target execution**: the plugin never spawns the analyzed file, its
  installers, macros or scripts.
- **No network**: no fetch, no telemetry, no updates, no sample upload.
- **Trusted toolchains only**: fixed CLI names resolved via PATH, structured
  argv, no shell, environment allowlist, timeout, output cap, tree kill.
- **Safe extraction**: absolute/drive/traversal/NUL names rejected; symlinks,
  encrypted ZIP members and suspicious compression ratios rejected; entry and
  total size limits; CRC verification; output must be new/empty; files 0600.
- **Path policy**: absolute paths inside allowed roots; input symlinks/special
  files rejected; output parents realpath-checked.
- **Reports**: hashes/summaries only; doctor redacts home paths; no file content
  is embedded.
- **Evidence bundles**: stored ZIP with a manifest that hashes every artifact,
  both reports and a bundle digest; `verify-bundle` recomputes every hash and
  reports missing, size, hash, digest and undeclared-artifact issues. A bundle
  that fails verification is not evidence-safe. The digest is unkeyed; sign
  bundles externally for authenticity.
- **Concurrency**: one writer per output path via a cross-process lock; stale
  locks from dead processes are reclaimed after a grace period. A second writer
  receives `E_BUSY` rather than interleaving output.
- **Cancellation**: tool `exec.signal` and CLI SIGINT are forwarded to trusted
  backends; backend timeouts and output caps still apply.
- **Evidence honesty**: recovery level S0–S4 is explicit; missing backend is a
  gap, never a pass.

## Operator guidance

1. Analyze only targets you own or are explicitly authorized to analyze.
2. Prefer offline copies; malware analysis on an isolated host.
3. Treat extracted files as untrusted; never execute them or open them in
   macro-enabled software.
4. Keep reports free of credentials, personal data and C2 details you are not
   allowed to disclose.
5. Control your `PATH`; a replaced jadx/apktool/objdump is outside the plugin's
   threat boundary.
6. Remember that DSH tool approval does not isolate same-process plugins.

## Known limitations

See `KNOWN-LIMITATIONS.md`. Notably: original native source is usually not
recoverable; APK/.NET/firmware depth depends on installed toolchains or REA MCP;
no dynamic analysis; no sample submission; Windows ACLs are not a sandbox.
