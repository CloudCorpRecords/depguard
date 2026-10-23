# Changelog

## 0.2.0 - 2026-10-23

- Content-based update vetting (Gap A, ledger P-158): a new `--content` mode for `check` and `package` (and a `content` parameter on both MCP tools) fetches both versions' tarballs from the npm registry and diffs the install-time surface statically: file inventory, package.json install scripts, and install-reachable code (script targets plus relative imports to depth 3), scanning for credential-path strings, network endpoints, added binaries, and obfuscation-shaped code. New rules: CONTENT-INSTALL-SCRIPT-ADDED, CONTENT-INSTALL-SCRIPT-CHANGED, CONTENT-CRED-SIGNAL-ADDED, CONTENT-NETWORK-ENDPOINT-ADDED, CONTENT-BINARY-ADDED, CONTENT-OBFUSCATED-ADDED. Tarballs are extracted in memory only; nothing is installed or executed. Retrieval sits behind an injectable layer, so tests run on recorded fixtures with no network. A benign build postinstall with no credential or network signals does not grade high.
- Name vetting, the offline diff core, and online registry checks are unchanged from 0.1.0.

## 0.1.0 - 2026-10-22

- First release. Offline-deterministic dependency diff core: package.json plus package-lock.json (full), yarn.lock and pnpm-lock.yaml (best-effort), diffed against a git ref base or a base directory.
- Local rules: install script additions and presence, typosquat edit distance against the repo's own dependency set and a bundled popular-names list, downgrades, prerelease jumps, widened and unpinned ranges, lockfile drift, resolved host changes, integrity changes.
- Online rules behind an explicit flag only: version age under 7 days, publisher change versus the previous version, provenance presence, deprecation, version not found.
- CLI (`check`, `package`) and stdio MCP server (`guard_path`, `check_package`) in one bin, with the factory flush-aware emit contract: single-write emit resolving in the stdout flush callback, process.exitCode on report paths, exit 141 on EPIPE, and spawned-CLI pipe regression tests over 200 KiB.
