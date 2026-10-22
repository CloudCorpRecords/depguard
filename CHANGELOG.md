# Changelog

## 0.1.0 - 2026-10-22

- First release. Offline-deterministic dependency diff core: package.json plus package-lock.json (full), yarn.lock and pnpm-lock.yaml (best-effort), diffed against a git ref base or a base directory.
- Local rules: install script additions and presence, typosquat edit distance against the repo's own dependency set and a bundled popular-names list, downgrades, prerelease jumps, widened and unpinned ranges, lockfile drift, resolved host changes, integrity changes.
- Online rules behind an explicit flag only: version age under 7 days, publisher change versus the previous version, provenance presence, deprecation, version not found.
- CLI (`check`, `package`) and stdio MCP server (`guard_path`, `check_package`) in one bin, with the factory flush-aware emit contract: single-write emit resolving in the stdout flush callback, process.exitCode on report paths, exit 141 on EPIPE, and spawned-CLI pipe regression tests over 200 KiB.
