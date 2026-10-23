# depguard

PR-time and dependency-change early warning for npm repos. The Shai-Hulud / ChainDrop worm family backdoored 500+ npm packages in 2026, executing at install time through preinstall dropper scripts and propagating through the dependency graph. depguard is the diff-time check: given a repo and a base (a git ref or a second manifest set), it diffs `package.json` and the lockfiles, and grades every added, removed, and changed dependency with evidence, before the change merges.

The base verdict is fully offline and deterministic. Registry checks (version age, publisher change, provenance, deprecation) run only behind an explicit `--online` flag or the matching MCP parameter, and a failed lookup never changes the local verdict.

## What it checks

| Signal | Source | Rule ids |
| --- | --- | --- |
| New install scripts in the repo's own package.json, escalated when the content fetches remote code, reads credentials, or runs the documented `setup.mjs` dropper name | local | INSTALL-SCRIPT-ADDED, INSTALL-SCRIPT-CHANGED |
| A changed dependency newly marked as having an install script in the lockfile; install scripts present on added dependencies | local | INSTALL-SCRIPT-ADDED, INSTALL-SCRIPT-PRESENT |
| Typosquat-shaped added names: edit distance 1 (or 2, longer names) against the repo's own existing dependency set and a bundled popular-names list (about 380 names, shipped in the package) | local | TYPOSQUAT-SUSPECT, TYPOSQUAT-POSSIBLE |
| Version anomalies: silent downgrades, stable-to-prerelease jumps, non-semver versions, ranges widened (to `*` or `latest` is high), newly added unpinned ranges | local | DOWNGRADE, PRERELEASE-JUMP, VERSION-PATTERN, RANGE-WIDENED, RANGE-UNPINNED |
| Lockfile drift: manifests changed but the lockfile is identical; lockfile changed with no manifest change; resolved URL host changes for the same version; integrity hash removed or changed at the same version | local | LOCKFILE-DRIFT, LOCKFILE-ONLY-DRIFT, RESOLVED-HOST-CHANGE, INTEGRITY-REMOVED, INTEGRITY-CHANGED |
| Manifest dependencies with no lockfile entry (single-snapshot mode) | local | LOCK-MISSING |
| Version published under 7 days ago; publisher or maintainer change versus the previous version; missing provenance attestation; deprecation marking; version absent from the registry | online only | VERSION-AGE, MAINTAINER-CHANGE, NO-PROVENANCE, DEPRECATED, VERSION-NOT-FOUND |
| Content diff of the two versions' tarballs: a version bump that adds an install script, or adds credential-path strings, network endpoints, binaries, or obfuscation-shaped code in install-reachable files (the script targets plus their relative imports). A quiet bump that adds a preinstall loading credential paths grades HIGH-RISK and names the added signals; a benign build postinstall with no such signals does not grade high | content mode only (`--content`) | CONTENT-INSTALL-SCRIPT-ADDED, CONTENT-INSTALL-SCRIPT-CHANGED, CONTENT-CRED-SIGNAL-ADDED, CONTENT-NETWORK-ENDPOINT-ADDED, CONTENT-BINARY-ADDED, CONTENT-OBFUSCATED-ADDED |

Lockfiles: `package-lock.json` is parsed fully (v1 legacy tree and v2/v3 packages map). `yarn.lock` and `pnpm-lock.yaml` are parsed best-effort for resolved entries and versions.

Verdicts: per dependency and overall, `CLEAR` / `REVIEW` / `HIGH-RISK`, with one evidence line per finding naming the dep, the change, the rule id, the severity, and whether the signal is local or online. Exit code is 0 for CLEAR and 1 for REVIEW or HIGH-RISK.

## CLI

```bash
depguard check [path] [--json] [--offline] [--online] [--content] [--base <ref>] [--base-path <dir>]
depguard package <name> [version] [--json] [--online] [--content]
depguard mcp
```

`check` defaults to the offline core against the current directory, as a single snapshot (every manifest dependency graded on what is here now). Pass `--base HEAD~1` (any git ref) or `--base-path <dir>` to diff against a base. `package` grades one name without a repo. There are no timestamps in the JSON report, so identical inputs produce byte-identical output.

`--content` adds content-based update vetting (v0.2.0, ledger P-158): for every changed or added dependency, and for snapshot pins with a prior published version, depguard fetches both versions' tarballs from the npm registry and diffs the install-time surface statically. Tarballs are extracted in memory only: depguard never installs or executes anything from a tarball. In `package` mode with `--content`, the named version is diffed against the greatest lower published version.

## MCP

One bin serves the CLI and a stdio MCP server (`depguard mcp`). Tools:

- `guard_path(path, base?, base_path?, online?, content?)`: the full diff report as JSON.
- `check_package(name, version?, online?, content?)`: grade a single package name and version.

## Limits

- Root manifests only: nested workspace package.json files and nested lockfiles are not inventoried in v0.1.0. (Ledger P-132, documented limit.)
- pnpm-lock.yaml parsing is key-based and best-effort: resolved tarball URLs are captured only where the lockfile layout exposes them inline, so resolved-host drift detection is strongest on package-lock.json, then yarn.lock, then pnpm-lock.yaml.
- Install scripts of dependencies themselves are known only where the lockfile records them (package-lock `hasInstallScript`) or, online, where registry metadata declares them. Content mode (`--content`, v0.2.0) goes one step further and downloads the two versions' tarballs to diff their install-time surface, but the inspection is static only: tarballs are extracted in memory, nothing is installed, and no tarball code is ever executed. Offline and online modes download nothing.
- Content mode follows install script targets and their relative imports to depth 3; signals buried deeper in a dependency's own internal graph, or generated at install time, are out of reach of this signal.
- Typosquat detection is name-shape only. A name that is itself a bundled popular name is never flagged (ledger P-130), and a well-chosen name at edit distance 3 or more is out of reach of this signal by design.
- Online signals are only as good as the registry packument: publisher comparison uses the recorded publisher of the greatest lower version, and provenance means an attestation entry exists in registry metadata, not that it was verified.
- Caps are explicit, never silent: lockfile parsing stops at 50,000 entries and any manifest file over 64 MiB is skipped, both reported in the output (`caps` in JSON, a cap line in human output, plus warnings).

## Development

```bash
npm install
npm run build
npm test
```

TypeScript, Node >= 20, tests with `tsx --test`, no network in unit tests (registry responses are injected fixtures).
