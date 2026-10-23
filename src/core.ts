/**
 * depguard core: deterministic, offline-first dependency change analysis.
 *
 * A snapshot is the dependency state of one directory (or one git ref):
 * the manifest dependency map, the manifest install scripts, and the
 * lockfile entries. guardPath diffs a current snapshot against an
 * optional base snapshot and grades every change with local rules.
 * Registry checks live in registry.ts and run only behind an explicit
 * online flag; nothing in this file touches the network.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { basename, join } from "node:path";
import { POPULAR_NAMES } from "./popular.js";
import type { ContentFetch } from "./content.js";

export const VERSION = "0.2.0";
export const MAX_LOCK_ENTRIES = 50_000;
export const MAX_FILE_BYTES = 64 * 1024 * 1024;
export const INSTALL_SCRIPTS = ["preinstall", "install", "postinstall", "prepare"];

export type Severity = "high" | "medium" | "low";
export type Verdict = "CLEAR" | "REVIEW" | "HIGH-RISK";

export interface Finding {
  rule: string;
  severity: Severity;
  source: "local" | "online";
  evidence: string;
}

export interface ManifestDep {
  name: string;
  range: string;
  section: string;
}

export interface LockEntry {
  name: string;
  version?: string;
  resolved?: string;
  integrity?: string;
  hasInstallScript?: boolean;
  sourceFile: string;
}

export interface Snapshot {
  label: string;
  deps: Map<string, ManifestDep>;
  scripts: Record<string, string>;
  lock: Map<string, LockEntry>;
  lockEntryCount: number;
  lockFiles: string[];
  lockTruncated: boolean;
  warnings: string[];
}

export interface Change {
  name: string;
  change: "added" | "removed" | "changed" | "lock-changed";
  rangeFrom?: string;
  rangeTo?: string;
  versionFrom?: string;
  versionTo?: string;
  verdict: Verdict;
  findings: Finding[];
}

export interface GuardReport {
  tool: "depguard";
  version: string;
  path: string;
  base: string | null;
  mode: "offline" | "online";
  verdict: Verdict;
  counts: { added: number; removed: number; changed: number; findings: number; high: number; medium: number; low: number };
  changes: Change[];
  repoFindings: Finding[];
  caps: { lockEntriesSeen: number; lockEntriesCap: number; lockTruncated: boolean };
  warnings: string[];
  note?: string;
}

// ---------------------------------------------------------------- semver

export interface SemVer { major: number; minor: number; patch: number; pre: string | null }

export function parseSemver(v: string | undefined): SemVer | null {
  if (!v) return null;
  const m = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(v.trim());
  if (!m) return null;
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]), pre: m[4] ?? null };
}

export function compareSemver(a: SemVer, b: SemVer): number {
  for (const k of ["major", "minor", "patch"] as const) {
    if (a[k] !== b[k]) return a[k] < b[k] ? -1 : 1;
  }
  if (a.pre === null && b.pre === null) return 0;
  if (a.pre === null) return 1;
  if (b.pre === null) return -1;
  const pa = a.pre.split("."), pb = b.pre.split(".");
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    if (pa[i] === undefined) return -1;
    if (pb[i] === undefined) return 1;
    const na = /^\d+$/.test(pa[i]) ? Number(pa[i]) : null;
    const nb = /^\d+$/.test(pb[i]) ? Number(pb[i]) : null;
    if (na !== null && nb !== null) { if (na !== nb) return na < nb ? -1 : 1; }
    else if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1;
  }
  return 0;
}

/** The concrete version a range points at, when it names one. */
export function rangeTarget(range: string | undefined): string | null {
  if (!range) return null;
  const r = range.trim();
  if (r === "*" || r === "latest" || r === "") return null;
  if (/^(file:|link:|workspace:|git\+|git:|https?:|github:)/.test(r)) return null;
  const m = /(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)/.exec(r);
  return m ? m[1] : null;
}

/** Specificity ladder: 0 exact, 1 caret/tilde, 2 comparators, 3 star/latest. */
export function rangeWidth(range: string | undefined): number {
  if (!range) return 0;
  const r = range.trim();
  if (r === "*" || r === "latest" || r === "x" || r === "") return 3;
  if (/^(>=|>|<|<=|\|\|)/.test(r) || /\s-\s/.test(r)) return 2;
  if (r.startsWith("^") || r.startsWith("~")) return 1;
  return 0;
}

// ------------------------------------------------------- edit distance

/** Damerau-Levenshtein (optimal string alignment): one adjacent swap costs 1. */
export function editDistance(a: string, b: string): number {
  const m = a.length, n = b.length;
  if (Math.abs(m - n) > 3) return Math.abs(m - n);
  const d: number[][] = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 0; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
  }
  return d[m][n];
}

export function closestName(name: string, candidates: Iterable<string>): { match: string; distance: number } | null {
  let best: { match: string; distance: number } | null = null;
  for (const c of candidates) {
    if (c === name) continue;
    const dist = editDistance(name, c);
    if (dist > 0 && (best === null || dist < best.distance)) best = { match: c, distance: dist };
  }
  return best;
}

/**
 * Typosquat findings for a name being introduced. A name that IS a
 * popular name is never a suspect (express is distance 2 from cypress;
 * flagging it taught us this in the first test run, ledger P-130).
 * Distance is checked against the repo's own base dependency set and,
 * unless the name is itself popular, the bundled popular list.
 */
export function typosquatFindings(name: string, baseNames: Iterable<string>, popularNames: readonly string[]): Finding[] {
  const out: Finding[] = [];
  const popularSet = new Set(popularNames);
  const vsBase = closestName(name, baseNames);
  if (vsBase && vsBase.distance === 1) {
    out.push({ rule: "TYPOSQUAT-SUSPECT", severity: "high", source: "local", evidence: `name "${name}" is edit distance 1 from existing dependency "${vsBase.match}"` });
    return out;
  }
  if (!popularSet.has(name)) {
    const vsPopular = closestName(name, popularNames);
    if (vsPopular && vsPopular.distance === 1) {
      out.push({ rule: "TYPOSQUAT-SUSPECT", severity: "high", source: "local", evidence: `name "${name}" is edit distance 1 from popular name "${vsPopular.match}"` });
    } else if (vsPopular && vsPopular.distance === 2 && name.replace(/^@[^/]+\//, "").length >= 6 && !vsBase) {
      out.push({ rule: "TYPOSQUAT-POSSIBLE", severity: "medium", source: "local", evidence: `name "${name}" is edit distance 2 from popular name "${vsPopular.match}"` });
    } else if (vsBase && vsBase.distance === 2 && name.replace(/^@[^/]+\//, "").length >= 6) {
      out.push({ rule: "TYPOSQUAT-POSSIBLE", severity: "medium", source: "local", evidence: `name "${name}" is edit distance 2 from existing dependency "${vsBase.match}"` });
    }
  }
  return out;
}

// ------------------------------------------------------------ snapshots

function emptySnapshot(label: string): Snapshot {
  return { label, deps: new Map(), scripts: {}, lock: new Map(), lockEntryCount: 0, lockFiles: [], lockTruncated: false, warnings: [] };
}

function applyPackageJson(snap: Snapshot, pkg: Record<string, unknown>): void {
  for (const section of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    const block = pkg[section] as Record<string, string> | undefined;
    if (block && typeof block === "object") {
      for (const [name, range] of Object.entries(block)) {
        if (typeof range === "string" && !snap.deps.has(name)) snap.deps.set(name, { name, range, section });
      }
    }
  }
  const scripts = pkg.scripts as Record<string, string> | undefined;
  if (scripts && typeof scripts === "object") snap.scripts = { ...scripts };
}

function parsePackageLock(snap: Snapshot, text: string): void {
  let data: Record<string, unknown>;
  try { data = JSON.parse(text) as Record<string, unknown>; } catch { snap.warnings.push("package-lock.json is not valid JSON and was skipped"); return; }
  const add = (name: string, e: Record<string, unknown>) => {
    if (snap.lockEntryCount >= MAX_LOCK_ENTRIES) { snap.lockTruncated = true; return; }
    snap.lockEntryCount++;
    if (!snap.lock.has(name)) {
      snap.lock.set(name, {
        name,
        version: typeof e.version === "string" ? e.version : undefined,
        resolved: typeof e.resolved === "string" ? e.resolved : undefined,
        integrity: typeof e.integrity === "string" ? e.integrity : undefined,
        hasInstallScript: e.hasInstallScript === true,
        sourceFile: "package-lock.json",
      });
    }
  };
  const packages = data.packages as Record<string, Record<string, unknown>> | undefined;
  if (packages && typeof packages === "object") {
    for (const [key, entry] of Object.entries(packages)) {
      if (!key || !entry || typeof entry !== "object") continue;
      const idx = key.lastIndexOf("node_modules/");
      if (idx < 0) continue;
      add(key.slice(idx + "node_modules/".length), entry);
      if (snap.lockTruncated) break;
    }
  }
  const walkLegacy = (deps: Record<string, Record<string, unknown>> | undefined) => {
    if (!deps || typeof deps !== "object") return;
    for (const [name, entry] of Object.entries(deps)) {
      if (entry && typeof entry === "object") {
        add(name, entry);
        walkLegacy(entry.dependencies as Record<string, Record<string, unknown>> | undefined);
      }
      if (snap.lockTruncated) return;
    }
  };
  if (snap.lock.size === 0) walkLegacy(data.dependencies as Record<string, Record<string, unknown>> | undefined);
}

/** Best-effort yarn.lock (classic) resolved-entry parse. */
export function parseYarnLock(snap: Snapshot, text: string): void {
  const blocks = text.split(/\n(?=\S)/);
  for (const block of blocks) {
    const head = block.split("\n")[0]?.trim().replace(/:$/, "") ?? "";
    const firstKey = head.split(/,\s*/)[0]?.replace(/^"|"$/g, "") ?? "";
    const at = firstKey.lastIndexOf("@");
    if (at <= 0) continue;
    const name = firstKey.slice(0, at);
    const version = /\n\s+version\s+"?([^"\n]+)"?/.exec(block)?.[1];
    const resolved = /\n\s+resolved\s+"?([^"\n]+)"?/.exec(block)?.[1];
    const integrity = /\n\s+integrity\s+(\S+)/.exec(block)?.[1];
    if (snap.lockEntryCount >= MAX_LOCK_ENTRIES) { snap.lockTruncated = true; break; }
    snap.lockEntryCount++;
    if (!snap.lock.has(name)) snap.lock.set(name, { name, version, resolved, integrity, sourceFile: "yarn.lock" });
  }
}

/** Best-effort pnpm-lock.yaml parse of the packages: section keys. */
export function parsePnpmLock(snap: Snapshot, text: string): void {
  const seen = new Set<string>();
  const re = /^\s{2,4}\/?((?:@[^/\s]+\/)?[^@\s/]+)@(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const [, name, version] = m;
    if (seen.has(name)) continue;
    seen.add(name);
    if (snap.lockEntryCount >= MAX_LOCK_ENTRIES) { snap.lockTruncated = true; break; }
    snap.lockEntryCount++;
    if (!snap.lock.has(name)) snap.lock.set(name, { name, version, sourceFile: "pnpm-lock.yaml" });
  }
  // Resolution URLs in pnpm lockfiles hang off each package entry; a
  // tarball line directly under a package key is rare, so resolved host
  // drift is only partially visible here (documented limit).
  const resRe = /resolution:\s*\{[^}]*tarball:\s*(\S+?)[,}]/g;
  const urls: string[] = [];
  while ((m = resRe.exec(text)) !== null) urls.push(m[1]);
  let i = 0;
  for (const name of seen) {
    const e = snap.lock.get(name);
    if (e && urls[i]) e.resolved = urls[i];
    i++;
  }
}

const LOCK_READERS: Record<string, (snap: Snapshot, text: string) => void> = {
  "package-lock.json": parsePackageLock,
  "yarn.lock": parseYarnLock,
  "pnpm-lock.yaml": parsePnpmLock,
};
export const MANIFEST_FILES = ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"];

export function loadSnapshotFromDir(dir: string, label: string): Snapshot {
  const snap = emptySnapshot(label);
  for (const file of MANIFEST_FILES) {
    const p = join(dir, file);
    if (!existsSync(p)) continue;
    let text: string;
    try {
      if (statSync(p).size > MAX_FILE_BYTES) { snap.warnings.push(`${file} exceeds the ${MAX_FILE_BYTES} byte cap and was skipped`); continue; }
      text = readFileSync(p, "utf8");
    } catch { snap.warnings.push(`${file} could not be read and was skipped`); continue; }
    if (file === "package.json") {
      try { applyPackageJson(snap, JSON.parse(text) as Record<string, unknown>); }
      catch { snap.warnings.push("package.json is not valid JSON and was skipped"); }
    } else {
      snap.lockFiles.push(file);
      LOCK_READERS[file](snap, text);
    }
  }
  return snap;
}

export function loadSnapshotFromGit(dir: string, ref: string): Snapshot | null {
  const snap = emptySnapshot(ref);
  let any = false;
  for (const file of MANIFEST_FILES) {
    let text: string | null = null;
    try {
      text = execFileSync("git", ["-C", dir, "show", `${ref}:${file}`], { encoding: "utf8", maxBuffer: MAX_FILE_BYTES, stdio: ["ignore", "pipe", "ignore"] });
    } catch { text = null; }
    if (text === null) continue;
    any = true;
    if (file === "package.json") {
      try { applyPackageJson(snap, JSON.parse(text) as Record<string, unknown>); } catch { /* base package.json unparsable: treat as absent */ }
    } else {
      snap.lockFiles.push(file);
      LOCK_READERS[file](snap, text);
    }
  }
  return any ? snap : null;
}

// ---------------------------------------------------------------- rules

// setup.mjs / setup.js is the documented Shai-Hulud preinstall dropper
// name from public reporting (see SPEC.md); an install script that runs
// one is treated as risky content, not a bare presence.
const RISKY_SCRIPT_RE = /(curl|wget|https?:\/\/|base64\s+-d|eval\(|node\s+-e|child_process|execSync|spawn\(|\.ssh|\.aws|credentials|process\.env|setup\.mjs|setup\.js)/;

function verdictOf(findings: Finding[]): Verdict {
  if (findings.some((f) => f.severity === "high")) return "HIGH-RISK";
  if (findings.length > 0) return "REVIEW";
  return "CLEAR";
}

function hostOf(url: string | undefined): string | null {
  if (!url) return null;
  try { return new URL(url).host; } catch { return null; }
}

function lockDigest(snap: Snapshot): string {
  const parts: string[] = [];
  for (const name of [...snap.lock.keys()].sort()) {
    const e = snap.lock.get(name)!;
    parts.push(`${name}@${e.version ?? ""}|${e.resolved ?? ""}|${e.integrity ?? ""}|${e.hasInstallScript ? "s" : ""}`);
  }
  return createHash("sha256").update(parts.join("\n")).digest("hex");
}

export interface GuardOptions {
  baseRef?: string;
  basePath?: string;
  online?: boolean;
  /** Content mode (Gap A): fetch both versions' tarballs and diff the install-time surface. Implies network use, like online. */
  content?: boolean;
  /** Injectable registry and tarball retrieval for content mode; tests pass recorded fixtures. */
  contentFetch?: ContentFetch;
  fetchFn?: typeof fetch;
  now?: Date;
}

export async function guardPath(targetPath: string, opts: GuardOptions = {}): Promise<GuardReport> {
  const warnings: string[] = [];
  const current = loadSnapshotFromDir(targetPath, "current");
  warnings.push(...current.warnings);

  let base: Snapshot | null = null;
  let baseLabel: string | null = null;
  if (opts.basePath) {
    base = loadSnapshotFromDir(opts.basePath, opts.basePath);
    warnings.push(...base.warnings.map((w) => `base: ${w}`));
    baseLabel = opts.basePath;
  } else if (opts.baseRef) {
    base = loadSnapshotFromGit(targetPath, opts.baseRef);
    baseLabel = opts.baseRef;
    if (!base) warnings.push(`base ref ${opts.baseRef} yielded no manifests; treated as a first snapshot`);
  }

  const changes: Change[] = [];
  const repoFindings: Finding[] = [];
  const popular = POPULAR_NAMES;

  const checkAdded = (dep: ManifestDep, lockE: LockEntry | undefined): Finding[] => {
    const out: Finding[] = [];
    out.push(...typosquatFindings(dep.name, base ? base.deps.keys() : [], popular));
    const w = rangeWidth(dep.range);
    if (w === 3) out.push({ rule: "RANGE-UNPINNED", severity: "medium", source: "local", evidence: `added dependency range "${dep.range}" accepts any version` });
    if (lockE?.hasInstallScript) out.push({ rule: "INSTALL-SCRIPT-PRESENT", severity: "medium", source: "local", evidence: `lockfile marks added dependency "${dep.name}" as having an install script (hasInstallScript)` });
    return out;
  };

  if (base) {
    const names = new Set([...base.deps.keys(), ...current.deps.keys()]);
    for (const name of [...names].sort()) {
      const b = base.deps.get(name), c = current.deps.get(name);
      const bLock = base.lock.get(name), cLock = current.lock.get(name);
      if (c && !b) {
        const findings = checkAdded(c, cLock);
        changes.push({ name, change: "added", rangeTo: c.range, versionTo: cLock?.version, verdict: verdictOf(findings), findings });
      } else if (b && !c) {
        changes.push({ name, change: "removed", rangeFrom: b.range, versionFrom: bLock?.version, verdict: "CLEAR", findings: [] });
      } else if (b && c) {
        const findings: Finding[] = [];
        const rangeChanged = b.range !== c.range;
        const versionChanged = (bLock?.version ?? null) !== (cLock?.version ?? null);
        if (!rangeChanged && !versionChanged && (bLock?.resolved ?? null) === (cLock?.resolved ?? null) && (bLock?.integrity ?? null) === (cLock?.integrity ?? null)) continue;
        const fromV = parseSemver(bLock?.version ?? rangeTarget(b.range) ?? undefined);
        const toV = parseSemver(cLock?.version ?? rangeTarget(c.range) ?? undefined);
        if (rangeChanged) {
          const bw = rangeWidth(b.range), cw = rangeWidth(c.range);
          if (cw > bw) {
            const sev: Severity = cw === 3 ? "high" : "medium";
            findings.push({ rule: "RANGE-WIDENED", severity: sev, source: "local", evidence: `range widened from "${b.range}" to "${c.range}"` });
          }
        }
        if (fromV && toV) {
          const cmp = compareSemver(toV, fromV);
          if (cmp < 0) findings.push({ rule: "DOWNGRADE", severity: "medium", source: "local", evidence: `locked version moved down from ${bLock?.version ?? rangeTarget(b.range)} to ${cLock?.version ?? rangeTarget(c.range)}` });
          if (fromV.pre === null && toV.pre !== null && compareSemver({ ...toV, pre: null }, fromV) <= 0) {
            findings.push({ rule: "PRERELEASE-JUMP", severity: "medium", source: "local", evidence: `stable version ${fromV.major}.${fromV.minor}.${fromV.patch} replaced by prerelease ${cLock?.version ?? rangeTarget(c.range)}` });
          }
        }
        const rawVersion = cLock?.version ?? rangeTarget(c.range);
        if (rawVersion && !parseSemver(rawVersion)) findings.push({ rule: "VERSION-PATTERN", severity: "low", source: "local", evidence: `version "${rawVersion}" is not a plain semver release (yanked or retagged releases often look like this)` });
        if (cLock?.hasInstallScript && !bLock?.hasInstallScript) {
          findings.push({ rule: "INSTALL-SCRIPT-ADDED", severity: "high", source: "local", evidence: `lockfile now marks "${name}" as having an install script; the base lockfile did not` });
        }
        if ((bLock?.version ?? null) === (cLock?.version ?? null) && bLock && cLock) {
          const bh = hostOf(bLock.resolved), ch = hostOf(cLock.resolved);
          if (bh && ch && bh !== ch) findings.push({ rule: "RESOLVED-HOST-CHANGE", severity: "high", source: "local", evidence: `same version ${cLock.version} now resolves from host ${ch} instead of ${bh}` });
          if (bLock.integrity && !cLock.integrity) findings.push({ rule: "INTEGRITY-REMOVED", severity: "medium", source: "local", evidence: `integrity hash for ${name}@${cLock.version} disappeared from the lockfile` });
          else if (bLock.integrity && cLock.integrity && bLock.integrity !== cLock.integrity) findings.push({ rule: "INTEGRITY-CHANGED", severity: "medium", source: "local", evidence: `integrity hash for ${name}@${cLock.version} changed without a version change` });
        }
        changes.push({ name, change: "changed", rangeFrom: b.range, rangeTo: c.range, versionFrom: bLock?.version, versionTo: cLock?.version, verdict: verdictOf(findings), findings });
      }
    }
    // Lock-only changes: entries whose manifest dep did not change.
    const changedNames = new Set(changes.map((c) => c.name));
    const lockNames = new Set([...base.lock.keys(), ...current.lock.keys()]);
    for (const name of [...lockNames].sort()) {
      if (changedNames.has(name)) continue;
      const bLock = base.lock.get(name), cLock = current.lock.get(name);
      if (!bLock || !cLock) continue;
      if ((bLock.version ?? null) === (cLock.version ?? null) && (bLock.resolved ?? null) !== (cLock.resolved ?? null)) {
        const findings: Finding[] = [];
        const bh = hostOf(bLock.resolved), ch = hostOf(cLock.resolved);
        if (bh && ch && bh !== ch) findings.push({ rule: "RESOLVED-HOST-CHANGE", severity: "high", source: "local", evidence: `lockfile-only change: ${name}@${cLock.version} now resolves from host ${ch} instead of ${bh}, with no manifest change` });
        else findings.push({ rule: "LOCKFILE-ONLY-DRIFT", severity: "medium", source: "local", evidence: `resolved URL for ${name}@${cLock.version} changed with no manifest change` });
        changes.push({ name, change: "lock-changed", versionFrom: bLock.version, versionTo: cLock.version, verdict: verdictOf(findings), findings });
      }
    }
    // Repo level: install scripts in the repo's own package.json.
    for (const s of INSTALL_SCRIPTS) {
      const before = base.scripts[s], after = current.scripts[s];
      if (after && !before) {
        const risky = RISKY_SCRIPT_RE.test(after);
        repoFindings.push({ rule: "INSTALL-SCRIPT-ADDED", severity: risky ? "high" : "medium", source: "local", evidence: `the repo's own package.json gained a ${s} script: ${after.slice(0, 160)}` });
      } else if (after && before && after !== before) {
        const risky = RISKY_SCRIPT_RE.test(after);
        repoFindings.push({ rule: "INSTALL-SCRIPT-CHANGED", severity: risky ? "high" : "medium", source: "local", evidence: `the repo's own ${s} script changed to: ${after.slice(0, 160)}` });
      }
    }
    // Repo level: manifest moved but the lockfile did not.
    const manifestChanged = changes.some((c) => c.change === "added" || c.change === "removed" || c.change === "changed");
    const lockChanged = lockDigest(base) !== lockDigest(current);
    if (manifestChanged && !lockChanged && base.lockFiles.length > 0) {
      repoFindings.push({ rule: "LOCKFILE-DRIFT", severity: "medium", source: "local", evidence: "dependency manifests changed but every lockfile entry is identical to the base; the lockfile was not regenerated" });
    }
    if (!manifestChanged && lockChanged && !changes.some((c) => c.change === "lock-changed")) {
      repoFindings.push({ rule: "LOCKFILE-ONLY-DRIFT", severity: "medium", source: "local", evidence: "lockfile entries changed while dependency manifests are identical to the base" });
    }
  } else {
    // Single snapshot: audit what is here now.
    for (const dep of [...current.deps.values()].sort((a, b) => a.name.localeCompare(b.name))) {
      const findings: Finding[] = [];
      const lockE = current.lock.get(dep.name);
      findings.push(...typosquatFindings(dep.name, [], popular));
      if (rangeWidth(dep.range) === 3) findings.push({ rule: "RANGE-UNPINNED", severity: "medium", source: "local", evidence: `dependency range "${dep.range}" accepts any version` });
      // Aliased and non-registry protocols (npm:, workspace:, file:,
      // link:, git) resolve under a different name or no lock entry at
      // all; expecting a same-name entry false-positives on them
      // (ledger P-134, found on facebook/react's npm: alias deps).
      if (current.lockFiles.length > 0 && !lockE && !/^(npm:|workspace:|file:|link:|git\+|git:|github:|https?:)/.test(dep.range.trim())) findings.push({ rule: "LOCK-MISSING", severity: "medium", source: "local", evidence: `dependency "${dep.name}" is in the manifest but has no lockfile entry` });
      if (lockE?.hasInstallScript) findings.push({ rule: "INSTALL-SCRIPT-PRESENT", severity: "medium", source: "local", evidence: `lockfile marks "${dep.name}" as having an install script (hasInstallScript)` });
      if (findings.length > 0) changes.push({ name: dep.name, change: "changed", rangeTo: dep.range, versionTo: lockE?.version, verdict: verdictOf(findings), findings });
    }
    for (const s of INSTALL_SCRIPTS) {
      const cmd = current.scripts[s];
      if (cmd) {
        const risky = RISKY_SCRIPT_RE.test(cmd);
        repoFindings.push({ rule: "INSTALL-SCRIPT-PRESENT", severity: risky ? "high" : "medium", source: "local", evidence: `the repo's own package.json has a ${s} script: ${cmd.slice(0, 160)}` });
      }
    }
  }

  if (opts.online) {
    const { applyOnlineChecks } = await import("./registry.js");
    await applyOnlineChecks(changes, { fetchFn: opts.fetchFn, now: opts.now, warnings });
    for (const c of changes) c.verdict = verdictOf(c.findings);
  }

  if (opts.content) {
    const { applyContentChecks } = await import("./content.js");
    // Snapshot mode only lists deps that already carry findings; a
    // pinned dep with a prior published version still deserves a
    // content diff, so stage candidate entries for the rest and drop
    // the ones the content diff leaves clean.
    const staged = new Set<string>();
    if (!base) {
      const listed = new Set(changes.map((c) => c.name));
      for (const dep of current.deps.values()) {
        const lockE = current.lock.get(dep.name);
        if (!lockE?.version || listed.has(dep.name)) continue;
        changes.push({ name: dep.name, change: "changed", rangeTo: dep.range, versionTo: lockE.version, verdict: "CLEAR", findings: [] });
        staged.add(dep.name);
      }
    }
    await applyContentChecks(changes, { fetchFn: opts.fetchFn, contentFetch: opts.contentFetch, warnings });
    for (let i = changes.length - 1; i >= 0; i--) {
      if (staged.has(changes[i].name) && changes[i].findings.length === 0) changes.splice(i, 1);
    }
    for (const c of changes) c.verdict = verdictOf(c.findings);
  }

  changes.sort((a, b) => a.name.localeCompare(b.name));
  const allFindings = [...changes.flatMap((c) => c.findings), ...repoFindings];
  const verdict = verdictOf(allFindings);
  const report: GuardReport = {
    tool: "depguard",
    version: VERSION,
    path: targetPath,
    base: baseLabel,
    mode: opts.online || opts.content ? "online" : "offline",
    verdict,
    counts: {
      added: changes.filter((c) => c.change === "added").length,
      removed: changes.filter((c) => c.change === "removed").length,
      changed: changes.filter((c) => c.change === "changed" || c.change === "lock-changed").length,
      findings: allFindings.length,
      high: allFindings.filter((f) => f.severity === "high").length,
      medium: allFindings.filter((f) => f.severity === "medium").length,
      low: allFindings.filter((f) => f.severity === "low").length,
    },
    changes,
    repoFindings,
    caps: { lockEntriesSeen: current.lockEntryCount, lockEntriesCap: MAX_LOCK_ENTRIES, lockTruncated: current.lockTruncated },
    warnings,
  };
  if (current.deps.size === 0 && current.lockEntryCount === 0) {
    report.note = "No dependency manifests or lockfiles were found at this path; nothing was audited and the verdict covers an empty estate.";
    if (report.verdict === "CLEAR") report.verdict = "REVIEW";
  }
  if (current.lockTruncated) warnings.push(`lockfile entries exceeded the ${MAX_LOCK_ENTRIES} entry cap and were truncated`);
  return report;
}

// --------------------------------------------------------- check_package

export interface PackageReport {
  tool: "depguard";
  version: string;
  name: string;
  requestedVersion: string | null;
  mode: "offline" | "online";
  verdict: Verdict;
  findings: Finding[];
  warnings: string[];
}

export async function checkPackage(name: string, version: string | undefined, opts: GuardOptions = {}): Promise<PackageReport> {
  const findings: Finding[] = [];
  const warnings: string[] = [];
  findings.push(...typosquatFindings(name, [], POPULAR_NAMES));
  if (version && !parseSemver(version)) findings.push({ rule: "VERSION-PATTERN", severity: "low", source: "local", evidence: `version "${version}" is not a plain semver release` });
  const report: PackageReport = { tool: "depguard", version: VERSION, name, requestedVersion: version ?? null, mode: opts.online || opts.content ? "online" : "offline", verdict: "CLEAR", findings, warnings };
  if (opts.online) {
    const { checkPackageOnline } = await import("./registry.js");
    const extra = await checkPackageOnline(name, version, { fetchFn: opts.fetchFn, now: opts.now, warnings });
    findings.push(...extra);
  }
  if (opts.content) {
    const { contentCheckPackage, defaultContentFetch } = await import("./content.js");
    const fetcher = opts.contentFetch ?? defaultContentFetch(opts.fetchFn);
    findings.push(...(await contentCheckPackage(fetcher, name, version, warnings)));
  }
  report.verdict = verdictOf(findings);
  return report;
}

// --------------------------------------------------------------- render

export function renderGuardReport(r: GuardReport): string {
  const lines: string[] = [];
  lines.push(`depguard ${r.version}  ${r.path}${r.base ? `  (base: ${r.base})` : ""}  mode: ${r.mode}`);
  lines.push(`verdict: ${r.verdict}  added: ${r.counts.added}  removed: ${r.counts.removed}  changed: ${r.counts.changed}  findings: ${r.counts.findings} (high ${r.counts.high}, medium ${r.counts.medium}, low ${r.counts.low})`);
  if (r.note) lines.push(`note: ${r.note}`);
  for (const w of r.warnings) lines.push(`warning: ${w}`);
  for (const f of r.repoFindings) lines.push(`[repo] ${f.rule} (${f.severity}, ${f.source}): ${f.evidence}`);
  for (const c of r.changes) {
    const span = c.change === "added" ? `added ${c.rangeTo ?? ""}` : c.change === "removed" ? `removed ${c.rangeFrom ?? ""}` : `${c.versionFrom ?? c.rangeFrom ?? "?"} -> ${c.versionTo ?? c.rangeTo ?? "?"}`;
    lines.push(`${c.name}: ${c.change} ${span}  [${c.verdict}]`);
    for (const f of c.findings) lines.push(`  ${f.rule} (${f.severity}, ${f.source}): ${f.evidence}`);
  }
  if (r.caps.lockTruncated) lines.push(`cap: lockfile entries truncated at ${r.caps.lockEntriesCap}`);
  return lines.join("\n");
}

export function renderPackageReport(r: PackageReport): string {
  const lines = [`depguard ${r.version}  package ${r.name}${r.requestedVersion ? `@${r.requestedVersion}` : ""}  mode: ${r.mode}`, `verdict: ${r.verdict}`];
  for (const w of r.warnings) lines.push(`warning: ${w}`);
  for (const f of r.findings) lines.push(`  ${f.rule} (${f.severity}, ${f.source}): ${f.evidence}`);
  return lines.join("\n");
}

export { basename };
