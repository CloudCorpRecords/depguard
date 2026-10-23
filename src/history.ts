/**
 * depguard history mode (Gap B, ledger P-159).
 *
 * A staged npm worm (the testmetest / Miasma shape) publishes in three
 * steps: a 0.0.0-stage stub, a harmless decoy release, then a rapid
 * malicious-shaped patch that becomes dist-tags.latest, often with a
 * version regression (1.0.0 down to 0.0.1). No single package tree
 * shows the pattern; it lives only in registry publish history.
 * History mode fetches the packument and analyzes the publish
 * timeline: version order and gaps, the staged pattern, per-version
 * publisher and maintainer changes, repository slug changes, and
 * provenance presence changes.
 *
 * Read-only and static: history mode reads registry metadata only and
 * never downloads a tarball. The fetch function is injectable so unit
 * tests run on synthetic packument fixtures with no network.
 */
import type { Finding, Verdict } from "./core.js";
import { VERSION, compareSemver, parseSemver } from "./core.js";

export interface HistoryOptions {
  fetchFn?: typeof fetch;
  warnings?: string[];
}

export interface HistoryEntry {
  version: string;
  publishedAt: string | null;
  publisher: string | null;
}

export interface HistoryReport {
  tool: "depguard";
  version: string;
  name: string;
  mode: "online";
  verdict: Verdict;
  findings: Finding[];
  warnings: string[];
  timeline: HistoryEntry[];
  distTags: Record<string, string>;
}

interface PackumentLike {
  time?: Record<string, string>;
  versions?: Record<string, Record<string, unknown>>;
  "dist-tags"?: Record<string, string>;
  maintainers?: { name?: string }[];
}

interface VersionInfo {
  version: string;
  publishedAt: string | null;
  timeMs: number | null;
  publisher: string | null;
  maintainers: string | null;
  repoSlug: string | null;
  hasProvenance: boolean;
  hasInstallScript: boolean;
}

const DAY_MS = 86_400_000;

function verdictOf(findings: Finding[]): Verdict {
  if (findings.some((f) => f.severity === "high")) return "HIGH-RISK";
  if (findings.length > 0) return "REVIEW";
  return "CLEAR";
}

function publisherOf(v: Record<string, unknown> | undefined): string | null {
  if (!v) return null;
  const u = v._npmUser as { name?: string } | undefined;
  if (u?.name) return u.name;
  const ms = v.maintainers as { name?: string }[] | undefined;
  if (Array.isArray(ms) && ms.length > 0) return ms.map((m) => m.name ?? "?").sort().join(",");
  return null;
}

function maintainersOf(v: Record<string, unknown> | undefined): string | null {
  const ms = v?.maintainers as { name?: string }[] | undefined;
  if (Array.isArray(ms) && ms.length > 0) return ms.map((m) => m.name ?? "?").sort().join(",");
  return null;
}

export function repoSlug(repo: unknown): string | null {
  const url = typeof repo === "string" ? repo : (repo as { url?: string } | undefined)?.url;
  if (!url || typeof url !== "string") return null;
  const m = /github\.com[:/]([^/]+)\/([^/\s]+?)(?:\.git)?(?:\/.*)?$/.exec(url.trim());
  if (m) return `${m[1]}/${m[2]}`;
  return url.trim().replace(/^git\+/, "").replace(/\.git$/, "");
}

function versionInfos(pack: PackumentLike): VersionInfo[] {
  const versions = pack.versions ?? {};
  const infos: VersionInfo[] = [];
  for (const [version, entry] of Object.entries(versions)) {
    const publishedAt = pack.time?.[version] ?? null;
    const scripts = entry.scripts as Record<string, string> | undefined;
    const dist = entry.dist as { attestations?: unknown } | undefined;
    infos.push({
      version,
      publishedAt,
      timeMs: publishedAt ? new Date(publishedAt).getTime() : null,
      publisher: publisherOf(entry),
      maintainers: maintainersOf(entry),
      repoSlug: repoSlug(entry.repository),
      hasProvenance: Boolean(dist?.attestations),
      hasInstallScript: Boolean(scripts && (scripts.preinstall || scripts.install || scripts.postinstall || scripts.prepare)),
    });
  }
  infos.sort((a, b) => {
    if (a.timeMs !== null && b.timeMs !== null && a.timeMs !== b.timeMs) return a.timeMs - b.timeMs;
    const sa = parseSemver(a.version), sb = parseSemver(b.version);
    if (sa && sb) return compareSemver(sa, sb);
    return a.version.localeCompare(b.version);
  });
  return infos;
}

const STAGE_PRE_RE = /(^|[-.])stage($|[-.])/;

export function isStageStub(version: string): boolean {
  if (version === "0.0.0") return true;
  const sv = parseSemver(version);
  if (!sv || !sv.pre) return false;
  if (sv.major === 0 && sv.minor === 0 && sv.patch === 0) return true;
  return STAGE_PRE_RE.test(sv.pre);
}

export function analyzeHistory(name: string, pack: PackumentLike): Finding[] {
  const out: Finding[] = [];
  const infos = versionInfos(pack);
  if (infos.length === 0) return out;
  const latest = pack["dist-tags"]?.latest ?? null;

  // Stage stubs.
  const stubs = infos.filter((i) => isStageStub(i.version));
  for (const s of stubs) {
    out.push({
      rule: "HISTORY-STAGE-STUB",
      severity: "medium",
      source: "online",
      evidence: `${name} published a stage-shaped stub version ${s.version}${s.publishedAt ? ` at ${s.publishedAt}` : ""}${s.publisher ? ` by ${s.publisher}` : ""}; stub publishes are the first step of the staged worm pattern`,
    });
  }

  // Greatest stable (non-prerelease) version, for latest regression.
  let maxStable: string | null = null;
  for (const i of infos) {
    const sv = parseSemver(i.version);
    if (sv && sv.pre === null && (!maxStable || compareSemver(sv, parseSemver(maxStable)!) > 0)) maxStable = i.version;
  }
  let latestRegressed = false;
  if (latest && maxStable) {
    const lv = parseSemver(latest), mv = parseSemver(maxStable);
    if (lv && mv && compareSemver(lv, mv) < 0) {
      latestRegressed = true;
      out.push({
        rule: "HISTORY-LATEST-REGRESSION",
        severity: "medium",
        source: "online",
        evidence: `dist-tags.latest for ${name} points at ${latest}, which is lower than the greatest stable version ${maxStable} in its own publish history`,
      });
    }
  }

  // The staged pattern: stub, then a decoy-looking higher release,
  // then a rapid lower patch that becomes latest.
  let staged: { stub: VersionInfo; decoy: VersionInfo; patch: VersionInfo } | null = null;
  for (const stub of stubs) {
    if (stub.timeMs === null) continue;
    for (const decoy of infos) {
      if (decoy.timeMs === null || decoy.timeMs <= stub.timeMs) continue;
      if (decoy.timeMs - stub.timeMs > 14 * DAY_MS) continue;
      const dv = parseSemver(decoy.version), sv = parseSemver(stub.version);
      if (!dv || !sv || compareSemver(dv, sv) <= 0 || dv.pre !== null) continue;
      for (const patch of infos) {
        if (patch.timeMs === null || patch.timeMs <= decoy.timeMs) continue;
        if (patch.timeMs - decoy.timeMs > 14 * DAY_MS) continue;
        const pv = parseSemver(patch.version);
        if (!pv || compareSemver(pv, dv) >= 0) continue;
        if (latest !== patch.version && patch.timeMs !== Math.max(...infos.map((i) => i.timeMs ?? 0))) continue;
        staged = { stub, decoy, patch };
        break;
      }
      if (staged) break;
    }
    if (staged) break;
  }
  if (staged) {
    const gapHours = staged.patch.timeMs !== null && staged.stub.timeMs !== null ? ((staged.patch.timeMs - staged.stub.timeMs) / 3_600_000).toFixed(1) : "?";
    out.push({
      rule: "HISTORY-STAGED-PATTERN",
      severity: "high",
      source: "online",
      evidence: `${name} shows the staged publishing pattern: stub ${staged.stub.version} published ${staged.stub.publishedAt}, decoy release ${staged.decoy.version} published ${staged.decoy.publishedAt}, then patch ${staged.patch.version} published ${staged.patch.publishedAt} regressing below the decoy (${staged.decoy.version} down to ${staged.patch.version})${latest === staged.patch.version ? ` and holding dist-tags.latest` : ""}; all three steps inside ${gapHours} hours`,
    });
    // The regression is a named element of the staged pattern; the
    // standalone finding above records it at medium when it appears
    // without staging, so do not double count it here.
    for (let i = out.length - 1; i >= 0; i--) {
      if (out[i].rule === "HISTORY-LATEST-REGRESSION") out[i] = { ...out[i], severity: "high" };
    }
  }

  // Rapid succession with a regression inside the cluster.
  for (let i = 0; i + 2 < infos.length; i++) {
    const a = infos[i], c = infos[i + 2];
    if (a.timeMs === null || c.timeMs === null || c.timeMs - a.timeMs > 3 * DAY_MS) continue;
    let regressed = false;
    let best: VersionInfo | null = null;
    for (let j = i; j <= i + 2; j++) {
      const v = parseSemver(infos[j].version);
      if (v && (!best || compareSemver(v, parseSemver(best.version)!) > 0)) best = infos[j];
      if (best && v && compareSemver(v, parseSemver(best.version)!) < 0) regressed = true;
    }
    if (regressed) {
      out.push({
        rule: "HISTORY-RAPID-REGRESSION",
        severity: "medium",
        source: "online",
        evidence: `${name} published ${infos[i].version}, ${infos[i + 1].version}, and ${infos[i + 2].version} inside 72 hours with a version regression inside the cluster (down to ${infos[i + 2].version})`,
      });
      break;
    }
  }

  // Consecutive publisher, maintainer set, repository, provenance.
  for (let i = 1; i < infos.length; i++) {
    const prev = infos[i - 1], cur = infos[i];
    if (prev.publisher && cur.publisher && prev.publisher !== cur.publisher) {
      const rapid = prev.timeMs !== null && cur.timeMs !== null && cur.timeMs - prev.timeMs <= 14 * DAY_MS;
      out.push({
        rule: "HISTORY-MAINTAINER-CHANGE",
        severity: rapid ? "medium" : "low",
        source: "online",
        evidence: `publisher of ${name} changed between ${prev.version} (${prev.publisher}) and ${cur.version} (${cur.publisher})`,
      });
    } else if (prev.maintainers && cur.maintainers && prev.maintainers !== cur.maintainers) {
      out.push({
        rule: "HISTORY-MAINTAINER-CHANGE",
        severity: "low",
        source: "online",
        evidence: `maintainer set of ${name} changed between ${prev.version} (${prev.maintainers}) and ${cur.version} (${cur.maintainers})`,
      });
    }
    if (prev.repoSlug && cur.repoSlug && prev.repoSlug !== cur.repoSlug) {
      out.push({
        rule: "HISTORY-REPO-CHANGE",
        severity: "low",
        source: "online",
        evidence: `repository of ${name} changed between ${prev.version} (${prev.repoSlug}) and ${cur.version} (${cur.repoSlug})`,
      });
    }
    if (prev.hasProvenance && !cur.hasProvenance) {
      out.push({
        rule: "HISTORY-PROVENANCE-DROP",
        severity: "low",
        source: "online",
        evidence: `${name}@${prev.version} carried a provenance attestation but ${cur.version} does not`,
      });
    }
  }
  return out;
}

export async function historyPackage(name: string, opts: HistoryOptions = {}): Promise<HistoryReport> {
  const warnings: string[] = opts.warnings ?? [];
  const doFetch = opts.fetchFn ?? fetch;
  const report: HistoryReport = {
    tool: "depguard",
    version: VERSION,
    name,
    mode: "online",
    verdict: "CLEAR",
    findings: [],
    warnings,
    timeline: [],
    distTags: {},
  };
  let pack: PackumentLike | null = null;
  try {
    const res = await doFetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
    if (!res.ok) {
      report.findings.push({
        rule: "HISTORY-PACKAGE-NOT-FOUND",
        severity: "medium",
        source: "online",
        evidence: `registry lookup for ${name} returned HTTP ${res.status}; the package has no readable publish history (removed packages look like this)`,
      });
      report.verdict = verdictOf(report.findings);
      return report;
    }
    pack = (await res.json()) as PackumentLike;
  } catch (err) {
    warnings.push(`history lookup for ${name} failed (${err instanceof Error ? err.message : String(err)})`);
    report.findings.push({
      rule: "HISTORY-PACKAGE-NOT-FOUND",
      severity: "medium",
      source: "online",
      evidence: `registry lookup for ${name} failed, so no publish history could be analyzed`,
    });
    report.verdict = verdictOf(report.findings);
    return report;
  }
  report.distTags = pack["dist-tags"] ?? {};
  report.timeline = versionInfos(pack).map((i) => ({ version: i.version, publishedAt: i.publishedAt, publisher: i.publisher }));
  report.findings = analyzeHistory(name, pack);
  report.verdict = verdictOf(report.findings);
  return report;
}

export function renderHistoryReport(r: HistoryReport): string {
  const lines: string[] = [];
  lines.push(`depguard ${r.version}  history ${r.name}  mode: ${r.mode}`);
  lines.push(`verdict: ${r.verdict}  versions: ${r.timeline.length}  latest: ${r.distTags.latest ?? "?"}`);
  for (const w of r.warnings) lines.push(`warning: ${w}`);
  for (const f of r.findings) lines.push(`  ${f.rule} (${f.severity}, ${f.source}): ${f.evidence}`);
  return lines.join("\n");
}
