/**
 * depguard online checks. These run ONLY behind an explicit online
 * flag. The fetch function is injectable so unit tests use fixture
 * packuments and never touch the network. A failed lookup adds a
 * warning and changes no verdict: the offline core stands on its own.
 */
import type { Change, Finding } from "./core.js";
import { compareSemver, parseSemver } from "./core.js";

export interface OnlineOptions {
  fetchFn?: typeof fetch;
  now?: Date;
  warnings: string[];
}

interface Packument {
  time?: Record<string, string>;
  versions?: Record<string, Record<string, unknown>>;
  "dist-tags"?: Record<string, string>;
}

async function fetchPackument(name: string, opts: OnlineOptions): Promise<Packument | null> {
  const doFetch = opts.fetchFn ?? fetch;
  const url = `https://registry.npmjs.org/${encodeURIComponent(name)}`;
  try {
    const res = await doFetch(url);
    if (!res.ok) { opts.warnings.push(`online lookup for ${name} returned HTTP ${res.status}; local verdict unchanged`); return null; }
    return (await res.json()) as Packument;
  } catch (err) {
    opts.warnings.push(`online lookup for ${name} failed (${err instanceof Error ? err.message : String(err)}); local verdict unchanged`);
    return null;
  }
}

function publisherOf(v: Record<string, unknown> | undefined): string | null {
  if (!v) return null;
  const u = v._npmUser as { name?: string } | undefined;
  if (u?.name) return u.name;
  const ms = v.maintainers as { name?: string }[] | undefined;
  if (Array.isArray(ms) && ms.length > 0) return ms.map((m) => m.name ?? "?").sort().join(",");
  return null;
}

export function packumentFindings(name: string, version: string, pack: Packument, now: Date): Finding[] {
  const out: Finding[] = [];
  const versions = pack.versions ?? {};
  const entry = versions[version];
  if (!entry) {
    out.push({ rule: "VERSION-NOT-FOUND", severity: "medium", source: "online", evidence: `version ${version} of ${name} is not in the registry packument (unpublished or yanked versions look like this)` });
    return out;
  }
  const published = pack.time?.[version];
  if (published) {
    const ageDays = (now.getTime() - new Date(published).getTime()) / 86_400_000;
    if (ageDays >= 0 && ageDays < 7) out.push({ rule: "VERSION-AGE", severity: "medium", source: "online", evidence: `${name}@${version} was published ${ageDays.toFixed(1)} days ago (under 7 days)` });
  }
  // Previous version: greatest published semver strictly below this one.
  const target = parseSemver(version);
  if (target) {
    let prev: string | null = null;
    for (const v of Object.keys(versions)) {
      const sv = parseSemver(v);
      if (sv && compareSemver(sv, target) < 0 && (!prev || compareSemver(sv, parseSemver(prev)!) > 0)) prev = v;
    }
    if (prev) {
      const before = publisherOf(versions[prev]);
      const after = publisherOf(entry);
      if (before && after && before !== after) {
        out.push({ rule: "MAINTAINER-CHANGE", severity: "high", source: "online", evidence: `publisher changed between ${prev} (${before}) and ${version} (${after})` });
      }
    }
  }
  const dist = entry.dist as { attestations?: unknown } | undefined;
  if (!dist?.attestations) {
    out.push({ rule: "NO-PROVENANCE", severity: "low", source: "online", evidence: `${name}@${version} carries no provenance attestation in its registry metadata` });
  }
  const dep = entry.deprecated;
  if (typeof dep === "string" && dep.length > 0) {
    out.push({ rule: "DEPRECATED", severity: "medium", source: "online", evidence: `${name}@${version} is marked deprecated: ${dep.slice(0, 120)}` });
  }
  const scripts = entry.scripts as Record<string, string> | undefined;
  if (scripts) {
    for (const s of ["preinstall", "install", "postinstall", "prepare"]) {
      if (scripts[s]) out.push({ rule: "INSTALL-SCRIPT-PRESENT", severity: "medium", source: "online", evidence: `registry metadata for ${name}@${version} declares a ${s} script: ${String(scripts[s]).slice(0, 120)}` });
    }
  }
  return out;
}

export async function applyOnlineChecks(changes: Change[], opts: OnlineOptions): Promise<void> {
  const now = opts.now ?? new Date();
  for (const change of changes) {
    if (change.change === "removed") continue;
    const version = change.versionTo;
    if (!version) continue;
    const pack = await fetchPackument(change.name, opts);
    if (!pack) continue;
    change.findings.push(...packumentFindings(change.name, version, pack, now));
  }
}

export async function checkPackageOnline(name: string, version: string | undefined, opts: OnlineOptions): Promise<Finding[]> {
  const pack = await fetchPackument(name, opts);
  if (!pack) return [];
  const v = version ?? pack["dist-tags"]?.latest;
  if (!v) { opts.warnings.push(`online lookup for ${name} found no latest version`); return []; }
  return packumentFindings(name, v, pack, opts.now ?? new Date());
}
