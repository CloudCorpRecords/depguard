/**
 * depguard content mode (Gap A, ledger P-158).
 *
 * Name vetting and lockfile flags cannot see a compromised version of
 * a legitimate package: the tensorlake 0.5.144 compromise carried a
 * correctly spelled name and only its tarball content (a new
 * preinstall running a loader that read credential paths and posted
 * them out) showed the attack. Content mode fetches BOTH versions'
 * tarballs from the npm registry and diffs the install-time surface
 * statically: file inventory, package.json install scripts, and the
 * files those scripts can reach (their direct targets plus relative
 * imports), scanning for credential-path strings, network endpoints,
 * newly added binaries, and obfuscation-shaped code.
 *
 * Safety contract: tarballs are extracted in memory only. Nothing is
 * installed, nothing is executed, no file from a tarball is written
 * to disk. Retrieval sits behind the injectable ContentFetch layer so
 * unit tests run on recorded fixtures and never touch the network.
 * Content mode runs only behind an explicit flag, like online mode.
 */
import { gunzipSync } from "node:zlib";
import type { Change, Finding } from "./core.js";
import { compareSemver, parseSemver, INSTALL_SCRIPTS } from "./core.js";

export interface ContentFetch {
  packument: (name: string) => Promise<unknown>;
  tarball: (url: string) => Promise<Buffer>;
}

export interface ContentOptions {
  fetchFn?: typeof fetch;
  contentFetch?: ContentFetch;
  warnings: string[];
}

export const MAX_TARBALL_BYTES = 64 * 1024 * 1024;
export const MAX_TARBALL_FILES = 20_000;
export const MAX_TEXT_FILE_BYTES = 2 * 1024 * 1024;

export function defaultContentFetch(fetchFn?: typeof fetch): ContentFetch {
  const doFetch = fetchFn ?? fetch;
  return {
    packument: async (name: string) => {
      const res = await doFetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
    tarball: async (url: string) => {
      const res = await doFetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const buf = Buffer.from(await res.arrayBuffer());
      if (buf.length > MAX_TARBALL_BYTES) throw new Error(`tarball exceeds the ${MAX_TARBALL_BYTES} byte cap`);
      return buf;
    },
  };
}

// ------------------------------------------------------------ tar reader

/**
 * Minimal read-only tar reader (ustar, GNU longname, pax path) over a
 * gzipped npm tarball. Extracts to an in-memory map only.
 */
export function extractTarball(buf: Buffer): Map<string, Buffer> {
  let raw: Buffer;
  try { raw = gunzipSync(buf); } catch { raw = buf; }
  const out = new Map<string, Buffer>();
  let offset = 0;
  let longName: string | null = null;
  let paxPath: string | null = null;
  while (offset + 512 <= raw.length) {
    const header = raw.subarray(offset, offset + 512);
    if (header.every((b) => b === 0)) break;
    const nameField = header.subarray(0, 100).toString("utf8").replace(/\0.*$/s, "");
    const prefix = header.subarray(345, 500).toString("utf8").replace(/\0.*$/s, "");
    const sizeText = header.subarray(124, 136).toString("ascii").replace(/\0.*$/s, "").trim();
    const size = sizeText ? parseInt(sizeText, 8) || 0 : 0;
    const type = String.fromCharCode(header[156]);
    const dataStart = offset + 512;
    const data = raw.subarray(dataStart, dataStart + size);
    let full = prefix ? `${prefix}/${nameField}` : nameField;
    if (type === "L") { longName = data.toString("utf8").replace(/\0.*$/s, ""); }
    else if (type === "x" || type === "g") {
      const text = data.toString("utf8");
      const m = /(?:^|\n)\d+ path=([^\n]+)/.exec(text);
      if (m) paxPath = m[1];
    } else if (type === "0" || type === "\0" || type === "") {
      if (longName) { full = longName; longName = null; }
      if (paxPath) { full = paxPath; paxPath = null; }
      const rel = full.startsWith("package/") ? full.slice("package/".length) : full;
      if (rel && !rel.endsWith("/") && out.size < MAX_TARBALL_FILES) out.set(rel, Buffer.from(data));
    }
    offset = dataStart + Math.ceil(size / 512) * 512;
  }
  return out;
}

// ------------------------------------------------------------- surface

export interface Surface {
  version: string;
  files: string[];
  scripts: Record<string, string>;
  installScripts: Record<string, string>;
  reachable: Map<string, string>;
  credSignals: { label: string; file: string }[];
  endpoints: { value: string; file: string }[];
  binaries: string[];
  obfuscated: { file: string; why: string }[];
}

const CRED_PATTERNS: { label: string; re: RegExp }[] = [
  { label: ".ssh", re: /\.ssh\b/ },
  { label: "id_rsa", re: /id_rsa/ },
  { label: ".aws", re: /\.aws\b/ },
  { label: "aws credentials", re: /aws_access_key_id|AWS_SECRET_ACCESS_KEY/i },
  { label: ".env", re: /\.env\b/ },
  { label: ".npmrc", re: /\.npmrc\b/ },
  { label: ".gnupg", re: /\.gnupg\b/ },
  { label: "credentials file", re: /credentials(\.json)?\b/ },
  { label: ".kube/config", re: /\.kube\b/ },
  { label: ".git-credentials", re: /\.git-credentials\b/ },
  { label: "process.env secret access", re: /process\.env(\.|\[)[A-Za-z0-9_'"\]]*(TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL)/i },
];

const ENDPOINT_RE = /https?:\/\/[A-Za-z0-9.-]+(?::\d+)?(?:\/[^\s'"`)]*)?/g;
const FETCH_CALL_RE = /\b(fetch|axios|http\.request|https\.request|net\.connect|XMLHttpRequest)\s*\(/;
const TEXT_EXT = /\.(js|mjs|cjs|ts|mts|cts|json|sh|bash|py|rb|txt|md)$/;

function isTextFile(path: string, data: Buffer): boolean {
  if (TEXT_EXT.test(path)) return true;
  if (data.length === 0) return true;
  const sample = data.subarray(0, Math.min(data.length, 4096));
  let nonText = 0;
  for (const b of sample) if (b === 0 || (b < 9) || (b > 13 && b < 32)) nonText++;
  return nonText / sample.length < 0.05;
}

function looksBinary(path: string, data: Buffer): boolean {
  if (/\.(node|exe|dll|so|dylib|wasm|bin|dat)$/i.test(path)) return true;
  return !isTextFile(path, data) && data.length > 0;
}

function obfuscationWhy(text: string): string | null {
  if (/\beval\s*\(/.test(text) && /(atob|Buffer\.from\([^)]*['"]base64|fromCharCode)/.test(text)) return "eval over decoded content";
  const b64 = /[A-Za-z0-9+/=]{240,}/.exec(text);
  if (b64) return "a base64-shaped blob over 240 characters";
  for (const line of text.split("\n")) {
    if (line.length > 5000) return "a single code line over 5000 characters";
  }
  return null;
}

/** File tokens an install script command points at (node lib/setup.mjs, ./install.js, sh scripts/x.sh). */
function scriptTargets(command: string): string[] {
  const out: string[] = [];
  for (const tok of command.split(/[\s;|&]+/)) {
    const t = tok.replace(/^['"]|['"]$/g, "");
    if (/^(\.|\/|[A-Za-z0-9_-]+\/)/.test(t) && /\.(js|mjs|cjs|sh|bash|py|rb)$/.test(t)) {
      out.push(t.replace(/^\.\//, "").replace(/^\//, ""));
    } else if (/^[A-Za-z0-9_.-]+\.(js|mjs|cjs|sh)$/.test(t)) {
      out.push(t);
    }
  }
  return out;
}

function resolveImport(fromFile: string, spec: string, files: Map<string, Buffer>): string | null {
  if (!spec.startsWith(".")) return null;
  const dir = fromFile.includes("/") ? fromFile.slice(0, fromFile.lastIndexOf("/")) : "";
  const joined = (dir ? `${dir}/` : "") + spec;
  const parts: string[] = [];
  for (const seg of joined.split("/")) {
    if (seg === "." || seg === "") continue;
    if (seg === "..") parts.pop(); else parts.push(seg);
  }
  const base = parts.join("/");
  for (const cand of [base, `${base}.js`, `${base}.mjs`, `${base}.cjs`, `${base}/index.js`, `${base}/index.mjs`]) {
    if (files.has(cand)) return cand;
  }
  return null;
}

export function surfaceOf(version: string, files: Map<string, Buffer>): Surface {
  let scripts: Record<string, string> = {};
  const pkgRaw = files.get("package.json");
  if (pkgRaw) {
    try {
      const pkg = JSON.parse(pkgRaw.toString("utf8")) as Record<string, unknown>;
      if (pkg.scripts && typeof pkg.scripts === "object") scripts = pkg.scripts as Record<string, string>;
    } catch { /* unparsable package.json inside a tarball: scripts stay empty */ }
  }
  const installScripts: Record<string, string> = {};
  for (const s of INSTALL_SCRIPTS) if (typeof scripts[s] === "string") installScripts[s] = scripts[s];

  // Install-reachable set: install script targets, then relative
  // imports followed up to depth 3.
  const reachable = new Map<string, string>();
  const queue: string[] = [];
  for (const cmd of Object.values(installScripts)) queue.push(...scriptTargets(cmd));
  const seenDepth = new Map<string, number>();
  while (queue.length > 0) {
    const path = queue.shift()!;
    const depth = seenDepth.get(path) ?? 0;
    if (reachable.has(path)) continue;
    const data = files.get(path);
    if (!data) continue;
    const text = data.subarray(0, MAX_TEXT_FILE_BYTES).toString("utf8");
    reachable.set(path, text);
    if (depth >= 3) continue;
    const importRe = /(?:import\s[^'"]*from\s*|import\s*|require\s*\()\s*['"](\.[^'"]+)['"]/g;
    let m: RegExpExecArray | null;
    while ((m = importRe.exec(text)) !== null) {
      const resolved = resolveImport(path, m[1], files);
      if (resolved && !reachable.has(resolved)) { seenDepth.set(resolved, depth + 1); queue.push(resolved); }
    }
  }
  // The manifest itself is install-reachable by definition.
  if (pkgRaw) reachable.set("package.json", pkgRaw.toString("utf8"));

  const credSignals: Surface["credSignals"] = [];
  const endpoints: Surface["endpoints"] = [];
  const obfuscated: Surface["obfuscated"] = [];
  for (const [file, text] of reachable) {
    for (const { label, re } of CRED_PATTERNS) {
      if (re.test(text)) credSignals.push({ label, file });
    }
    const urls = text.match(ENDPOINT_RE) ?? [];
    for (const u of urls) {
      if (!/registry\.npmjs\.org|www\.w3\.org|schemas\.|npmjs\.com\/package/.test(u)) endpoints.push({ value: u.slice(0, 120), file });
    }
    if (FETCH_CALL_RE.test(text) && urls.length === 0) endpoints.push({ value: "network call with a non-literal destination", file });
    const why = obfuscationWhy(text);
    if (why) obfuscated.push({ file, why });
  }
  const binaries: string[] = [];
  for (const [path, data] of files) if (looksBinary(path, data)) binaries.push(path);
  return {
    version,
    files: [...files.keys()].sort(),
    scripts,
    installScripts,
    reachable,
    credSignals,
    endpoints,
    binaries,
    obfuscated,
  };
}

// ---------------------------------------------------------------- diff

function keySet<T extends { label?: string; value?: string; file: string }>(items: T[]): Set<string> {
  return new Set(items.map((i) => `${i.label ?? i.value ?? ""}@${i.file}`));
}

export function diffSurfaces(name: string, from: Surface, to: Surface): Finding[] {
  const out: Finding[] = [];
  const addedScripts = Object.keys(to.installScripts).filter((s) => !(s in from.installScripts));
  const changedScripts = Object.keys(to.installScripts).filter((s) => s in from.installScripts && from.installScripts[s] !== to.installScripts[s]);

  const fromCred = keySet(from.credSignals);
  const addedCred = to.credSignals.filter((c) => !fromCred.has(`${c.label}@${c.file}`));
  const fromEp = keySet(from.endpoints);
  const addedEp = to.endpoints.filter((e) => !fromEp.has(`${e.value}@${e.file}`));
  const fromBin = new Set(from.binaries);
  const addedBin = to.binaries.filter((b) => !fromBin.has(b));
  const fromObf = new Set(from.obfuscated.map((o) => o.file));
  const addedObf = to.obfuscated.filter((o) => !fromObf.has(o.file));

  const credLabels = [...new Set(addedCred.map((c) => c.label))];
  const epValues = [...new Set(addedEp.map((e) => e.value))];

  for (const s of addedScripts) {
    const risky = addedCred.length > 0 || addedEp.length > 0;
    out.push({
      rule: "CONTENT-INSTALL-SCRIPT-ADDED",
      severity: risky ? "high" : "medium",
      source: "online",
      evidence: risky
        ? `${name}@${to.version} adds a ${s} install script ("${to.installScripts[s]}") whose reachable code carries added signals: ${[...credLabels.map((l) => `credential path ${l}`), ...epValues.map((v) => `network endpoint ${v}`)].join("; ")}`
        : `${name}@${to.version} adds a ${s} install script ("${to.installScripts[s]}"); no credential or network signals were found in its reachable code`,
    });
  }
  for (const s of changedScripts) {
    out.push({
      rule: "CONTENT-INSTALL-SCRIPT-CHANGED",
      severity: addedCred.length > 0 || addedEp.length > 0 ? "high" : "medium",
      source: "online",
      evidence: `${name}@${to.version} changes the ${s} install script from "${from.installScripts[s]}" to "${to.installScripts[s]}"`,
    });
  }
  if (addedCred.length > 0) {
    out.push({
      rule: "CONTENT-CRED-SIGNAL-ADDED",
      severity: "high",
      source: "online",
      evidence: `${name}@${to.version} adds credential-path strings in install-reachable code: ${addedCred.map((c) => `${c.label} in ${c.file}`).join("; ")}`,
    });
  }
  if (addedEp.length > 0) {
    out.push({
      rule: "CONTENT-NETWORK-ENDPOINT-ADDED",
      severity: addedCred.length > 0 || addedScripts.length > 0 || Object.keys(to.installScripts).length > 0 ? "high" : "medium",
      source: "online",
      evidence: `${name}@${to.version} adds network endpoints in install-reachable code: ${addedEp.map((e) => `${e.value} in ${e.file}`).join("; ")}`,
    });
  }
  if (addedBin.length > 0) {
    out.push({
      rule: "CONTENT-BINARY-ADDED",
      severity: addedScripts.length > 0 ? "high" : "medium",
      source: "online",
      evidence: `${name}@${to.version} adds binary or non-text files: ${addedBin.slice(0, 8).join(", ")}`,
    });
  }
  for (const o of addedObf) {
    out.push({
      rule: "CONTENT-OBFUSCATED-ADDED",
      severity: "medium",
      source: "online",
      evidence: `${name}@${to.version} adds obfuscation-shaped code in install-reachable file ${o.file}: ${o.why}`,
    });
  }
  return out;
}

// ------------------------------------------------------- registry flow

interface PackumentLike {
  versions?: Record<string, { dist?: { tarball?: string } }>;
  "dist-tags"?: Record<string, string>;
}

export function previousPublishedVersion(pack: PackumentLike, version: string): string | null {
  const target = parseSemver(version);
  if (!target || !pack.versions) return null;
  let prev: string | null = null;
  for (const v of Object.keys(pack.versions)) {
    const sv = parseSemver(v);
    if (sv && compareSemver(sv, target) < 0 && (!prev || compareSemver(sv, parseSemver(prev)!) > 0)) prev = v;
  }
  return prev;
}

export async function contentDiff(
  fetcher: ContentFetch,
  name: string,
  fromVersion: string,
  toVersion: string,
  warnings: string[],
): Promise<Finding[]> {
  let pack: PackumentLike | null = null;
  try { pack = (await fetcher.packument(name)) as PackumentLike | null; }
  catch (err) { warnings.push(`content lookup for ${name} failed (${err instanceof Error ? err.message : String(err)}); content verdict unchanged`); return []; }
  if (!pack || !pack.versions) { warnings.push(`content lookup for ${name} returned no packument; content verdict unchanged`); return []; }
  const fromUrl = pack.versions[fromVersion]?.dist?.tarball;
  const toUrl = pack.versions[toVersion]?.dist?.tarball;
  if (!fromUrl || !toUrl) {
    warnings.push(`content diff for ${name} needs tarballs for ${fromVersion} and ${toVersion}; one is missing from the packument`);
    return [];
  }
  try {
    const [fromBuf, toBuf] = await Promise.all([fetcher.tarball(fromUrl), fetcher.tarball(toUrl)]);
    const fromSurface = surfaceOf(fromVersion, extractTarball(fromBuf));
    const toSurface = surfaceOf(toVersion, extractTarball(toBuf));
    return diffSurfaces(name, fromSurface, toSurface);
  } catch (err) {
    warnings.push(`content diff for ${name} ${fromVersion} to ${toVersion} failed (${err instanceof Error ? err.message : String(err)}); content verdict unchanged`);
    return [];
  }
}

/** Content-diff one package version against the greatest lower published version. */
export async function contentCheckVersion(
  fetcher: ContentFetch,
  name: string,
  version: string,
  warnings: string[],
): Promise<Finding[]> {
  let pack: PackumentLike | null = null;
  try { pack = (await fetcher.packument(name)) as PackumentLike | null; }
  catch (err) { warnings.push(`content lookup for ${name} failed (${err instanceof Error ? err.message : String(err)}); content verdict unchanged`); return []; }
  if (!pack || !pack.versions) { warnings.push(`content lookup for ${name} returned no packument; content verdict unchanged`); return []; }
  if (!pack.versions[version]) {
    warnings.push(`content check for ${name}@${version}: version is not in the registry packument, so no tarball diff is possible`);
    return [];
  }
  const prev = previousPublishedVersion(pack, version);
  if (!prev) { warnings.push(`content check for ${name}@${version}: no earlier published version to diff against`); return []; }
  return contentDiffWithPack(fetcher, pack, name, prev, version, warnings);
}

async function contentDiffWithPack(
  fetcher: ContentFetch,
  pack: PackumentLike,
  name: string,
  fromVersion: string,
  toVersion: string,
  warnings: string[],
): Promise<Finding[]> {
  const fromUrl = pack.versions?.[fromVersion]?.dist?.tarball;
  const toUrl = pack.versions?.[toVersion]?.dist?.tarball;
  if (!fromUrl || !toUrl) {
    warnings.push(`content diff for ${name} needs tarballs for ${fromVersion} and ${toVersion}; one is missing from the packument`);
    return [];
  }
  try {
    const [fromBuf, toBuf] = await Promise.all([fetcher.tarball(fromUrl), fetcher.tarball(toUrl)]);
    return diffSurfaces(name, surfaceOf(fromVersion, extractTarball(fromBuf)), surfaceOf(toVersion, extractTarball(toBuf)));
  } catch (err) {
    warnings.push(`content diff for ${name} ${fromVersion} to ${toVersion} failed (${err instanceof Error ? err.message : String(err)}); content verdict unchanged`);
    return [];
  }
}

/** Content-check one package, resolving dist-tags.latest when no version is given. */
export async function contentCheckPackage(
  fetcher: ContentFetch,
  name: string,
  version: string | undefined,
  warnings: string[],
): Promise<Finding[]> {
  if (version) return contentCheckVersion(fetcher, name, version, warnings);
  let pack: PackumentLike | null = null;
  try { pack = (await fetcher.packument(name)) as PackumentLike | null; }
  catch (err) { warnings.push(`content lookup for ${name} failed (${err instanceof Error ? err.message : String(err)}); content verdict unchanged`); return []; }
  const latest = pack?.["dist-tags"]?.latest;
  if (!latest) { warnings.push(`content check for ${name}: no latest version in the packument`); return []; }
  return contentCheckVersion(fetcher, name, latest, warnings);
}

/**
 * Apply content diffs to guard changes. Diff mode uses the recorded
 * versionFrom when present; added deps and snapshot pins diff against
 * the greatest lower published version.
 */
export async function applyContentChecks(changes: Change[], opts: ContentOptions): Promise<void> {
  const fetcher = opts.contentFetch ?? defaultContentFetch(opts.fetchFn);
  for (const change of changes) {
    if (change.change === "removed" || !change.versionTo) continue;
    if (change.versionFrom && change.versionFrom !== change.versionTo) {
      change.findings.push(...(await contentDiff(fetcher, change.name, change.versionFrom, change.versionTo, opts.warnings)));
    } else {
      change.findings.push(...(await contentCheckVersion(fetcher, change.name, change.versionTo, opts.warnings)));
    }
  }
}
