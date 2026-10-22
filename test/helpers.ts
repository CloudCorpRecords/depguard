import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export function makeDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

export function writePkg(dir: string, pkg: Record<string, unknown>): void {
  writeFileSync(join(dir, "package.json"), JSON.stringify(pkg, null, 2));
}

export function lockEntry(version: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { version, resolved: `https://registry.npmjs.org/pkg/-/pkg-${version}.tgz`, integrity: `sha512-fake-${version}`, ...extra };
}

/** A v3 package-lock with the given name -> entry map (plus the root entry). */
export function writeLock(dir: string, deps: Record<string, Record<string, unknown>>): void {
  const packages: Record<string, unknown> = { "": { name: "fixture", version: "1.0.0" } };
  for (const [name, entry] of Object.entries(deps)) packages[`node_modules/${name}`] = entry;
  writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ name: "fixture", lockfileVersion: 3, packages }, null, 2));
}

export function mkdirp(dir: string): void {
  mkdirSync(dir, { recursive: true });
}
