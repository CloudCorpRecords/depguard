/**
 * Acceptance fixture 6: online mode with injected registry responses.
 * No live network: fetchFn returns fixture packuments.
 * Covers a version published under 7 days ago and a publisher change
 * versus the previous version, plus the guarantee that a failed lookup
 * changes no verdict.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { guardPath, checkPackage } from "../src/core.js";
import { makeDir, writePkg, writeLock, lockEntry, mkdirp } from "./helpers.js";

const NOW = new Date("2026-10-22T12:00:00.000Z");

function packument(versions: Record<string, Record<string, unknown>>, times: Record<string, string>): Record<string, unknown> {
  return { versions, time: times, "dist-tags": { latest: Object.keys(versions).sort().at(-1) } };
}

function fetchReturning(map: Record<string, Record<string, unknown>>): typeof fetch {
  return (async (url: string) => {
    const name = decodeURIComponent(String(url).replace("https://registry.npmjs.org/", ""));
    const body = map[name];
    if (!body) return { ok: false, status: 404, json: async () => ({}) };
    return { ok: true, status: 200, json: async () => body };
  }) as unknown as typeof fetch;
}

describe("online mode (fixture 6, injected fetch)", () => {
  it("flags a version published under 7 days ago", async () => {
    const fetchFn = fetchReturning({
      widgets: packument(
        { "1.0.0": { _npmUser: { name: "alice" }, dist: {} }, "1.1.0": { _npmUser: { name: "alice" }, dist: {} } },
        { "1.0.0": "2026-01-01T00:00:00.000Z", "1.1.0": "2026-10-20T00:00:00.000Z" },
      ),
    });
    const r = await checkPackage("widgets", "1.1.0", { online: true, fetchFn, now: NOW });
    assert.ok(r.findings.some((f) => f.rule === "VERSION-AGE" && f.source === "online"), JSON.stringify(r.findings));
  });

  it("flags a publisher change versus the previous version as high", async () => {
    const fetchFn = fetchReturning({
      widgets: packument(
        { "1.0.0": { _npmUser: { name: "alice" }, dist: { attestations: { url: "https://x" } } }, "1.1.0": { _npmUser: { name: "mallory" }, dist: { attestations: { url: "https://x" } } } },
        { "1.0.0": "2026-01-01T00:00:00.000Z", "1.1.0": "2026-06-01T00:00:00.000Z" },
      ),
    });
    const r = await checkPackage("widgets", "1.1.0", { online: true, fetchFn, now: NOW });
    assert.equal(r.verdict, "HIGH-RISK");
    assert.ok(r.findings.some((f) => f.rule === "MAINTAINER-CHANGE" && f.severity === "high"));
    assert.ok(!r.findings.some((f) => f.rule === "NO-PROVENANCE"));
    assert.ok(!r.findings.some((f) => f.rule === "VERSION-AGE"));
  });

  it("guard_path online mode annotates changed deps and offline mode never fetches", async () => {
    const root = makeDir("depguard-online-");
    const base = join(root, "base"); const current = join(root, "current");
    mkdirp(base); mkdirp(current);
    writePkg(base, { name: "fx", dependencies: { widgets: "^1.0.0" } });
    writeLock(base, { widgets: lockEntry("1.0.0") });
    writePkg(current, { name: "fx", dependencies: { widgets: "^1.1.0" } });
    writeLock(current, { widgets: lockEntry("1.1.0") });
    let calls = 0;
    const countingFetch = (async () => { calls++; return { ok: true, status: 200, json: async () => packument(
      { "1.0.0": { _npmUser: { name: "alice" }, dist: {} }, "1.1.0": { _npmUser: { name: "alice" }, dist: {} } },
      { "1.0.0": "2026-01-01T00:00:00.000Z", "1.1.0": "2026-10-21T00:00:00.000Z" },
    ) }; }) as unknown as typeof fetch;
    const offline = await guardPath(current, { basePath: base, fetchFn: countingFetch, now: NOW });
    assert.equal(calls, 0);
    assert.equal(offline.mode, "offline");
    const online = await guardPath(current, { basePath: base, online: true, fetchFn: countingFetch, now: NOW });
    assert.equal(calls, 1);
    assert.equal(online.mode, "online");
    assert.ok(online.changes[0].findings.some((f) => f.rule === "VERSION-AGE"));
  });

  it("a failed lookup warns and changes no verdict", async () => {
    const failing = (async () => { throw new Error("network down"); }) as unknown as typeof fetch;
    const r = await checkPackage("express", "4.18.2", { online: true, fetchFn: failing, now: NOW });
    assert.equal(r.verdict, "CLEAR");
    assert.ok(r.warnings.some((w) => w.includes("online lookup")));
  });

  it("deprecated versions and missing provenance are reported", async () => {
    const fetchFn = fetchReturning({
      oldlib: packument({ "2.0.0": { _npmUser: { name: "alice" }, dist: {}, deprecated: "use newlib instead" } }, { "2.0.0": "2025-01-01T00:00:00.000Z" }),
    });
    const r = await checkPackage("oldlib", "2.0.0", { online: true, fetchFn, now: NOW });
    assert.ok(r.findings.some((f) => f.rule === "DEPRECATED" && f.severity === "medium"));
    assert.ok(r.findings.some((f) => f.rule === "NO-PROVENANCE" && f.severity === "low"));
  });
});
