/**
 * Gap B (ledger P-159): registry-history mode.
 *
 * depguard 0.1.0 snapshot on the testmetest stage-stub verdicted
 * REVIEW with zero findings, because the staged pattern (a 0.0.0-stage
 * stub, a harmless 1.0.0 decoy, then a rapid malicious-shaped patch
 * that becomes dist-tags.latest with a version regression) lives only
 * in registry publish history. History mode fetches the packument and
 * analyzes the publish timeline. These tests use synthetic packument
 * fixtures shaped like the incident; no test touches the network.
 * On pre-B code this file fails: that is the red.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeHistory, historyPackage } from "../src/history.js";

interface VSpec { version: string; at: string; publisher: string; scripts?: Record<string, string>; repo?: string; provenance?: boolean }

function packument(specs: VSpec[], latest: string): Record<string, unknown> {
  const versions: Record<string, unknown> = {};
  const time: Record<string, string> = {};
  for (const s of specs) {
    versions[s.version] = {
      _npmUser: { name: s.publisher },
      scripts: s.scripts ?? {},
      repository: { type: "git", url: s.repo ?? "git+https://github.com/example/pkg.git" },
      dist: s.provenance ? { attestations: { url: "https://registry.npmjs.org/attest" }, tarball: "https://registry.invalid/x.tgz" } : { tarball: "https://registry.invalid/x.tgz" },
    };
    time[s.version] = s.at;
  }
  return { versions, time, "dist-tags": { latest } };
}

function fetchReturning(body: Record<string, unknown> | null): typeof fetch {
  return (async () => {
    if (!body) return { ok: false, status: 404, json: async () => ({}) };
    return { ok: true, status: 200, json: async () => body };
  }) as unknown as typeof fetch;
}

const TESTMETEST_SHAPE = packument([
  { version: "0.0.0-stage", at: "2026-10-19T10:00:00.000Z", publisher: "mallory" },
  { version: "1.0.0", at: "2026-10-20T10:00:00.000Z", publisher: "mallory", scripts: { postinstall: "node hello.js" } },
  { version: "0.0.1", at: "2026-10-21T10:00:00.000Z", publisher: "mallory", scripts: { postinstall: "node install.js" } },
], "0.0.1");

const WELL_BEHAVED = packument([
  { version: "1.0.0", at: "2023-01-10T10:00:00.000Z", publisher: "alice", provenance: true },
  { version: "1.1.0", at: "2023-06-10T10:00:00.000Z", publisher: "alice", provenance: true },
  { version: "1.2.0", at: "2024-02-10T10:00:00.000Z", publisher: "alice", provenance: true },
  { version: "2.0.0", at: "2025-01-10T10:00:00.000Z", publisher: "alice", provenance: true },
], "2.0.0");

describe("history mode (Gap B, P-159)", () => {
  it("flags the staged publishing pattern as HIGH-RISK and names its elements", async () => {
    const r = await historyPackage("testmetest-shape", { fetchFn: fetchReturning(TESTMETEST_SHAPE) });
    assert.equal(r.verdict, "HIGH-RISK", JSON.stringify(r.findings));
    const staged = r.findings.find((f) => f.rule === "HISTORY-STAGED-PATTERN");
    assert.ok(staged, JSON.stringify(r.findings));
    assert.equal(staged.severity, "high");
    assert.ok(staged.evidence.includes("0.0.0-stage"), staged.evidence);
    assert.ok(staged.evidence.includes("1.0.0"), staged.evidence);
    assert.ok(staged.evidence.includes("0.0.1"), staged.evidence);
    assert.ok(staged.evidence.includes("latest"), staged.evidence);
    assert.ok(r.findings.some((f) => f.rule === "HISTORY-STAGE-STUB"), JSON.stringify(r.findings));
    assert.ok(r.findings.some((f) => f.rule === "HISTORY-LATEST-REGRESSION"), JSON.stringify(r.findings));
  });

  it("analyzeHistory is deterministic and pure on the same packument", () => {
    const a = analyzeHistory("testmetest-shape", TESTMETEST_SHAPE as never);
    const b = analyzeHistory("testmetest-shape", TESTMETEST_SHAPE as never);
    assert.deepEqual(a, b);
    assert.ok(a.some((f) => f.rule === "HISTORY-STAGED-PATTERN" && f.severity === "high"));
  });

  it("control: a well-behaved packument stays clean of high findings", async () => {
    const r = await historyPackage("wellbehaved", { fetchFn: fetchReturning(WELL_BEHAVED) });
    assert.ok(!r.findings.some((f) => f.severity === "high"), JSON.stringify(r.findings));
    assert.equal(r.verdict, "CLEAR", JSON.stringify(r.findings));
  });

  it("flags maintainer and repository changes between consecutive versions", async () => {
    const pack = packument([
      { version: "1.0.0", at: "2026-01-01T10:00:00.000Z", publisher: "alice", repo: "git+https://github.com/alice/pkg.git" },
      { version: "1.0.1", at: "2026-01-03T10:00:00.000Z", publisher: "mallory", repo: "git+https://github.com/mallory/pkg-copy.git" },
    ], "1.0.1");
    const r = await historyPackage("takeover-shape", { fetchFn: fetchReturning(pack) });
    const maint = r.findings.find((f) => f.rule === "HISTORY-MAINTAINER-CHANGE");
    assert.ok(maint, JSON.stringify(r.findings));
    assert.ok(maint.evidence.includes("alice") && maint.evidence.includes("mallory"), maint.evidence);
    const repo = r.findings.find((f) => f.rule === "HISTORY-REPO-CHANGE");
    assert.ok(repo, JSON.stringify(r.findings));
    assert.ok(repo.evidence.includes("mallory/pkg-copy"), repo.evidence);
  });

  it("a missing packument reports HISTORY-PACKAGE-NOT-FOUND and never grades CLEAR", async () => {
    const r = await historyPackage("gone-package", { fetchFn: fetchReturning(null) });
    assert.notEqual(r.verdict, "CLEAR");
    assert.ok(r.findings.some((f) => f.rule === "HISTORY-PACKAGE-NOT-FOUND"), JSON.stringify(r.findings));
  });
});
