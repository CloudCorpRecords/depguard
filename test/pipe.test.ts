/**
 * Pipe regression tests for the factory emit contract (FACTORY-NOTES.md).
 * A report larger than 200 KiB through a real pipe must arrive whole
 * and parseable, and an early-closing reader must yield exit 141 or
 * SIGPIPE, never 0.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { makeDir, writePkg } from "./helpers.js";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

function bigTarget(): string {
  const dir = makeDir("depguard-pipe-");
  const deps: Record<string, string> = {};
  for (let i = 0; i < 3000; i++) deps[`some-lib-${i}`] = "*";
  writePkg(dir, { name: "fx", dependencies: deps });
  return dir;
}

function runCli(args: string[], destroyFirstChunk = false): Promise<{ code: number | null; signal: string | null; stdout: string }> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, ["--import", "tsx", "src/cli.ts", ...args], { cwd: REPO_ROOT, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (d: Buffer) => {
      if (destroyFirstChunk) { child.stdout.destroy(); return; }
      out += d.toString("utf8");
    });
    child.stderr.on("data", () => {});
    child.on("error", rejectPromise);
    child.on("close", (code, signal) => resolvePromise({ code, signal: signal as string | null, stdout: out }));
  });
}

describe("pipe contract", () => {
  it("a report over 200 KiB arrives whole through a pipe and parses", async () => {
    const dir = bigTarget();
    const r = await runCli(["check", dir, "--json"]);
    assert.ok(r.stdout.length > 200 * 1024, `got ${r.stdout.length} bytes`);
    const parsed = JSON.parse(r.stdout) as { verdict: string; counts: { findings: number } };
    assert.equal(parsed.verdict, "REVIEW");
    assert.ok(parsed.counts.findings >= 3000);
    assert.equal(r.code, 1);
  });
  it("the human renderer is byte-identical through a pipe across runs", async () => {
    const dir = bigTarget();
    const a = await runCli(["check", dir]);
    const b = await runCli(["check", dir]);
    assert.ok(a.stdout.length > 200 * 1024);
    assert.equal(a.stdout, b.stdout);
  });
  it("an early-closing reader yields 141 or SIGPIPE, never 0", async () => {
    const dir = bigTarget();
    const r = await runCli(["check", dir, "--json"], true);
    assert.ok(r.code === 141 || r.signal === "SIGPIPE", `code=${r.code} signal=${r.signal}`);
  });
});
