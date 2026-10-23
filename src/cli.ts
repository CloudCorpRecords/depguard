#!/usr/bin/env node
/**
 * depguard CLI.
 *
 *   depguard check [path] [--json] [--offline] [--online] [--content] [--base <ref>] [--base-path <dir>]
 *   depguard package <name> [version] [--json] [--online] [--content]
 *   depguard history <name> [--json]
 *   depguard mcp
 *   depguard --version
 *
 * Exit codes: 0 CLEAR, 1 REVIEW or HIGH-RISK, 2 usage error,
 * 141 when the reader closed the output pipe before the report was
 * delivered (the shell-visible equivalent of death by SIGPIPE).
 *
 * Every report goes through emit(), which waits for stdout to flush
 * before the exit code takes effect. Calling process.exit() right
 * after console.log() truncates piped output once it passes one pipe
 * buffer (64 KiB on Linux), which is the factory emit contract in
 * FACTORY-NOTES.md (validation problems P-001, P-017, P-021).
 */
import { checkPackage, guardPath, renderGuardReport, renderPackageReport, VERSION } from "./core.js";
import { historyPackage, renderHistoryReport } from "./history.js";

function exitBrokenPipe(): never {
  process.exit(141);
}

process.stdout.on("error", (err: NodeJS.ErrnoException) => {
  if (err.code === "EPIPE") exitBrokenPipe();
  throw err;
});

/** Write one full report and resolve only after stdout has flushed it. */
async function emit(text: string, code: number): Promise<void> {
  process.exitCode = code;
  await new Promise<void>((resolve, reject) => {
    process.stdout.write(`${text}\n`, (err) => {
      if (!err) { resolve(); return; }
      if ((err as NodeJS.ErrnoException).code === "EPIPE") exitBrokenPipe();
      reject(err);
    });
  });
}

function usage(): never {
  console.error(`Usage:
  depguard check [path] [--json] [--offline] [--online] [--content] [--base <ref>] [--base-path <dir>]
  depguard package <name> [version] [--json] [--online] [--content]
  depguard history <name> [--json]
  depguard mcp
  depguard --version`);
  process.exit(2);
}

function flagValue(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : undefined;
}

function positional(args: string[]): string[] {
  const skip = new Set(["--base", "--base-path"]);
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (skip.has(args[i])) { i++; continue; }
    if (!args[i].startsWith("--")) out.push(args[i]);
  }
  return out;
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  if (cmd === "--version" || cmd === "-v" || cmd === "version") {
    console.log(VERSION);
    return;
  }
  if (cmd === "mcp") {
    await import("./mcp.js");
    return;
  }
  if (!cmd) usage();
  try {
    if (cmd === "check") {
      const [target] = positional(rest);
      const online = rest.includes("--online");
      const report = await guardPath(target ?? ".", {
        online,
        content: rest.includes("--content"),
        baseRef: flagValue(rest, "--base"),
        basePath: flagValue(rest, "--base-path"),
      });
      const text = rest.includes("--json") ? JSON.stringify(report, null, 2) : renderGuardReport(report);
      await emit(text, report.verdict === "CLEAR" ? 0 : 1);
    } else if (cmd === "package") {
      const [name, version] = positional(rest);
      if (!name) usage();
      const report = await checkPackage(name, version, { online: rest.includes("--online"), content: rest.includes("--content") });
      const text = rest.includes("--json") ? JSON.stringify(report, null, 2) : renderPackageReport(report);
      await emit(text, report.verdict === "CLEAR" ? 0 : 1);
    } else if (cmd === "history") {
      const [name] = positional(rest);
      if (!name) usage();
      const report = await historyPackage(name);
      const text = rest.includes("--json") ? JSON.stringify(report, null, 2) : renderHistoryReport(report);
      await emit(text, report.verdict === "CLEAR" ? 0 : 1);
    } else {
      usage();
    }
  } catch (err) {
    console.error(`error: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 2;
  }
}

void main();
