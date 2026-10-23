/**
 * depguard MCP server. Tools: guard_path, check_package, check_history.
 * The offline core is the default; registry checks run only when the
 * caller passes online: true.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { checkPackage, guardPath, VERSION } from "./core.js";
import { historyPackage } from "./history.js";

const server = new McpServer({ name: "depguard", version: VERSION });

function text(value: unknown): { content: { type: "text"; text: string }[] } {
  return { content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }] };
}

server.tool(
  "guard_path",
  "Diff a repo's dependency manifests and lockfiles against a base (git ref or directory) and grade every added, removed, and changed dependency: install scripts, typosquat-shaped names, downgrades, prerelease jumps, widened ranges, and lockfile drift. Fully offline unless online is true, which adds npm registry checks (version age, publisher change, provenance, deprecation).",
  {
    path: z.string().describe("Local path of the repo or directory to check"),
    base: z.string().optional().describe("Git ref to diff against (for example HEAD~1 or a tag)"),
    base_path: z.string().optional().describe("Directory holding the base manifest set to diff against"),
    online: z.boolean().optional().describe("Also run npm registry checks (default false; the base verdict never needs the network)"),
    content: z.boolean().optional().describe("Also run content mode: fetch both versions' tarballs and diff the install-time surface statically, nothing installed or executed (default false)"),
  },
  async ({ path, base, base_path, online, content }) => text(await guardPath(path, { baseRef: base, basePath: base_path, online: online ?? false, content: content ?? false })),
);

server.tool(
  "check_package",
  "Grade a single package name (and optional version): typosquat distance against a bundled popular-names list and version pattern checks offline; with online true, registry checks for version age under 7 days, publisher change versus the previous version, provenance attestation, and deprecation.",
  {
    name: z.string().describe("Package name, for example lodash or @scope/name"),
    version: z.string().optional().describe("Version to check (default: offline name checks only, or the registry latest when online)"),
    online: z.boolean().optional().describe("Also run npm registry checks (default false)"),
    content: z.boolean().optional().describe("Also run content mode against the greatest lower published version (default false)"),
  },
  async ({ name, version, online, content }) => text(await checkPackage(name, version, { online: online ?? false, content: content ?? false })),
);

server.tool(
  "check_history",
  "Analyze a package's npm registry publish history for the staged worm pattern (a 0.0.0-stage stub, a decoy release, then a rapid regressed patch holding dist-tags.latest), plus publisher and maintainer changes, repository slug changes, and provenance drops between consecutive versions. Registry metadata only; no tarballs are downloaded.",
  {
    name: z.string().describe("Package name, for example lodash or @scope/name"),
  },
  async ({ name }) => text(await historyPackage(name)),
);

const transport = new StdioServerTransport();
await server.connect(transport);
