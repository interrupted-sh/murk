// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// How the plugin runs the murk CLI: which key, environment, cwd and vault each
// call gets, and what reaches the caller when murk fails. A recording `murk`
// shim first on PATH logs every call (cwd, argv, MURK_* and BB_* variables)
// and then runs this repo's murk. HOME is a temp dir, as in server.test.ts.
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { createFakePluginHost, type FakePluginHost } from "@get-bb/plugin-sdk/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import plugin from "./server";

const THREAD = "thread-calls";
const PROJECT = "project-test";
const HOST = "host_local";
const SECRET = "sk-test-swordfish-12345";
const mintArgs = ["grant", "mint", "--keys", "TEST_API_KEY", "--ttl", "1h"];

let root: string;
let worktree: string;
let siblingTree: string;
let dataDir: string;
let shimLog: string;
let host: FakePluginHost;
let operatorKeyFile: string;
const saved: Record<string, string | undefined> = {};

interface Call {
  cwd: string;
  argv: string[];
  env: Record<string, string>;
}

/** Every logged murk call except the plugin's start-up `murk --version` probe. */
function calls(): Call[] {
  if (!existsSync(shimLog)) return [];
  return readFileSync(shimLog, "utf8")
    .split("\n---\n")
    .filter((block) => block.trim())
    .map((block) => {
      const call: Call = { cwd: "", argv: [], env: {} };
      for (const line of block.split("\n")) {
        if (line.startsWith("cwd=")) call.cwd = line.slice(4);
        else if (line.startsWith("arg:")) call.argv.push(line.slice(4));
        else if (line.startsWith("env:")) {
          const [name, ...rest] = line.slice(4).split("=");
          call.env[name] = rest.join("=");
        }
      }
      return call;
    })
    .filter((call) => call.argv[0] !== "--version");
}
const clearCalls = () => rmSync(shimLog, { force: true });
const murkVars = (call: Call) => Object.keys(call.env).filter((name) => name.startsWith("MURK_")).sort();
const vaultArg = (call: Call) => call.argv[call.argv.indexOf("--vault") + 1];
const runCli = (argv: string[], ctx: Record<string, unknown>) => host.harness.behavior.runCli(argv, ctx as never);

async function withServerEnv(env: Record<string, string>, fn: () => Promise<void>): Promise<void> {
  const before = Object.fromEntries(Object.keys(env).map((name) => [name, process.env[name]]));
  Object.assign(process.env, env);
  try {
    await fn();
  } finally {
    for (const [name, value] of Object.entries(before)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

async function mintedId(argv: string[], ctx: Record<string, unknown>): Promise<string> {
  const minted = await runCli(argv, ctx);
  expect(minted.exitCode, minted.stderr).toBe(0);
  return minted.stdout.match(/minted grant (g[0-9a-f]{8})/)![1];
}

beforeAll(async () => {
  root = realpathSync(mkdtempSync(path.join(tmpdir(), "bb-murk-calls-")));
  const home = path.join(root, "home");
  worktree = path.join(root, "worktree");
  dataDir = path.join(root, "bb-data");
  shimLog = path.join(root, "shim.log");
  mkdirSync(home, { recursive: true });
  mkdirSync(worktree, { recursive: true });

  for (const name of Object.keys(process.env)) {
    if (name.startsWith("MURK_") || ["BB_THREAD_ID", "BB_PROJECT_ID", "CLAUDECODE", "OMPCODE"].includes(name)) {
      saved[name] = process.env[name];
      delete process.env[name];
    }
  }
  saved.HOME = process.env.HOME;
  saved.PATH = process.env.PATH;
  process.env.HOME = home;

  const found = spawnSync("sh", ["-c", "command -v murk"], { encoding: "utf8" });
  const realMurk = found.stdout.trim();
  if (found.status !== 0 || !realMurk) throw new Error("murk is not on PATH");
  const shimDir = path.join(root, "shim");
  mkdirSync(shimDir);
  writeFileSync(
    path.join(shimDir, "murk"),
    [
      "#!/bin/bash",
      `{ echo "cwd=$PWD"; for a in "$@"; do echo "arg:$a"; done;`,
      `  env | grep -E '^(MURK_|BB_)' | sed 's/^/env:/'; echo '---'; } >> "${shimLog}"`,
      `exec "${realMurk}" "$@"`,
      "",
    ].join("\n"),
    { mode: 0o755 },
  );
  process.env.PATH = `${shimDir}${path.delimiter}${process.env.PATH}`;

  const run = (cmd: string, args: string[], input?: string, env?: NodeJS.ProcessEnv) => {
    const result = spawnSync(cmd, args, { cwd: worktree, input, encoding: "utf8", env: { ...process.env, ...env } });
    if (result.status !== 0) throw new Error(`${cmd} ${args.join(" ")} failed: ${result.stderr}`);
  };
  run("git", ["init", "-q"]);
  run(realMurk, ["init"], "bb-calls\n");
  const pointer = readFileSync(path.join(worktree, ".env"), "utf8").match(/^export MURK_KEY_FILE='([^']+)'$/m);
  if (!pointer) throw new Error("murk init wrote no MURK_KEY_FILE pointer to .env");
  operatorKeyFile = pointer[1];
  run(realMurk, ["add", "TEST_API_KEY", "--desc", "d", "--tag", "agents"], SECRET, { MURK_KEY_FILE: operatorKeyFile });

  // A sibling git worktree of the checkout whose key murk stored: a bb thread's worktree.
  const git = ["-c", "user.name=t", "-c", "user.email=t@example.com"];
  run("git", [...git, "add", ".murk"]);
  run("git", [...git, "commit", "-q", "-m", "vault"]);
  siblingTree = path.join(root, "sibling");
  run("git", ["worktree", "add", "-q", "-b", "sibling", siblingTree]);

  host = createFakePluginHost({
    pluginId: "murk",
    dataDir,
    agentSkillIds: ["murk"],
    sdk: {
      system: { config: async () => ({ primaryHostId: HOST }) },
      providers: { catalog: async () => [{ id: "acp-omp" }] },
      threads: {
        get: async (args: { threadId: string }) => ({
          id: args.threadId,
          projectId: PROJECT,
          environmentId: args.threadId === "thread-sibling" ? "env_sibling" : "env_1",
        }),
      },
      environments: {
        get: async (args: { environmentId: string }) => ({
          id: args.environmentId,
          hostId: HOST,
          path: args.environmentId === "env_sibling" ? siblingTree : worktree,
          projectId: PROJECT,
        }),
      },
      files: {
        write: async (args: { path: string; content: string; mode?: number }) => {
          writeFileSync(args.path, args.content, { mode: args.mode ?? 0o644 });
          return { outcome: "written", sha256: "x", sizeBytes: args.content.length };
        },
        read: async () => ({ content: "", contentEncoding: "utf8", sha256: "x", sizeBytes: 0 }),
        remove: async () => ({ ok: true }),
      },
    },
  });
  await plugin(host.bb);
  await host.harness.behavior.setSettings({ keyFile: operatorKeyFile });
  // Let the plugin's start-up `murk --version` probe finish, so it cannot
  // interleave its log lines with a test's calls.
  for (let i = 0; i < 100 && !(existsSync(shimLog) && readFileSync(shimLog, "utf8").includes("arg:--version\n")); i++) {
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  await new Promise((resolve) => setTimeout(resolve, 200));
  clearCalls();
}, 60_000);

afterAll(async () => {
  await host?.harness.lifecycle.dispose();
  for (const [name, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  rmSync(root, { recursive: true, force: true });
});

describe("paths that need no operator key", () => {
  it("grant list runs no murk, and murk_plan runs murk with no key and no agent flags", async () => {
    clearCalls();
    expect((await runCli(["grant", "list", "--all"], { threadId: THREAD })).exitCode).toBe(0);
    expect(calls()).toEqual([]);

    let plan: unknown;
    await withServerEnv({ MURK_KEY_FILE: operatorKeyFile, MURK_AGENT: "1", MURK_STRICT: "1", MURK_VAULT: "/nonexistent" }, async () => {
      plan = await host.harness.behavior.callAgentTool("murk_plan", {}, { threadId: THREAD, projectId: PROJECT });
    });
    const recorded = calls();
    expect(recorded).toHaveLength(1);
    expect(recorded[0].argv.slice(0, 2)).toEqual(["agent", "plan"]);
    expect(murkVars(recorded[0])).toEqual([]);
    expect(JSON.stringify(plan)).toContain("TEST_API_KEY");
    expect(JSON.stringify(plan)).not.toContain(SECRET);
  });
});

describe("the murk child's environment", () => {
  it("blank keyFile: MURK_AGENT, MURK_STRICT and MURK_VAULT are stripped, and every call names the vault", async () => {
    await host.harness.behavior.setSettings({ keyFile: "" });
    await withServerEnv({ MURK_AGENT: "1", MURK_STRICT: "1", MURK_VAULT: "/nonexistent/vault" }, async () => {
      clearCalls();
      const id = await mintedId(mintArgs, { cwd: worktree, projectId: PROJECT });
      const revoked = await runCli(["grant", "revoke", id], {});
      expect(revoked.exitCode, revoked.stderr).toBe(0);
    });
    const recorded = calls();
    expect(recorded.map((call) => call.argv.slice(0, 2).join(" "))).toEqual(["agent grant", "agent ls", "agent revoke"]);
    for (const call of recorded) {
      expect(call.cwd).toBe(worktree);
      expect(vaultArg(call)).toBe(path.join(worktree, ".murk"));
      expect(murkVars(call)).toEqual([]);
    }
    await host.harness.behavior.setSettings({ keyFile: operatorKeyFile });
  });

  it("blank keyFile: a key in the bb server's environment reaches murk unchanged", async () => {
    await host.harness.behavior.setSettings({ keyFile: "" });
    const key = readFileSync(operatorKeyFile, "utf8").trim();
    const serverEnvs: Array<Record<string, string>> = [{ MURK_KEY_FILE: operatorKeyFile }, { MURK_KEY: key }];
    for (const env of serverEnvs) {
      await withServerEnv(env, async () => {
        clearCalls();
        await mintedId(mintArgs, { cwd: worktree, projectId: PROJECT });
        expect(murkVars(calls()[0])).toEqual(Object.keys(env));
      });
    }
    await host.harness.behavior.setSettings({ keyFile: operatorKeyFile });
  });

  it("keyFile set: every call gets MURK_KEY_FILE=<setting> and no MURK_KEY, whatever the server holds", async () => {
    await host.harness.behavior.setSettings({ keyFile: operatorKeyFile });
    await withServerEnv({ MURK_KEY: "AGE-SECRET-KEY-NOT-A-KEY", MURK_KEY_FILE: "/dev/null/none" }, async () => {
      clearCalls();
      const id = await mintedId(mintArgs, { cwd: worktree, projectId: PROJECT });
      expect((await runCli(["grant", "revoke", id], {})).exitCode).toBe(0);
    });
    const recorded = calls();
    expect(recorded.map((call) => call.argv.slice(0, 2).join(" "))).toEqual(["agent grant", "agent ls", "agent revoke"]);
    for (const call of recorded) {
      expect(call.env.MURK_KEY_FILE).toBe(operatorKeyFile);
      expect(call.env.MURK_KEY).toBeUndefined();
    }
  });
});

describe("where the operator key comes from", () => {
  it("keyFile alone signs mint, agent ls and revoke when murk cannot find the key itself", async () => {
    const explicit = path.join(root, "explicit.key");
    writeFileSync(explicit, readFileSync(operatorKeyFile), { mode: 0o600 });
    const hidden = `${operatorKeyFile}.hidden`;
    renameSync(operatorKeyFile, hidden);
    try {
      await host.harness.behavior.setSettings({ keyFile: "" });
      expect((await runCli(mintArgs, { cwd: worktree, projectId: PROJECT })).exitCode).toBe(1);
      await host.harness.behavior.setSettings({ keyFile: explicit });
      const id = await mintedId(mintArgs, { cwd: worktree, projectId: PROJECT });
      const revoked = await runCli(["grant", "revoke", id], {});
      expect(revoked.exitCode, revoked.stderr).toBe(0);
    } finally {
      renameSync(hidden, operatorKeyFile);
      await host.harness.behavior.setSettings({ keyFile: operatorKeyFile });
    }
  });

  it("blank keyFile in a sibling git worktree: murk finds the stored key itself", async () => {
    await host.harness.behavior.setSettings({ keyFile: "" });
    clearCalls();
    const id = await mintedId([...mintArgs, "--thread", "thread-sibling"], { projectId: PROJECT });
    const first = calls()[0];
    expect(vaultArg(first)).toBe(path.join(siblingTree, ".murk"));
    expect(murkVars(first)).toEqual([]);
    expect((await runCli(["grant", "revoke", id], {})).exitCode).toBe(0);
    await host.harness.behavior.setSettings({ keyFile: operatorKeyFile });
  });
});

describe("errors name no key path", () => {
  it("murk's hint for a key file that others can read reaches the caller without the path", async () => {
    await host.harness.behavior.setSettings({ keyFile: "" });
    const stored = readdirSync(path.dirname(operatorKeyFile)).map((name) => path.join(path.dirname(operatorKeyFile), name));
    for (const file of stored) chmodSync(file, 0o644);
    try {
      const minted = await runCli(mintArgs, { cwd: worktree, projectId: PROJECT });
      expect(minted.exitCode).toBe(1);
      expect(minted.stderr).toContain("<key file>");
      expect(minted.stderr).not.toContain(".config/murk/keys");
    } finally {
      for (const file of stored) chmodSync(file, 0o600);
    }

    const loose = path.join(root, "loose.key");
    writeFileSync(loose, readFileSync(operatorKeyFile), { mode: 0o644 });
    await host.harness.behavior.setSettings({ keyFile: loose });
    const minted = await runCli(mintArgs, { cwd: worktree, projectId: PROJECT });
    expect(minted.exitCode).toBe(1);
    expect(minted.stderr).toContain("<key file>");
    expect(minted.stderr).not.toContain(loose);

    // Blank keyFile: the bb server's own MURK_KEY_FILE names the loose file.
    await host.harness.behavior.setSettings({ keyFile: "" });
    await withServerEnv({ MURK_KEY_FILE: loose }, async () => {
      const fromEnv = await runCli(mintArgs, { cwd: worktree, projectId: PROJECT });
      expect(fromEnv.exitCode).toBe(1);
      expect(fromEnv.stderr).toContain("<key file>");
      expect(fromEnv.stderr).not.toContain(loose);
    });
    await host.harness.behavior.setSettings({ keyFile: operatorKeyFile });
  });
});

describe("revoke with a stale keyFile", () => {
  it("still deletes the grant's key file and marks it revoked, then names the murk command to finish", async () => {
    await host.harness.behavior.setSettings({ keyFile: operatorKeyFile });
    const id = await mintedId(mintArgs, { cwd: worktree, projectId: PROJECT });
    const murkName = `bb-${id}`;
    await host.harness.behavior.setSettings({ keyFile: path.join(root, "moved-away.key") });
    const revoked = await runCli(["grant", "revoke", id], {});
    expect(revoked.exitCode).toBe(1);
    expect(revoked.stderr).toContain(`murk agent revoke ${murkName} --vault`);
    expect(revoked.stderr).not.toContain("moved-away.key");
    expect(existsSync(path.join(dataDir, "plugins", "murk", "agent-keys", `${id}.key`))).toBe(false);
    expect((await runCli(["grant", "list", "--all"], {})).stdout).toMatch(new RegExp(`${id}  revoked`));

    // The vault still holds the grant until the operator finishes the revoke.
    const ls = spawnSync("murk", ["agent", "ls", "--json"], {
      cwd: worktree,
      encoding: "utf8",
      env: { ...process.env, MURK_KEY_FILE: operatorKeyFile },
    });
    expect(ls.stdout).toContain(murkName);
    await host.harness.behavior.setSettings({ keyFile: operatorKeyFile });
  });
});
