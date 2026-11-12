// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// bb plugin: grant-scoped murk secrets for agent threads.
//
// Agents get two native tools — murk_plan (value-free schema) and murk_get
// (grant-gated reads). Grants are minted by the operator with `bb murk grant
// mint`, which uses murk's own grant machinery: an ephemeral age identity that
// can decrypt exactly the named keys. By default murk_get delivers values as a
// 0600 dotenv file in the thread's worktree and returns only key names + the
// file path; a grant minted with --reveal (and allowed by settings) may return
// its keys' values inline. Everything fails closed: unknown keys, expired
// TTLs, revoked grants, non-local hosts.
import { existsSync, mkdirSync, realpathSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import * as path from "node:path";
import type { BbPluginApi } from "@get-bb/plugin-sdk";
import { z } from "zod";
import { withGrantIdentity } from "./lib/binding";
import { KEY_NAME_PATTERN, renderDotenv } from "./lib/dotenv";
import { GRANT_MIGRATIONS, GrantStore, isExpired, type GrantRecord } from "./lib/grants";
import { agentPlan, mintGrant, redactKeyPaths, resolveOperatorKey, revokeGrant, runMurk, shellQuote } from "./lib/murk-cli";
import { legacyUpgradeRefusal, readVaultFormat, vaultCheckout } from "./lib/vault-format";

/**
 * Per-thread delivery filename. Namespacing by thread id means the plugin
 * never guesses at a user's filename and never collides across threads
 * sharing one worktree/environment.
 */
function deliveryFilename(threadId: string): string {
  return `.murk-${threadId}.env`;
}

const PRIMARY_HOST_TTL_MS = 60_000;

const TOOL_IDS = ["murk_plan", "murk_get"];
const SKILL_IDS = ["murk"];

interface ThreadTarget {
  worktree: string;
  hostId: string;
}

/**
 * Resolve symlinks in a vault path, so /var/folders and /private/var (macOS)
 * name one vault: git reports resolved paths, and vaultCheckout compares
 * against them.
 */
function canonicalVault(vaultPath: string): string {
  try {
    return realpathSync(vaultPath);
  } catch {
    return vaultPath;
  }
}

/** Human-readable grant scope: project-wide, or narrowed to one thread. */
function scopeLabel(grant: GrantRecord): string {
  return grant.threadId ? `thread ${grant.threadId}` : `project ${grant.projectId}`;
}

export default async function plugin(bb: BbPluginApi) {
  const settings = bb.settings.define({
    keyFile: {
      type: "string",
      label: "Operator key file",
      description:
        "Optional. Absolute path to your murk key file: the MURK_KEY_FILE path that murk init wrote to the vault's .env. " +
        "bb murk grant mint and grant revoke sign the vault with it. The plugin passes it only to the murk commands " +
        "it runs on the bb server, never to agent threads. Leave blank to use MURK_KEY_FILE or MURK_KEY from the " +
        "bb server's environment, or, if neither is set, the key murk stored for the vault in ~/.config/murk/keys.",
      default: "",
    },
    vaultPath: {
      type: "string",
      label: "Vault path",
      description:
        "Absolute path to the murk vault. Leave blank to use the .murk file in each thread's worktree.",
      default: "",
    },
    allowRevealGrants: {
      type: "boolean",
      label: "Allow reveal grants",
      description:
        "When on, a grant minted with --reveal lets murk_get return its values in the tool result, " +
        "where the agent and the saved transcript can see them. " +
        "When off, minting with --reveal fails and every grant delivers values to a file only.",
      default: true,
    },
  });

  const db = bb.storage.database();
  bb.storage.migrate(db, GRANT_MIGRATIONS);
  const store = new GrantStore(db);

  // Identity key material lives ONLY here, as 0600 files in the plugin's own
  // data directory — never in SQLite, kv, or anything frontend-readable.
  function agentKeysDir(): string {
    const dir = path.join(bb.server.experimental_dataDir, "plugins", bb.pluginId, "agent-keys");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    return dir;
  }

  async function vaultOverride(): Promise<string | null> {
    const { vaultPath } = await settings.get();
    const trimmed = vaultPath.trim();
    if (!trimmed) return null;
    if (!path.isAbsolute(trimmed)) throw new Error(`the vaultPath setting must be an absolute path, got ${trimmed}`);
    return trimmed;
  }

  // ---- local-host gate -----------------------------------------------------
  // v1 is local-host-only. The documented contract for "the server's own
  // machine" is SystemConfigResponse.primaryHostId (bb.sdk.system.config);
  // bb.sdk.files documents that an omitted hostId targets that same
  // "primary/local host". The gate fails closed: unknown or null primary host
  // withholds the tools, and execute() re-checks asynchronously.
  const gate: { primaryHostId: string | null | undefined; fetchedAt: number } = {
    primaryHostId: undefined,
    fetchedAt: 0,
  };

  async function primaryHostId(): Promise<string | null> {
    const now = Date.now();
    if (gate.primaryHostId !== undefined && now - gate.fetchedAt < PRIMARY_HOST_TTL_MS) {
      return gate.primaryHostId;
    }
    try {
      const config = await bb.sdk.system.config();
      gate.primaryHostId = config.primaryHostId ?? null;
      gate.fetchedAt = now;
    } catch (error) {
      bb.log.warn(`could not resolve the primary host id: ${error instanceof Error ? error.message : String(error)}`);
      return gate.primaryHostId ?? null;
    }
    return gate.primaryHostId;
  }

  bb.agents.configure((context) => {
    const known = gate.primaryHostId !== undefined && gate.primaryHostId !== null;
    if (!known) void primaryHostId(); // warm the cache for the next resolution; withhold now
    const local = known && context.host.id === gate.primaryHostId;
    return local ? { tools: TOOL_IDS, skills: SKILL_IDS } : { tools: [], skills: [] };
  });

  async function requireLocal(hostId: string): Promise<void> {
    const primary = await primaryHostId();
    if (primary === null || hostId !== primary) {
      throw new Error(
        "murk tools are local-host-only in v1: this thread's environment does not run on the bb server's own host",
      );
    }
  }

  // ---- thread → worktree resolution ---------------------------------------
  async function resolveThreadTarget(threadId: string): Promise<ThreadTarget> {
    const thread = await bb.sdk.threads.get({ threadId });
    if (!thread.environmentId) throw new Error("this thread has no environment to deliver secrets into");
    const environment = await bb.sdk.environments.get({ environmentId: thread.environmentId });
    if (!environment.path) throw new Error("this thread's environment has no workspace path");
    await requireLocal(environment.hostId);
    return { worktree: environment.path, hostId: environment.hostId };
  }

  /**
   * A tool error result. Tool results reach the agent, so key file paths are
   * redacted (murk and the binding name the key file in some errors). The
   * operator's own `bb murk grant` output keeps full paths.
   */
  async function toolError(message: string): Promise<{ content: Array<{ type: "text"; text: string }>; isError: true }> {
    const text = redactKeyPaths(`murk: ${message}`, {
      files: [(await settings.get()).keyFile.trim(), process.env.MURK_KEY_FILE],
      dirs: [path.join(homedir(), ".config", "murk", "keys"), agentKeysDir()],
    });
    return { content: [{ type: "text", text }], isError: true };
  }

  // ---- key → grant resolution ----------------------------------------------
  /**
   * Map requested keys to covering grants. Every explicitly requested key must
   * be covered by an active grant or the whole call fails closed. When reveal
   * grants are allowed, a covering reveal grant wins for its keys.
   */
  function assignGrants(
    requested: string[],
    grants: GrantRecord[],
    allowReveal: boolean,
    threadId: string,
  ): Map<string, GrantRecord> {
    const assignment = new Map<string, GrantRecord>();
    for (const key of requested) {
      const covering = grants.filter((grant) => grant.keys.includes(key));
      if (covering.length === 0) {
        throw new Error(
          `${key} is not covered by any active grant for this thread — ` +
            `ask the user to mint one with: bb murk grant mint --keys ${key} --thread ${threadId}`,
        );
      }
      const revealGrant = allowReveal ? covering.find((grant) => grant.reveal) : undefined;
      assignment.set(key, revealGrant ?? covering[0]);
    }
    return assignment;
  }

  /** Decrypt each key with its assigned grant identity. Fails closed per key. */
  function decryptAssigned(assignment: Map<string, GrantRecord>): Map<string, string> {
    const byGrant = new Map<GrantRecord, string[]>();
    for (const [key, grant] of assignment) {
      byGrant.set(grant, [...(byGrant.get(grant) ?? []), key]);
    }
    const values = new Map<string, string>();
    for (const [grant, keys] of byGrant) {
      withGrantIdentity(grant.keyPath, grant.vaultPath, (vault) => {
        for (const key of keys) {
          const value = vault.get(key);
          if (value === null) {
            throw new Error(`${key}: not found or outside grant ${grant.id}'s scope`);
          }
          values.set(key, value);
        }
      });
    }
    return values;
  }

  // ---- murk_plan -----------------------------------------------------------
  bb.agents.registerTool({
    name: "murk_plan",
    description:
      "List the murk vault's secret schema — key names and tags only, as JSON. " +
      "Never returns secret values. Use murk_get to read keys covered by a grant.",
    presentation: {
      label: { pending: "Reading murk schema", completed: "Read murk schema" },
    },
    parameters: z.object({
      tags: z.array(z.string()).optional().describe("Only include keys carrying one of these tags"),
    }),
    async execute({ tags }, { threadId }) {
      try {
        const target = await resolveThreadTarget(threadId);
        const vaultPath = canonicalVault((await vaultOverride()) ?? path.join(target.worktree, ".murk"));
        const entries = await agentPlan(vaultPath, tags);
        // Key names and tags only — no descriptions, examples, paths, or
        // grant annotations. Values never existed on this path at all.
        const schema = entries.map((entry) => ({ key: entry.key, tags: entry.tags ?? [] }));
        return JSON.stringify({ entries: schema }, null, 2);
      } catch (error) {
        return toolError(error instanceof Error ? error.message : String(error));
      }
    },
  });

  // ---- murk_get ------------------------------------------------------------
  bb.agents.registerTool({
    name: "murk_get",
    description:
      "Fetch granted murk secrets. By default the values are written to a 0600 dotenv file " +
      "(.murk-<threadId>.env) in this thread's worktree and only key names + the file path are returned; " +
      "values appear inline only for keys covered by a reveal grant. Keys outside the thread's grants fail closed.",
    instructions:
      "murk_get delivers secrets as a dotenv file by default — source it or pass it to tools; " +
      "never print its contents. The file is deleted when the thread goes idle, so re-fetch in a later " +
      "turn instead of caching values. Treat any inline revealed value as sensitive: never echo, log, or commit it.",
    presentation: {
      label: { pending: "Fetching murk secrets", completed: "Fetched murk secrets" },
    },
    parameters: z.object({
      keys: z
        .array(z.string().regex(KEY_NAME_PATTERN))
        .min(1)
        .optional()
        .describe("Key names to fetch; omit to fetch every key granted to this thread"),
    }),
    async execute({ keys }, { threadId, projectId }) {
      try {
        const target = await resolveThreadTarget(threadId);
        const { allowRevealGrants } = await settings.get();
        const grants = store.activeFor(projectId, threadId);
        if (grants.length === 0) {
          return toolError(
            "no active grant covers this thread — ask the user to mint one with: " +
              `bb murk grant mint --keys KEY[,KEY…] --thread ${threadId}`,
          );
        }
        const requested = keys ?? [...new Set(grants.flatMap((grant) => grant.keys))];
        const assignment = assignGrants(requested, grants, allowRevealGrants, threadId);
        const values = decryptAssigned(assignment);

        const revealKeys = requested.filter((key) => allowRevealGrants && assignment.get(key)?.reveal);
        const fileKeys = requested.filter((key) => !revealKeys.includes(key));

        const filePath = path.join(target.worktree, deliveryFilename(threadId));
        let deliveredToFile: string[] = [];
        if (fileKeys.length > 0) {
          // Merge with keys already delivered to this thread's file so a second
          // murk_get does not clobber the first. Values are always re-read from
          // the vault; stale (expired/revoked) merge keys are dropped silently.
          const previous = store
            .deliveriesFor(threadId)
            .filter((delivery) => delivery.filePath === filePath)
            .flatMap((delivery) => delivery.keys)
            .filter((key) => !requested.includes(key));
          const mergeValues = new Map<string, string>();
          for (const key of previous) {
            try {
              const merged = decryptAssigned(assignGrants([key], grants, false, threadId));
              const value = merged.get(key);
              if (value !== undefined) mergeValues.set(key, value);
            } catch {
              // dropped from the merged file: no longer covered
            }
          }
          deliveredToFile = [...new Set([...fileKeys, ...mergeValues.keys()])].sort();
          const entries = deliveredToFile.map((key): readonly [string, string] => {
            const value = values.get(key) ?? mergeValues.get(key);
            if (value === undefined) throw new Error(`${key}: lost during delivery merge`);
            return [key, value] as const;
          });
          // Invariant: never write over or delete bytes the plugin did not
          // write, across the file's whole life. No delivery record → the
          // first write is create-only (an existing file belongs to the
          // user). Owned path → CAS against the sha256 of the plugin's own
          // last write, so a file the user replaced after delivery is left
          // alone and ownership is relinquished.
          const owning = store.deliveriesFor(threadId).find((delivery) => delivery.filePath === filePath);
          const saved = await bb.sdk.files.write({
            hostId: target.hostId,
            path: filePath,
            rootPath: target.worktree,
            content: renderDotenv(entries),
            mode: 0o600,
            expectedSha256: owning ? owning.sha256 : null,
          });
          if (saved.outcome === "conflict") {
            if (owning) {
              store.forgetDelivery(threadId, filePath);
              return toolError(
                `the file at ${filePath} was modified externally since the plugin wrote it — ` +
                  "it will not be touched again; move it aside and call murk_get again",
              );
            }
            return toolError(
              `a file already exists at ${filePath} that this plugin did not create — ` +
                "move it aside (or delete it) and call murk_get again",
            );
          }
          store.recordDelivery({
            threadId,
            hostId: target.hostId,
            rootPath: target.worktree,
            filePath,
            keys: deliveredToFile,
            sha256: saved.sha256,
          });
        }

        const result: Record<string, unknown> = {};
        if (fileKeys.length > 0) {
          result.file = filePath;
          result.delivered = deliveredToFile;
          result.note = "values are in the file only (mode 0600); it is deleted when this thread goes idle — do not commit it";
        }
        if (revealKeys.length > 0) {
          result.revealed = Object.fromEntries(revealKeys.map((key) => [key, values.get(key)]));
        }
        return JSON.stringify(result, null, 2);
      } catch (error) {
        return toolError(error instanceof Error ? error.message : String(error));
      }
    },
  });

  // ---- agent context for every provider ------------------------------------
  // murk_get is the sanctioned path to secrets, but an agent's shell can still
  // run `murk` itself. Outside an agent context, murk falls back to
  // the operator's stored key (~/.config/murk/keys, sibling git worktrees
  // included), and an inherited MURK_KEY / MURK_KEY_FILE is the operator's
  // identity outright. Every provider process therefore starts as an agent
  // context with no usable key, so a direct `murk` call fails closed.
  //
  // MURK_KEY_FILE gets a path that can never exist rather than "": some
  // providers (omp) refill an empty variable from dotenv files in the launch
  // dir and the home dir, where `murk init` leaves a MURK_KEY_FILE pointer at
  // the operator key. MURK_KEY is blanked, which masks an inherited one; if a
  // dotenv file refills it with a legacy inline key, murk refuses MURK_KEY and
  // MURK_KEY_FILE set together, so that fails closed too. A child handed a
  // grant through MURK_KEY_FILE alone (a `murk agent connect` MCP entry) still
  // works. A guardrail, not a sandbox: the agent runs as the operator's user.
  const agentContextEnv = [
    { name: "MURK_AGENT", value: "1", reason: "Run murk as an agent context: no fallback to the operator's stored key" },
    { name: "MURK_KEY", value: "", reason: "Blank any operator key inherited from the host environment" },
    {
      name: "MURK_KEY_FILE",
      value: "/dev/null/none",
      reason: "Shadow any operator key file from the host environment or a dotenv file; this path can never exist",
    },
  ];
  const coveredProviders = new Set<string>();

  // Env contributions are keyed by exact provider id, so cover every provider
  // in the catalog: at load, and again whenever a thread is created, which
  // picks up providers registered after this plugin (boot order, a new custom
  // ACP agent).
  async function coverProviders(): Promise<void> {
    let ids: string[];
    try {
      ids = (await bb.sdk.providers.catalog()).map((provider) => provider.id);
    } catch (error) {
      bb.log.warn(`could not list providers for murk agent context: ${error instanceof Error ? error.message : String(error)}`);
      return;
    }
    for (const id of ids) {
      if (coveredProviders.has(id)) continue;
      coveredProviders.add(id);
      bb.providers.experimental_contributeEnv(id, () => agentContextEnv);
    }
  }
  bb.events.on("thread.created", () => coverProviders());

  // ---- delivered-file cleanup ----------------------------------------------
  bb.events.on("thread.idle", async ({ thread }) => {
    const deliveries = store.deliveriesFor(thread.id);
    if (deliveries.length === 0) return;
    let removed = 0;
    for (const delivery of deliveries) {
      // files.remove has no CAS guard, so read-compare-then-remove: delete
      // only when the file still hashes to the plugin's own last write.
      // Mismatch, missing file, or read error → leave the file alone.
      try {
        const current = await bb.sdk.files.read({
          hostId: delivery.hostId,
          path: delivery.filePath,
          rootPath: delivery.rootPath,
        });
        if (current.sha256 === delivery.sha256) {
          await bb.sdk.files.remove({
            hostId: delivery.hostId,
            path: delivery.filePath,
            rootPath: delivery.rootPath,
          });
          removed++;
        } else {
          bb.log.info(`leaving ${delivery.filePath} in place: modified externally since delivery`);
        }
      } catch (error) {
        // Already gone (or the worktree was destroyed) — nothing to clean.
        bb.log.debug(
          `delivery cleanup for ${delivery.filePath}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
    store.clearDeliveries(thread.id);
    bb.log.info(`removed ${removed} delivered env file(s) for idle thread ${thread.id}`);
  });

  // ---- bb murk CLI ---------------------------------------------------------
  bb.cli.register({
    name: "murk",
    summary: "Scoped murk secret grants for agent threads",
    commands: [
      {
        name: "grant-mint",
        summary: "Mint a scoped grant (ephemeral murk identity for exactly the named keys)",
        usage:
          "bb murk grant mint --keys KEY[,KEY…] [--ttl 2h] [--thread <threadId>] [--project <projectId>] [--reveal] [--upgrade]",
      },
      {
        name: "grant-list",
        summary: "List grants with scope, keys, expiry, and reveal status",
        usage: "bb murk grant list [--all]",
      },
      {
        name: "grant-revoke",
        summary: "Revoke a grant: remove its vault identity and delete its key file",
        usage: "bb murk grant revoke <grantId>",
      },
    ],
    async run(argv, ctx) {
      try {
        if (argv[0] !== "grant") {
          return { exitCode: 1, stderr: "usage: bb murk grant <mint|list|revoke> …" };
        }
        const sub = argv[1];
        const rest = argv.slice(2);
        if ((sub === "mint" || sub === "revoke") && ctx.threadId) return refuseFromThread(sub, ctx.threadId);
        if (sub === "mint") return await cliMint(rest, ctx.cwd, ctx.projectId);
        if (sub === "list") return await cliList(rest.includes("--all"));
        if (sub === "revoke") return await cliRevoke(rest[0]);
        return { exitCode: 1, stderr: "usage: bb murk grant <mint|list|revoke> …" };
      } catch (error) {
        return { exitCode: 1, stderr: `murk: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  });

  /**
   * Granting and revoking secrets is the user's decision, never an agent's: a
   * thread that could mint would grant itself any key. The bb CLI forwards
   * the caller's thread id (BB_THREAD_ID, set in every thread's shell), so a
   * call that carries one is refused. A guardrail, not a sandbox: a process
   * that clears BB_THREAD_ID, or calls the server directly, looks like the
   * user's terminal.
   */
  function refuseFromThread(sub: "mint" | "revoke", threadId: string): { exitCode: number; stderr: string } {
    const command =
      sub === "mint" ? `bb murk grant mint --keys KEY[,KEY…] --thread ${threadId}` : "bb murk grant revoke <grantId>";
    return {
      exitCode: 1,
      stderr:
        `murk: bb murk grant ${sub} is refused from a bb thread. This call came from thread ${threadId}. ` +
        `Only the user grants or revokes secrets. Ask the user to run this in their own terminal: ${command}\n` +
        "That terminal must be outside bb threads, because the bb CLI reports the thread of the shell it runs in.",
    };
  }

  interface MintFlags {
    keys: string[];
    ttl: string;
    thread: string | null;
    project: string | null;
    reveal: boolean;
    /** Allow this mint to make a pre-0.14 vault's first 0.14 save. */
    upgrade: boolean;
  }

  function parseMintFlags(argv: string[]): MintFlags {
    const flags: MintFlags = { keys: [], ttl: "2h", thread: null, project: null, reveal: false, upgrade: false };
    for (let i = 0; i < argv.length; i++) {
      const arg = argv[i];
      const takeValue = (): string => {
        const value = argv[++i];
        if (value === undefined || value.startsWith("--")) throw new Error(`${arg} needs a value`);
        return value;
      };
      if (arg === "--keys") flags.keys.push(...takeValue().split(",").map((key) => key.trim()).filter(Boolean));
      else if (arg === "--ttl") flags.ttl = takeValue();
      else if (arg === "--thread") flags.thread = takeValue();
      else if (arg === "--project") flags.project = takeValue();
      else if (arg === "--reveal") flags.reveal = true;
      else if (arg === "--upgrade") flags.upgrade = true;
      else throw new Error(`unknown flag ${arg}`);
    }
    if (flags.keys.length === 0) throw new Error("--keys is required (fails closed): name every key this grant may read");
    for (const key of flags.keys) {
      if (!KEY_NAME_PATTERN.test(key)) throw new Error(`${key} is not a valid secret key name`);
    }
    return flags;
  }

  async function cliMint(
    argv: string[],
    cwd: string | undefined,
    ctxProjectId: string | undefined,
  ): Promise<{ exitCode: number; stdout?: string; stderr?: string }> {
    const flags = parseMintFlags(argv);
    const { allowRevealGrants, keyFile } = await settings.get();

    if (flags.reveal && !allowRevealGrants) {
      return {
        exitCode: 1,
        stderr: "murk: reveal grants are disabled (plugin setting allowRevealGrants=false)",
      };
    }

    // Resolve project + vault. Grants default to project scope; --thread
    // narrows to one thread and finds the vault in its worktree.
    let projectId = flags.project ?? ctxProjectId ?? null;
    let worktree: string | null = null;
    if (flags.thread) {
      const thread = await bb.sdk.threads.get({ threadId: flags.thread });
      projectId ??= thread.projectId;
      if (thread.environmentId) {
        const environment = await bb.sdk.environments.get({ environmentId: thread.environmentId });
        worktree = environment.path;
      }
    }
    if (!projectId) {
      return { exitCode: 1, stderr: "murk: cannot resolve a project — pass --project <projectId>" };
    }

    let vaultPath = await vaultOverride();
    if (!vaultPath && worktree && existsSync(path.join(worktree, ".murk"))) {
      vaultPath = path.join(worktree, ".murk");
    }
    if (!vaultPath && cwd && existsSync(path.join(cwd, ".murk"))) {
      vaultPath = path.join(cwd, ".murk");
    }
    if (!vaultPath) {
      return {
        exitCode: 1,
        stderr: "murk: no vault found — run from a directory containing .murk, or set the plugin's vaultPath setting",
      };
    }
    if (!existsSync(vaultPath)) {
      return { exitCode: 1, stderr: `murk: vault not found at ${vaultPath}` };
    }
    vaultPath = canonicalVault(vaultPath);

    // Minting saves the vault. On a pre-0.14 vault that save is its format
    // upgrade, which belongs on the default branch, committed — not left
    // uncommitted on whichever branch this thread is on.
    const format = readVaultFormat(vaultPath);
    if (format.legacy && !flags.upgrade) {
      const checkout = await vaultCheckout(vaultPath);
      return { exitCode: 1, stderr: `murk: ${legacyUpgradeRefusal(vaultPath, format, checkout, "minting a grant")}` };
    }

    const operatorKey = resolveOperatorKey(keyFile);

    const id = store.newGrantId();
    const murkName = `bb-${id}`;
    const keyFilePath = path.join(agentKeysDir(), `${id}.key`);
    const { expiresAt } = await mintGrant({
      vaultPath,
      name: murkName,
      keys: flags.keys,
      ttl: flags.ttl,
      keyFilePath,
      operatorKey,
    });
    const grant = store.create({
      id,
      murkName,
      projectId,
      threadId: flags.thread,
      keys: flags.keys,
      reveal: flags.reveal,
      vaultPath,
      keyPath: keyFilePath,
      expiresAt,
    });

    const scope = scopeLabel(grant);
    const delivery = grant.reveal ? "reveal (murk_get may return these values inline)" : "file-only (dotenv delivery)";
    return {
      exitCode: 0,
      stdout: [
        `minted grant ${grant.id} (${murkName})`,
        `  keys:     ${grant.keys.join(", ")}`,
        `  scope:    ${scope}`,
        `  expires:  ${grant.expiresAt}`,
        `  delivery: ${delivery}`,
        `  vault:    ${grant.vaultPath}`,
        "",
        "agents in scope can now call murk_get; revoke with: bb murk grant revoke " + grant.id,
      ].join("\n"),
    };
  }

  async function cliList(includeRevoked: boolean): Promise<{ exitCode: number; stdout: string }> {
    const grants = store.list({ includeRevoked });
    if (grants.length === 0) return { exitCode: 0, stdout: "no grants" };
    const lines = grants.map((grant) => {
      const scope = scopeLabel(grant);
      const status = grant.revokedAt
        ? "revoked"
        : grant.revokePendingAt
          ? "REVOKE-PENDING"
          : isExpired(grant.expiresAt)
            ? "EXPIRED"
            : "active";
      const reveal = grant.reveal ? "reveal" : "file-only";
      return `${grant.id}  ${status}  ${reveal}  ${scope}  expires ${grant.expiresAt}  keys: ${grant.keys.join(", ")}`;
    });
    return { exitCode: 0, stdout: lines.join("\n") };
  }

  async function cliRevoke(id: string | undefined): Promise<{ exitCode: number; stdout?: string; stderr?: string }> {
    if (!id) return { exitCode: 1, stderr: "usage: bb murk grant revoke <grantId>" };
    const grant = store.get(id);
    if (!grant) return { exitCode: 1, stderr: `murk: no grant ${id}` };
    if (grant.revokedAt) return { exitCode: 0, stdout: `grant ${id} is already revoked` };
    // Only murk can say the grant is gone from the vault. A vault that now
    // reads as pre-0.14 is not the one the grant was minted into (mint never
    // writes a grant into that format), and murk must not save it, so the
    // revoke stays pending until the vault is back.
    let vaultError: string | null = null;
    let legacy = false;
    try {
      legacy = readVaultFormat(grant.vaultPath).legacy;
    } catch {
      // unreadable or missing: murk reports it below
    }
    if (legacy) {
      vaultError = `${grant.vaultPath} is in the pre-0.14 format, which cannot hold this grant; restore the vault the grant was minted into`;
    } else {
      try {
        await revokeGrant(grant.vaultPath, grant.murkName, resolveOperatorKey((await settings.get()).keyFile));
      } catch (error) {
        vaultError = error instanceof Error ? error.message : String(error);
      }
    }
    // Delete the key file even when the vault write failed (a stale keyFile
    // setting, a vault that does not load): the plugin then cannot serve the
    // grant. But the grant stays live in the vault for any copy of its key,
    // so it is marked revoked only once murk removed it from the vault; until
    // then it is pending, and every retry runs the vault revoke again.
    rmSync(grant.keyPath, { force: true });
    if (vaultError) {
      store.markRevokePending(id);
      return {
        exitCode: 1,
        stderr:
          `murk: grant ${id} (${grant.murkName}) is still live in the vault: could not remove it: ${vaultError}\n` +
          `deleted its key file here, so threads no longer get it from the plugin; a copy of the key still reads the vault\n` +
          `fix the cause and run bb murk grant revoke ${id} again, or run: ` +
          `murk agent revoke ${shellQuote(grant.murkName)} --vault ${shellQuote(grant.vaultPath)}`,
      };
    }
    store.markRevoked(id);
    return {
      exitCode: 0,
      stdout:
        `revoked grant ${id} (${grant.murkName}) and deleted its key file\n` +
        `note: rotate the affected keys (murk rotate KEY) — old vault versions in git history remain readable`,
    };
  }

  // The murk CLI is required for minting, revocation, and the schema; surface
  // its absence as a configuration problem instead of failing per call.
  void runMurk(["--version"]).catch(() => {
    bb.status.needsConfiguration("The murk CLI is not on the bb server's PATH — install murk, then reload the plugin.");
  });

  // Warm the local-host gate so the first thread resolution after load
  // already knows the primary host (bb binds bb.sdk before loading plugins).
  void primaryHostId();

  // Start every provider as a murk agent context (see coverProviders). Awaited
  // so no thread launches before the contributions exist.
  await coverProviders();

  bb.log.info("murk plugin loaded");
}
