// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Wrappers around the murk CLI for the operations the Node binding does not
// expose: minting and revoking agent grants, and the value-free schema
// (`murk agent plan`). All of these run server-side against a server-local
// vault file — the plugin's v1 contract is local-host-only.
import { execFile } from "node:child_process";
import { chmodSync, existsSync } from "node:fs";
import * as path from "node:path";
import { z } from "zod";

export interface MurkResult {
  code: number;
  stdout: string;
  stderr: string;
}

const planEntrySchema = z.object({
  key: z.string(),
  description: z.string().optional(),
  example: z.string().optional(),
  tags: z.array(z.string()).optional(),
});
const planSchema = z.object({ entries: z.array(planEntrySchema) });
export type PlanEntry = z.infer<typeof planEntrySchema>;

const grantInfoSchema = z.object({
  name: z.string(),
  scope: z.array(z.string()),
  issued_at: z.string(),
  expires_at: z.string(),
  expired: z.boolean(),
});
export type MurkGrantInfo = z.infer<typeof grantInfoSchema>;

const MURK_TIMEOUT_MS = 30_000;

/**
 * Run `murk <args>`. Never a shell. The environment is inherited except:
 * - MURK_AGENT / MURK_STRICT are stripped: these calls run as the operator
 *   (mint, list and revoke) or need no key (plan), never as an agent context.
 * - MURK_VAULT is stripped — every call passes --vault explicitly.
 * - With `keyFile`, MURK_KEY_FILE is that path and MURK_KEY is stripped, so
 *   the call uses exactly that identity. Without it, murk resolves the key
 *   from the inherited MURK_KEY / MURK_KEY_FILE, else from the key it stored
 *   for the vault in ~/.config/murk/keys.
 * - With `keyless: true`, MURK_KEY / MURK_KEY_FILE are stripped too, so the
 *   call can never depend on (or exercise) an identity.
 *
 * `cwd` should be the directory holding the vault.
 */
export function runMurk(
  args: string[],
  options?: { keyless?: boolean; keyFile?: string | null; cwd?: string },
): Promise<MurkResult> {
  const env: Record<string, string | undefined> = { ...process.env };
  delete env.MURK_AGENT;
  delete env.MURK_STRICT;
  delete env.MURK_VAULT;
  if (options?.keyless) {
    delete env.MURK_KEY;
    delete env.MURK_KEY_FILE;
  } else if (options?.keyFile) {
    delete env.MURK_KEY;
    env.MURK_KEY_FILE = options.keyFile;
  }
  const { promise, resolve, reject } = Promise.withResolvers<MurkResult>();
  execFile(
    "murk",
    args,
    { cwd: options?.cwd, env: env as NodeJS.ProcessEnv, timeout: MURK_TIMEOUT_MS, maxBuffer: 1 << 20 },
    (error, stdout, stderr) => {
      if (error?.code === "ENOENT") {
        reject(new Error("the murk CLI is not on the bb server's PATH — install murk and reload the plugin"));
        return;
      }
      const code = typeof error?.code === "number" ? error.code : error ? 1 : 0;
      resolve({ code, stdout, stderr });
    },
  );
  return promise;
}

/**
 * The operator identity for `murk agent grant`, `agent ls` and `agent revoke`.
 * The keyFile setting wins. When it is blank, this returns null and murk runs
 * with the bb server's environment: its MURK_KEY or MURK_KEY_FILE, else the
 * key murk stored for the vault (see `runMurk`). The vault's .env is never
 * read: it sits in a worktree that an agent can edit.
 */
export function resolveOperatorKey(setting: string): string | null {
  const keyFile = setting.trim();
  if (!keyFile) return null;
  // The messages name no path: plugin output can reach agent threads.
  if (!path.isAbsolute(keyFile)) throw new Error("the keyFile setting must be an absolute path");
  if (!existsSync(keyFile)) throw new Error("the keyFile setting names a file that does not exist");
  return keyFile;
}

/**
 * `text` with key file paths replaced by `<key file>`: the configured
 * `keyFile`, the bb server's own `MURK_KEY_FILE`, and any path into murk's key
 * store (`~/.config/murk/keys`). murk names the key file in some errors, such
 * as its `chmod 600 <path>` hint for a key file that others can read.
 */
export function redactKeyPaths(text: string, keyFile?: string | null, env: NodeJS.ProcessEnv = process.env): string {
  let out = text;
  for (const file of [keyFile, env.MURK_KEY_FILE]) {
    if (file) out = out.split(file).join("<key file>");
  }
  out = out.replace(/[^\s'"`]*[\\/]\.config[\\/]murk[\\/]keys[^\s'"`]*/g, "<key file>");
  return out;
}

function murkError(what: string, result: MurkResult, keyFile?: string | null): Error {
  const detail = redactKeyPaths((result.stderr.trim() || result.stdout.trim()).replace(/\s+/g, " "), keyFile);
  return new Error(`${what} failed: ${detail || `murk exited ${result.code}`}`);
}

/**
 * Mint a scoped grant in the vault and write its ephemeral identity to
 * `keyFilePath` (0600). Signs as the operator identity from
 * `resolveOperatorKey`. Returns the grant's expiry.
 */
export async function mintGrant(options: {
  vaultPath: string;
  name: string;
  keys: string[];
  ttl: string;
  keyFilePath: string;
  operatorKey: string | null;
}): Promise<{ expiresAt: string }> {
  const args = ["agent", "grant", "--name", options.name, "--ttl", options.ttl, "--out", options.keyFilePath, "--vault", options.vaultPath];
  for (const key of options.keys) args.push("--only", key);
  const result = await runMurk(args, { keyFile: options.operatorKey, cwd: path.dirname(options.vaultPath) });
  if (result.code !== 0) throw murkError(`minting grant for ${options.keys.join(", ")}`, result, options.operatorKey);
  // murk writes the key file itself; clamp to 0600 regardless.
  chmodSync(options.keyFilePath, 0o600);

  const grants = await listGrants(options.vaultPath, options.operatorKey);
  const minted = grants.find((grant) => grant.name === options.name);
  if (!minted) throw new Error(`grant ${options.name} was minted but is missing from 'murk agent ls'`);
  return { expiresAt: minted.expires_at };
}

export async function listGrants(vaultPath: string, operatorKey: string | null): Promise<MurkGrantInfo[]> {
  const result = await runMurk(["agent", "ls", "--json", "--vault", vaultPath], {
    keyFile: operatorKey,
    cwd: path.dirname(vaultPath),
  });
  if (result.code !== 0) throw murkError("listing grants", result, operatorKey);
  return z.array(grantInfoSchema).parse(JSON.parse(result.stdout));
}

/** Revoke a grant by its murk name. Missing grants are treated as already revoked. */
export async function revokeGrant(vaultPath: string, name: string, operatorKey: string | null): Promise<void> {
  const result = await runMurk(["agent", "revoke", name, "--vault", vaultPath], {
    keyFile: operatorKey,
    cwd: path.dirname(vaultPath),
  });
  if (result.code !== 0 && !/no grant named|not found/i.test(result.stderr + result.stdout)) {
    throw murkError(`revoking grant ${name}`, result, operatorKey);
  }
}

/**
 * The value-free schema: key names, descriptions, examples, tags. Needs no
 * key — murk reads only the vault's plaintext schema.
 */
export async function agentPlan(vaultPath: string, tags?: string[]): Promise<PlanEntry[]> {
  const args = ["agent", "plan", "--json", "--vault", vaultPath];
  for (const tag of tags ?? []) args.push("--tag", tag);
  const result = await runMurk(args, { keyless: true, cwd: path.dirname(vaultPath) });
  if (result.code !== 0) throw murkError("reading the vault schema", result);
  return planSchema.parse(JSON.parse(result.stdout)).entries;
}
