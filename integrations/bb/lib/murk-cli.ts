// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Wrappers around the murk CLI for the operations the Node binding does not
// expose: minting and revoking agent grants, and the value-free schema
// (`murk agent plan`). All of these run server-side against a server-local
// vault file — the plugin's v1 contract is local-host-only.
import { execFile } from "node:child_process";
import { chmodSync, existsSync, readFileSync, realpathSync } from "node:fs";
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

/** Lines murk writes into every grant key file (`src/agents.rs`), never into an operator key. */
const GRANT_KEY_MARKERS = ["# murk-grant-id:", "# murk-trusted-signer:"];

function isGrantKeyText(text: string): boolean {
  return text.split(/\r?\n/).some((line) => GRANT_KEY_MARKERS.some((marker) => line.trim().startsWith(marker)));
}

function grantKeyRefusal(source: string): Error {
  return new Error(`the operator key must be a full recipient key, not an agent grant: ${source} names a grant key`);
}

/**
 * The operator identity for `murk agent grant`, `agent ls` and `agent revoke`.
 * The keyFile setting wins. When it is blank, this returns null and murk runs
 * with the bb server's environment: its MURK_KEY or MURK_KEY_FILE, else the
 * key murk stored for the vault (see `runMurk`). The vault's .env is never
 * read: it sits in a worktree that an agent can edit.
 *
 * A key file with grant key lines is refused, a common mistake that would
 * only fail later. This is a guard, not a guarantee: murk also accepts a bare
 * grant key with no such lines.
 */
export function resolveOperatorKey(setting: string, env: NodeJS.ProcessEnv = process.env): string | null {
  const keyFile = setting.trim();
  if (keyFile) {
    if (!path.isAbsolute(keyFile)) throw new Error(`the keyFile setting must be an absolute path, got ${keyFile}`);
    if (!existsSync(keyFile)) throw new Error(`the keyFile setting points at ${keyFile}, which does not exist`);
    if (isGrantKeyText(readKeyText(keyFile))) throw grantKeyRefusal("the keyFile setting");
    return keyFile;
  }
  if (env.MURK_KEY && isGrantKeyText(env.MURK_KEY)) throw grantKeyRefusal("MURK_KEY on the bb server");
  if (env.MURK_KEY_FILE && isGrantKeyText(readKeyText(env.MURK_KEY_FILE))) {
    throw grantKeyRefusal("MURK_KEY_FILE on the bb server");
  }
  return null;
}

/** A key file's text, or "" when it cannot be read (murk then reports why). */
function readKeyText(file: string): string {
  try {
    return readFileSync(file, "utf8");
  } catch {
    return "";
  }
}

/** `value` quoted for a POSIX shell, so a printed command copies as one argument per value. */
export function shellQuote(value: string): string {
  return /^[\w@%+=:,./-]+$/.test(value) ? value : `'${value.replaceAll("'", `'\\''`)}'`;
}

/** A path and the other spellings murk may print for it (macOS `/private`, symlinks resolved). */
function spellings(p: string): string[] {
  const out = new Set([p]);
  if (p.startsWith("/private/")) out.add(p.slice("/private".length));
  else if (/^\/(tmp|var|etc)\//.test(p)) out.add(`/private${p}`);
  try {
    out.add(realpathSync(p));
  } catch {
    // a path that does not exist has no other spelling
  }
  // Longest first, so a shorter spelling never cuts into a longer one.
  return [...out].sort((a, b) => b.length - a.length);
}

const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
/** Where a path ends: not followed by a character that would extend it. */
const PATH_END = String.raw`(?![\w.~/\\-])`;

/**
 * `text` with key file paths replaced by `<key file>`, for output that can
 * reach an agent thread (tool results). Exact paths only, so a path with
 * spaces is caught whole and a path that merely starts with a key file's path
 * (`<keyFile>-project/.murk`) is left alone:
 * - `files`: the operator's `keyFile` setting, the bb server's `MURK_KEY_FILE`;
 * - `dirs`: murk's key store and the plugin's grant key directory, whose
 *   entries (`<dir>/<name>`) and the directory itself are redacted.
 * murk names key files in some errors, such as its `chmod 600 <path>` hint.
 */
export function redactKeyPaths(text: string, keys: { files: Array<string | null | undefined>; dirs: string[] }): string {
  let out = text;
  for (const dir of keys.dirs.flatMap(spellings)) {
    out = out.replace(new RegExp(`${escapeRegExp(dir)}(?:[\\\\/][^\\s'"\`/\\\\]+)?${PATH_END}`, "g"), "<key file>");
  }
  for (const file of keys.files.filter((f): f is string => Boolean(f)).flatMap(spellings)) {
    out = out.replace(new RegExp(`${escapeRegExp(file)}${PATH_END}`, "g"), "<key file>");
  }
  return out;
}

function murkError(what: string, result: MurkResult): Error {
  // One line, but spaces inside a path are kept, so a later redaction of an
  // agent-facing copy still matches the path exactly.
  const detail = (result.stderr.trim() || result.stdout.trim()).replace(/\s*\n\s*/g, " ");
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
  if (result.code !== 0) throw murkError(`minting grant for ${options.keys.join(", ")}`, result);
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
  if (result.code !== 0) throw murkError("listing grants", result);
  return z.array(grantInfoSchema).parse(JSON.parse(result.stdout));
}

/**
 * Revoke a grant by its murk name. Succeeds only when `murk agent revoke`
 * exits 0, that is when murk removed the grant from the vault. Every other
 * outcome throws, a grant murk reports as not in the vault included: neither
 * murk's error text (a vault writer can plant text in fields murk echoes) nor
 * a grant listing (a grant key sees only its own record) proves it is gone.
 */
export async function revokeGrant(vaultPath: string, name: string, operatorKey: string | null): Promise<void> {
  const result = await runMurk(["agent", "revoke", name, "--vault", vaultPath], {
    keyFile: operatorKey,
    cwd: path.dirname(vaultPath),
  });
  if (result.code !== 0) throw murkError(`revoking grant ${name}`, result);
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
