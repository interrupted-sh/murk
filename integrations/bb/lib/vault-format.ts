// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Keyless vault-format check. A vault written by murk 0.13 or older (header
// version 2.x, no `vault_id`) is rewritten in the 0.14 format by the next
// save, whatever that save is. Minting a grant is such a save, so the plugin
// checks the header first: an upgrade should be committed on the default
// branch, not left uncommitted on whatever branch a thread happens to be on.
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface VaultFormat {
  /** Header `version`, e.g. "2.0" or "3.0". */
  version: string;
  /** True when the next save would be the vault's first 0.14 save. */
  legacy: boolean;
}

/**
 * Read the vault's plaintext JSON header. No key is needed: `version` and
 * `vault_id` sit outside every ciphertext. The first 0.14 save is the one
 * that assigns a `vault_id`, so a vault without one is legacy, as is any
 * header older than format 3.
 */
export function readVaultFormat(vaultPath: string): VaultFormat {
  let header: unknown;
  try {
    header = JSON.parse(readFileSync(vaultPath, "utf8"));
  } catch (error) {
    throw new Error(`cannot read the vault header at ${vaultPath}: ${error instanceof Error ? error.message : String(error)}`);
  }
  const fields = header !== null && typeof header === "object" ? (header as Record<string, unknown>) : {};
  const version = typeof fields.version === "string" ? fields.version : "";
  const vaultId = typeof fields.vault_id === "string" ? fields.vault_id : "";
  const major = Number.parseInt(version.split(".")[0] ?? "", 10);
  return { version, legacy: vaultId === "" || !(major >= 3) };
}

async function git(cwd: string, args: string[]): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync("git", ["-C", cwd, ...args], { timeout: 10_000 });
    return stdout.trim() || null;
  } catch {
    return null;
  }
}

export interface VaultCheckout {
  /** Checked-out branch, or null on a detached HEAD or outside git. */
  branch: string | null;
  /** The same vault file in the repository's main worktree, or null outside git. */
  mainVaultPath: string | null;
}

/** Where the vault lives in git: its branch and its counterpart in the main checkout. */
export async function vaultCheckout(vaultPath: string): Promise<VaultCheckout> {
  const dir = path.dirname(vaultPath);
  const [branch, toplevel, worktrees] = await Promise.all([
    git(dir, ["symbolic-ref", "--short", "-q", "HEAD"]),
    git(dir, ["rev-parse", "--show-toplevel"]),
    git(dir, ["worktree", "list", "--porcelain"]),
  ]);
  // `git worktree list` always lists the main worktree first.
  const main = worktrees?.split("\n").find((line) => line.startsWith("worktree "))?.slice("worktree ".length);
  let mainVaultPath: string | null = null;
  if (toplevel && main) {
    // Compare canonical paths: git reports resolved ones (/private/var on macOS).
    const relative = path.relative(toplevel, vaultPath);
    if (!relative.startsWith("..") && !path.isAbsolute(relative)) mainVaultPath = path.join(main, relative);
  }
  return { branch, mainVaultPath };
}

/**
 * The refusal shown when a write would make the vault's first 0.14 save.
 * `action` names the write, e.g. "minting a grant".
 */
export function legacyUpgradeRefusal(
  vaultPath: string,
  format: VaultFormat,
  checkout: VaultCheckout,
  action: string,
): string {
  const where = checkout.branch ? `on branch ${checkout.branch}` : "in this checkout";
  const main = checkout.mainVaultPath ?? "<main checkout>/.murk";
  return [
    `the vault at ${vaultPath} is in the pre-0.14 format (version ${format.version || "unknown"}, no vault id);`,
    `${action} here would upgrade it to the 0.14 format ${where} (uncommitted).`,
    `Upgrade it on the default branch first: run \`murk trust --vault ${main}\`, then make one write there`,
    "(any write saves it in the 0.14 format, e.g. `murk describe`), commit the vault, and merge it into this branch.",
    "Or pass --upgrade to upgrade it here anyway.",
  ].join("\n");
}
