// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// The murk Node binding (@interrupted/murk-secrets) is a napi native module,
// which esbuild cannot bundle — so it is loaded at runtime through
// createRequire, resolved from the plugin's own node_modules. It stays in
// `dependencies` so path and git installs have it on disk.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

/** The subset of the binding's Vault class this plugin uses (see node/index.d.ts). */
export interface MurkVault {
  /** Decrypted value, or null when the key is absent or outside the identity's scope. */
  get(key: string): string | null;
}

interface MurkBinding {
  load(vaultPath?: string | null): MurkVault;
  hasIdentity(): boolean;
}

const requireBinding = createRequire(import.meta.url);
let cached: MurkBinding | null = null;

const BINDING_MODULE = "@interrupted/murk-secrets";

/**
 * The binding version this process actually loaded, by resolved package path.
 * A native addon, once loaded, stays loaded for the life of the process: a
 * plugin reload re-evaluates this module, but the loader hands back the cached
 * image for the same path, so the version on disk after `npm ci` is not the
 * code that runs. The record therefore lives on `process`, which outlives a
 * plugin reload, and is written once per path.
 */
const LOADED_VERSIONS = Symbol.for("bb-plugin-murk.loadedBindingVersions");
/** Recorded when a binding was already loaded before this code first ran. */
const EARLIER_VERSION = "an earlier version";

function loadedVersions(): Map<string, string> {
  const holder = process as unknown as Record<symbol, Map<string, string> | undefined>;
  holder[LOADED_VERSIONS] ??= new Map();
  return holder[LOADED_VERSIONS];
}

/** The version in the binding's package.json on disk now, bypassing the module cache. */
function diskBindingVersion(manifestPath: string): string {
  try {
    const manifest: unknown = JSON.parse(readFileSync(manifestPath, "utf8"));
    if (manifest && typeof manifest === "object" && "version" in manifest && typeof manifest.version === "string") {
      return manifest.version;
    }
  } catch {
    // Fall through: the version only decorates the error message.
  }
  return "unknown";
}

function manifestPath(): string | null {
  try {
    return requireBinding.resolve(`${BINDING_MODULE}/package.json`);
  } catch {
    return null;
  }
}

function binding(): MurkBinding {
  if (!cached) {
    let entry: string | null = null;
    try {
      entry = requireBinding.resolve(BINDING_MODULE);
    } catch {
      // Unresolvable: the require below reports it.
    }
    // A binding loaded before this code ran (an older plugin version, before
    // a reload) left its module cached without a recorded version.
    const loadedEarlier = entry !== null && entry in requireBinding.cache;
    try {
      cached = requireBinding(BINDING_MODULE) as MurkBinding;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(
        `the ${BINDING_MODULE} native binding is unavailable (${message}); ` +
          `reinstall the plugin with its dependencies`,
      );
    }
    const manifest = manifestPath();
    const versions = loadedVersions();
    if (manifest && !versions.has(manifest)) {
      versions.set(manifest, loadedEarlier ? EARLIER_VERSION : diskBindingVersion(manifest));
    }
  }
  return cached;
}

// First binding release that reads each vault format major. Every vault write
// by a murk CLI stamps the newest format, so the binding must keep up.
const BINDING_FOR_FORMAT: Record<string, string> = { "3": "0.14.0" };

/** True when dotted version `a` is at least `b`; false when either is unparseable. */
function versionAtLeast(a: string, b: string): boolean {
  const parse = (v: string) => (/^\d+(\.\d+)*$/.test(v) ? v.split(".").map(Number) : null);
  const [x, y] = [parse(a), parse(b)];
  if (!x || !y) return false;
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const diff = (x[i] ?? 0) - (y[i] ?? 0);
    if (diff !== 0) return diff > 0;
  }
  return true;
}

/**
 * The error for a vault format the running binding cannot read. When the
 * binding on disk differs from the one this process loaded and could read the
 * format, the fix is a bb restart, not another install.
 */
export function unsupportedFormatMessage(options: {
  loaded: string;
  onDisk: string;
  format: string;
  cause: string;
}): string {
  const { loaded, onDisk, format, cause } = options;
  const needed = BINDING_FOR_FORMAT[format];
  if (loaded !== onDisk && needed !== undefined && versionAtLeast(onDisk, needed)) {
    return (
      `the bb server still has ${BINDING_MODULE} ${loaded} loaded, which cannot read vault format ${format}.x; ` +
      `restart bb to load ${onDisk} (${cause})`
    );
  }
  return (
    `the installed ${BINDING_MODULE} ${onDisk} cannot read vault format ${format}.x; ` +
    `it needs ${BINDING_MODULE} ${needed ?? "newer than this"} or later — ` +
    `update the plugin's dependencies, then restart bb: a plugin reload keeps the loaded binding (${cause})`
  );
}

/** Load a vault, turning an "unsupported vault version" parse error into an upgrade instruction. */
function loadVault(vaultPath: string): MurkVault {
  try {
    return binding().load(vaultPath);
  } catch (error) {
    const cause = error instanceof Error ? error.message : String(error);
    const format = /unsupported vault version: (\d+)\./.exec(cause)?.[1];
    if (!format) throw error;
    const manifest = manifestPath();
    const onDisk = manifest ? diskBindingVersion(manifest) : "unknown";
    const loaded = (manifest && loadedVersions().get(manifest)) || onDisk;
    throw new Error(unsupportedFormatMessage({ loaded, onDisk, format, cause }));
  }
}

/**
 * Load a vault as a specific grant identity and run `fn` against it.
 *
 * The binding reads MURK_KEY / MURK_KEY_FILE from the process environment at
 * load() time, so the grant key is swapped in around the synchronous load and
 * restored in a finally block. Node is single-threaded and load() is
 * synchronous, so no other code observes the swapped environment. MURK_AGENT=1
 * marks the load as an agent context: murk forces strict mode and never falls
 * back to the operator's stored key.
 *
 * TTL expiry and the vault's agent allow-tag policy are enforced by murk
 * itself inside the binding — an expired grant fails to load, and a
 * policy-forbidden key throws on get().
 */
export function withGrantIdentity<T>(
  keyFilePath: string,
  vaultPath: string,
  fn: (vault: MurkVault) => T,
): T {
  const saved: Record<string, string | undefined> = {
    MURK_KEY: process.env.MURK_KEY,
    MURK_KEY_FILE: process.env.MURK_KEY_FILE,
    MURK_AGENT: process.env.MURK_AGENT,
    MURK_STRICT: process.env.MURK_STRICT,
  };
  delete process.env.MURK_KEY;
  process.env.MURK_KEY_FILE = keyFilePath;
  process.env.MURK_AGENT = "1";
  try {
    return fn(loadVault(vaultPath));
  } finally {
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}
