// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { redactKeyPaths, resolveOperatorKey, shellQuote } from "./murk-cli";

describe("redactKeyPaths", () => {
  it("redacts a key file whose path has spaces, doubled spaces and regex characters", () => {
    const file = "/tmp/a dir/two  spaces/(key)+[1].key";
    const text = `MURK_KEY_FILE is readable by others (mode 644). Run: chmod 600 ${file}`;
    expect(redactKeyPaths(text, { files: [file], dirs: [] })).toBe(
      "MURK_KEY_FILE is readable by others (mode 644). Run: chmod 600 <key file>",
    );
  });

  it("redacts an entry of a key directory under a HOME with a space", () => {
    const dir = "/Users/some one/.config/murk/keys";
    const text = `key file ${dir}/6edbc1bfb937b6db is readable by others`;
    expect(redactKeyPaths(text, { files: [], dirs: [dir] })).toBe("key file <key file> is readable by others");
  });

  it("leaves a path that only starts with a key file's path", () => {
    const file = "/srv/key";
    const text = `vault /srv/key-project/.murk and /srv/key.bak and /srv/keys/x, key /srv/key`;
    expect(redactKeyPaths(text, { files: [file], dirs: [] })).toBe(
      "vault /srv/key-project/.murk and /srv/key.bak and /srv/keys/x, key <key file>",
    );
  });

  it("redacts the resolved spelling of a key file reached through a symlinked directory", () => {
    const root = realpathSync(mkdtempSync(path.join(tmpdir(), "murk-redact-")));
    try {
      mkdirSync(path.join(root, "real"));
      writeFileSync(path.join(root, "real", "op.key"), "k");
      symlinkSync(path.join(root, "real"), path.join(root, "link"));
      const resolved = path.join(root, "real", "op.key");
      expect(redactKeyPaths(`cannot read ${resolved}`, { files: [path.join(root, "link", "op.key")], dirs: [] })).toBe(
        "cannot read <key file>",
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("redacts the macOS /private spelling of a /tmp path", () => {
    expect(redactKeyPaths("cannot read /private/tmp/k/op.key", { files: ["/tmp/k/op.key"], dirs: [] })).toBe(
      "cannot read <key file>",
    );
  });
});

describe("resolveOperatorKey refuses a grant key", () => {
  const age = "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ";
  const refusal = "the operator key must be a full recipient key, not an agent grant";
  // Each text is a key file as the operator might hand it over, and whether
  // the guard must refuse it. murk trims a line before it reads a marker.
  const cases: Array<[string, string, boolean]> = [
    ["a grant-id line only", `# murk-grant-id: bb-g1\n${age}\n`, true],
    ["a trusted-signer line only", `# murk-trusted-signer: age1abc\n${age}\n`, true],
    ["an indented grant-id line", `  # murk-grant-id: bb-g1\n${age}\n`, true],
    ["an indented trusted-signer line", `\t# murk-trusted-signer: age1abc\n${age}\n`, true],
    ["a comment that only mentions a marker", `# not a # murk-grant-id: line\n# see # murk-trusted-signer: docs\n${age}\n`, false],
    ["a bare key", `${age}\n`, false],
  ];

  it("in the keyFile setting, the server's MURK_KEY_FILE and the server's MURK_KEY", () => {
    const root = realpathSync(mkdtempSync(path.join(tmpdir(), "murk-guard-")));
    try {
      for (const [label, text, refused] of cases) {
        const file = path.join(root, "op.key");
        writeFileSync(file, text, { mode: 0o600 });
        const sources: Array<[string, () => string | null]> = [
          ["the keyFile setting", () => resolveOperatorKey(file, {})],
          ["MURK_KEY_FILE on the bb server", () => resolveOperatorKey("", { MURK_KEY_FILE: file })],
          ["MURK_KEY on the bb server", () => resolveOperatorKey("", { MURK_KEY: text })],
        ];
        for (const [source, resolve] of sources) {
          if (refused) expect(resolve, `${label} in ${source}`).toThrow(`${refusal}: ${source} names a grant key`);
          else expect(resolve, `${label} in ${source}`).not.toThrow();
        }
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("names the line that marks the key as a grant key", () => {
    expect(() => resolveOperatorKey("", { MURK_KEY: `# murk-trusted-signer: age1abc\n${age}` })).toThrow(
      "it has a # murk-trusted-signer: line",
    );
    expect(() => resolveOperatorKey("", { MURK_KEY: `# murk-grant-id: bb-g1\n${age}` })).toThrow(
      "it has a # murk-grant-id: line",
    );
  });
});

describe("shellQuote", () => {
  it("passes each value through a POSIX shell as one argument", () => {
    for (const value of ["bb-g1234abcd", "/srv/a dir/.murk", "it's", "$HOME `x` \\n", "a  b"]) {
      const echoed = spawnSync("sh", ["-c", `printf %s ${shellQuote(value)}`], { encoding: "utf8" }).stdout;
      expect(echoed).toBe(value);
    }
    expect(shellQuote("/srv/repo/.murk")).toBe("/srv/repo/.murk");
  });
});
