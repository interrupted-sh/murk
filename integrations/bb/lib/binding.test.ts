// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
import { describe, expect, it } from "vitest";
import { unsupportedFormatMessage } from "./binding";

const cause = "vault parse error: unsupported vault version: 3.0";

describe("unsupportedFormatMessage", () => {
  it("asks for a bb restart when a newer binding is on disk than the one loaded", () => {
    const message = unsupportedFormatMessage({ loaded: "0.11.0", onDisk: "0.14.0", format: "3", cause });
    expect(message).toContain("the bb server still has @interrupted/murk-secrets 0.11.0 loaded");
    expect(message).toContain("restart bb to load 0.14.0");
    expect(message).not.toContain("needs");
  });

  it("asks for a restart when the loaded version predates the record", () => {
    const message = unsupportedFormatMessage({ loaded: "an earlier version", onDisk: "0.14.1", format: "3", cause });
    expect(message).toContain("still has @interrupted/murk-secrets an earlier version loaded");
    expect(message).toContain("restart bb to load 0.14.1");
  });

  it("asks for an update when the binding on disk is the one loaded", () => {
    const message = unsupportedFormatMessage({ loaded: "0.13.0", onDisk: "0.13.0", format: "3", cause });
    expect(message).toContain("the installed @interrupted/murk-secrets 0.13.0 cannot read vault format 3.x");
    expect(message).toContain("needs @interrupted/murk-secrets 0.14.0 or later");
    expect(message).not.toContain("still has");
  });

  it("asks for an update, not just a restart, when the binding on disk is also too old", () => {
    const message = unsupportedFormatMessage({ loaded: "an earlier version", onDisk: "0.12.0", format: "3", cause });
    expect(message).toContain("needs @interrupted/murk-secrets 0.14.0 or later");
    expect(message).not.toContain("still has");
  });

  it("asks for an update for a format no known binding reads", () => {
    const message = unsupportedFormatMessage({ loaded: "0.14.0", onDisk: "0.15.0", format: "4", cause });
    expect(message).toContain("newer than this or later");
    expect(message).not.toContain("still has");
  });
});
