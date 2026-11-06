# murk brand guide

This guide is the single source of truth for murk's color, mark, and voice. The
live CLI and the fixed brand assets follow different color rules. Read the split
below before you change either.

## The one purple

murk's brand purple is `#8760FF`. It is the project's one canonical purple.
Every fixed-color surface uses this exact hex: logo, lockup, favicon, social
card, website accent, and recorded demo GIFs.

UI accent ramps may derive tints from it. The site's Starlight theme uses a
dark low (`#241a4d`), a light high (`#d3c8ff`), and an alpha glow (`#8760ff40`,
the brand purple at 25%). These are sanctioned derivations of the one purple,
not new brand colors. A second, standalone base purple anywhere is drift. Fix
it. Do not add to it.

## CLI color vs. asset color

Two surfaces follow two rules:

- The live CLI emits semantic ANSI colors, never a fixed hex. Status colors and
  the mark go through the `colored` crate's semantic helpers (see
  [cli-style.md](./cli-style.md)). The `◆` mark is ANSI magenta (SGR 35). The
  terminal picks the actual RGB from the user's theme, so murk adapts to the
  terminal instead of fighting it. Use semantic colors for new CLI output.
- Fixed-color assets use `#8760FF`. Anything murk ships as a rendered image is
  drawn in the brand purple, not left to a theme. This covers the logo, the
  favicon, the social card, and the recorded demo GIFs.

The `murk info` nameplate is the one exception to the first rule. It prints the
vault name in bold `#8760FF`. It writes the escape itself, because `colored`
downgrades 24-bit color to bright blue unless `COLORTERM` is `truecolor` or
`24bit`. When `COLORTERM` says so, it prints 24-bit `#8760FF`. Otherwise it
prints 256-color 99 (`#875FFF`), the nearest palette entry. `NO_COLOR`,
`CLICOLOR` and `CLICOLOR_FORCE` still apply.

The demo GIFs link the two rules. The CLI still emits ANSI magenta, but the VHS
recording theme overrides magenta to `#8760FF`. The recorded mark then shows the
brand color instead of the terminal palette's magenta.

## Palette

The CLI emits ANSI slots (universal, theme-decided). The hex column shows how
those slots render in brand and demo contexts: Catppuccin Mocha, with magenta
overridden to the brand purple.

| Role             | Glyph | CLI emits (ANSI)    | Brand hex             |
|------------------|-------|---------------------|-----------------------|
| brand mark       | ◆     | magenta (SGR 35)    | `#8760FF` (fixed)     |
| private-value mote | ✦   | faint (SGR 2)       | `#6c7086` (assets only) |
| ok / recipient   |       | green bold (1;32); your own name in `circle` is magenta bold (1;35) | `#a6e3a1` |
| warn             | ⚠     | yellow (33), with the `warn` word in yellow bold (1;33) | `#f9e2af` |
| error            | ✕     | red (31)            | `#f38ba8`             |
| hint             |       | cyan bold (1;36)    | `#94e2d5`             |
| dimmed           |       | faint (SGR 2)       | `#6c7086` (assets only) |
| foreground       |       | default fg (39)     | `#cdd6f4`             |
| background       |       | default bg (49)     | `#1e1e2e`             |

`dimmed` has no palette slot. It is the SGR 2 faint attribute over the
foreground, so its rendered color varies by terminal. `#6c7086` is only for
drawing dimmed text in static assets.

## The mark

The murk mark is a diamond (`◆`), a rotated square. In vector assets it is
drawn as a path, never as a font glyph, because a glyph renders differently
across platforms and fonts. The CLI prints the diamond as the `◆` glyph.

The lockup is the diamond followed by the lowercase wordmark: `◆ murk`. The
wordmark is live text, not a path. It is set in Inter in the lockup and in
Helvetica Neue in the social card.

## Contrast

`#8760FF` measured against common backgrounds:

| Background             | Ratio  |
|------------------------|--------|
| Mocha base `#1e1e2e`   | 4.02:1 |
| White                  | 4.08:1 |
| GitHub dark `#0d1117`  | 4.64:1 |

All three clear the 3:1 bar for graphics and large marks, so the purple is safe
as a mark on light and dark READMEs. Mocha base and white fall under the 4.5:1
bar for small text. GitHub dark clears it by a narrow margin. Use the purple for
marks and accents. Do not set small text in it on any background.

## Voice

murk is "an encrypted secrets manager for developers." The voice is plain and
technical, with no marketing gloss. Say what murk does, then what it does not do.

Pair a public claim with the honesty line: "murk is pre-1.0 and has not been
independently audited. Use good judgment with production secrets." The caveat is
part of the voice. Do not bury it as a disclaimer. It makes the security claims
credible.

### Writing style

Write short sentences with one idea each. Do not use em dashes. Split a clause
joined by a semicolon into two sentences. Cut filler and marketing words. Use one
term for one concept. No CI check enforces this rule.

## Agent positioning

This is reusable copy for the agent-safe story, in the plain voice above. Use it
in the README, docs, and launch materials so the claim stays consistent and
precise. You may adapt the wording if the claim and the boundary line stay the
same. The AI agents & MCP guide on the docs site has the full narrative and the
security boundary.

Use "AI agents" in docs headings, "agents" in running text, and "coding agents"
in marketing copy.

**Headline:** Let coding agents use your secrets without giving them your key.

**Subhead:** Agents read the vault's schema (names and descriptions, no values)
to write code and config. When they need to run something, you mint a
short-lived grant scoped to only the secrets you name. They never get the
key that decrypts everything.

**One-liner:** Scoped, revocable secret access for coding agents.

**Two-sentence pitch:** murk lets coding agents work with your secrets without
handing over the key to your vault. They read the schema to plan, then run
against a grant scoped to only the secrets you name.

**Boundary line** (include wherever the claim appears): This reduces where
secrets are exposed. It does not prevent a commanded process from printing one.
murk enforces a grant's TTL at read time. It refuses an expired grant on every
value read (get, exec, MCP get and exec, bindings). The key itself cannot expire
and still reads old vault versions with raw age, so revoke and rotate to close
it. It is least-privilege, not a sandbox.
