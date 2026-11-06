# murk CLI style guide

Internal reference for how murk commands present output and word their help.
Follow this when adding a new command so the CLI feels consistent.

## Prefixes

Every status line starts with a one-word prefix. It has no colon or other
punctuation, is lowercase and bold-colored, and has one space before the
message. Data lines have no prefix (see [Streams](#streams)).

| Prefix  | Color          | Use                                             |
|---------|----------------|-------------------------------------------------|
| `ok`    | green bold     | check passed / operation succeeded              |
| `warn`  | yellow bold    | non-fatal issue the user should see             |
| `✕`     | red            | fatal error, printed right before exit. Each further line of the message prints as an indented `hint` line |
| `hint`  | cyan bold      | next-action suggestion under a warn or `✕` line |
| `◆`     | magenta        | action-completed branding mark (not a status)   |

Fatal errors go through `die()`, which prints the `✕` form. The `error`
word prefix (red bold) appears in four places only: `scan`, the merge
driver and the two strict-mode guards.

Examples:

```
ok vault integrity verified
warn 1 ssh-rsa key authorized — ed25519 is recommended
✕ MURK_KEY not set
  hint run `murk init` to generate a key
  hint or point MURK_KEY_FILE at an existing key file
◆ authorized alice
```

Never write `ok:`, `warn:`, `Error:`, `OK` etc. Prefixes are lowercase and
colon-free. Current exceptions: clap's own usage errors print `error:`, and
the warning about a `.env` readable by others prints `warning:`.

## Inline markers

| Marker | Color   | Use                                           |
|--------|---------|-----------------------------------------------|
| `◆`    | magenta | completed action / branding dot               |
| `✦`    | faint   | private-value variant of `◆`, used in `info` for recipients that hold a private value |
| `⚠`    | yellow  | warning, as the lead of a line or inside a list item |
| `✕`    | red     | fatal error line (see Prefixes), a step that failed while the command goes on, or a failed check inside a list item |
| `*`    | plain   | "this entry is you" marker in `info` and `group ls`. `circle` marks you with a magenta `◆` |
| `▸`    | dimmed  | bullet in a list of secret names (revoke and grant output) |
| `✓`    | green   | rotation summary line |
| `+` `-` `~` | magenta, red, yellow (bold) | added, removed and changed secrets in `murk diff` |

Use `◆` for "something happened" lines, not for status. Use `ok` / `warn` /
`error` prefixes for status lines. A finding list under a `warn` header
should use `✕` for each failing item, not repeated `warn` prefixes.

## Formatting

- **Recipient display names**: green bold in `info` and `group ls`. `circle`
  prints your own name in magenta bold after a magenta `◆`, and every other
  recipient dimmed.
- **Pubkeys**: dimmed, shown as the first 8 and last 4 characters joined by
  `…` (for example `age1ps8p…a26p`) when displayed next to a name. Strings of
  13 characters or fewer are shown whole. A full key is fine when it is the
  subject of the line.
- **File paths and secret names**: `bold()`
- **Fix hints and follow-ups**: two-space indent under the parent line,
  dimmed color
- **Errors from external causes**: include the raw message in dimmed style
  at the end of the line

## Streams

Status goes to stderr and data goes to stdout. Status means the `ok`, `warn`,
`✕`, `hint` and `◆` lines. Data means what a script reads: secret values,
names, JSON and exports. `murk get KEY` prints the value on stdout and any
status on stderr, so `TOKEN=$(murk get KEY)` and `murk export | ...` stay
clean.

## Layout

- No trailing period on status lines.
- No decorative horizontal rules or ASCII art.
- Use empty lines only between logical sections, never between consecutive
  status lines of the same kind.
- Totals/summaries on their own line, not inline with item lists.
- Right-align counts when printing tables of counts. Otherwise use plain
  left-aligned output.

## Exit codes

- `0`: success, no findings.
- `1`: any fatal error, or any unresolved `warn` from a check command
  (`verify`, `doctor`, `scan`, etc.).
- `2`: usage error. The arguments themselves are invalid, so nothing was
  attempted. clap exits 2 for unknown flags and missing arguments. A command
  that validates an argument value itself (`describe --rotate-every`/`--expires`,
  an unknown editor in `agent connect`/`disconnect`) uses 2 as well. Failures
  while doing the work (I/O, parse, crypto) are runtime errors and exit 1.

`murk exec` and `murk agent exec` exit with the status of the command they run.
If murk cannot start the command, it prints a `✕` line and exits 1.

Check commands must be fail-closed by default: a finding that the user
should act on exits 1, even if the vault itself is readable.

## Help text

The doc comments in `src/cli.rs` become `--help`, the man pages and the CLI
reference. Write them like this:

- A command's first line is one short sentence under 100 characters, with no
  trailing period. Command lists show only this line. Put detail after a
  blank `///` line. Do the same for an option whose help runs past one
  sentence.
- End the first line with `(experimental)` for an experimental command.
- Call a vault entry a "secret" and an age or SSH key a "key". Use the same
  word for the same thing everywhere.
- Write `(repeatable)` after a flag that can appear more than once, and
  `(repeatable, required)` when it is also required.
- Say where a value comes from when it is not an argument, such as a prompt
  or stdin.
- Say so in the detail when the command line has a trap, such as `murk exec`
  passing every word after the command name to the command.
- Avoid em dashes and semicolons. Write two sentences instead.
- Run `cargo run --features doc-gen --bin gen-docs` after any change. The CLI
  reference, man pages and completions are generated, and CI runs the same
  command with `--check`.

## Colors

The demo theme is Catppuccin Mocha but the CLI should degrade gracefully
on any terminal. Always use the `colored` crate's semantic helpers
(`.green().bold()`, `.dimmed()`). Do not use raw ANSI escapes. Two current
exceptions: the `.env` permission warning in the library, and the `murk info`
nameplate.

See [brand.md](./brand.md) for the canonical palette (ANSI slots and brand
hex), the brand purple `#8760FF`, and the rule that the CLI stays
theme-adaptive while fixed assets use the locked hex.

Use semantic colors for new CLI output. The `murk info` nameplate is the one
fixed-color exception. It prints the vault name in bold `#8760FF`: 24-bit
(`ESC[1;38;2;135;96;255m`) when `COLORTERM` is `truecolor` or `24bit`,
otherwise 256-color 99 (`ESC[1;38;5;99m`, `#875FFF`), because `colored` would
downgrade it to bright blue. It still follows `NO_COLOR`, `CLICOLOR` and
`CLICOLOR_FORCE`.

## Output examples

```rust
// status line
eprintln!("{} vault integrity verified", "ok".green().bold());

// warning with a count
eprintln!(
    "{} {} ssh-rsa key{} skipped — ed25519 is strongly recommended",
    "warn".yellow().bold(),
    rsa_count,
    if rsa_count == 1 { "" } else { "s" }
);

// action-completed branding
eprintln!("{} authorized {}", "◆".magenta(), display.bold());

// finding list under a warn header
eprintln!(
    "{} {} issue{} in {}",
    "warn".yellow().bold(),
    findings.len(),
    if findings.len() == 1 { "" } else { "s" },
    header
);
for f in &findings {
    eprintln!("  {} {} — {}", "✕".red(), f.category.bold(), f.message);
    if let Some(fix) = &f.fix {
        eprintln!("      {}", fix.dimmed());
    }
}
```
