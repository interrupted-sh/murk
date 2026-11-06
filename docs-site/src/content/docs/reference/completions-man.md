---
title: Completions & man pages
description: Shell completion scripts and man pages for murk, and how to install them.
sidebar:
  order: 3
---

murk builds its shell completions and man pages from its command model, so
they match the binary.

## Shell completions

`murk completion install SHELL` writes the completion script for your shell.
SHELL is `bash`, `zsh`, `fish`, `elvish` or `powershell`:

```bash
murk completion install zsh
```

murk writes the file under your home directory and replaces a file that is
already there. It reads `HOME`, not `USERPROFILE`, so on Windows set `HOME`
first. For some shells you must then load the file yourself:

| Shell | File murk writes | Then |
| --- | --- | --- |
| zsh | `~/.zfunc/_murk` | murk prints two lines for `~/.zshrc`: `fpath+=~/.zfunc` and `autoload -Uz compinit && compinit`. Add them and start a new shell. |
| bash | `~/.local/share/bash-completion/completions/murk` | murk prints a line for `~/.bashrc` that sources the file. Add it and start a new shell. |
| fish | `~/.config/fish/completions/murk.fish` | Nothing. murk prints a note that fish loads the file by itself. |
| elvish | `~/.config/elvish/lib/murk.elv` | murk prints no step. Load the file from your elvish startup file. |
| powershell | `~/.config/powershell/_murk.ps1` | murk prints no step. Load the file from your PowerShell profile. |

To print a script to stdout instead, for another location or a system
package, use `generate`. The directory must exist, so for zsh run:

```bash
mkdir -p ~/.zfunc
murk completion generate zsh > ~/.zfunc/_murk
```

Then add the same two `~/.zshrc` lines as in the table.

Both commands are in the [CLI reference](/reference/cli/#murk-completion).
Pre-generated scripts for every supported shell (bash, zsh, fish, elvish,
PowerShell) are committed under
[`docs/completions/`](https://github.com/interrupted-sh/murk/tree/main/docs/completions)
for packagers who want to ship them without running murk.

## Man pages

No installer ships man pages. Homebrew, `install.sh`, `cargo install` and the
release archives contain only the `murk` binary, and
`murk completion install` writes completions only.

The man pages for the root command and every documented subcommand are
committed under
[`docs/man/`](https://github.com/interrupted-sh/murk/tree/main/docs/man) in
roff format (`murk.1`, `murk-init.1`, `murk-agent-plan.1`, …). Copy them to a
directory on your `MANPATH`, or read one directly from a clone of the
repository:

```bash
man ./docs/man/murk.1
```

Maintainers regenerate the completions, man pages and references with
`gen-docs`. See
[CONTRIBUTING](https://github.com/interrupted-sh/murk/blob/main/CONTRIBUTING.md).
