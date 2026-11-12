---
title: AI agents & MCP
description: Grant AI agents scoped access to secrets over MCP.
sidebar:
  order: 10
---

:::caution[Experimental]
Agent grants, `murk agent exec`, `murk mcp`, `murk agent connect`/`disconnect` and the agent policy are experimental. They are new, and their access rules changed in 0.14. Treat these features as a guardrail, not a security boundary.
:::

AI coding agents need secrets to do real work: an API key to call a service, a database URL to run a migration. The usual way to hand them over is to paste a value into a prompt or point the agent at a `.env` file. Both can leak. Prompts are often logged, and sometimes sent to third-party APIs. `.env` files get committed by accident. Once a value is in a log or a prompt, you cannot pull it back.

murk splits this into two steps.

To understand a project, an agent does not need values. It needs to know which secrets exist. `murk agent plan` prints the schema (key names, descriptions and tags) with no decryption and no key. The agent writes code and config against those names without seeing a value.

To run a command, you mint a grant: an ephemeral key that decrypts only the secrets you name, with a murk-enforced expiry. The agent runs with that grant, never your own key, and you can revoke it. If a task needs only `STRIPE_KEY`, that is the only thing the grant can read.

This narrows where secrets are exposed. It does not make a leak impossible. A command the agent runs can still print a value, and anything that runs as your user can read a grant key stored on disk. murk gives you least-privilege, revocable access, not a sandbox. For real isolation, run the agent as a separate user or in a container: see [Agent isolation](/guides/agent-isolation/). For how this compares with a credential broker, see [What each approach protects against](/guides/agent-protection-compared/). To run murk itself in a container, see [Containers](/guides/containers/).

## Rules

1. **Never paste secrets into prompts.** Agent conversations are logged, cached, and sometimes sent to third-party APIs. Once a secret is in a prompt, assume it has leaked.

2. **Never give an agent your own key.** That covers `MURK_KEY`, `MURK_KEY_FILE` pointing at your key file, and the file in `~/.config/murk/keys`. Your key is your identity. An agent that holds it can decrypt everything you can, and you cannot revoke it without re-keying.

3. **Inject only the secrets a command needs.** Do not export secrets to the shell. When the agent runs the command, use `murk agent exec` with a grant key. When you run it yourself, use `murk exec --only`:

   ```bash
   MURK_KEY_FILE=~/.config/murk/agent-keys/<...>-codex murk agent exec --only DATABASE_URL -- npm test
   murk exec --only DATABASE_URL -- npm run migrate
   ```

   Plain `murk exec` without `--only` injects every secret your key can read.

   `murk agent exec` requires `--only`. It clears the inherited environment except `PATH`, `HOME` and `TERM`, and removes `MURK_KEY` and `MURK_KEY_FILE`. It sets `MURK_AGENT=1` and `MURK_STRICT=1` for the command, and masks the injected values in the command's output. So the command sees only the secrets you named.

   `agent exec` needs an agent grant key in `MURK_KEY` or `MURK_KEY_FILE`. Set only one of the two: murk refuses to run when both are set. `agent exec` refuses every key that is not a grant:

   - It refuses your stored key from `~/.config/murk/keys` before it loads the vault. An agent shell with no `MURK_*` set would otherwise get that key without asking.
   - It refuses a personal key passed in `MURK_KEY` or `MURK_KEY_FILE` once the vault is open, before it reads any secret.

   When you run it yourself and mean to use your own key, pass `--allow-operator-key`. murk then prints a one-line warning on every run that decrypts with a key that is not a grant:

   ```bash
   murk agent exec --allow-operator-key --only DATABASE_URL --only PG_PASSWORD -- ./migrate.sh
   ```

4. **Use `murk agent plan` to tell the agent what exists.** An agent does not need values to know which secrets there are. `agent plan` prints key names, descriptions, examples and tags, as text or JSON. It decrypts nothing, needs no key, and shows no recipients:

   ```bash
   murk agent plan            # human-readable
   murk agent plan --json     # machine-readable
   murk agent plan --tag db   # filter by tag
   ```

   It works anywhere the vault file is. The agent can run it, or you can put its output in a system prompt. An MCP server also offers the `murk_plan` tool (see below), filtered to the server's grant and policy. Either way, the agent learns which variables exist and how to reference them without seeing a value.

   For more detail, use `murk info`: it also shows recipients, your key source and private values. To share a vault file shaped like the real one, use `murk skeleton`: it blanks `recipients`, `secrets` and `meta`.

   Full flags for every command here are in the [CLI reference](/reference/cli/).

![murk agent plan, then a scoped grant the agent runs against: the schema has no values, and every key outside the grant is refused](/demos/agent.gif)

## Agent context

Set `MURK_AGENT=1` to tell murk it runs for an agent. In an agent context, murk forces strict mode:

- murk does not look up your stored key in `~/.config/murk/keys`. The agent must present its own key in `MURK_KEY` or `MURK_KEY_FILE`, such as a grant key, or the command fails.
- `murk get`, `murk export` and `murk diff --show-values` refuse to write to a stdout that is a regular file.
- `murk edit` requires a RAM-backed temporary directory. `murk edit` is itself experimental: its lifecycle is new and its process handling is Unix-only.

Strict mode does not stop a program from saving values elsewhere. A program that receives a value can write it anywhere.

**Strict mode is a default, not a sandbox.** It holds only while `MURK_AGENT`, `MURK_STRICT`, `MURK_KEY` and `MURK_KEY_FILE` stay set in the agent's shell. A process controls its own environment. An agent that runs as your user can unset those variables, and its next `murk` command then finds your stored key from the vault's path. It can also read `~/.config/murk/keys` directly. A change to the stored-key lookup is planned for 0.15. Until then, run the agent as a separate user or in a container: see [Isolating the agent](#isolating-the-agent).

For a non-strict shell of your own, leave `MURK_AGENT` unset.

In CI, murk prints a short hint toward a grant key when it sees a pipeline decrypt with a personal key. It does not refuse. `murk agent exec` does refuse such a key, in CI or not, unless you pass `--allow-operator-key`.

**Holding your own key to the policy.** The allow-tag policy (see [Restricting which secrets agents can touch](#restricting-which-secrets-agents-can-touch)) normally binds only grant keys. `murk get`, `export` and `edit` with your own key ignore it. Set `MURK_SELF_SCOPE=1` to hold your own reads to the policy too. An agent context sets it for you. Then:

- `get`, `exec`, `agent exec` and single-key `edit KEY` fail on a key the policy does not allow.
- `export` leaves out forbidden keys and says so on stderr.
- murk refuses a bulk `murk edit`.

Use it when you run an agent in your own shell and want the policy to apply. The murk binary still enforces it. It is not a sandbox.

![murk agent exec: run a command with only the named secret injected, and no key](/demos/agent-exec.gif)

## Scoped agent grants

A [grant](/concepts/grants/) is an ephemeral key that decrypts only the secrets you name. The safest pattern is `murk agent exec` with a grant key: the agent's command gets secret values in its environment, never a key, and the grant limits which values it can reach. The same grant key also serves an agent that runs `murk` itself during a session, for example a long-running agent that calls `murk get` as it works.

### One-shot setup: `murk agent init`

`murk agent init` does the whole setup in one command. It can set the allow-list, it mints a grant, and when it writes a key file it prints the run command, an isolation note and a link to the [isolation recipes](/guides/agent-isolation/):

```bash
murk agent init --name codex --only STRIPE_SECRET_KEY --ttl 2h
murk agent init --name claude --only DATABASE_URL --allow-tag agents --ttl 30m
```

`--allow-tag` sets the vault's agent allow-list before it grants. One vault write covers both. A scope the allow-list forbids fails before anything is saved.

### `murk agent grant`

`murk agent grant` mints a fresh age identity and gives it read access to exactly the keys you name. It never uses your own key as the grant:

```bash
murk agent grant --name codex --only STRIPE_SECRET_KEY --ttl 2h
murk agent grant --name migrate --only DATABASE_URL --only PG_PASSWORD --ttl 30m
```

These rules apply to every grant:

- **TTL.** `--ttl` takes a number and a unit: `s`, `m`, `h` or `d`. The default is `2h` and the maximum is `365d`.
- **Names.** A grant name is unique. murk refuses a name that still has a grant record. `--renew` revokes the old key and mints a new one under the same name, in one vault write. Use it when a short TTL runs out during a session.
- **Expired grants.** An expired grant keeps its record, and `agent ls` shows it, until the next vault write by anyone. That write removes the grant and its recipient entry. The name is then free, and the old key fails with `not a recipient of this vault` instead of `expired`.

murk writes the grant key to `~/.config/murk/agent-keys/<vault-hash>-<name>` and prints how to use it. `--out PATH` writes it elsewhere and refuses an existing file unless you pass `--force`. `--out -` writes it to stdout.

Run the agent with that key and `MURK_AGENT=1`:

```bash
MURK_KEY_FILE=~/.config/murk/agent-keys/<...>-codex MURK_AGENT=1 \
  murk agent exec --only STRIPE_SECRET_KEY -- python scripts/refund.py
```

The grant key reads only its own keys. Any other key fails: `murk get` reports `KEY is outside this grant's scope`, and `agent exec` reports `key not found: KEY`. This is a decryption boundary, not a check. The grant is left out of the shared layer, so the other values were never encrypted to it.

List, renew and revoke grants:

```bash
murk agent ls                                                      # name, scope, TTL status
murk agent grant --name codex --only STRIPE_SECRET_KEY --renew     # new key, old one revoked
murk agent revoke codex --rotate                                   # remove the grant, rotate its keys
```

`agent revoke --rotate` asks for a new value for each secret the grant could read, or reads them from `--values-from FILE`. It stores the new values in the vault. It does not rotate them at the provider. A running `murk mcp` server refuses the revoked grant from its next tool call.

### Four things to keep in mind

- **murk enforces the TTL at read time. Cryptography does not.** Past its expiry, a grant fails on every read: `murk get`, `agent exec`, the MCP tools and the bindings. `agent ls` flags it. A running `murk mcp` server checks expiry on every tool call, `murk_plan` included. An age key cannot expire by itself, and old vault versions stay readable in git. So a leaked grant key still decrypts history with raw age. Revoke the grant and rotate its secrets to close that.
- **The key file carries the expiry too.** The key file has a `# murk-grant-expires:` line next to its trusted-signer lines. murk enforces the earlier of the key file's expiry and the vault's. So an unchanged copy of the key file stops working at its TTL, whatever a later vault says. The line bounds the file, not its holder: whoever can edit a copy can delete the line, and murk then uses the vault's record alone. A key file without that line (from an older murk, or a bare key line) uses the vault's record, and murk warns once that you should re-mint it with `--renew`. To keep the expiry in CI, pass the whole key file to murk-action v1.2.0 or later.
- **The key is a bearer credential.** Whoever holds the key file has the access. Protect it like the secrets it unlocks.
- **An agent that runs as you can get past the grant.** It can read `~/.config/murk/keys` directly. It can also unset `MURK_AGENT`, `MURK_STRICT`, `MURK_KEY` and `MURK_KEY_FILE` in its own shell: its next `murk` command then finds your stored key from the vault's path, and the grant no longer limits it. A change to this lookup is planned for 0.15. Until then, the boundary is a separate user, a container, or a hardware key that needs a touch for each decrypt.

## Isolating the agent

A grant's scope is a real boundary only when the grant key is the only murk key the agent can reach. That is true in CI, in a container and under a separate OS user. It is not true for an agent that runs as you on your laptop.

[Agent isolation](/guides/agent-isolation/) has three tested recipes: a container, a devcontainer and a separate OS user. In each one, the agent gets a checkout of the repository and one grant key file, and nothing else from `~/.config/murk`. Each recipe ships with a check script that runs as the agent and fails if the agent can reach any murk key other than the grant.

## Vault trust and reserved names

**Agents never sign and never decide what to trust.** A grant key is read-only. murk refuses a vault signed by a grant key, and `murk trust` refuses to run under a grant identity. `murk trust` is the human review step. Do not give an agent `murk trust --yes`.

**A fresh environment needs a trust anchor.** murk checks every vault against the trust pin of the machine it runs on. A full-recipient key in a container, a CI job or any other place with no pin gets "not trusted on this machine yet", and `murk trust` is a human step.

A grant key works differently. It never reads or writes the pin. It trusts only the signers named in the `# murk-trusted-signer:` lines at the top of its key file, plus any in `MURK_TRUSTED_SIGNERS`. `murk agent grant` writes those lines when it mints or renews the key. They name the signers this machine's pin trusts, plus your key if it can sign. So a grant key works on a machine with no pin, as long as the lines stay with the key.

A signer added after the grant was minted is not in the key file. The grant then refuses the vault until you re-mint it with `--renew`, or list that signer in `MURK_TRUSTED_SIGNERS`. A key file with no signer lines, such as one from before 0.14, needs `MURK_TRUSTED_SIGNERS`.

Where there is no pin and the key is not a grant with signer lines, set `MURK_TRUSTED_SIGNERS` to the entries of the people who write the vault. `murk trust --print-key` prints one entry, as `age1...:<verifying key>` or an `ssh-ed25519` public key line. Set it only from a CI secret or the real process environment, never from a file in the repository or a `.env` that an app's dotenv loader reads, because it decides which signers this machine trusts. See [CI/CD](/guides/cicd/#telling-ci-who-may-sign-the-vault).

**The vault cannot choose the agent's environment.** Whoever last wrote the vault chose its key names. So `murk agent exec` refuses to inject a key with a reserved name, such as `PATH`, `NODE_OPTIONS`, `LD_PRELOAD` or any `MURK_` name, unless you pass `--allow-reserved`. The MCP `murk_exec` tool always refuses them, with no override. [Variable names a vault may not set](/concepts/env-vars/#variable-names-a-vault-may-not-set) has the full list.

## Output masking

`murk agent exec` and the MCP `murk_exec` tool replace each injected value in the command's stdout and stderr with `***NAME***`, where `NAME` is the key's name. So an `env` dump or a debug line does not put a secret in the agent's transcript. Masking is always on. There is no flag to turn it off.

:::caution[An accident guard, not a security boundary]
It works like GitHub Actions' `::add-mask::`. Its limits:

- It matches a value byte for byte. A value that is encoded (base64, URL encoding, hex), transformed, printed in part, or split between stdout and stderr gets through.
- It covers stdout and stderr only. murk does not touch a value the command writes to a file, a socket or another process.
- murk does not mask values shorter than 4 bytes. Masking `1`, `on` or `dev` would change unrelated output and still not hide so short a value.
- When one value contains another, the longer one wins: the output shows the longer key's placeholder.

A command that wants to leak a value it was given can do so. Masking stops only the accidental case.
:::

**What changes for the command under `agent exec`.** To read the output, `agent exec` supervises the command instead of replacing itself with it. Plain `murk exec` still replaces itself.

- The command's stdout and stderr are pipes, not your terminal. A program that checks for a terminal may drop color or progress bars, or buffer its output differently. stdin is still your terminal.
- murk holds back only the end of a chunk that could be the start of a value: at most one byte less than your longest masked value. It writes everything else at once. murk matches each stream on its own.
- murk exits with the command's exit code. If a signal killed the command, murk raises the same signal.
- On Linux, Ctrl-C reaches the command once, straight from the terminal. On macOS, a Ctrl-C or Ctrl-\ typed in the terminal can reach the command twice: once from the terminal and once forwarded by murk. A command that treats a second Ctrl-C as "quit now" can then skip its clean shutdown. murk forwards SIGINT, SIGTERM, SIGHUP and SIGQUIT that another process sends to murk alone, for example a harness timeout. As a container's PID 1, murk also forwards a signal sent from outside the container, such as the SIGTERM from `docker stop` (murk 0.14.1 did not). See [Containers](/guides/containers/).
- murk waits until both streams close. A background process that inherits them keeps `agent exec` running.

## Restricting which secrets agents can touch

Tag your secrets and set an allow-list. murk then refuses to inject or grant anything outside it in agent mode:

```bash
murk describe DATABASE_URL "..." --tag agents   # tag the keys agents may use
murk policy set --allow-tag agents              # deny every other key to agents
```

Now `agent exec` and `agent grant` work only for keys tagged `agents`. A request for an untagged or production key fails with a clear error. There is no override flag, so an agent cannot argue its way past the policy. `agents` is only an example tag. Use the tags that fit your vault (`dev`, `ci`, and so on).

The policy denies by default only once you set it. With no policy, every key a grant can read is allowed: `murk policy show` then reports `no agent policy — agent mode is unrestricted`.

The policy lives in the vault header. The vault MAC covers it, and `murk policy show` reads it without a key, so it travels with the repository and applies in CI. The murk binary enforces the policy as a guardrail, not as access control (see the [threat model](/security/threat-model/)).

A granted agent is held to the policy however it reads: `murk get`, `murk agent exec`, or the Python and Node bindings (`murk-secrets`). The bindings' `get()` and `export()` refuse a forbidden key, as the CLI does.

A tighter policy takes effect on the next murk process that reads the vault. Drop a tag, and the agent's next `murk get` (with `MURK_AGENT=1`) or `agent exec` refuses that key, even though its grant key still exists. A running `murk mcp` server applies the change from its next tool call. A loaded binding object keeps the vault state from its last load, so reload it after you change the policy or revoke a grant. Grant expiry is the exception: murk checks it again on every value read.

## Serving secrets over MCP (`murk mcp`)

Agent harnesses that speak the [Model Context Protocol](https://modelcontextprotocol.io), such as Claude Code, Cursor and omp, can read murk secrets through `murk mcp`. It is a stdio MCP server built into the murk binary. It calls murk in-process, with no subprocess and no Node runtime. The same grants and policy that bind the CLI bind it.

It runs only as a scoped agent. It refuses to start unless it has a grant key and `MURK_AGENT=1`. With your stored key, a plain recipient key, or no grant, it does not start. So an MCP client never gets your full read scope.

The editor launches `murk mcp` itself, from an entry in its MCP config. `murk agent connect` writes that entry for you (see [Where the MCP entry goes](#where-the-mcp-entry-goes)). To wire an editor by hand, mint a grant first, then add an entry like this one, which is the shape `agent connect` writes to Claude Code's `.mcp.json`:

```json
{
  "mcpServers": {
    "murk": {
      "command": "murk",
      "args": ["mcp"],
      "env": {
        "MURK_KEY_FILE": "/home/you/.config/murk/agent-keys/<vault-hash>-mcp",
        "MURK_KEY": "",
        "MURK_AGENT": "1"
      }
    }
  }
}
```

The empty `MURK_KEY` hides a `MURK_KEY` the editor may pass down from your shell. murk refuses to run with both key variables set.

On every tool call, the server checks whether the vault file changed. If it did, the server loads the file again with the same checks as at startup: MAC, signature, trust and grant expiry. So a revoke or a tighter policy takes effect from the next call, without a restart. If the changed file does not load (it was tampered with, or it is not a vault), the call fails. murk also checks grant expiry on every tool call, so an expired grant gets an error from `murk_plan`, `murk_get` and `murk_exec`, and no key names. The reload does not reach old vault versions: the grant key still decrypts them from git history with raw age, so rotate after you revoke.

The server speaks JSON-RPC over stdout and logs only to stderr. It offers two read tools, always on and limited to the grant, and one exec tool that is off by default:

- **`murk_plan`** lists the key names, descriptions, examples and tags of the secrets this grant may read, as JSON. It returns no values, and it leaves out keys outside the grant or the agent policy. That limits the tool only. The schema is plaintext in `.murk`, so an agent that can read the file or run `murk agent plan` still sees every key name. It takes an optional `tags` filter.
- **`murk_get { key }`** returns one secret value if the grant may read it. The value goes into the model's context, so it ends up in the agent's transcript. Prefer `murk_exec` or `murk agent exec` when the command can take the secret from its environment. A key outside the grant or forbidden by the policy returns an error result, never the value.
- **`murk_exec { only, command }`** is off unless you start the server with `murk mcp --allow-exec`. It runs `command` (an argv array, no shell) with the secrets named in `only` in its environment. It returns `exit_code`, `stdout`, `stderr` and `truncated` as JSON, with the injected values masked (see [Output masking](#output-masking)). Every key in `only` must be in the grant's scope and allowed by the policy, or nothing runs.

The `murk_exec` command gets a clean environment: `PATH`, `HOME` and `TERM` on Unix, plus `MURK_AGENT=1` and `MURK_STRICT=1`. It gets no stdin, a 120-second timeout and 1 MiB per output stream, and murk kills it past either limit. A non-zero exit or a truncated stream returns an error result. `only` limits the injected secrets, not the command. The command runs as your user, with your filesystem and network access, so `murk_exec` is not a sandbox. Turn it on only where the server already runs under OS-level isolation.

To test the server without a client, drive the handshake over a pipe:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | MURK_KEY_FILE=<grant> MURK_AGENT=1 murk mcp
```

The transport is a local stdio pipe, not a network listener. The grant limits which secret values reach the agent. `murk_exec`, when on, runs real commands as your user, so treat it like `murk agent exec`: a safe default, not a sandbox. OS-level isolation is the boundary (see [Isolating the agent](#isolating-the-agent)).

### Where the MCP entry goes

`murk agent connect` writes the wiring for you, but only for hosts that manage their own MCP servers. There are two cases. If you wire the wrong one, nothing tells you.

**The editor manages its own MCP servers.** Claude Code, Cursor, VS Code, Zed, Gemini CLI, omp and Codex each read a project-local config file, such as `.mcp.json` or `.codex/config.toml`. `murk agent connect` writes the `murk` entry there: the command, its arguments, and an `env` block with `MURK_KEY_FILE` (a path, never the key), `MURK_AGENT=1` and an empty `MURK_KEY`. The editor launches `murk mcp` with that environment, so the grant and the agent context reach the server.

Run `murk agent connect claude --only STRIPE_SECRET_KEY`, or leave out the editor name to detect editors from the config files and marker directories in the repository. `--only` is required and repeatable.

- The grant is named `mcp` (change it with `--name`) and expires after 2 hours (change it with `--ttl`).
- Running `connect` again reuses a grant with the same scope. If the scope differs, it fails and prints the command to fix it.
- When the grant expires, the editor's murk tools fail with `grant mcp expired`. Renew it with `murk agent grant --name mcp --only STRIPE_SECRET_KEY --renew`, which rewrites the same key file. Then restart the editor.
- `murk agent disconnect [editor]` removes the entry and leaves the grant live. Add `--rotate` to revoke the grant and rotate its keys.

```bash
# Detect the editors this repository uses and wire them all:
murk agent connect --only STRIPE_SECRET_KEY --only DATABASE_URL --ttl 2h

# ...or name one (claude, cursor, vscode, zed, gemini, omp, codex):
murk agent connect cursor --only STRIPE_SECRET_KEY
```

| Editor | Config file | Format |
| --- | --- | --- |
| Claude Code | `.mcp.json` | JSON |
| Cursor | `.cursor/mcp.json` | JSON |
| VS Code | `.vscode/mcp.json` | JSON |
| Zed | `.zed/settings.json` | JSON |
| Gemini CLI | `.gemini/settings.json` | JSON |
| omp | `.omp/mcp.json` | JSON |
| Codex | `.codex/config.toml` | TOML |

`connect` writes only a key-file path, never key material. It keeps any other servers and comments in the file. Add `--allow-exec` to turn on the exec tool as well. These files are often committed, so murk warns and offers to add the path to `.gitignore`. `disconnect` removes only murk's entry and leaves other servers alone.

![murk agent connect mints a scoped grant and writes the editor's MCP entry with a key-file path. A read outside the grant fails closed, and disconnect --rotate revokes and rotates](/demos/agent-connect.gif)

**The host delegates MCP to a provider CLI it wraps.** Some agentic IDEs do not manage MCP servers. They run one of the provider CLIs above for you and only show its MCP tool calls. bb is one: it shows MCP activity but has no MCP config of its own. Here the `murk` entry belongs in the provider's config, not the IDE's: Claude Code's `.mcp.json` or Codex's `.codex/config.toml`. `MURK_KEY_FILE` and `MURK_AGENT` must reach the provider process that launches `murk mcp`, not the IDE process around it. So connect the provider, not the wrapper: `murk agent connect claude --only KEY` (or `codex`) writes the entry, with its `env` block, to the file the provider reads.

To tell which case you are in: if your IDE is one of the editors above and has its own MCP settings, connect it directly. If it works by driving Claude Code, Codex or another provider CLI, connect that provider. If you wire the wrong layer, the agent gets a config it never reads, or a grant key the provider never sees, and there is no error.

## Configuring your agent harness

An agent harness such as Claude Code or Codex can run some murk commands without asking and ask before the rest. The split follows from what each command reads. Commands that read only the vault header and the plaintext schema return no secret values. The others decrypt values, change the vault, or change who can decrypt. Allow the first set. Ask before the second. Treat any command not listed as Ask.

**Allow: no secret value can come out.**

| Command | Why it is safe |
| --- | --- |
| `murk info`, `murk info --json` | Reads the header. With a key, it also shows recipient names and your key source. Never values. |
| `murk ls`, `murk ls --json` | Lists key names from the header. No values. |
| `murk agent plan`, `murk agent plan --json` (to stdout) | Prints the schema: key names, descriptions, tags. No values. |
| `murk skeleton` (to stdout) | Prints a copy of the vault's shape with recipients, secrets and meta blanked. |
| `murk circle`, `murk circle --json` | Lists recipients from the header. With a key, it also shows recipient names. Never values. |
| `murk policy show` | Prints the agent policy from the header. No key needed. |
| `murk doctor` | Checks repository hygiene and the plaintext schema. No key. |

**Ask: decrypts, changes the vault, or changes trust.**

| Command | Why it needs confirmation |
| --- | --- |
| `murk add`, `murk rm`, `murk describe`, `murk import`, `murk generate`, `murk rotate`, `murk edit` | Write to the vault. |
| `murk get`, `murk export` | Decrypt secret values and return them. |
| `murk diff`, `murk diff --show-values`, `murk diff --json` | Decrypt the old and current values to compute the diff. Only `--show-values` prints them, as text or in `--json`, and under an agent policy only for keys it allows. |
| `murk verify` | Loads and decrypts the whole vault to check it. Shows no values, but needs the key. |
| `murk scan` | Decrypts every secret to search files for leaked values. |
| `murk env` | Writes an `.envrc` that runs `murk export`, which decrypts your full scope into the shell. |
| `murk circle authorize`, `murk circle revoke`, `murk policy set` | Change who can decrypt the vault, or the agent policy. |
| `murk trust` | Records a vault as trusted on this machine and can re-sign it. That decision is yours. Never `--yes`. |
| `murk init`, `murk recover`, `murk restore` | Create a key, or print your recovery phrase or secret key. |
| `murk skeleton -o PATH`, `murk agent plan -o PATH` | Create a new file at `PATH`. They refuse a path that exists, so they never overwrite. |
| `murk exec -- CMD` | Decrypts your full scope into a subprocess. Use `murk agent exec` instead. |
| `murk agent grant`, `murk agent init`, `murk agent revoke`, `murk agent connect`, `murk agent disconnect` | Mint, revoke or wire a grant. |

**Special case: `murk agent exec --only KEY -- CMD`.** The wrapper is safe by default. It clears the inherited environment, removes `MURK_KEY` and `MURK_KEY_FILE`, injects only the named secrets, marks the command as an agent context, masks the injected values, and refuses a key that is not a grant unless you pass `--allow-operator-key`. Allow it only when the harness itself supplies the grant key through its own environment. The command text cannot prove which key a run uses. These still need confirmation:

- **Any command that sets `MURK_KEY` or `MURK_KEY_FILE`.** It can swap in a different grant key, a wider one for example.
- **`--allow-operator-key`.** It tells `agent exec` to decrypt with a key that is not a grant: your stored key, or a personal key in `MURK_KEY` or `MURK_KEY_FILE`. That is your decision, never the agent's.
- **The inner `CMD`.** It runs as your user, with your filesystem and network access, so it must pass the harness's normal rules like any other command. Deny environment dumps (`env`, `printenv`, `set`, `export -p`) under `agent exec` or any other wrapper that injects secrets. Masking catches a verbatim value, not an encoded or partial one.

**Why the split holds.** Under `murk agent exec`, the command has no `MURK_KEY` or `MURK_KEY_FILE`, and `MURK_AGENT=1` stops murk from looking up your stored key. So a nested command that needs decryption fails, while those variables stay as murk set them. The allow list is the set of commands that still work in that state: they read the header and the schema and nothing more. Even without a key, nothing on the list can print a secret value. An agent that runs as your user can unset `MURK_AGENT` and get your stored key back. The harness rules do not stop that. [Isolating the agent](#isolating-the-agent) does.

### Claude Code

Put this in `.claude/settings.json` in the repository, or in `~/.claude/settings.json`. Claude Code checks deny rules first, then ask, then allow. In its default mode it asks before any Bash command no rule allows.

```json
{
  "permissions": {
    "allow": [
      "Bash(murk info)",
      "Bash(murk info --json)",
      "Bash(murk ls)",
      "Bash(murk ls --json)",
      "Bash(murk agent plan)",
      "Bash(murk agent plan --json)",
      "Bash(murk skeleton)",
      "Bash(murk circle)",
      "Bash(murk circle --json)",
      "Bash(murk policy show)",
      "Bash(murk doctor)"
    ],
    "ask": [
      "Bash(murk add *)", "Bash(murk rm *)", "Bash(murk describe *)",
      "Bash(murk import *)", "Bash(murk generate *)", "Bash(murk rotate *)",
      "Bash(murk edit *)", "Bash(murk get *)", "Bash(murk export *)",
      "Bash(murk diff *)", "Bash(murk verify *)", "Bash(murk scan *)",
      "Bash(murk env *)", "Bash(murk circle authorize *)",
      "Bash(murk circle revoke *)", "Bash(murk policy set *)",
      "Bash(murk trust *)", "Bash(murk init *)", "Bash(murk recover *)",
      "Bash(murk restore *)", "Bash(murk exec *)", "Bash(murk group *)",
      "Bash(murk agent grant *)", "Bash(murk agent init *)",
      "Bash(murk agent revoke *)", "Bash(murk agent connect *)",
      "Bash(murk agent disconnect *)", "Bash(murk agent exec *)",
      "Bash(env *)", "Bash(export MURK_*)"
    ],
    "deny": [
      "Bash(murk agent exec * -- env*)",
      "Bash(murk agent exec * -- printenv*)",
      "Bash(murk exec * -- env*)",
      "Bash(murk exec * -- printenv*)"
    ]
  }
}
```

How the rules apply:

- The allow rules are exact. `Bash(murk circle)` does not allow `murk circle authorize`, and `Bash(murk agent plan)` does not allow `murk agent plan -o PATH`.
- Claude Code matches an ask or deny rule past a leading variable assignment, so `MURK_KEY_FILE=... murk get KEY` still asks. An allow rule does not match past an assignment of `MURK_KEY` or `MURK_KEY_FILE`, so a command that sets one always asks.
- An ask rule wins over an allow rule. So with `Bash(murk agent exec *)` in the ask list, every `agent exec` asks. If the harness supplies the grant key through its own environment, you can move one exact command to the allow list instead, for example `Bash(murk agent exec --only DATABASE_URL -- npm test)`, and remove `Bash(murk agent exec *)` from ask.

Claude Code's own docs say that Bash rules match the command text and are not a security boundary: `sh -c 'murk get KEY'` does not match `Bash(murk get *)`. The rules catch the commands an agent usually writes. Isolation stops the rest.

### Codex

Codex reads rules from `.rules` files in a `rules/` directory next to a config layer, for example `~/.codex/rules/murk.rules`. A rule matches a command's arguments by prefix. When several rules match, the strictest decision wins. Commands that no rule matches follow your `approval_policy` and sandbox settings, so the read-only commands need no rule.

```python
# Ask before any murk command that decrypts, changes the vault, or changes trust.
prefix_rule(
    pattern = ["murk", ["get", "export", "exec", "diff", "verify", "scan", "env",
                        "add", "rm", "describe", "import", "generate", "rotate", "edit",
                        "trust", "init", "recover", "restore", "group", "mcp"]],
    decision = "prompt",
    justification = "decrypts secret values, changes the vault, or changes trust",
    match = ["murk get API_KEY", "murk exec -- npm test", "murk trust"],
    not_match = ["murk info", "murk agent plan --json"],
)
prefix_rule(
    pattern = ["murk", "circle", ["authorize", "revoke"]],
    decision = "prompt",
    justification = "changes who can decrypt the vault",
)
prefix_rule(
    pattern = ["murk", "policy", "set"],
    decision = "prompt",
    justification = "changes the agent policy",
)
prefix_rule(
    pattern = ["murk", "agent", ["exec", "grant", "init", "revoke", "connect", "disconnect"]],
    decision = "prompt",
    justification = "decrypts with a grant, or mints, revokes or wires a grant",
)
prefix_rule(
    pattern = [["env", "printenv"]],
    decision = "prompt",
    justification = "can set MURK_KEY or MURK_KEY_FILE, or dump injected secrets",
)
```

Check a command against the file with `codex execpolicy check --rules ~/.codex/rules/murk.rules -- murk get API_KEY`. It prints the decision and the rule that matched.

Codex splits a `bash -lc` script into separate commands only when the script is plain words joined by `&&`, `||`, `;` or `|`. It does not split a script that sets a variable, such as `MURK_KEY_FILE=... murk get KEY`, and these rules do not match it. As with Claude Code, the rules catch the usual commands. Isolation stops the rest.

## Checking for leaked values

`murk scan` reports any value your key can read, 8 bytes or longer, that appears verbatim in a text file. It exits with status 1 when it finds one. It reports only. It never changes a file. It runs locally and decrypts every secret your key can read, so it belongs on the Ask list for agents.

**Check the code an agent wrote.** Agents can hardcode a secret they were given. After an agent edits code, run `murk scan` in the repository. It skips hidden directories, `target/`, `node_modules/`, `.murk`, `.lock` files and binary files.

![murk scan flags a vault value hardcoded into a file, then reports clean after the fix](/demos/agent-scan.gif)

**Check what the session left behind.** An agent session can leave values in its transcripts and in the MCP config it was given. After the session, scan those paths by name:

```bash
murk scan ~/.claude/projects .mcp.json       # Claude Code
murk scan ~/.codex/sessions .codex/config.toml   # Codex
```

Adapt the paths to your harness. Pass each path explicitly. `murk scan` skips hidden directories below the path you give it, so `murk scan ~` misses `~/.claude/projects` and `murk scan .` misses `.claude/`. A hidden file or directory that you name on the command line is scanned.

What `murk scan` cannot tell you:

- It finds only exact copies. It misses a value that is encoded, split, or copied in part.
- It finds only values your key can read now. A value you rotated away, or one outside your scope, is not checked.
- A clean result is not proof that no value leaked. A value sent over the network, or stored outside the paths you scanned, leaves nothing to find.

## Auditing agent activity

murk keeps no separate agent log. Commit each vault change, and git becomes the record:

```bash
git log -p .murk        # who changed the vault and when
murk diff HEAD~1        # which secrets changed in the last commit
```

`git log -p .murk` attributes each change to its commit author, and to the commit signature if you sign commits. The diff shows policy edits and added or removed recipient keys in plaintext.

A new grant shows up as a new recipient key and new `scoped` ciphertexts under the secrets it can read. So the diff shows which secrets that key can read. Its name, TTL and issuer are encrypted and show up only as a changed `meta` blob.

`murk diff` also lists recipients added and removed, signer changes, and policy, grant and group-member changes. It verifies the old revision's MAC and signature before it shows anything from it.

Git cannot show secret reads on a developer's machine, because murk never sees them. The absence of a read trail is not proof that a secret was not used. See the [threat model](/security/threat-model/) for the full audit boundary.
