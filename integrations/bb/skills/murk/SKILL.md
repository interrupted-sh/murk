---
name: murk
description: Read project secrets from the murk vault through grant-scoped tools. Use when a task needs an API key, database URL, token, or other secret. Never ask the user to paste one.
---

# murk secrets in bb threads

This project keeps secrets in an encrypted murk vault (`.murk`). You never get
the vault key. You get **grants**: short-lived identities that the user mints
for exactly the keys a task needs. Everything outside a grant fails closed,
because the other values were never encrypted to your identity.

## Rules

1. **Never run `bb murk grant` yourself.** Granting and revoking access is the
   user's decision. The plugin refuses `bb murk grant mint` and
   `bb murk grant revoke` when they come from a thread. Do not try to get
   around that refusal. When you need a key, tell the user which key and why,
   and give them the command to run in their own terminal.
2. **Never ask the user to paste a secret into chat.** Prompts are logged and
   cached. Point them at `bb murk grant mint` instead.
3. **Never echo, log, or commit secret values.** That includes values you read
   from a delivered env file and values that a reveal grant returns inline.
   Do not write them into code, config, commit messages, or tool output.
4. **Never commit the delivered env file.** It is `.murk-<threadId>.env`, mode
   0600. murk_get returns its path when it delivers to a file. If the file
   shows up in `git status`, leave it out of the commit.
5. **Never run `murk trust`, and never pass `--allow-reserved`.** If murk
   says that the vault is not trusted, unsigned, rolled back, or signed by an
   unknown key, stop and tell the user. The user decides who may sign the
   vault, after they review `murk diff`.

## Discovering what exists: murk_plan

`murk_plan` returns the vault schema: key names and tags only. It never
returns values, descriptions, or grant state. Call it before you ask the user
for access, so that you can name the exact keys. You learn whether a key is
granted when murk_get delivers it or fails closed.

## Reading secrets: murk_get

`murk_get` reads the keys that an active grant covers.

**File delivery (the default).** murk_get writes the values to
`.murk-<threadId>.env` in this worktree (mode 0600). The tool returns only the
key names and the exact file path. Load the file in a subshell, so the values
do not stay in your shell (see below). You can also hand the path to a
dotenv-aware tool without printing its contents.

When this thread goes idle, the plugin deletes the file, but only if the file
is still exactly what the plugin wrote. If the file changed, the plugin leaves
it in place and does not touch it again. Call murk_get again in a later turn
instead of caching values.

murk_get never writes over bytes that it did not write. If another file
already sits at the delivery path, or the file changed after delivery,
murk_get fails closed. It asks you to move that file aside.

**Reveal grants.** Values come back inline only when the user minted the grant
with `--reveal`, and only for that grant's keys. Use these values, but never
repeat them.

## When a key is not granted

A key outside your grants fails closed. Do not retry with variations. Ask the
user to mint access, and give them the command:

```
bb murk grant mint --keys STRIPE_SECRET_KEY
bb murk grant mint --keys DATABASE_URL,PG_PASSWORD --thread <threadId>
bb murk grant mint --keys TEST_TOKEN --reveal        # inline values, if allowed
```

- A grant lasts 2 hours unless the user passes `--ttl` (for example
  `--ttl 30m`).
- Without `--thread`, the grant covers every thread in the project.
- With `--thread <threadId>`, only that thread can read the keys. Suggest this
  thread's id: it gives the smallest access.
- The user runs this in their own terminal, outside bb threads. The bb CLI
  reports the thread of the shell it runs in, so the plugin refuses the
  command from any thread's shell.

The user checks grants with `bb murk grant list`, which shows each grant's
scope, keys, expiry, and reveal status. To close access early, the user runs
`bb murk grant revoke <id>`. To learn what you can read, call murk_get: it
delivers the key or fails closed.

If a mint fails because the vault is in the pre-0.14 format, tell the user and
stop. A mint would make the vault's first 0.14 save, which rewrites `.murk` on
the current branch. The user decides whether to upgrade the vault on the
default branch first or to mint with `--upgrade` here. Never pass `--upgrade`
yourself. Never write to the vault to get around the refusal.

## Running commands that need secrets

Load the delivered file into the command's environment in a subshell. Do not
export the values into your shell session:

```bash
( set -a; . "$FILE"; set +a; ./migrate.sh )   # FILE: the path from the murk_get result
```

**Never dump the environment under anything that injects secrets.** After you
load the delivered file, and inside `murk exec`, `murk agent exec`, or any
other wrapper that injects secrets, do not run `env`, `printenv`, `set`,
`export -p`, `declare -x`, or any other command that prints environment
variables. To check that a variable is set, test it without printing it:
`test -n "$KEY" && echo set`.

## Do not run murk yourself

Do not read secrets by running `murk` yourself, and that includes
`murk agent exec`. Use murk_get.

Every thread starts as a murk agent context: `MURK_AGENT=1`, `MURK_KEY` blank,
and `MURK_KEY_FILE` set to a path that cannot exist. Grant identities live
only as 0600 files in the plugin's data directory, so this thread holds no
key. murk in an agent context never uses the user's personal key in
`~/.config/murk/keys`.

So any `murk` command that needs a key fails closed. The error is
`cannot read MURK_KEY_FILE`, or `MURK_KEY and MURK_KEY_FILE are both set` if
something filled in `MURK_KEY`. `--allow-operator-key` does not change that.
It only lets `agent exec` use a personal key that murk has already found, and
murk finds none here.

That is by design. Do not unset or change those variables. Never point
`MURK_KEY_FILE` at anything under `~/.config/murk`. That decision belongs to
the user, not to you.

`agent exec` masks injected values in its output. Masking guards against
accidents. It is not permission to print: an encoded or partial value gets
through. Use the delivered dotenv file instead.
