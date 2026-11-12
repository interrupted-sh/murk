---
title: What each approach protects against
description: Env injection, a credential broker and a separate OS user give an AI agent secrets in different ways. What each one stops, and what it does not.
sidebar:
  order: 13
---

There are three common ways to let an AI agent use a secret. They protect
against different things, and they combine. This page says what each one
stops and what it leaves open, and where murk fits.

## Env injection

The agent runs a command, and the secret goes into that command's
environment. In murk this is `murk agent exec --only KEY -- CMD`, or the MCP
`murk_exec` tool.

**What it protects against:**

- The value never appears in the prompt, and the agent does not have to read
  it to use it.
- The command gets only the keys you name. With a grant key, murk cannot
  decrypt any other key.
- murk masks the injected values in the command's stdout and stderr, so an
  `env` dump does not land in the transcript as plaintext.

**What it does not protect against:**

- The value reaches the command in plaintext. murk decides which values a
  command gets, not what the command does with them. A command can write a
  value to a file, send it over the network, or print it encoded.
- Masking matches exact bytes only. A base64, hex, partial or split copy gets
  through. See [Output masking](/guides/ai-agents-mcp/#output-masking).
- The MCP `murk_get` tool returns the value to the model itself. It ends up
  in the transcript.

## A credential broker

A broker holds the secret and makes the authenticated call itself, for
example an HTTP request with an API token. The agent asks the broker to act
and gets the result. It never holds the value.

**What it protects against:**

- The agent cannot leak a value it never had. A prompt injection cannot make
  it print the token.
- The broker can limit which calls the agent may make, not only which
  secrets it may use, and it can log each call.

**What it does not protect against:**

- The broker must support each kind of call. A tool that expects the secret
  in its own environment, such as a database client or a migration script,
  cannot use it without the value.
- The agent can still misuse the calls it is allowed to make.

murk is not a broker and does not plan to become one. If you need the agent
never to hold the value, use a broker. murk can still be the team's store
underneath it: the broker reads its credentials with its own grant key.

## A separate OS user or a container

The agent runs as another user, or in a container, where your key directory
does not exist or cannot be read.

**What it protects against:**

- The agent cannot reach your own murk key. The grant key is the only murk
  key present, so the grant's scope becomes a real boundary.
- Combined with env injection, a compromised agent reads at most the keys in
  its grant.
- The operating system enforces it, not murk.

**What it does not protect against:**

- It costs setup: a user or an image, a checkout, and a key file to hand
  over. [Agent isolation](/guides/agent-isolation/) has tested recipes.
- The agent still holds the grant key and the values it is given.

## murk's own limits

These hold whichever approach you use with murk:

- **Expiry is enforced by murk, not by cryptography.** murk refuses a
  grant past its expiry on every read. Raw age still decrypts the current
  vault file with the grant key until the next vault write removes the grant,
  and old vault versions in git stay readable. Revoke and rotate to close
  access.
- **No read log.** murk records vault changes in git. It does not record who
  read a secret, or when.
- **Static secrets only.** murk stores values. It does not issue short-lived
  credentials or rotate them at the provider.
- **Same-user agents can reach your key.** In murk 0.14, an agent that runs as
  your user can read `~/.config/murk/keys`. It can also unset `MURK_AGENT`,
  `MURK_STRICT`, `MURK_KEY` and `MURK_KEY_FILE` so that murk finds your stored
  key. A change to that lookup is planned for 0.16. Until then, a separate user
  or a container is the boundary.

## Summary

| | Env injection (murk) | Broker | Separate user or container |
|---|---|---|---|
| Value kept out of the prompt | Yes (`agent exec`, `murk_exec`) | Yes | No effect on its own |
| Agent never holds the value | No | Yes | No |
| Agent cannot reach your own key | Only with isolation | Depends on where the broker runs | Yes |
| Works with any tool that reads env vars | Yes | No | Yes |
| Setup | Low | A broker per kind of call | A user or an image |

See also [AI agents & MCP](/guides/ai-agents-mcp/) and
[Is murk right for you?](/suitability/).
