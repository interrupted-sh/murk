---
title: Shared, group and private secrets
description: When to use shared secrets, group secrets and private per-user values.
sidebar:
  order: 1
---

A secret in a `.murk` vault has one of three tiers. The tier decides who can
decrypt it:

- **Shared**: every recipient except agent grants.
- **Group**: the members of one named group.
- **Private** (`me`): only you. A private value overrides the shared or group
  value of the same key for you.

The tier is the main decision you make when you add a secret.

## Shared secrets

murk encrypts a shared secret to every recipient except agent grants (see
[Grants](/concepts/grants/)). A new key that you add with `murk add KEY` is
shared, so every authorized teammate can decrypt it. When you update an
existing key without `--group`, it stays in its tier. Use the shared tier
for production credentials, third-party API keys and other secrets for the
whole team.

```bash
# Everyone sees this (prompts for value, hidden input)
murk add DATABASE_URL
```

## Group secrets

A group secret is encrypted only to the members of one named group. Groups
are experimental. Create the group, add its members, then add the secret to
it:

```bash
murk group create ops
murk group add ops --member bob@example.com
murk add STRIPE_KEY --group ops
```

A key's value is either shared or in one group. `murk add KEY --group NAME`
on a shared key moves it into the group. A recipient who is not a member
cannot read it, and an agent grant cannot read it. See [working in
teams](/guides/teams/#listing-and-managing-recipients) for how to list,
change and sign group membership.

## Private secrets

A private secret is encrypted only to your key. It is in a reserved personal
group named `me`. When you run `murk add KEY --group me`, murk encrypts the
value so that only you can decrypt it. No other recipient can read it, even
one with full vault access.

During `murk export`, `murk exec` and `murk get`, your private value overrides
the shared or group value of the same key. So you can point `DATABASE_URL`
at a local database while the rest of the team uses the shared production
value. Your export does not change the value that anyone else gets.

```bash
# Only you see this; it overrides the shared value during export
murk add DATABASE_URL --group me
```

You can also pipe a value in for scripting. Use a command that does not
write the value to your shell history:

```bash
pbpaste | murk add DATABASE_URL
```

## Choosing between them

- **Shared**: a value that the whole team needs, such as production API
  keys, shared database URLs and third-party service credentials.
- **Group**: a value that only part of the team may read, such as a payment
  provider key for the people who run operations.
- **Private**: a value that is different for each developer or only for
  you, such as a local database URL, a personal API token, or a value that no
  other recipient may read.

Tiers do not change who is authorized on the vault. That is the recipient
list, which you manage with `murk circle` (see [working in
teams](/guides/teams/)). Tiers add encryption *within* the vault, on top of
the recipient list. See [how murk's vault format
works](/concepts/vault-format/) for the details of the file, and the [`murk
add`](/reference/cli/#murk-add) reference for all the flags.

Tags and descriptions in the schema do not restrict anyone. Every recipient
except an agent grant can decrypt every shared secret. To limit a secret to
part of the team, put it in a group (`--group NAME`). To keep it to
yourself, use `--group me`.
