---
title: Hardware keys (YubiKey)
description: Back murk with a hardware security key.
sidebar:
  order: 6
---

:::caution[Experimental]
Hardware and plugin identities are experimental. No test runs a real plugin yet, once a plugin recipient exists every writer needs the plugin installed, and plugin identities have no BIP39 recovery phrase.
:::

By default, `murk init` generates an age key and stores it under
`~/.config/murk/keys/`. That is fine for development, but the private key
is then plaintext bytes on disk. Anyone who can read the file can decrypt
everything that the key is authorized for.

murk has no "yubikey" flag or subcommand. Instead, it supports **age plugin
identities**. In this guide, a hardware key is such an identity. Point
`MURK_KEY_FILE` at the identity file of the hardware key. With the YubiKey,
Secure Enclave and OpenPGP card plugins, the private key stays on the
device. murk uses the [age plugin
mechanism](https://github.com/FiloSottile/age#plugins) of the wider age
ecosystem, so every plugin that implements it works with murk.

| Hardware | Plugin |
| --- | --- |
| YubiKey 4 and 5 | [`age-plugin-yubikey`](https://github.com/str4d/age-plugin-yubikey) |
| Apple Secure Enclave (Touch ID) | [`age-plugin-se`](https://github.com/remko/age-plugin-se) |
| OpenPGP card (YubiKey, Nitrokey) | [`age-plugin-openpgp-card`](https://crates.io/crates/age-plugin-openpgp-card) |
| FIDO2 key with `hmac-secret` (experimental; the identity is held in memory while decrypting) | [`age-plugin-fido2-hmac`](https://github.com/olastor/age-plugin-fido2-hmac) |

## Example: setting up a YubiKey

```bash
# 1. Install the plugin. murk runs it to encrypt and to decrypt, so it must
#    be on $PATH.
brew install age-plugin-yubikey

# 2. Generate an identity bound to the YubiKey. Prompts for the PIV PIN
#    and a touch. --touch-policy always asks for a tap on every decrypt.
#    --pin-policy once asks for the PIN once per session.
mkdir -p ~/.config/murk
age-plugin-yubikey --generate --touch-policy always --pin-policy once \
  > ~/.config/murk/yubikey.txt

# murk refuses identity files readable by others
chmod 600 ~/.config/murk/yubikey.txt

# 3. With your current key, authorize the YubiKey's public key.
murk circle authorize "$(grep -i recipient ~/.config/murk/yubikey.txt | awk '{print $NF}')" --name yubikey

# 4. Switch to the YubiKey. Add these lines to your shell profile or .envrc.
#    murk refuses to run when both variables are set.
unset MURK_KEY
export MURK_KEY_FILE=~/.config/murk/yubikey.txt

# 5. Read a secret. The YubiKey blinks; tap it to decrypt.
murk get SOME_KEY
```

:::caution
A new YubiKey has the default PIV PIN `123456`. When `age-plugin-yubikey`
finds the default PIN, it asks you to change it, and it sets the PUK to the
same value. Choose a PIN that is not easy to guess. See the [plugin's
documentation](https://github.com/str4d/age-plugin-yubikey#readme).
:::

Authorize first, then switch. When `MURK_KEY_FILE` points at the YubiKey,
murk uses only that identity. That identity is not a recipient yet, so
`murk circle authorize` would fail. murk does not read `.env`, so the export
must reach your shell.

The identity file has a `#    Recipient: age1yubikey1...` header, then an
`AGE-PLUGIN-YUBIKEY-1...` line. murk reads your public key from the header
and does not call the plugin for it. murk runs the plugin each time it
encrypts to a hardware key or decrypts with one.

Every write re-encrypts the vault metadata to all recipients. So when a
vault has a hardware key as a recipient, every teammate who writes to it
needs the plugin installed, whatever kind of key they use. Teammates with
software keys can read without the plugin.

Each command decrypts the vault metadata and each secret that you can read
as separate operations, and each operation runs the plugin. So with
`--touch-policy always`, one command can ask for more than one tap. The
number of taps and how long the PIN stays cached depend on the plugin and
the device. This guide has not measured them. Try a few commands with your
own key before you depend on it.

Adding the YubiKey does not remove your software key. It is still a
recipient, its file is still in `~/.config/murk/keys/`, and its recovery
words still recreate it. Anyone who can read that file can still decrypt the
vault. To complete the move, first enroll and test a backup device (see
below). Then revoke the old key with `murk circle revoke <name> --rotate`
(`murk circle` lists the names) and delete its key file. The old key can
still decrypt every earlier version of `.murk` in git history, so also change
the secrets at their provider.

The same steps apply to the other plugins in the table. Generate an identity
file with the plugin's own CLI. Authorize the public key that it prints with
your current key. Then point `MURK_KEY_FILE` at the identity file.

## Errors

If the plugin binary is not on `$PATH`, murk fails with an
`age-plugin-<name> unavailable` error. Install the plugin and try again.

`MURK_KEY` (the inline variable, not `MURK_KEY_FILE`) rejects
`AGE-PLUGIN-...` strings. A bare plugin line does not contain the recipient
public key that murk needs. So a hardware key works only through
`MURK_KEY_FILE`, pointed at the identity file.

## No BIP39 recovery for hardware keys

The raw bytes of a hardware key never leave the device, so there are no bytes
to encode as a recovery phrase. `murk recover` fails on hardware keys (and
on SSH keys). `murk restore` does not look at your current identity. It turns
a phrase back into the age key that the phrase encodes. That key has no
connection to your hardware key.

For a hardware key, recovery works differently. **Enroll a second hardware
device at setup, and add both public keys as recipients**
(`murk circle authorize <backup-pubkey>`). If you lose one device, the backup
still decrypts. Treat it as you treat a backup SSH key or a spare security
key for another account. Set it up before you need it, not after you lose the
primary device.

## Signing implications

age keys and `ssh-ed25519` keys sign the vault when they write it. Hardware
keys and `ssh-rsa` keys cannot sign, because age gives no signing scalar for
them. So a write with a hardware key leaves the vault unsigned.

What happens next depends on the key that loads the vault:

- A hardware or `ssh-rsa` key loads an unsigned vault with a warning.
  `murk verify` reports the unsigned vault as a finding.
- An age or `ssh-ed25519` key refuses an unsigned vault, because anyone with
  write access to the repository could have made it.
- Any machine that sets `MURK_TRUSTED_SIGNERS` refuses an unsigned vault,
  whatever its key.

A team that uses only hardware keys never makes a signature. Signed git
commits are then the integrity anchor. Do not set `MURK_TRUSTED_SIGNERS` in
such a team, because murk would then refuse every vault. See the [threat
model](/security/threat-model/) for the full signing rules.

### Mixed teams

If some teammates sign and some do not, the unsigned writes reach the
machines of the signing teammates, and those machines refuse them. To accept
the change of a hardware-key teammate, a signing teammate reviews it
(`git log -p -- .murk`, and `murk diff ORIG_HEAD` right after a pull) and runs:

```bash
murk trust
```

`murk trust` re-signs the vault with their key. That is a save, so they
commit and push the result. After that, the machines of the signing
teammates load the vault again. Review the change carefully. The new
signature vouches for the whole file, including recipient changes.

A hardware or `ssh-rsa` machine that last accepted this vault signed refuses
it once when it becomes unsigned ("signed when this machine last accepted
it"). Review it the same way. `murk trust` on that machine cannot sign. So it
accepts the vault and forgets that it saw a signed version. Later unsigned
loads then give only the warning.

## Choosing `MURK_KEY` vs `MURK_KEY_FILE`

Setting `MURK_KEY` to a raw `AGE-SECRET-KEY-1...` string works, but then the
key is plaintext in your environment or your `.env`. Prefer `MURK_KEY_FILE`.
Point it at a file under `~/.config/murk/keys/` (the `murk init` default,
fine for development) or at a hardware key's identity file (recommended for
production). Set only one of the two. murk refuses to run when both are
non-empty, and it treats an empty value as unset. See [environment
variables](/concepts/env-vars/) for the full list of variables that murk
reads.
