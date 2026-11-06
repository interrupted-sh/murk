---
title: Is murk right for you?
description: "Who murk is for, who should use SOPS or Vault instead, and what the 0.x public beta does and does not promise."
---

murk is a public beta (the 0.x line) for developer and team secrets. It has
not been independently audited. Read the [threat model](/security/threat-model/)
to see what it protects before you use it. This page helps you decide whether
murk fits your situation, points you elsewhere when it does not, and states
what the beta promises.

For a feature-by-feature comparison with SOPS, Vault, dotenvx, and git-crypt, see
the table on the [overview](/). This page is about your situation.

## Suitability at a glance

| Your situation | Use murk? | Why, or what to use instead |
|---|---|---|
| Solo dev or small team keeping secrets out of git and synced through the repo | Yes | This is the core use case: one key, one committed `.murk` file, readable key names so diffs stay meaningful. |
| Onboarding and offboarding teammates with age or SSH keys | Yes | Each teammate has their own key, with no shared password. `murk circle` adds and revokes recipients. `murk rotate` reissues secrets after someone leaves. |
| Giving an AI agent or CI job scoped access to specific secrets without sharing your key | Yes (experimental, a guardrail) | `murk agent exec` and grants inject only the named keys and fail closed. An agent running as your user can drop agent mode and reach your stored key, so the grant is a real boundary only under a separate OS user or in a container. See [AI agents & MCP](/guides/ai-agents-mcp/) and [Agent protection compared](/guides/agent-protection-compared/). |
| Application and CI configuration secrets loaded through your shell | Yes | Works with [direnv](/guides/direnv/). murk is a single binary with no runtime to install. |
| You want dynamic credentials or server-driven rotation | No | murk stores static secrets in a file. An agent grant is a key with murk-enforced expiry that reads static secrets. Use HashiCorp Vault or a cloud secrets manager. |
| You need provable access control and audit logs for compliance (SOC 2, PCI, HIPAA) | Not yet | murk's only audit trail is git history, and murk is not independently audited. Use Vault. |
| You need cloud-KMS or network-HSM-backed keys, or central policy-driven access control | No | Use Vault or a cloud KMS. murk keys live on your machine or in a hardware token (through [age plugins](/guides/hardware-keys/)). Every ordinary recipient can read shared values. Named groups, private values (`--group me`) and agent grants narrow who reads a secret, but no central server enforces policy or logs reads. |
| You want the broadest KMS backend support and the largest ecosystem today | Consider SOPS | SOPS is the closest alternative, with more backends and a bigger community. |

## The 0.x release contract

"Public beta" is a specific promise. This section states what it covers.

**What murk is.** murk is a git-native secrets tool for developers, built on
[age](https://age-encryption.org/). It uses one key on your machine and one
encrypted file in your repo, with no server and no runtime. It is meant for
real secrets today.

**What the 0.x line already gives you:**

- age encrypts the values, and key names stay readable.
- Per-recipient encryption. A revoked teammate cannot read values written after
  the revoke. They keep what they could already read in git history, so rotate
  those secrets.
- Tamper evidence. Writers sign the vault with Ed25519, from an age key or an
  `ssh-ed25519` key. Each machine checks the signer against a trust it
  recorded locally, and a signed vault that was altered fails to load.
  Hardware and `ssh-rsa` keys cannot sign. They load an unsigned vault with a
  warning, unless this machine has already accepted that vault signed, so sign
  your git commits too. See the [threat model](/security/threat-model/).
- A documented, tested vault format.
- Attested releases (SLSA Build L2), with reproducible Linux and Windows x86-64
  builds, that you can [verify](/security/verifying/).
- A private channel for reporting vulnerabilities
  ([SECURITY.md](https://github.com/interrupted-sh/murk/blob/main/SECURITY.md)).

**What murk deliberately does not claim yet.** No independent security audit
has been completed. murk makes no promises beyond what the
[threat model](/security/threat-model/) states. The table above covers
regulated use, dynamic credentials and automatic rotation.

**What changes at 1.0.** 1.0 is a trust milestone. The features are in place,
and 1.0 adds validation and stability. It ships only when all of the gates on
the [roadmap](/roadmap/#toward-10) hold.

If you are unsure whether murk fits, read the [threat model](/security/threat-model/)
first: it states exactly what murk protects and what it does not.
