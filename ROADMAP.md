# Roadmap

murk is pre-1.0. This roadmap describes the direction for roughly the next year. murk has one maintainer, so nothing here has a date or a promise attached. The 1.0 gates below are the target. Priorities shift with real usage.

murk is a public beta (the 0.x line) for developer and team secrets. It has not been independently audited. Read [THREAT_MODEL.md](THREAT_MODEL.md) to see what it protects before you use it.

## Toward 1.0

1.0 is a trust milestone. The features are in place, and 1.0 adds validation and stability. Those features are the encrypted single-file vault, per-recipient encryption, scoped agent access over MCP, team management, and BIP39 recovery. 1.0 ships when all of these hold:

- Vault-format stability: 1.x reads every 0.x vault. Any format change ships with a documented, tested migration.
- External security review: an independent review of the age recipient management and grant-scope enforcement, with findings published and addressed. This is planned. Work has not started.
- Continuous fuzzing: OSS-Fuzz onboarding, beyond the current nightly in-repo fuzz run. This is planned.
- SLSA Build L3 provenance: up from the current attested (L2) releases. Every GitHub release archive from 0.3.1 on carries Sigstore build provenance, and the crates.io package is attested from 0.13.0 (see [VERIFYING.md](VERIFYING.md)).
- Soak: several months of the current 0.x line in real use with no vault-format change and no critical security fix.
- Migration and policy docs: an upgrade guide, an MSRV policy, and a deprecation policy.

## Later

- Secret versioning (`murk history`, `murk rollback`)
- Access logging
- First-class environment separation (dev/staging/prod)
- Nix flake, Debian packages

## Non-goals

These are deliberate boundaries:

- Centralized secrets server (use HashiCorp Vault)
- Custom cryptographic primitives (murk uses age)
- Fine-grained cryptographic access control (all recipients can read shared secrets by design). See [grants](https://murk.interrupted.sh/concepts/grants/) for the scoped-access model that does exist.
- Regulated/compliance environments (no audit trail beyond git, no provable access controls)
- Algorithm agility (age uses a fixed suite by design)
