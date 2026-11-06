---
title: Changelog
description: Release history for murk and how releases are versioned.
sidebar:
  order: 2
---

The authoritative, per-version changelog lives on the GitHub releases page:

- [github.com/interrupted-sh/murk/releases](https://github.com/interrupted-sh/murk/releases)

This page does not mirror the notes. A copy here would go stale between
builds, so this page points at that single source.

## Reading the release notes

Read a release's notes before you upgrade across a minor version. The notes
for 0.14.0 and 0.14.1 open with hand-written sections, above the list of
changes. Those sections hold the upgrade steps ("Upgrade first" in 0.14.0,
"Upgrade notes" in 0.14.1), any breaking changes, and the known limits.

Every release's notes end with a list of changes. It is generated from the
commit subjects at tag time (via [git-cliff](https://git-cliff.org/), grouped
by [conventional-commit](https://www.conventionalcommits.org/) type).

## Versioning

murk is pre-1.0 and uses [Semantic Versioning](https://semver.org/). Before
1.0, a minor bump (0.13 to 0.14) may break compatibility. Patch bumps are
fixes and additions.

A newer murk reads vaults written by older 0.x versions, but a vault written by
a newer murk may not open in an older one. For example, murk 0.14 changed the
vault format to 3.0, and murk 0.13 cannot read a 3.0 vault. The
[roadmap](/roadmap/) lists the format guarantee 1.0 will add.

## Installing a specific version of the CLI

Pick a version from the releases page, then install it:

```bash
cargo install murk-cli --version X.Y.Z
```

To pin the separate Python library instead, run
`pip install murk-secrets==X.Y.Z`. It does not include the CLI.

Pre-built binaries for each release are attached to its GitHub release. Recent
releases carry signed build provenance on every channel (the crates.io package
from 0.13.0). See [verifying releases](/security/verifying/) for what each
version has and how to check it before you trust a downloaded artifact.
