# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Type stubs for the murk Python module."""

class TrustError(RuntimeError):
    """The vault was refused: not trusted on this machine, or tampered with."""

class Vault:
    @property
    def warnings(self) -> list[str]: ...
    def get(self, key: str) -> str | None: ...
    def export(self) -> dict[str, str]: ...
    def keys(self) -> list[str]: ...
    def add(
        self,
        key: str,
        value: str,
        *,
        tier: str | None = None,
        desc: str | None = None,
        tags: list[str] | None = None,
    ) -> None:
        """Experimental. Store a secret, like `murk add`.

        `tier` is "everyone", "me" or a group name. Without it, an existing
        secret keeps its tier and a new one is shared. Raises `TrustError`
        if this machine does not trust the vault, and `RuntimeError` for any
        other failure. Nothing is written when the call raises.
        """
    def describe(
        self,
        key: str,
        description: str,
        *,
        tags: list[str] | None = None,
        example: str | None = None,
    ) -> None:
        """Experimental. Set a secret's description, like `murk describe`.

        Non-empty `tags` replace the existing tags. Leaving out `example`
        clears it. The value is not touched. Raises as `add` does.
        """
    def __len__(self) -> int: ...
    def __getitem__(self, key: str) -> str: ...
    def __contains__(self, key: str) -> bool: ...
    def __repr__(self) -> str: ...

def load(vault_path: str = ".murk") -> Vault: ...
def get(key: str, vault_path: str = ".murk") -> str | None: ...
def export_all(vault_path: str = ".murk") -> dict[str, str]: ...
def add(
    key: str,
    value: str,
    vault_path: str = ".murk",
    *,
    tier: str | None = None,
    desc: str | None = None,
    tags: list[str] | None = None,
) -> None:
    """Experimental. Load the vault and store a secret. See `Vault.add`."""
def has_identity() -> bool: ...
