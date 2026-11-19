# SPDX-FileCopyrightText: murk contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""The experimental write API: ``Vault.add``, ``Vault.describe`` and ``murk.add``.

It mirrors the Node binding's. Every write is checked from disk and through
the CLI, so a value that only lives in the handle does not pass.
"""

import inspect
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import murk

MURK_BIN = Path(__file__).resolve().parents[2] / "target" / "release" / "murk"


@pytest.fixture()
def vault(vault_dir, monkeypatch):
    """The ``vault_dir`` vault plus a ``backend`` group, with the key set."""
    for var in ("MURK_KEY_FILE", "MURK_AGENT", "MURK_SELF_SCOPE", "MURK_VAULT"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("MURK_KEY", vault_dir["key"])
    monkeypatch.chdir(vault_dir["path"])
    path = Path(vault_dir["path"]) / ".murk"

    def cli(*args, stdin="", check=True):
        return subprocess.run(
            [str(MURK_BIN), *args, "--vault", ".murk"],
            input=stdin,
            capture_output=True,
            text=True,
            cwd=vault_dir["path"],
            env={**os.environ, "NO_COLOR": "1"},
            check=check,
        )

    cli("group", "create", "backend")

    def tiers(key):
        """Base tiers of a key in the file: (has shared value, group names, has scoped)."""
        entry = json.loads(path.read_text())["secrets"][key]
        return (
            bool(entry.get("shared")),
            sorted(entry.get("grouped") or {}),
            bool(entry.get("scoped")),
        )

    def schema(key):
        return json.loads(path.read_text())["schema"][key]

    class V:
        pass

    v = V()
    v.path, v.cli, v.tiers, v.schema = path, cli, tiers, schema
    return v


def cli_get(v, key):
    """The value `murk get` prints, without its trailing newline."""
    return v.cli("get", key).stdout.removesuffix("\n")


class TestAdd:
    def test_add_stores_a_shared_secret(self, vault):
        handle = murk.load()
        handle.add("SHARED_TOKEN", "shared-value")

        assert cli_get(vault, "SHARED_TOKEN") == "shared-value"
        assert vault.tiers("SHARED_TOKEN") == (True, [], False)
        # The handle refreshes its own snapshot.
        assert handle.get("SHARED_TOKEN") == "shared-value"
        assert "SHARED_TOKEN" in handle

    def test_add_records_desc_and_tags(self, vault):
        murk.load().add("TAGGED", "tagged-value", desc="a tagged token", tags=["agents"])

        assert cli_get(vault, "TAGGED") == "tagged-value"
        assert vault.schema("TAGGED")["description"] == "a tagged token"
        assert vault.schema("TAGGED")["tags"] == ["agents"]

    def test_add_stores_a_personal_secret(self, vault):
        murk.load().add("PERSONAL", "my-value", tier="me")

        assert cli_get(vault, "PERSONAL") == "my-value"
        assert vault.tiers("PERSONAL") == (False, [], True)

    def test_add_stores_a_group_secret(self, vault):
        murk.load().add("GROUP_SECRET", "group-value", tier="backend")

        assert cli_get(vault, "GROUP_SECRET") == "group-value"
        assert vault.tiers("GROUP_SECRET") == (False, ["backend"], False)

    def test_add_without_a_tier_keeps_a_group_key_in_its_group(self, vault):
        handle = murk.load()
        handle.add("GROUP_DB", "old", tier="backend")
        handle.add("GROUP_DB", "new")

        assert cli_get(vault, "GROUP_DB") == "new"
        assert vault.tiers("GROUP_DB") == (False, ["backend"], False)

    @pytest.mark.parametrize(
        ("alias", "stored"),
        [
            ("all", (True, [], False)),
            ("shared", (True, [], False)),
            ("self", (False, [], True)),
            ("mine", (False, [], True)),
        ],
    )
    def test_reserved_tier_aliases_route_like_the_cli(self, vault, alias, stored):
        # A mapping regression would treat the alias as a group name and fail
        # with "group not found".
        key = f"ALIAS_{alias.upper()}"
        murk.load().add(key, f"{alias}-value", tier=alias)

        assert cli_get(vault, key) == f"{alias}-value"
        assert vault.tiers(key) == stored

    def test_add_to_an_unknown_group_raises_and_writes_nothing(self, vault):
        before = vault.path.read_bytes()
        with pytest.raises(RuntimeError, match="group not found") as exc:
            murk.load().add("NOPE", "x", tier="no-such-group")
        assert not isinstance(exc.value, murk.TrustError)
        assert vault.path.read_bytes() == before

    def test_add_rejects_an_invalid_key_name(self, vault):
        before = vault.path.read_bytes()
        with pytest.raises(RuntimeError, match="invalid key name: 1BAD"):
            murk.load().add("1BAD", "x")
        assert vault.path.read_bytes() == before

    def test_add_refuses_text_that_could_forge_output(self, vault):
        handle = murk.load()
        with pytest.raises(RuntimeError, match=r"schema\.SPOOF\.description: contains control"):
            handle.add("SPOOF", "x", desc="ok\rforged")
        with pytest.raises(RuntimeError, match=r"schema\.SPOOF\.tags\[0\]: contains invisible"):
            handle.add("SPOOF", "x", tags=["a\u202eb"])
        assert "SPOOF" not in murk.load()

    def test_reserved_env_name_is_stored_without_a_warning(self, vault, capfd):
        # Like the Node binding: no warning and no refusal on write. The CLI
        # still refuses to inject the name.
        murk.load().add("PATH", "/evil/bin")

        assert capfd.readouterr().err == ""
        assert cli_get(vault, "PATH") == "/evil/bin"
        export = vault.cli("export", check=False)
        assert export.returncode != 0
        assert "refusing to set PATH" in export.stderr


class TestOneLiner:
    def test_add_one_liner_stores_a_secret(self, vault):
        murk.add("ONELINER", "oneliner-value")
        assert cli_get(vault, "ONELINER") == "oneliner-value"

    def test_add_one_liner_takes_a_path_and_options(self, vault, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        murk.add("ONELINER_ME", "mine", str(vault.path), tier="me", tags=["agents"])

        assert cli_get(vault, "ONELINER_ME") == "mine"
        assert vault.tiers("ONELINER_ME") == (False, [], True)
        assert vault.schema("ONELINER_ME")["tags"] == ["agents"]


class TestHandlePath:
    def test_a_relative_path_keeps_naming_the_vault_it_loaded(self, vault, tmp_path, monkeypatch):
        # A second vault the same key opens, in another directory.
        other = tmp_path / "other"
        other.mkdir()
        subprocess.run(
            [str(MURK_BIN), "init", "--vault", ".murk"],
            input="testuser\n",
            capture_output=True,
            text=True,
            cwd=other,
            check=True,
        )
        other_before = (other / ".murk").read_bytes()

        handle = murk.load(".murk")
        monkeypatch.chdir(other)
        handle.add("WHERE", "meant-for-the-first")
        handle.describe("WHERE", "described on the first")

        assert (other / ".murk").read_bytes() == other_before
        assert cli_get(vault, "WHERE") == "meant-for-the-first"
        assert vault.schema("WHERE")["description"] == "described on the first"


@pytest.mark.skipif(sys.platform == "win32", reason="holds the vault lock with fcntl")
class TestLockWait:
    def test_a_write_waiting_for_the_lock_lets_other_threads_run(self, vault):
        # This thread holds the vault lock while a writer thread waits for it.
        # Releasing it needs the GIL, so a writer that waits with the GIL held
        # never finishes. The child process keeps a hang out of the test run.
        script = textwrap.dedent(
            """
            import fcntl, threading, time
            import murk

            handle = murk.load()
            lock = open(".murk.lock", "a")
            fcntl.flock(lock, fcntl.LOCK_EX)
            writer = threading.Thread(target=handle.add, args=("WAITED", "after-the-lock"))
            writer.start()
            time.sleep(0.5)
            fcntl.flock(lock, fcntl.LOCK_UN)
            writer.join()
            print("done")
            """
        )
        try:
            child = subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True,
                text=True,
                cwd=vault.path.parent,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            pytest.fail("the write held the GIL while it waited for the vault lock")

        assert child.stdout == "done\n", child.stderr
        assert cli_get(vault, "WAITED") == "after-the-lock"


class TestDescribe:
    def test_describe_documents_a_key_without_a_value(self, vault):
        murk.load().describe("DOCUMENTED", "documented but unset", tags=["agents"], example="x")

        reloaded = murk.load()
        assert "DOCUMENTED" in reloaded
        assert reloaded.get("DOCUMENTED") is None
        entry = vault.schema("DOCUMENTED")
        assert (entry["description"], entry["tags"], entry["example"]) == (
            "documented but unset",
            ["agents"],
            "x",
        )
        assert vault.cli("get", "DOCUMENTED", check=False).returncode != 0

    def test_describe_keeps_the_value_and_clears_an_omitted_example(self, vault):
        handle = murk.load()
        handle.describe("API_KEY", "first", example="sk-...")
        handle.describe("API_KEY", "second")

        assert cli_get(vault, "API_KEY") == "sk-test-123"
        assert vault.schema("API_KEY")["description"] == "second"
        assert "example" not in vault.schema("API_KEY")

    def test_describe_refuses_invisible_text(self, vault):
        with pytest.raises(RuntimeError, match=r"schema\.SPOOF\.description: contains invisible"):
            murk.load().describe("SPOOF", "a\u200bb")
        assert "SPOOF" not in murk.load()


class TestSurface:
    """The options and defaults match the Node binding's AddOptions and DescribeOptions."""

    @staticmethod
    def params(fn):
        return [(p.name, p.kind, p.default) for p in inspect.signature(fn).parameters.values()]

    def test_vault_add_signature(self):
        kw, pos = inspect.Parameter.KEYWORD_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD
        empty = inspect.Parameter.empty
        assert self.params(murk.Vault.add) == [
            ("self", inspect.Parameter.POSITIONAL_ONLY, empty),
            ("key", pos, empty),
            ("value", pos, empty),
            ("tier", kw, None),
            ("desc", kw, None),
            ("tags", kw, None),
        ]

    def test_vault_describe_signature(self):
        kw, pos = inspect.Parameter.KEYWORD_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD
        empty = inspect.Parameter.empty
        assert self.params(murk.Vault.describe) == [
            ("self", inspect.Parameter.POSITIONAL_ONLY, empty),
            ("key", pos, empty),
            ("description", pos, empty),
            ("tags", kw, None),
            ("example", kw, None),
        ]

    def test_module_add_signature(self):
        kw, pos = inspect.Parameter.KEYWORD_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD
        empty = inspect.Parameter.empty
        assert self.params(murk.add) == [
            ("key", pos, empty),
            ("value", pos, empty),
            ("vault_path", pos, ".murk"),
            ("tier", kw, None),
            ("desc", kw, None),
            ("tags", kw, None),
        ]


class TestAgentWrites:
    def test_grant_key_cannot_write(self, agent_vault_dir, monkeypatch):
        path = Path(agent_vault_dir["vault"])
        before = path.read_bytes()
        monkeypatch.delenv("MURK_KEY_FILE", raising=False)
        monkeypatch.setenv("MURK_KEY", agent_vault_dir["agent_key"])

        for key, opts in [
            ("AGENT_WRITE", {"tier": "me", "tags": ["agents"]}),
            ("AGENT_WRITE", {"tier": "everyone", "tags": ["agents"]}),
            ("EXFIL", {"tags": ["prod"]}),
        ]:
            with pytest.raises(RuntimeError, match="agent grants are read-only"):
                murk.add(key, "agent-authored", str(path), **opts)
        with pytest.raises(RuntimeError, match="agent grants are read-only"):
            murk.load(str(path)).describe("AGENT_DB", "changed", tags=["agents"])

        assert path.read_bytes() == before
        assert murk.get("AGENT_DB", str(path)) == "postgres://agent"
