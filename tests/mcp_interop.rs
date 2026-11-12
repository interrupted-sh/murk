// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Real MCP-client interop test: drives `murk mcp` with the official rmcp
//! client (not hand-crafted JSON-RPC) to prove a real client can connect,
//! handshake, list tools, and call tools — with scope enforcement holding
//! over the real transport.

mod common;
use common::{MURK_CONTEXT_VARS, init_vault, murk};

use rmcp::{
    RoleClient, ServiceExt,
    model::{CallToolRequestParams, CallToolResult, ContentBlock},
    object,
    service::RunningService,
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use std::path::Path;
use std::process::Stdio;
use tokio::io::AsyncReadExt;
use tokio::process::{ChildStderr, Command};

/// `murk mcp` for the grant key at `grant` in `dir`, with `extra` flags, as a
/// connected rmcp client plus the server's stderr.
async fn start_server(
    dir: &Path,
    grant: &Path,
    extra: &[&str],
) -> (RunningService<RoleClient, ()>, ChildStderr) {
    let cmd = Command::new(env!("CARGO_BIN_EXE_murk")).configure(|cmd| {
        for var in MURK_CONTEXT_VARS {
            cmd.env_remove(var);
        }
        cmd.arg("mcp")
            .args(["--vault", "test.murk"])
            .args(extra)
            .current_dir(dir)
            .env("HOME", dir)
            .env("XDG_RUNTIME_DIR", dir)
            .env("MURK_KEY_FILE", grant)
            .env("MURK_AGENT", "1");
    });
    let (transport, stderr) = TokioChildProcess::builder(cmd)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    (().serve(transport).await.unwrap(), stderr.unwrap())
}

/// Stop the server and return everything it wrote to stderr.
async fn stop_server(client: RunningService<RoleClient, ()>, mut stderr: ChildStderr) -> String {
    client.cancel().await.unwrap();
    let mut log = String::new();
    stderr.read_to_string(&mut log).await.unwrap();
    log
}

fn text(result: &CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(ContentBlock::as_text)
        .map(|t| t.text.as_str())
        .collect()
}

async fn get(client: &RunningService<RoleClient, ()>, key: &str) -> CallToolResult {
    client
        .call_tool(CallToolRequestParams::new("murk_get").with_arguments(object!({ "key": key })))
        .await
        .unwrap()
}

async fn plan(client: &RunningService<RoleClient, ()>) -> CallToolResult {
    client
        .call_tool(CallToolRequestParams::new("murk_plan").with_arguments(object!({})))
        .await
        .unwrap()
}

/// A vault with `API_KEY` (tags `agents`, `api`) and `OTHER_KEY` (tag
/// `agents`), and a grant `probe` for `API_KEY` under an `agents` policy.
/// Returns the operator key and the grant key file.
fn setup_grant(dir: &Path) -> (String, std::path::PathBuf) {
    let (key, _) = init_vault(dir);
    murk(dir, &key)
        .args(["add", "API_KEY", "--tag", "agents", "--tag", "api"])
        .args(["--vault", "test.murk"])
        .write_stdin("reload-secret\n")
        .assert()
        .success();
    murk(dir, &key)
        .args([
            "add",
            "OTHER_KEY",
            "--tag",
            "agents",
            "--vault",
            "test.murk",
        ])
        .write_stdin("other-secret\n")
        .assert()
        .success();
    let grant = dir.join("grant.key");
    murk(dir, &key)
        .args(["agent", "init", "--name", "probe", "--only", "API_KEY"])
        .args(["--allow-tag", "agents", "--out"])
        .arg(&grant)
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    (key, grant)
}

#[tokio::test]
async fn mcp_a_revoke_applies_to_the_next_call() {
    let dir = assert_fs::TempDir::new().unwrap();
    let (key, grant) = setup_grant(dir.path());
    let (client, stderr) = start_server(dir.path(), &grant, &[]).await;

    assert_eq!(text(&get(&client, "API_KEY").await), "reload-secret");

    murk(dir.path(), &key)
        .args(["agent", "revoke", "probe", "--vault", "test.murk"])
        .assert()
        .success();

    let after = get(&client, "API_KEY").await;
    assert_eq!(after.is_error, Some(true));
    assert!(!text(&after).contains("reload-secret"), "{}", text(&after));
    let plan = plan(&client).await;
    assert_eq!(plan.is_error, Some(true), "{}", text(&plan));
    assert!(!text(&plan).contains("API_KEY"), "{}", text(&plan));
    stop_server(client, stderr).await;
}

#[tokio::test]
async fn mcp_a_tightened_policy_applies_to_the_next_call() {
    let dir = assert_fs::TempDir::new().unwrap();
    let (key, grant) = setup_grant(dir.path());
    let (client, stderr) = start_server(dir.path(), &grant, &[]).await;

    assert_eq!(text(&get(&client, "API_KEY").await), "reload-secret");

    // API_KEY carries `agents` and `api`; a policy of only `other` forbids it.
    murk(dir.path(), &key)
        .args([
            "policy",
            "set",
            "--allow-tag",
            "other",
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    let after = get(&client, "API_KEY").await;
    assert_eq!(after.is_error, Some(true));
    assert!(text(&after).contains("policy forbids"), "{}", text(&after));
    assert!(!text(&plan(&client).await).contains("API_KEY"));
    stop_server(client, stderr).await;
}

#[tokio::test]
async fn mcp_a_tampered_or_unloadable_vault_fails_closed() {
    let dir = assert_fs::TempDir::new().unwrap();
    let (key, grant) = setup_grant(dir.path());
    murk(dir.path(), &key)
        .args(["describe", "API_KEY", "original description"])
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    let path = dir.path().join("test.murk");
    let original = std::fs::read_to_string(&path).unwrap();
    let (client, stderr) = start_server(dir.path(), &grant, &[]).await;
    assert_eq!(text(&get(&client, "API_KEY").await), "reload-secret");

    // Signed bytes edited by hand: the reload refuses them.
    assert!(original.contains("original description"));
    std::fs::write(
        &path,
        original.replace("original description", "tampered description"),
    )
    .unwrap();
    let tampered = get(&client, "API_KEY").await;
    assert_eq!(tampered.is_error, Some(true));
    assert!(
        text(&tampered).contains("refusing this call"),
        "{}",
        text(&tampered)
    );
    assert!(!text(&tampered).contains("reload-secret"));

    // A file that does not parse at all.
    std::fs::write(&path, "not a vault").unwrap();
    let garbage = get(&client, "API_KEY").await;
    assert_eq!(garbage.is_error, Some(true));
    assert!(
        text(&garbage).contains("refusing this call"),
        "{}",
        text(&garbage)
    );

    // A missing file.
    std::fs::remove_file(&path).unwrap();
    let missing = plan(&client).await;
    assert_eq!(missing.is_error, Some(true));
    assert!(
        text(&missing).contains("refusing this call"),
        "{}",
        text(&missing)
    );

    let log = stop_server(client, stderr).await;
    assert!(!log.contains("reloaded it"), "{log}");
}

#[tokio::test]
async fn mcp_reloads_only_when_the_vault_bytes_change() {
    let dir = assert_fs::TempDir::new().unwrap();
    let (key, grant) = setup_grant(dir.path());
    let path = dir.path().join("test.murk");
    let (client, stderr) = start_server(dir.path(), &grant, &[]).await;
    assert_eq!(text(&get(&client, "API_KEY").await), "reload-secret");

    // The same bytes written again (a new mtime) are not a change.
    std::fs::write(&path, std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(text(&get(&client, "API_KEY").await), "reload-secret");

    // A real write by the operator is, and the new value is served.
    murk(dir.path(), &key)
        .args(["add", "API_KEY", "--vault", "test.murk"])
        .write_stdin("rotated-secret\n")
        .assert()
        .success();
    assert_eq!(text(&get(&client, "API_KEY").await), "rotated-secret");
    assert_eq!(text(&get(&client, "API_KEY").await), "rotated-secret");

    let log = stop_server(client, stderr).await;
    assert_eq!(log.matches("reloaded it").count(), 1, "{log}");
}

#[tokio::test]
async fn mcp_reload_keeps_the_key_the_server_started_with() {
    let dir = assert_fs::TempDir::new().unwrap();
    let (key, grant) = setup_grant(dir.path());
    let other = dir.path().join("other.key");
    murk(dir.path(), &key)
        .args([
            "agent",
            "grant",
            "--name",
            "two",
            "--only",
            "OTHER_KEY",
            "--out",
        ])
        .arg(&other)
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    let (client, stderr) = start_server(dir.path(), &grant, &[]).await;
    assert_eq!(text(&get(&client, "API_KEY").await), "reload-secret");

    // The key file now holds another grant's key, and the vault changes so the
    // next call reloads. The reload must still open the vault as the first
    // grant, never as the key the file holds now.
    std::fs::copy(&other, &grant).unwrap();
    murk(dir.path(), &key)
        .args(["add", "NEW_KEY", "--vault", "test.murk"])
        .write_stdin("n\n")
        .assert()
        .success();

    assert_eq!(text(&get(&client, "API_KEY").await), "reload-secret");
    let other_key = get(&client, "OTHER_KEY").await;
    assert_eq!(other_key.is_error, Some(true), "{}", text(&other_key));
    assert!(!text(&other_key).contains("other-secret"));
    let log = stop_server(client, stderr).await;
    assert_eq!(log.matches("reloaded it").count(), 1, "{log}");
}

async fn exec(client: &RunningService<RoleClient, ()>, key: &str) -> CallToolResult {
    client
        .call_tool(
            CallToolRequestParams::new("murk_exec")
                .with_arguments(object!({ "only": [key], "command": ["printenv", key] })),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn mcp_a_revoke_applies_to_murk_exec_on_the_next_call() {
    let dir = assert_fs::TempDir::new().unwrap();
    let (key, grant) = setup_grant(dir.path());
    let (client, stderr) = start_server(dir.path(), &grant, &["--allow-exec"]).await;

    let before = exec(&client, "API_KEY").await;
    assert_ne!(before.is_error, Some(true), "{}", text(&before));
    assert!(text(&before).contains("***API_KEY***"), "{}", text(&before));

    murk(dir.path(), &key)
        .args(["agent", "revoke", "probe", "--vault", "test.murk"])
        .assert()
        .success();

    let after = exec(&client, "API_KEY").await;
    assert_eq!(after.is_error, Some(true), "{}", text(&after));
    assert!(
        text(&after).contains("refusing this call"),
        "{}",
        text(&after)
    );
    stop_server(client, stderr).await;
}

/// Assert that every tool refuses the call and leaks nothing of `API_KEY`.
async fn assert_all_tools_refuse(client: &RunningService<RoleClient, ()>, why: &str) {
    for result in [
        get(client, "API_KEY").await,
        exec(client, "API_KEY").await,
        plan(client).await,
    ] {
        assert_eq!(result.is_error, Some(true), "{}", text(&result));
        assert!(
            text(&result).contains("refusing this call"),
            "{}",
            text(&result)
        );
        assert!(text(&result).contains(why), "{}", text(&result));
        assert!(
            !text(&result).contains("reload-secret"),
            "{}",
            text(&result)
        );
        assert!(!text(&result).contains("API_KEY\""), "{}", text(&result));
    }
}

#[tokio::test]
async fn mcp_refuses_the_pre_revoke_vault_written_back() {
    let dir = assert_fs::TempDir::new().unwrap();
    let (key, grant) = setup_grant(dir.path());
    let path = dir.path().join("test.murk");
    let (client, stderr) = start_server(dir.path(), &grant, &["--allow-exec"]).await;
    assert_eq!(text(&get(&client, "API_KEY").await), "reload-secret");
    let pre_revoke = std::fs::read(&path).unwrap();

    murk(dir.path(), &key)
        .args(["agent", "revoke", "probe", "--vault", "test.murk"])
        .assert()
        .success();
    let revoked = get(&client, "API_KEY").await;
    assert_eq!(revoked.is_error, Some(true), "{}", text(&revoked));

    // The older, validly signed bytes that still hold the grant come back.
    std::fs::write(&path, &pre_revoke).unwrap();
    assert_all_tools_refuse(&client, "older than one this server already saw").await;
    // The refusal tells an operator who moved the vault back on purpose
    // (a branch switch, a restore) what to do.
    let hint = get(&client, "API_KEY").await;
    assert!(text(&hint).contains("restart murk mcp"), "{}", text(&hint));
    stop_server(client, stderr).await;
}

#[tokio::test]
async fn mcp_refuses_a_fork_and_still_reloads_a_newer_vault() {
    let dir = assert_fs::TempDir::new().unwrap();
    let (key, grant) = setup_grant(dir.path());
    let path = dir.path().join("test.murk");
    let pins = dir.path().join(".config/murk/signer-pins");
    let pins_copy = dir.path().join("pins-copy");
    let (client, stderr) = start_server(dir.path(), &grant, &["--allow-exec"]).await;
    assert_eq!(text(&get(&client, "API_KEY").await), "reload-secret");

    // Keep the vault and this machine's pin as they are, so a second save from
    // the same starting point gets the same save counter as the first.
    let base = std::fs::read(&path).unwrap();
    copy_dir(&pins, &pins_copy);
    let add = |name: &str, value: &str| {
        murk(dir.path(), &key)
            .args(["add", name, "--vault", "test.murk"])
            .write_stdin(format!("{value}\n"))
            .assert()
            .success();
    };
    add("FIRST", "1");
    assert_eq!(text(&get(&client, "API_KEY").await), "reload-secret");

    std::fs::write(&path, &base).unwrap();
    std::fs::remove_dir_all(&pins).unwrap();
    copy_dir(&pins_copy, &pins);
    add("SECOND", "2");
    assert_all_tools_refuse(&client, "a forked copy").await;

    // A save past the vault the server saw loads again.
    add("THIRD", "3");
    assert_eq!(text(&get(&client, "API_KEY").await), "reload-secret");
    let log = stop_server(client, stderr).await;
    assert_eq!(log.matches("reloaded it").count(), 2, "{log}");
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
    }
}

/// `contents` with a JSON edit applied (field order and layout may change,
/// which only matters to the signature where `edit` changes signed data).
fn edit_vault(contents: &str, edit: impl FnOnce(&mut serde_json::Value)) -> String {
    let mut vault: serde_json::Value = serde_json::from_str(contents).unwrap();
    edit(&mut vault);
    serde_json::to_string_pretty(&vault).unwrap()
}

#[tokio::test]
async fn mcp_an_unverified_newer_vault_never_raises_the_floor() {
    let dir = assert_fs::TempDir::new().unwrap();
    let (_key, grant) = setup_grant(dir.path());
    let path = dir.path().join("test.murk");
    let valid = std::fs::read_to_string(&path).unwrap();
    let (client, stderr) = start_server(dir.path(), &grant, &["--allow-exec"]).await;
    assert_eq!(text(&get(&client, "API_KEY").await), "reload-secret");

    let far_ahead = |v: &mut serde_json::Value| v["generation"] = 1_000_000_000_000_000u64.into();
    // Unsigned, and signed but edited (the signature no longer verifies).
    let unsigned = edit_vault(&valid, |v| {
        far_ahead(v);
        v.as_object_mut().unwrap().remove("sig");
    });
    let forged = edit_vault(&valid, far_ahead);
    for bad in [unsigned, forged] {
        std::fs::write(&path, bad).unwrap();
        assert_all_tools_refuse(&client, "refusing to read").await;

        // The valid bytes come back and serve: the bad file moved no floor.
        std::fs::write(&path, &valid).unwrap();
        assert_eq!(text(&get(&client, "API_KEY").await), "reload-secret");
    }
    stop_server(client, stderr).await;
}

#[tokio::test]
async fn mcp_refuses_another_vault_signed_by_the_same_operator() {
    let dir = assert_fs::TempDir::new().unwrap();
    let (_key, grant) = setup_grant(dir.path());
    // A second vault, made with the same operator key, so its signature
    // verifies under the grant's key file: only its id tells it apart.
    common::murk_bin(dir.path())
        .current_dir(dir.path())
        .args(["init", "--vault", "other.murk", "--reuse-key"])
        .write_stdin("testuser\n")
        .assert()
        .success();
    let path = dir.path().join("test.murk");
    let (client, stderr) = start_server(dir.path(), &grant, &["--allow-exec"]).await;
    assert_eq!(text(&get(&client, "API_KEY").await), "reload-secret");

    std::fs::copy(dir.path().join("other.murk"), &path).unwrap();
    assert_all_tools_refuse(&client, "the file is another vault").await;
    stop_server(client, stderr).await;
}

#[tokio::test]
async fn mcp_a_respelled_signer_is_the_same_vault() {
    let dir = assert_fs::TempDir::new().unwrap();
    let (_key, grant) = setup_grant(dir.path());
    let path = dir.path().join("test.murk");
    let valid = std::fs::read_to_string(&path).unwrap();
    let (client, stderr) = start_server(dir.path(), &grant, &["--allow-exec"]).await;
    assert_eq!(text(&get(&client, "API_KEY").await), "reload-secret");

    // An age recipient is case-insensitive and the signature does not cover
    // the signer's spelling, so this is the same signed vault, not a fork.
    let respelled = edit_vault(&valid, |v| {
        let signer = v["sig"]["signer"].as_str().unwrap().to_uppercase();
        v["sig"]["signer"] = signer.into();
    });
    std::fs::write(&path, respelled).unwrap();
    assert_eq!(text(&get(&client, "API_KEY").await), "reload-secret");
    std::fs::write(&path, &valid).unwrap();
    assert_eq!(text(&get(&client, "API_KEY").await), "reload-secret");
    stop_server(client, stderr).await;
}

#[tokio::test]
async fn mcp_a_refused_reload_of_the_loaded_bytes_keeps_refusing() {
    let dir = assert_fs::TempDir::new().unwrap();
    let (key, _) = init_vault(dir.path());
    murk(dir.path(), &key)
        .args(["add", "API_KEY", "--vault", "test.murk"])
        .write_stdin("latch-secret\n")
        .assert()
        .success();
    let grant = dir.path().join("grant.key");
    murk(dir.path(), &key)
        .args(["agent", "grant", "--name", "probe", "--only", "API_KEY"])
        .args(["--ttl", "4s", "--out"])
        .arg(&grant)
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    let path = dir.path().join("test.murk");
    let original = std::fs::read_to_string(&path).unwrap();
    let (client, stderr) = start_server(dir.path(), &grant, &[]).await;
    assert_eq!(text(&get(&client, "API_KEY").await), "latch-secret");

    // Refuse once, let the grant expire, and put the loaded bytes back: their
    // reload now fails (expired), and no later call may fall back to the state
    // loaded before the first refusal.
    std::fs::write(&path, "not a vault").unwrap();
    let refused = get(&client, "API_KEY").await;
    assert!(
        text(&refused).contains("refusing this call"),
        "{}",
        text(&refused)
    );
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    std::fs::write(&path, &original).unwrap();
    for _ in 0..2 {
        let again = get(&client, "API_KEY").await;
        assert_eq!(again.is_error, Some(true), "{}", text(&again));
        assert!(
            text(&again).contains("refusing this call: the vault could not be checked or reloaded"),
            "{}",
            text(&again)
        );
    }
    stop_server(client, stderr).await;
}

#[tokio::test]
async fn mcp_a_refused_reload_is_never_undone_by_the_cache() {
    let dir = assert_fs::TempDir::new().unwrap();
    let (key, grant) = setup_grant(dir.path());
    murk(dir.path(), &key)
        .args(["describe", "API_KEY", "original description"])
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    let path = dir.path().join("test.murk");
    let original = std::fs::read_to_string(&path).unwrap();
    let (client, stderr) = start_server(dir.path(), &grant, &["--allow-exec"]).await;
    assert_eq!(text(&get(&client, "API_KEY").await), "reload-secret");

    // A tampered file is refused for every tool.
    std::fs::write(
        &path,
        original.replace("original description", "tampered description"),
    )
    .unwrap();
    assert_all_tools_refuse(&client, "tampered with").await;

    // The original bytes come back. They must go through the full reload
    // again, not the cache of the state loaded before the refusal.
    std::fs::write(&path, &original).unwrap();
    assert_eq!(text(&get(&client, "API_KEY").await), "reload-secret");
    let ran = exec(&client, "API_KEY").await;
    assert_ne!(ran.is_error, Some(true), "{}", text(&ran));
    assert!(text(&plan(&client).await).contains("API_KEY"));
    let log = stop_server(client, stderr).await;
    assert_eq!(log.matches("reloaded it").count(), 1, "{log}");
}

#[tokio::test]
async fn mcp_exec_never_injects_a_reserved_name() {
    let dir = assert_fs::TempDir::new().unwrap();
    let (key, _) = init_vault(dir.path());
    let names = ["PATH", "KUBECONFIG", "xdg_config_home"];
    for name in names {
        murk(dir.path(), &key)
            .args(["add", name, "--vault", "test.murk"])
            .write_stdin("vault-chosen\n")
            .assert()
            .success();
    }
    let grant = dir.path().join("grant.key");
    murk(dir.path(), &key)
        .args(["agent", "grant", "--name", "probe"])
        .args(names.iter().flat_map(|n| ["--only", n]))
        .arg("--out")
        .arg(&grant)
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    let (client, stderr) = start_server(dir.path(), &grant, &["--allow-exec"]).await;

    for name in names {
        let result = exec(&client, name).await;
        assert_eq!(result.is_error, Some(true), "{name}: {}", text(&result));
        assert!(
            text(&result).contains("reserved"),
            "{name}: {}",
            text(&result)
        );
        assert!(
            !text(&result).contains("exit_code"),
            "{name}: {}",
            text(&result)
        );
    }
    stop_server(client, stderr).await;
}

#[tokio::test]
async fn mcp_every_tool_fails_closed_once_the_grant_expires() {
    let dir = assert_fs::TempDir::new().unwrap();
    let (key, _) = init_vault(dir.path());
    murk(dir.path(), &key)
        .args(["add", "API_KEY", "--vault", "test.murk"])
        .write_stdin("expiry-secret\n")
        .assert()
        .success();
    let grant = dir.path().join("grant.key");
    murk(dir.path(), &key)
        .args(["agent", "grant", "--name", "probe", "--only", "API_KEY"])
        .args(["--ttl", "4s", "--out"])
        .arg(&grant)
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    let (client, stderr) = start_server(dir.path(), &grant, &["--allow-exec"]).await;

    let before = plan(&client).await;
    assert_ne!(before.is_error, Some(true), "{}", text(&before));
    assert!(text(&before).contains("API_KEY"), "{}", text(&before));
    assert_eq!(text(&get(&client, "API_KEY").await), "expiry-secret");
    let ran = exec(&client, "API_KEY").await;
    assert_ne!(ran.is_error, Some(true), "{}", text(&ran));

    // The vault file does not change, so no reload runs: the per-call expiry
    // check alone must refuse every tool.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    for after in [
        plan(&client).await,
        get(&client, "API_KEY").await,
        exec(&client, "API_KEY").await,
    ] {
        assert_eq!(after.is_error, Some(true), "{}", text(&after));
        assert!(
            text(&after).contains("grant probe expired"),
            "{}",
            text(&after)
        );
        assert!(!text(&after).contains("API_KEY"), "{}", text(&after));
        assert!(!text(&after).contains("expiry-secret"), "{}", text(&after));
    }

    let log = stop_server(client, stderr).await;
    assert!(!log.contains("reloaded it"), "{log}");
}

#[tokio::test]
async fn mcp_client_lists_and_calls_tools() {
    let dir = assert_fs::TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);

    murk(&dir, &key)
        .args(["add", "API_KEY", "--tag", "agents", "--vault", "test.murk"])
        .write_stdin("interop-secret\n")
        .assert()
        .success();
    murk(&dir, &key)
        .args([
            "add",
            "OTHER_KEY",
            "--tag",
            "agents",
            "--vault",
            "test.murk",
        ])
        .write_stdin("other-secret\n")
        .assert()
        .success();

    let grant = dir.path().join("grant.key");
    murk(&dir, &key)
        .args([
            "agent",
            "init",
            "--name",
            "probe",
            "--only",
            "API_KEY",
            "--allow-tag",
            "agents",
            "--out",
            grant.to_str().unwrap(),
            "--vault",
            "test.murk",
        ])
        .assert()
        .success();

    let transport =
        TokioChildProcess::new(Command::new(env!("CARGO_BIN_EXE_murk")).configure(|cmd| {
            for var in MURK_CONTEXT_VARS {
                cmd.env_remove(var);
            }
            cmd.arg("mcp")
                .arg("--vault")
                .arg("test.murk")
                .current_dir(dir.path())
                .env("HOME", dir.path())
                .env("XDG_RUNTIME_DIR", dir.path())
                .env("MURK_KEY_FILE", grant.to_str().unwrap())
                .env("MURK_AGENT", "1");
        }))
        .unwrap();

    let client = ().serve(transport).await.unwrap();

    let tools = client.list_all_tools().await.unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    assert!(names.contains(&"murk_plan"), "tools: {names:?}");
    assert!(names.contains(&"murk_get"), "tools: {names:?}");

    let in_scope = client
        .call_tool(
            CallToolRequestParams::new("murk_get").with_arguments(object!({ "key": "API_KEY" })),
        )
        .await
        .unwrap();
    assert_ne!(in_scope.is_error, Some(true));
    let in_scope_text: String = in_scope
        .content
        .iter()
        .filter_map(ContentBlock::as_text)
        .map(|t| t.text.as_str())
        .collect();
    assert_eq!(in_scope_text, "interop-secret");

    let out_of_scope = client
        .call_tool(
            CallToolRequestParams::new("murk_get").with_arguments(object!({ "key": "OTHER_KEY" })),
        )
        .await
        .unwrap();
    assert_eq!(out_of_scope.is_error, Some(true));
    let out_of_scope_text: String = out_of_scope
        .content
        .iter()
        .filter_map(ContentBlock::as_text)
        .map(|t| t.text.as_str())
        .collect();
    assert!(
        !out_of_scope_text.contains("other-secret"),
        "leaked out-of-scope value: {out_of_scope_text}"
    );

    client.cancel().await.unwrap();
}

#[test]
fn mcp_refuses_to_start_with_an_expired_grant() {
    let dir = assert_fs::TempDir::new().unwrap();
    let (key, _) = init_vault(&dir);
    murk(&dir, &key)
        .args(["add", "API_KEY", "--vault", "test.murk"])
        .write_stdin("interop-secret\n")
        .assert()
        .success();
    let grant = dir.path().join("grant.key");
    murk(&dir, &key)
        .args([
            "agent", "grant", "--name", "mcp", "--only", "API_KEY", "--ttl", "3s",
        ])
        .arg("--out")
        .arg(&grant)
        .args(["--vault", "test.murk"])
        .assert()
        .success();
    // A 1s TTL could lapse before a slow (loaded, debug) mint saves, and the
    // save would then prune the grant: the read would fail for the wrong reason.
    std::thread::sleep(std::time::Duration::from_millis(3100));

    common::murk_bin(dir.path())
        .current_dir(dir.path())
        .env("MURK_KEY_FILE", &grant)
        .env("MURK_AGENT", "1")
        .args(["mcp", "--vault", "test.murk"])
        .write_stdin("")
        .assert()
        .failure()
        .stdout("")
        .stderr(predicates::str::contains("grant mcp expired"));
}
