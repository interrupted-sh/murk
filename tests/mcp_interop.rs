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
    let (client, stderr) = start_server(dir.path(), &grant, &["--allow-get"]).await;

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
    let (client, stderr) = start_server(dir.path(), &grant, &["--allow-get"]).await;

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
    let (client, stderr) = start_server(dir.path(), &grant, &["--allow-get"]).await;
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
    let (client, stderr) = start_server(dir.path(), &grant, &["--allow-get"]).await;
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
                .arg("--allow-get")
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
