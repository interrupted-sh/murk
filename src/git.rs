// SPDX-FileCopyrightText: murk contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Git integration helpers (merge driver setup, worktree layout).

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

/// The `.gitattributes` lines that enable the merge driver: one for vaults
/// named `*.murk` (`.murk`, `prod.murk`) and one for `.murk.*` (`.murk.prod`).
const GITATTRIBUTES_LINES: [&str; 2] = ["*.murk merge=murk", ".murk.* merge=murk"];

/// Git config keys for the merge driver.
const GIT_CONFIG_MERGE_NAME: &str = "merge.murk.name";
const GIT_CONFIG_MERGE_DRIVER: &str = "merge.murk.driver";

/// The `merge.murk.driver` command `setup-merge-driver` configures.
const MERGE_DRIVER_COMMAND: &str = "murk merge-driver -- %O %A %B %P";

/// A `git` command that runs no code from the repository it is pointed at, with
/// murk's key variables removed from its environment.
///
/// The only way murk spawns git. A repository's own `.git/config` is not
/// trusted: a working tree unpacked from an archive, a shared volume, or a CI
/// cache carries whatever config its author wrote, and several keys name a
/// program git runs. `core.fsmonitor` runs on any index refresh (`check-ignore`
/// does one), hooks run on writes, and a pager runs on terminal output, so all
/// three are switched off here. The signature programs (`gpg.*`) are refused per
/// call in [`last_commit_signature`], since overriding them would also override
/// the user's own choice. Repository-format settings are still read; git needs
/// them to open the repository at all.
///
/// None of the spawned git commands needs the key either. The merge driver is
/// unaffected: git invokes `murk merge-driver` with the user's environment, not
/// with the one murk hands git here.
///
/// Murk decides trust from history (which vault a commit holds, whether one
/// commit is an ancestor of another), so that history must be the object graph
/// as committed. Replace refs (`refs/replace/`) and a graft file both rewrite
/// the graph git reports, and anyone who can write to the repository can add
/// them, so both are switched off.
///
/// Some of these commands run under the trust pin lock, so none may wait on
/// the network or a prompt: a partial clone's lazy fetch of a missing object
/// (`GIT_NO_LAZY_FETCH`) and a credential prompt (`GIT_TERMINAL_PROMPT`) are
/// switched off. A missing object is then missing, which the removal rule
/// treats as history it cannot check.
pub fn git_command() -> Command {
    let mut cmd = Command::new("git");
    cmd.args([
        "--no-pager",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
    ]);
    cmd.env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_GRAFT_FILE", "/dev/null");
    crate::env::strip_key_env(&mut cmd);
    cmd
}

/// A step completed during merge driver setup.
#[derive(Debug, PartialEq, Eq)]
pub enum MergeDriverSetupStep {
    /// `.gitattributes` already contained the merge driver entry.
    GitattributesAlreadyExists,
    /// Appended the merge driver entry to an existing `.gitattributes`.
    GitattributesAppended,
    /// Created a new `.gitattributes` file with the merge driver entry.
    GitattributesCreated,
    /// Configured `git config merge.murk.*`.
    GitConfigured,
}

/// What [`setup_merge_driver`] did: the `.gitattributes` it used and the
/// steps it performed.
#[derive(Debug)]
pub struct MergeDriverSetup {
    /// The `.gitattributes` at the root of the working tree.
    pub gitattributes: PathBuf,
    pub steps: Vec<MergeDriverSetupStep>,
}

/// The root of the working tree that contains the current directory, as git
/// reports it. Fails, with git's own error, outside a working tree. Also
/// fails when git's root does not contain the current directory, which
/// happens when the repository's config sets `core.worktree` to another
/// directory: setup then would write that directory's `.gitattributes`.
fn working_tree_root() -> Result<PathBuf, String> {
    let out = git_command()
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|e| format!("running git rev-parse: {e}"))?;
    let root = String::from_utf8_lossy(&out.stdout)
        .trim_end_matches(['\n', '\r'])
        .to_string();
    if !out.status.success() || root.is_empty() {
        let git_said =
            crate::terminal_text(String::from_utf8_lossy(&out.stderr).trim(), true).into_owned();
        let mut msg =
            "not inside a git working tree; run murk setup-merge-driver in your repository"
                .to_string();
        if !git_said.is_empty() {
            msg = format!("git rev-parse failed: {git_said}\n{msg}");
        }
        return Err(msg);
    }
    let root = real_dir(Path::new(&root)).unwrap_or_else(|| PathBuf::from(&root));
    let cwd = std::env::current_dir()
        .ok()
        .and_then(|d| real_dir(&d))
        .ok_or("cannot resolve the current directory")?;
    if !cwd.starts_with(&root) {
        return Err(format!(
            "git's working tree for this repository is {}, which does not contain the current directory\n\
             the repository's core.worktree points elsewhere; murk setup-merge-driver changes nothing",
            crate::terminal_text(&root.display().to_string(), false)
        ));
    }
    Ok(root)
}

/// The `merge.murk.driver` lines murk itself has written, current and older.
const MURK_DRIVER_COMMANDS: [&str; 3] = [
    MERGE_DRIVER_COMMAND,
    "murk merge-driver %O %A %B %P",
    "murk merge-driver %O %A %B",
];

/// Refuse to replace a `merge.murk.driver` murk did not write, in any git
/// config scope git reads here: a custom wrapper is the user's choice, and
/// a local line would silently shadow a global one. Lines murk wrote, even
/// several of them, may be replaced.
fn check_existing_driver() -> Result<(), String> {
    let out = git_command()
        .args(["config", "--get-all", GIT_CONFIG_MERGE_DRIVER])
        .output()
        .map_err(|e| format!("running git config: {e}"))?;
    let values = String::from_utf8_lossy(&out.stdout);
    let custom: Vec<String> = values
        .lines()
        .filter(|v| !MURK_DRIVER_COMMANDS.contains(&v.trim()))
        .map(|v| crate::terminal_text(v, false).into_owned())
        .collect();
    if custom.is_empty() {
        return Ok(());
    }
    let mut lines = vec![format!(
        "git config already sets {GIT_CONFIG_MERGE_DRIVER} to a command murk did not write: {}",
        custom.join(" | ")
    )];
    lines.push("murk setup-merge-driver changed nothing".into());
    lines.push(format!(
        "to use murk's driver, remove it (git config --unset-all {GIT_CONFIG_MERGE_DRIVER}, add --global if it is set there), then run murk setup-merge-driver again"
    ));
    Err(lines.join("\n"))
}

/// What a glob character can stand for, as far as the names `*.murk` and
/// `.murk.*` care: one of the lower-case characters `.`, `m`, `u`, `r`, `k`,
/// or some other character that is not `/`. With `core.ignorecase` git
/// lower-cases the file name before it matches, so lower case covers every
/// name; without it `*.murk` matches only lower case, and `M` is "other".
const VAULT_NAME_CHARS: [char; 5] = ['.', 'm', 'u', 'r', 'k'];
const OTHER_CHAR: usize = VAULT_NAME_CHARS.len();

/// One element of a glob over a single path component.
struct GlobToken {
    /// `*`: any number of characters.
    repeat: bool,
    /// Which of [`VAULT_NAME_CHARS`] (then [`OTHER_CHAR`]) it can match.
    can: [bool; VAULT_NAME_CHARS.len() + 1],
}

impl GlobToken {
    fn any(repeat: bool) -> Self {
        Self {
            repeat,
            can: [true; VAULT_NAME_CHARS.len() + 1],
        }
    }

    /// A literal character; `fold` lower-cases it, as git does with
    /// `core.ignorecase`.
    fn literal(c: char, fold: bool) -> Self {
        let mut can = [false; VAULT_NAME_CHARS.len() + 1];
        let c = if fold { c.to_ascii_lowercase() } else { c };
        match VAULT_NAME_CHARS.iter().position(|&v| v == c) {
            Some(i) => can[i] = true,
            None => can[OTHER_CHAR] = c != '/',
        }
        Self { repeat: false, can }
    }
}

/// Parse a bracket expression after its `[`. `None` when it never closes:
/// git then matches nothing, and treating `[` as a literal errs toward
/// refusal only where a vault name could still match.
fn parse_class(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    fold: bool,
) -> Option<GlobToken> {
    let mut rest = chars.clone();
    let negated = matches!(rest.peek(), Some('!' | '^'));
    if negated {
        rest.next();
    }
    let mut ranges: Vec<(char, char)> = Vec::new();
    let mut posix = false;
    let mut first = true;
    loop {
        let mut c = rest.next()?;
        if c == ']' && !first {
            break;
        }
        first = false;
        if c == '[' && rest.peek() == Some(&':') {
            // `[:alpha:]` and friends: assume it can match anything, and
            // skip to its closing `:]`.
            posix = true;
            let mut last = ' ';
            loop {
                let next = rest.next()?;
                if last == ':' && next == ']' {
                    break;
                }
                last = next;
            }
            continue;
        }
        if c == '\\' {
            c = rest.next()?;
        }
        let mut hi = c;
        if rest.peek() == Some(&'-') {
            let mut ahead = rest.clone();
            ahead.next();
            if let Some(&end) = ahead.peek()
                && end != ']'
            {
                rest = ahead;
                hi = rest.next()?;
                if hi == '\\' {
                    hi = rest.next()?;
                }
            }
        }
        ranges.push((c, hi));
    }
    *chars = rest;
    if posix {
        return Some(GlobToken::any(false));
    }
    let member = |c: char| ranges.iter().any(|&(lo, hi)| lo <= c && c <= hi);
    let mut can = [false; VAULT_NAME_CHARS.len() + 1];
    for (i, &v) in VAULT_NAME_CHARS.iter().enumerate() {
        can[i] = if !fold {
            // Case-sensitive, as git's wildmatch: `[!M]` matches `m`.
            member(v) != negated
        } else if negated {
            // The name is lower case. git may compare a class member with
            // it as written or folded; `!member(v)` holds in either case,
            // so it errs toward refusal.
            !member(v)
        } else {
            member(v) || member(v.to_ascii_uppercase())
        };
    }
    // Some member is neither `/` nor a vault-name character (in either case
    // when folding).
    let specials: BTreeSet<char> = VAULT_NAME_CHARS
        .iter()
        .flat_map(|c| {
            if fold {
                vec![*c, c.to_ascii_uppercase()]
            } else {
                vec![*c]
            }
        })
        .chain(['/'])
        .collect();
    can[OTHER_CHAR] = negated
        || ranges.iter().any(|&(lo, hi)| {
            let size = u64::from(hi).saturating_sub(u64::from(lo)) + 1;
            let inside = specials.iter().filter(|&&c| lo <= c && c <= hi).count() as u64;
            lo <= hi && size > inside
        });
    Some(GlobToken { repeat: false, can })
}

/// The last path component of an attribute pattern as glob tokens. Earlier
/// components never matter here: `*.murk` and `.murk.*` match a file name
/// in any directory.
fn glob_tokens(pattern: &str, fold: bool) -> Vec<GlobToken> {
    let last = pattern.rsplit('/').next().unwrap_or(pattern);
    let last = if last == "**" { "*" } else { last };
    let mut tokens = Vec::new();
    let mut chars = last.chars().peekable();
    while let Some(c) = chars.next() {
        tokens.push(match c {
            '*' => {
                while chars.peek() == Some(&'*') {
                    chars.next();
                }
                GlobToken::any(true)
            }
            '?' => GlobToken::any(false),
            '[' => parse_class(&mut chars, fold).unwrap_or_else(|| GlobToken::literal('[', fold)),
            '\\' => GlobToken::literal(chars.next().unwrap_or('\\'), fold),
            c => GlobToken::literal(c, fold),
        });
    }
    tokens
}

/// Whether some file name that the glob `pattern` matches is also matched by
/// `*.murk` (when `suffix`) or `.murk.*` (when `prefix`). `fold`: git's
/// `core.ignorecase`, under which git ignores case on both sides. Walks the
/// product of the glob with a small automaton for each name shape.
fn glob_may_match_vault(pattern: &str, suffix: bool, prefix: bool, fold: bool) -> bool {
    const NAME: [usize; 6] = [0, 1, 2, 3, 4, 0]; // ".murk." as VAULT_NAME_CHARS indexes
    const DEAD: usize = 7;
    // `*.murk`: how much of ".murk" the name ends with (5 = all).
    let step_suffix = |s: usize, c: usize| {
        if s < 5 && c == NAME[s] {
            s + 1
        } else {
            usize::from(c == 0)
        }
    };
    // `.murk.*`: how much of ".murk." the name starts with (6 = all).
    let step_prefix = |p: usize, c: usize| match p {
        6 | DEAD => p,
        _ if c == NAME[p] => p + 1,
        _ => DEAD,
    };
    let tokens = glob_tokens(pattern, fold);
    let mut seen = BTreeSet::new();
    let mut todo = vec![(0usize, 0usize, 0usize)];
    while let Some(state) = todo.pop() {
        if !seen.insert(state) {
            continue;
        }
        let (i, s, p) = state;
        let Some(token) = tokens.get(i) else {
            if (suffix && s == 5) || (prefix && p == 6) {
                return true;
            }
            continue;
        };
        if token.repeat {
            todo.push((i + 1, s, p));
        }
        let next = if token.repeat { i } else { i + 1 };
        for c in (0..token.can.len()).filter(|&c| token.can[c]) {
            todo.push((next, step_suffix(s, c), step_prefix(p, c)));
        }
    }
    false
}

/// The case modes to judge patterns in: git's `core.ignorecase` for this
/// repository (unset is false). When git cannot say, both, so that a
/// pattern counts if it counts in either.
fn case_modes(root: &Path) -> Vec<bool> {
    let out = git_command()
        .arg("-C")
        .arg(root)
        .args(["config", "--type=bool", "--get", "core.ignorecase"])
        .output();
    match out {
        Ok(out) if out.status.success() => {
            vec![String::from_utf8_lossy(&out.stdout).trim() == "true"]
        }
        Ok(out) if out.status.code() == Some(1) => vec![false],
        _ => vec![false, true],
    }
}

/// Undo git's C-style quoting of a pattern (`"my vault.murk"`), as git does
/// before it matches the pattern: `\"`, `\\`, the control escapes and
/// three-digit octal bytes (`\155` is `m`). Returns the pattern and the rest
/// of the line, or `None` when the quoting is invalid, a line git ignores.
fn unquote_pattern(line: &str) -> Option<(String, &str)> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut at = 1;
    while at < bytes.len() {
        let b = bytes[at];
        at += 1;
        match b {
            b'"' => return Some((String::from_utf8_lossy(&out).into_owned(), &line[at..])),
            b'\\' => {
                let e = *bytes.get(at)?;
                at += 1;
                out.push(match e {
                    b'"' | b'\\' => e,
                    b'a' => 0x07,
                    b'b' => 0x08,
                    b'f' => 0x0c,
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'v' => 0x0b,
                    b'0'..=b'3' => {
                        let digits = bytes.get(at..at + 2)?;
                        if !digits.iter().all(|d| (b'0'..=b'7').contains(d)) {
                            return None;
                        }
                        at += 2;
                        ((e - b'0') << 6) | ((digits[0] - b'0') << 3) | (digits[1] - b'0')
                    }
                    _ => return None,
                });
            }
            b => out.push(b),
        }
    }
    None
}

/// One line of an attributes file: the pattern (`None` for a macro
/// definition `[attr]name`) and the attribute tokens.
fn parse_attribute_line(line: &str) -> Option<(Option<String>, Vec<&str>)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    if let Some(def) = line.strip_prefix("[attr]") {
        let mut words = def.split_whitespace();
        words.next()?;
        return Some((None, words.collect()));
    }
    let (pattern, rest) = if line.starts_with('"') {
        // An unclosed quote: git ignores the line, so do the same.
        unquote_pattern(line)?
    } else {
        let end = line.find(char::is_whitespace).unwrap_or(line.len());
        (line[..end].to_string(), &line[end..])
    };
    Some((Some(pattern), rest.split_whitespace().collect()))
}

/// Whether the attribute token `token` sets, unsets or resets `merge` to
/// anything but `murk`, directly or through one of `macros`.
fn touches_merge(token: &str, macros: &BTreeSet<String>) -> bool {
    let name = token.trim_start_matches(['-', '!']);
    let (name, value) = name
        .split_once('=')
        .map_or((name, None), |(n, v)| (n, Some(v)));
    if name == "merge" {
        return token.starts_with(['-', '!']) || value != Some("murk");
    }
    macros.contains(name)
}

/// Every attributes file git reads for this working tree that exists, with
/// the name to show for it: the system file, `core.attributesFile`, the
/// `.gitattributes` files in the tree (tracked or not) and
/// `.git/info/attributes`. The root `.gitattributes` is passed in, read
/// already.
fn attribute_files(
    root: &Path,
    root_contents: Option<&str>,
) -> Result<Vec<(String, String)>, String> {
    let git = |args: &[&str]| {
        git_command()
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
    };
    let line = |args: &[&str]| {
        git(args)
            .map(|s| s.trim_end_matches(['\n', '\r']).to_string())
            .filter(|s| !s.is_empty())
    };
    let mut paths: Vec<(String, PathBuf)> = Vec::new();
    if let Some(system) = line(&["var", "GIT_ATTR_SYSTEM"]) {
        paths.push((system.clone(), PathBuf::from(system)));
    }
    let global = line(&["config", "--type=path", "--get", "core.attributesFile"])
        .or_else(|| line(&["var", "GIT_ATTR_GLOBAL"]))
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("XDG_CONFIG_HOME")
                .filter(|d| !d.is_empty())
                .map(PathBuf::from)
                .or_else(|| crate::env::home_dir().map(|h| h.join(".config")))
                .map(|d| d.join("git").join("attributes"))
        });
    if let Some(global) = global {
        paths.push((global.display().to_string(), global));
    }
    // Nested .gitattributes files, tracked or not. One ls-files run whose
    // output git writes and murk only reads: no per-path work.
    let nested = git(&[
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
        "--",
        ":(glob)**/.gitattributes",
    ])
    .unwrap_or_default();
    let mut nested: Vec<&str> = nested
        .split('\0')
        .filter(|p| !p.is_empty() && *p != ".gitattributes")
        .collect();
    nested.sort_unstable();
    nested.dedup();
    paths.extend(nested.into_iter().map(|p| (p.to_string(), root.join(p))));
    if let Some(info) = line(&["rev-parse", "--git-path", "info/attributes"]) {
        paths.push((info.clone(), root.join(info)));
    }

    let mut files = Vec::new();
    if let Some(text) = root_contents {
        files.push((".gitattributes".to_string(), text.to_string()));
    }
    for (shown, path) in paths {
        match fs::read(&path) {
            Ok(bytes) => files.push((shown, String::from_utf8_lossy(&bytes).into_owned())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // git would read it: refuse rather than guess what it says.
            Err(e) => {
                return Err(format!(
                    "reading {}: {e}\nmurk setup-merge-driver changed nothing",
                    crate::terminal_text(&shown, false)
                ));
            }
        }
    }
    Ok(files)
}

/// Refuse to override a `merge` attribute the user gave vault files. Every
/// line, in every attributes file git reads here, that sets, unsets or
/// resets `merge` (also through a macro such as `binary`) to anything but
/// `murk`, for a pattern that could match a file name the `missing` lines
/// would match, is reported with its file and line number. Decided from
/// the lines alone, so it covers files that do not exist yet. A line in
/// `.git/info/attributes` or a subdirectory would override murk's line
/// instead; it is refused too, since murk's driver would then not run.
fn check_existing_attribute(
    root: &Path,
    root_contents: Option<&str>,
    missing: &[&str],
) -> Result<(), String> {
    let suffix = missing.contains(&GITATTRIBUTES_LINES[0]);
    let prefix = missing.contains(&GITATTRIBUTES_LINES[1]);
    if !suffix && !prefix {
        return Ok(());
    }
    let files = attribute_files(root, root_contents)?;
    let modes = case_modes(root);
    // Macros that touch merge, `binary` built in; a macro may use another.
    let mut macros = BTreeSet::from(["binary".to_string()]);
    loop {
        let before = macros.len();
        for (_, text) in &files {
            for line in text.lines() {
                if let Some((None, tokens)) = parse_attribute_line(line)
                    && tokens.iter().any(|t| touches_merge(t, &macros))
                    && let Some(name) = line.trim()["[attr]".len()..].split_whitespace().next()
                {
                    macros.insert(name.to_string());
                }
            }
        }
        if macros.len() == before {
            break;
        }
    }
    let mut found = Vec::new();
    for (shown, text) in &files {
        for (n, line) in text.lines().enumerate() {
            let Some((Some(pattern), tokens)) = parse_attribute_line(line) else {
                continue;
            };
            // git ignores negative patterns and patterns for directories.
            if pattern.starts_with('!') || pattern.ends_with('/') {
                continue;
            }
            // A name pattern that starts with `*` reaches `.murk.*` names only
            // through the wildcard. For those names it counts only when it
            // names a merge driver (`*.prod merge=custom` would override a
            // `.murk.prod` vault). `-merge`, `!merge` and macros such as
            // `binary` there describe a file type (`*.png binary`), not
            // vaults. Against `*.murk` every merge setting counts.
            let name = pattern.rsplit('/').next().unwrap_or(&pattern);
            let names_driver = tokens.iter().any(|t| {
                t.strip_prefix("merge=")
                    .is_some_and(|driver| driver != "murk")
            });
            let prefix = prefix && (!name.starts_with('*') || names_driver);
            if tokens.iter().any(|t| touches_merge(t, &macros))
                && modes
                    .iter()
                    .any(|&fold| glob_may_match_vault(&pattern, suffix, prefix, fold))
            {
                found.push(format!(
                    "{}:{}: {}",
                    crate::terminal_text(shown, false),
                    n + 1,
                    crate::terminal_text(line.trim(), false)
                ));
            }
        }
    }
    if found.is_empty() {
        return Ok(());
    }
    let mut lines = vec![
        "git attributes already set a merge attribute for files that murk's .gitattributes lines would cover:".to_string(),
    ];
    lines.extend(found);
    lines.push("murk setup-merge-driver changed nothing".into());
    lines.push(
        "to use murk's driver, remove the merge attribute from those lines, then run murk setup-merge-driver again"
            .into(),
    );
    Err(lines.join("\n"))
}

/// Configure git to use murk's custom merge driver for vault files.
///
/// Refuses, writing nothing, outside a working tree, when git's working tree
/// does not contain the current directory, when git config already sets a
/// `merge.murk.driver` murk did not write, or when an attributes line gives
/// files that the lines setup adds would cover another `merge` attribute.
/// Otherwise:
///
/// 1. Runs `git config merge.murk.name` and `git config merge.murk.driver`,
///    replacing a driver line an older murk wrote. When this fails,
///    `.gitattributes` is untouched.
/// 2. Ensures the `.gitattributes` at the root of the working tree contains
///    `*.murk merge=murk` and `.murk.* merge=murk`, appending whichever is
///    missing.
pub fn setup_merge_driver() -> Result<MergeDriverSetup, String> {
    // The `.gitattributes` at the root of the working tree: one in a
    // subdirectory only covers that subdirectory.
    let root = working_tree_root()?;
    let gitattributes_path = root.join(".gitattributes");
    let gitattributes = gitattributes_path.as_path();
    // Before anything is written: never replace someone else's driver.
    check_existing_driver()?;

    crate::env::reject_symlink(gitattributes, ".gitattributes")?;
    // Read what is there before git config changes, so a read error changes
    // nothing.
    let contents = if gitattributes.exists() {
        Some(
            fs::read_to_string(gitattributes)
                .map_err(|e| format!("reading .gitattributes: {e}"))?,
        )
    } else {
        None
    };
    let missing: Vec<&str> = GITATTRIBUTES_LINES
        .into_iter()
        .filter(|line| {
            !contents
                .as_deref()
                .is_some_and(|c| c.lines().any(|l| l.trim() == *line))
        })
        .collect();
    // Never override someone else's merge attribute.
    check_existing_attribute(&root, contents.as_deref(), &missing)?;

    // 1. Configure git merge driver first: if git config fails, no attribute
    // names a driver git does not have. `--` ends the options, so a vault
    // named like a flag (`-h.murk`) reaches the driver as a path. Setting the
    // key replaces a driver line an older murk wrote.
    let configs = [
        (GIT_CONFIG_MERGE_NAME, "murk vault merge"),
        (GIT_CONFIG_MERGE_DRIVER, MERGE_DRIVER_COMMAND),
    ];
    for (key, value) in &configs {
        // --replace-all: several local lines murk wrote collapse into one,
        // where a plain set would fail on a multi-valued key.
        let out = git_command()
            .args(["config", "--replace-all", key, value])
            .output()
            .map_err(|e| format!("running git config: {e}"))?;
        if !out.status.success() {
            let git_said = crate::terminal_text(String::from_utf8_lossy(&out.stderr).trim(), true)
                .into_owned();
            return Err(format!(
                "git config {key} failed: {git_said}\n.gitattributes was not changed\nfix the error, then run murk setup-merge-driver again"
            ));
        }
    }

    // 2. Write the .gitattributes entries.
    let written_after_config = |e: std::io::Error| {
        format!(
            "writing .gitattributes: {e}\ngit config already names murk's merge driver, but .gitattributes may lack its lines\nfix the error, then run murk setup-merge-driver again"
        )
    };
    let attributes_step = if let Some(contents) = contents {
        if missing.is_empty() {
            MergeDriverSetupStep::GitattributesAlreadyExists
        } else {
            // Never glue the first new line onto an unterminated last line.
            let mut text = String::new();
            if !contents.is_empty() && !contents.ends_with('\n') {
                text.push('\n');
            }
            for line in missing {
                text.push_str(line);
                text.push('\n');
            }
            fs::OpenOptions::new()
                .append(true)
                .open(gitattributes)
                .and_then(|mut file| file.write_all(text.as_bytes()))
                .map_err(written_after_config)?;
            MergeDriverSetupStep::GitattributesAppended
        }
    } else {
        fs::write(gitattributes, GITATTRIBUTES_LINES.join("\n") + "\n")
            .map_err(written_after_config)?;
        MergeDriverSetupStep::GitattributesCreated
    };

    Ok(MergeDriverSetup {
        gitattributes: gitattributes_path,
        steps: vec![attributes_step, MergeDriverSetupStep::GitConfigured],
    })
}

/// Who signed a commit, as git reports it for the signature it checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitSigner {
    /// git's `%GK`: the signing key's id for gpg, its `SHA256:` fingerprint
    /// for an ssh key. Empty when git reports none.
    pub key: String,
    /// git's `%GF`: the signing key's fingerprint. For an ssh key this is the
    /// `ssh-keygen -l` form ([`crate::signing::ssh_ed25519_fingerprint`]).
    /// Empty when git reports none.
    pub fingerprint: String,
}

impl CommitSigner {
    /// What names the key: its fingerprint, else its key id. `None` when git
    /// reported neither.
    pub fn id(&self) -> Option<&str> {
        [self.fingerprint.as_str(), self.key.as_str()]
            .into_iter()
            .find(|s| !s.is_empty())
    }
}

/// Signature status of the most recent commit that modified `path`.
///
/// The vault signature authenticates *content*; a signed commit authenticates
/// *who landed it* — together they anchor integrity in git (see `THREAT_MODEL`).
/// `murk verify` surfaces this so a team can confirm the vault's history is
/// signed, not just its bytes. A signature by *some* key proves nothing about
/// whether that key belongs to a person the vault trusts, so the signer is
/// carried along for the caller to compare with the vault's signers.
#[derive(Debug, PartialEq, Eq)]
pub enum CommitSignature {
    /// git checked the signature and it is valid (`G`, or `U`: valid, but git
    /// has no standing for the key). It says nothing about who the key is.
    Verified(CommitSigner),
    /// A signature is present but git does not vouch for it: `status` is `E`
    /// (it could not be checked, e.g. the key is unknown or the verifier is
    /// missing), `X` (the signature has expired) or `Y` (the key has expired).
    Unverified { status: char, signer: CommitSigner },
    /// A bad signature — the commit was altered or the signature doesn't match.
    Bad,
    /// The commit carries no signature.
    Unsigned,
    /// Not checked: the repository's own config sets `gpg.*`. Verifying would
    /// run the program that config names, and an allowed-signers file it names
    /// would let the repository vouch for its own signer.
    RepoConfigured,
}

/// The principal name in the allowed-signers file handed to git. git only
/// needs *a* principal to report a key as listed; the name is never shown.
const ALLOWED_SIGNERS_PRINCIPAL: &str = "murk-trusted-signer";

/// Write `keys` (ssh-ed25519 public key lines) as an allowed-signers file in a
/// fresh temporary directory, for `gpg.ssh.allowedSignersFile`. The directory
/// goes away when the returned handle is dropped. `None` when it cannot be
/// written. Keys that are not ssh-ed25519 are left out.
fn write_allowed_signers(keys: &[String]) -> Option<(tempfile::TempDir, PathBuf)> {
    let dir = tempfile::Builder::new()
        .prefix("murk-allowed-signers-")
        .tempdir()
        .ok()?;
    let path = dir.path().join("allowed_signers");
    let mut contents = String::new();
    for key in keys
        .iter()
        .filter_map(|k| crate::signing::ssh_ed25519_key_line(k))
    {
        contents.push_str(ALLOWED_SIGNERS_PRINCIPAL);
        contents.push_str(" namespaces=\"git\" ");
        contents.push_str(&key);
        contents.push('\n');
    }
    fs::write(&path, contents).ok()?;
    Some((dir, path))
}

/// Return the signature status of the last commit touching `path`, or `None`
/// when git is unavailable, the repo has no such commit, or the path is
/// untracked — i.e. there is no git anchor to check.
///
/// `trusted_ssh_signers` are the ssh-ed25519 keys the caller trusts to sign
/// commits. They go to git as the allowed-signers list for this one call
/// (`-c gpg.ssh.allowedSignersFile`), which makes the check independent of
/// the user's git config: without such a file git cannot check an ssh
/// signature at all and reports a signed commit as unsigned, and a user's own
/// list would decide what `G` means. With it, a valid ssh signature by one of
/// these keys is `G` and a valid one by any other key is `U`. A
/// `gpg.ssh.revocationFile` the user configured still applies.
///
/// Signature verification is governed entirely by `gpg.*` config, so only the
/// user's global and system config may set it; see
/// [`CommitSignature::RepoConfigured`].
pub fn last_commit_signature(
    path: &str,
    trusted_ssh_signers: &[String],
) -> Option<CommitSignature> {
    // No commit for this path (untracked / no history): no anchor to check.
    last_commit_field(path, "%H")?;
    if repo_sets_gpg_config()? {
        return Some(CommitSignature::RepoConfigured);
    }
    let allowed = write_allowed_signers(trusted_ssh_signers);
    let mut cmd = git_command();
    if let Some((_, file)) = &allowed {
        let mut setting = std::ffi::OsString::from("gpg.ssh.allowedSignersFile=");
        setting.push(file);
        cmd.arg("-c").arg(setting);
    }
    let output = cmd
        .args([
            "log",
            "-1",
            // `log.showSignature` would print the verifier's output into ours.
            "--no-show-signature",
            "--format=%G?%x00%GK%x00%GF",
            "--",
        ])
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_commit_signature(String::from_utf8(output.stdout).ok()?.trim_end())
}

/// Parse `%G?%x00%GK%x00%GF` output: `None` for no commit (an empty line) or a
/// status git does not define.
fn parse_commit_signature(line: &str) -> Option<CommitSignature> {
    let mut fields = line.split('\0');
    let status = fields.next()?;
    let mut signer = move || CommitSigner {
        key: fields.next().unwrap_or_default().to_string(),
        fingerprint: fields.next().unwrap_or_default().to_string(),
    };
    let mut chars = status.chars();
    let (Some(code), None) = (chars.next(), chars.next()) else {
        return None;
    };
    match code {
        'G' | 'U' => Some(CommitSignature::Verified(signer())),
        // X (expired signature), Y (expired key), E (cannot check) all mean "a
        // signature exists but we can't vouch for it".
        'X' | 'Y' | 'E' => Some(CommitSignature::Unverified {
            status: code,
            signer: signer(),
        }),
        'B' | 'R' => Some(CommitSignature::Bad),
        'N' => Some(CommitSignature::Unsigned),
        _ => None,
    }
}

/// `git log -1 --format=<format> -- <path>`, trimmed; `None` when git fails or
/// no commit touches `path`. `--no-show-signature` keeps a repository's
/// `log.showSignature` from verifying signatures where the format does not ask.
fn last_commit_field(path: &str, format: &str) -> Option<String> {
    let output = git_command()
        .args([
            "log",
            "-1",
            "--no-show-signature",
            &format!("--format={format}"),
            "--",
            path,
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let field = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!field.is_empty()).then_some(field)
}

/// Whether the repository's own config (local or per-worktree scope, including
/// files it includes) sets any `gpg.*` key. `None` when git cannot answer.
fn repo_sets_gpg_config() -> Option<bool> {
    let output = git_command()
        .args(["config", "--show-scope", "--get-regexp", r"^gpg\."])
        .output()
        .ok()?;
    match output.status.code() {
        // `--get-regexp` exits 1 when nothing matches.
        Some(1) => Some(false),
        Some(0) => Some(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line.starts_with("local\t") || line.starts_with("worktree\t")),
        ),
        _ => None,
    }
}

/// Read the vault file at `vault_path` as it was in git revision `git_ref`.
///
/// Returns `Ok(None)` only when git proves the file is absent from that
/// revision; every other failure (not a repository, unknown revision, a
/// non-file entry, a git error) is an `Err`, so a caller never mistakes a
/// failed lookup for an empty vault.
///
/// `git_ref` is untrusted input. It is refused if it starts with `-`, resolved
/// to a commit id with `rev-parse --verify --end-of-options` first, and only
/// that hex id reaches the later commands, so it can never be read as a git
/// option. The path is resolved against the repository that holds the vault
/// file, so it works from a subdirectory and with a vault outside the current
/// directory.
pub fn vault_at_revision(git_ref: &str, vault_path: &str) -> Result<Option<String>, String> {
    if git_ref.is_empty() || git_ref.starts_with('-') {
        return Err(format!("invalid git revision {git_ref:?}"));
    }
    let path = Path::new(vault_path);
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("invalid vault path {vault_path}"))?;
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let git = |args: &[&str]| {
        git_command()
            .args(args)
            .current_dir(dir)
            .output()
            .map_err(|e| format!("running git: {e}"))
    };

    let out = git(&["rev-parse", "--show-prefix"])?;
    if !out.status.success() {
        return Err(format!("{} is not inside a git repository", dir.display()));
    }
    let prefix = String::from_utf8(out.stdout)
        .map_err(|_| format!("{} has a non-UTF-8 path", dir.display()))?;
    let tree_path = format!("{}{file_name}", prefix.trim_end_matches('\n'));

    let out = git(&[
        "rev-parse",
        "--verify",
        "--quiet",
        "--end-of-options",
        &format!("{git_ref}^{{commit}}"),
    ])?;
    let commit = String::from_utf8(out.stdout).unwrap_or_default();
    let commit = commit.trim_end_matches('\n');
    if !out.status.success() || commit.is_empty() || !commit.bytes().all(|b| b.is_ascii_hexdigit())
    {
        if git_ref == "HEAD" && head_is_unborn(&git)? {
            return Ok(None);
        }
        return Err(format!("{git_ref} does not name a git commit"));
    }

    // `ls-tree` exits 0 with no output when the path is absent: that is the
    // only outcome treated as "no vault at this revision".
    let out = git(&[
        "--literal-pathspecs",
        "ls-tree",
        "-z",
        "--full-tree",
        commit,
        "--",
        &tree_path,
    ])?;
    if !out.status.success() {
        return Err(format!(
            "git ls-tree {git_ref} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    if out.stdout.is_empty() {
        return Ok(None);
    }
    // One entry: "<mode> <type> <id>\t<path>\0".
    let entry = String::from_utf8_lossy(&out.stdout);
    let mut fields = entry.split(['\t', '\0']).next().unwrap_or("").split(' ');
    let (mode, kind, id) = (fields.next(), fields.next(), fields.next());
    let id = match (mode, kind, id) {
        (Some("100644" | "100755"), Some("blob"), Some(id))
            if id.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            id
        }
        _ => return Err(format!("{tree_path} at {git_ref} is not a regular file")),
    };

    let out = git(&["cat-file", "blob", id])?;
    if !out.status.success() {
        return Err(format!(
            "reading {tree_path} at {git_ref}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout)
        .map(Some)
        .map_err(|_| format!("{tree_path} at {git_ref} is not UTF-8"))
}

/// Whether HEAD is unborn: it names a branch that does not exist at all, as in
/// a repository with no commits yet. A branch that exists but points at a
/// missing or corrupt object is not unborn, so a broken repository never reads
/// as "no vault here". `for-each-ref` lists a broken ref (and exits 0), and
/// prints nothing only when no such ref exists.
fn head_is_unborn(
    git: &impl Fn(&[&str]) -> Result<std::process::Output, String>,
) -> Result<bool, String> {
    let out = git(&["symbolic-ref", "--quiet", "HEAD"])?;
    if !out.status.success() {
        return Ok(false);
    }
    let target = String::from_utf8(out.stdout).unwrap_or_default();
    let target = target.trim_end_matches('\n');
    if !target.starts_with("refs/") {
        return Ok(false);
    }
    let out = git(&["for-each-ref", "--format=%(refname)", target])?;
    Ok(out.status.success() && out.stdout.is_empty())
}

/// The real path of directory `dir` (symlinks, `..`, 8.3 short names and
/// drive-letter case resolved), in the plain form every other spelling of it
/// resolves to: on Windows `fs::canonicalize` returns a verbatim path
/// (`\\?\C:\…`, `\\?\UNC\server\…`), which no lexical path ever equals, so
/// the prefix is removed. `None` when `dir` does not exist.
pub fn real_dir(dir: &Path) -> Option<PathBuf> {
    let real = fs::canonicalize(dir).ok()?;
    if !cfg!(windows) {
        return Some(real);
    }
    let s = real.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return Some(PathBuf::from(format!(r"\\{rest}")));
    }
    Some(
        s.strip_prefix(r"\\?\")
            .map_or_else(|| real.clone(), PathBuf::from),
    )
}

/// `path` with its directory replaced by [`real_dir`] and its file name kept
/// as given (a symlinked file is not resolved); `path` itself when the
/// directory does not exist.
pub fn real_parent(path: &Path) -> PathBuf {
    match (path.parent(), path.file_name()) {
        (Some(dir), Some(name)) => {
            real_dir(dir).map_or_else(|| path.to_path_buf(), |d| d.join(name))
        }
        _ => path.to_path_buf(),
    }
}

/// The working tree containing `path`: the nearest ancestor holding a `.git`
/// entry. `None` when `path` is not inside a checkout.
///
/// Lexical only — no `git` subprocess and no symlink resolution, so the answer
/// is a prefix of the path handed in. Key lookup hashes the literal vault path
/// (see `env::key_file_path`), and this must agree with it.
pub fn worktree_root(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|dir| dir.join(".git").exists())
        .map(Path::to_path_buf)
}

/// Every *other* working tree of the repository `root` belongs to: the main
/// checkout first, then linked worktrees in a stable order. Empty when `root`
/// is not a checkout, the repository has no other working tree, or the git
/// metadata is unreadable.
///
/// Read straight off the git directory rather than through `git worktree list`:
/// key resolution runs on every decrypt, and a secrets tool should not spawn a
/// binary off `PATH` to answer it.
///
/// Membership is checked in **both** directions, because a `.git` entry is just
/// a file anyone can write and the caller uses the answer to decide whose key a
/// vault may borrow. `root` must be a checkout the repository itself records —
/// so a planted `.git` pointer into someone else's repository lists nothing —
/// and every candidate must resolve back to the same common directory — so a
/// planted `.git` *directory* naming a foreign checkout as its worktree is
/// ignored too. Anything unverified is dropped: this fails closed.
pub fn sibling_worktrees(root: &Path) -> Vec<PathBuf> {
    let Some(common) = common_dir(root) else {
        return Vec::new();
    };

    // The main working tree is the parent of `<checkout>/.git`. A bare
    // repository — the `.bare` + worktrees layout — has no working tree of its
    // own, and its parent directory is not a checkout, so require the name.
    let main = if common.file_name() == Some(std::ffi::OsStr::new(".git")) {
        common.parent().map(Path::to_path_buf)
    } else {
        None
    };

    // Linked worktrees: `<common>/worktrees/<id>/gitdir` holds the path of that
    // checkout's own `.git` file.
    let mut linked: Vec<PathBuf> = match fs::read_dir(common.join("worktrees")) {
        Ok(entries) => entries
            .flatten()
            .filter_map(|entry| {
                let gitdir = fs::read_to_string(entry.path().join("gitdir")).ok()?;
                Path::new(gitdir.trim()).parent().map(Path::to_path_buf)
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    linked.sort();

    if main.as_deref() != Some(root) && !linked.iter().any(|checkout| checkout == root) {
        return Vec::new();
    }

    main.into_iter()
        .chain(linked)
        .filter(|checkout| {
            checkout != root && common_dir(checkout).as_deref() == Some(common.as_path())
        })
        .collect()
}

/// What the checkout containing a vault has checked out, read from its HEAD
/// file (no `git` process). The rollback check is per branch: switching to an
/// older branch is normal, a branch going backwards is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadState {
    /// The vault is not in a git checkout.
    NotARepo,
    /// A branch is checked out (`refs/heads/<name>`).
    Branch(String),
    /// A detached HEAD (a rebase, bisect, or CI checkout of a commit).
    Detached,
}

/// The HEAD state of the checkout holding `abs_vault`.
pub fn head_state(abs_vault: &Path) -> HeadState {
    let Some(root) = abs_vault.parent().and_then(worktree_root) else {
        return HeadState::NotARepo;
    };
    let dotgit = root.join(".git");
    let gitdir = if dotgit.is_dir() {
        dotgit
    } else {
        match fs::read_to_string(&dotgit)
            .ok()
            .and_then(|p| Some(root.join(p.trim().strip_prefix("gitdir:")?.trim())))
        {
            Some(dir) => dir,
            None => return HeadState::Detached,
        }
    };
    let reftable = gitdir.join("reftable").is_dir();
    let head = if reftable {
        // The reftable backend leaves HEAD as a stub (`refs/heads/.invalid`)
        // and keeps the real one in its tables: ask git.
        git_output(&root, &["symbolic-ref", "--quiet", "HEAD"]).map(|h| format!("ref: {h}"))
    } else {
        fs::read_to_string(gitdir.join("HEAD")).ok()
    };
    match head {
        Some(head) => match head.trim().strip_prefix("ref: refs/heads/") {
            Some(branch) => HeadState::Branch(stored_branch_name(&root, branch, reftable)),
            None => HeadState::Detached,
        },
        None => HeadState::Detached,
    }
}

/// The trimmed stdout of `git args` run in `dir` (murk's hardened git), or
/// `None` when git fails.
fn git_output(dir: &Path, args: &[&str]) -> Option<String> {
    let out = git_command()
        .args(args)
        .current_dir(dir)
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// `branch` as the repository stores it. On a case-insensitive filesystem
/// (`core.ignorecase`), `git checkout Main` checks out branch `main` while
/// HEAD records `Main`; the branch's trust marks are under the stored name,
/// so HEAD's spelling is mapped to the one ref that matches it ignoring
/// case. An exact match, no match, or several matches keep HEAD's spelling.
fn stored_branch_name(root: &Path, branch: &str, reftable: bool) -> String {
    let Some(common) = common_dir(root) else {
        return branch.to_string();
    };
    if !ignores_case(&common) {
        return branch.to_string();
    }
    let mut names = BTreeSet::new();
    if reftable {
        let refs = git_output(
            root,
            &["for-each-ref", "--format=%(refname)", "refs/heads/"],
        )
        .unwrap_or_default();
        names.extend(
            refs.lines()
                .filter_map(|l| l.strip_prefix("refs/heads/"))
                .map(str::to_string),
        );
    } else {
        collect_loose_refs(&common.join("refs/heads"), "", &mut names);
        if let Ok(packed) = fs::read_to_string(common.join("packed-refs")) {
            names.extend(
                packed
                    .lines()
                    .filter_map(|l| l.split_once(' ')?.1.strip_prefix("refs/heads/"))
                    .map(str::to_string),
            );
        }
    }
    if names.contains(branch) {
        return branch.to_string();
    }
    let mut folded = names.into_iter().filter(|n| n.eq_ignore_ascii_case(branch));
    match (folded.next(), folded.next()) {
        (Some(only), None) => only,
        _ => branch.to_string(),
    }
}

/// Whether the repository's config sets `core.ignorecase` true.
fn ignores_case(common: &Path) -> bool {
    let Ok(config) = fs::read_to_string(common.join("config")) else {
        return false;
    };
    let mut in_core = false;
    let mut ignore = false;
    for line in config.lines().map(str::trim) {
        if line.starts_with('[') {
            in_core = line
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim()
                .eq_ignore_ascii_case("core");
        } else if in_core
            && let Some((key, value)) = line.split_once('=')
            && key.trim().eq_ignore_ascii_case("ignorecase")
        {
            ignore = matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "true" | "yes" | "on" | "1"
            );
        }
    }
    ignore
}

/// Loose branch refs under `dir`, as names relative to `refs/heads`.
fn collect_loose_refs(dir: &Path, prefix: &str, out: &mut BTreeSet<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = format!("{prefix}{name}");
        match entry.file_type() {
            Ok(t) if t.is_dir() => collect_loose_refs(&entry.path(), &format!("{path}/"), out),
            Ok(t) if t.is_file() => {
                out.insert(path);
            }
            _ => {}
        }
    }
}

/// The commit checked out in the checkout holding `abs_vault`, as a full
/// hexadecimal id. `None` outside git, on an unborn branch, or when git
/// fails.
pub fn head_commit(abs_vault: &Path) -> Option<String> {
    let dir = abs_vault.parent()?;
    worktree_root(dir)?;
    let out = git_command()
        .args(["rev-parse", "--verify", "--quiet", "HEAD^{commit}"])
        .current_dir(dir)
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    let id = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (out.status.success() && is_commit_id(&id)).then_some(id)
}

fn is_commit_id(id: &str) -> bool {
    matches!(id.len(), 40 | 64) && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Run a git command in `dir`, output discarded; whether it succeeded.
fn git_succeeds(dir: &Path, cmd: &mut Command) -> bool {
    cmd.current_dir(dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Whether the vault file `name` in `dir` is exactly the one committed at
/// HEAD (tracked, no uncommitted change).
fn vault_committed_at_head(dir: &Path, name: &std::ffi::OsStr) -> bool {
    git_succeeds(
        dir,
        git_command()
            .args(["cat-file", "-e"])
            .arg(format!("HEAD:./{}", name.to_string_lossy())),
    ) && git_succeeds(
        dir,
        git_command()
            .args(["diff", "--quiet", "HEAD", "--"])
            .arg(name),
    )
}

/// The commit checked out in the checkout holding `abs_vault`, only when
/// the vault file is exactly the one committed there (see [`head_commit`]).
pub fn head_commit_holding_vault(abs_vault: &Path) -> Option<String> {
    let commit = head_commit(abs_vault)?;
    let (dir, name) = (abs_vault.parent()?, abs_vault.file_name()?);
    vault_committed_at_head(dir, name).then_some(commit)
}

/// Whether the commit checked out in the checkout holding `abs_vault` is
/// `commit` or an ancestor of it, and the vault file is exactly the one
/// committed at HEAD — so the vault being read is that commit's, not an
/// uncommitted copy of another. False when git fails, `commit` is unknown
/// here (rewritten and collected, say), or it is not a full commit id.
pub fn committed_vault_at_or_before(abs_vault: &Path, commit: &str) -> bool {
    let (Some(dir), Some(name)) = (abs_vault.parent(), abs_vault.file_name()) else {
        return false;
    };
    if !is_commit_id(commit) || worktree_root(dir).is_none() {
        return false;
    }
    is_ancestor(dir, "HEAD", commit) && vault_committed_at_head(dir, name)
}

/// Whether `a` is `b` or an ancestor of it, in the repository holding the
/// directory `dir` (`git merge-base --is-ancestor`). Each of `a` and `b` is
/// `HEAD` or a full commit id. False otherwise, and when git fails, for
/// example for a commit a rebase and `git gc` removed. Read-only: takes no
/// `index.lock`.
pub fn is_ancestor(dir: &Path, a: &str, b: &str) -> bool {
    let valid = |c: &str| c == "HEAD" || is_commit_id(c);
    valid(a)
        && valid(b)
        && git_succeeds(
            dir,
            git_command().args(["merge-base", "--is-ancestor", a, b]),
        )
}

/// The commit local branch `branch` points at, as a full id, in the
/// repository holding the directory `dir`. `None` when there is no such
/// branch (deleted, say) or git fails. Read-only: takes no `index.lock`.
pub fn branch_tip(dir: &Path, branch: &str) -> Option<String> {
    let spec = format!("refs/heads/{branch}^{{commit}}");
    let id = git_output(
        dir,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            &spec,
        ],
    )?;
    is_commit_id(&id).then_some(id)
}

/// The vault file `abs_vault` as committed at `commit` (a full commit id),
/// read with `git cat-file blob <commit>:./<name>` from the vault's
/// directory. `None` when the file is not in that commit, the commit is
/// missing here (a shallow clone, say), or git fails. Read-only: takes no
/// `index.lock`.
pub fn vault_at_commit(abs_vault: &Path, commit: &str) -> Option<Vec<u8>> {
    let (dir, name) = (abs_vault.parent()?, abs_vault.file_name()?.to_str()?);
    if !is_commit_id(commit) {
        return None;
    }
    let out = git_command()
        .args(["cat-file", "blob", &format!("{commit}:./{name}")])
        .current_dir(dir)
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status.success().then_some(out.stdout)
}

/// The most vault revisions [`vault_history_drops`] reads: commits that
/// change the vault file, on any path of HEAD's history back to the bound.
/// Past it the answer is [`HistoryCheck::TooLong`], which refuses a vault
/// listing the removed key. The cost of a walk to the cap: two `git rev-list`
/// runs and one blob read and JSON parse per distinct vault blob, about a
/// second per 10 MB of vault revisions, paid only when this machine reads a
/// vault that lists a key it recorded as removed, on a marked branch the
/// removal is not recorded on by name. A history longer than this costs only
/// that refusal, which `git fetch` cannot fix but `murk trust --re-add` or
/// `murk circle authorize` can.
pub const VAULT_HISTORY_CAP: usize = 10_000;

/// The largest vault revision [`vault_history_drops`] reads, in bytes
/// (8 MiB). A larger blob is not read: the walk runs under the trust pin
/// lock, and a repo writer could commit huge files to slow it down or
/// exhaust memory. Such a revision counts as unreadable, so the answer is
/// [`HistoryCheck::Unreadable`] (a refusal), never a load. A real vault is
/// far smaller.
pub const VAULT_BLOB_LIMIT: u64 = 8 * 1024 * 1024;

/// What [`vault_history_drops`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryCheck {
    /// A commit in the walk dropped the key.
    Found,
    /// The whole walk was read and no commit dropped the key.
    NotFound,
    /// No drop in the newest [`VAULT_HISTORY_CAP`] revisions, and there are
    /// more.
    TooLong,
    /// A shallow clone, and the walk reached its boundary before the bound.
    Shallow,
    /// A partial clone: a vault revision the walk needs was not downloaded.
    /// `remote` is the promisor remote.
    Partial { remote: String },
    /// The commit the removal was recorded at is not in this repository (a
    /// rewritten and garbage-collected history), or none was recorded.
    Gone,
    /// A vault revision in the walk could not be read: not a vault, its
    /// recipients do not parse, over [`VAULT_BLOB_LIMIT`], an object
    /// missing from a full clone, or a git failure.
    Unreadable,
}

/// The vault file at one commit, as the walk sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Listing {
    /// The vault's recipients do (`true`) or do not list the key.
    Lists(bool),
    /// No vault file at that commit: the commit's tree has no such entry.
    Absent,
    /// The commit's tree names a vault file whose object is not here (a
    /// partial clone, or a damaged repository).
    Missing,
    /// The file is there but is not a vault, its recipients do not parse,
    /// or it is over [`VAULT_BLOB_LIMIT`].
    Unreadable,
}

/// One running `git cat-file` process in batch mode: `--batch-check` for
/// object ids and sizes, or `--batch` for contents.
struct CatFile {
    child: std::process::Child,
    input: std::process::ChildStdin,
    output: std::io::BufReader<std::process::ChildStdout>,
}

impl CatFile {
    fn start(dir: &Path, mode: &str) -> Option<Self> {
        let mut child = git_command()
            .args(["cat-file", mode])
            .current_dir(dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        if let (Some(input), Some(output)) = (child.stdin.take(), child.stdout.take()) {
            return Some(Self {
                child,
                input,
                output: std::io::BufReader::new(output),
            });
        }
        let _ = child.kill();
        let _ = child.wait();
        None
    }

    /// Send `spec` and read the header line git answers with: `<oid> <type>
    /// <size>`, or `<spec> missing`. `None` when the stream broke.
    fn ask(&mut self, spec: &str) -> Option<Vec<String>> {
        use std::io::{BufRead, Write};
        let mut header = String::new();
        (writeln!(self.input, "{spec}").is_ok()
            && self.input.flush().is_ok()
            && self.output.read_line(&mut header).is_ok_and(|n| n > 0))
        .then(|| header.split_whitespace().map(str::to_string).collect())
    }

    /// The body of an object `--batch` answered with `size` bytes, read with
    /// its trailing newline. `None` when the stream broke.
    fn body(&mut self, size: usize) -> Option<Vec<u8>> {
        use std::io::Read;
        let mut bytes = vec![0; size + 1];
        self.output.read_exact(&mut bytes).ok()?;
        bytes.pop();
        Some(bytes)
    }
}

impl Drop for CatFile {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Whether the raw tree object `tree` (git's binary format, object ids of
/// `oid_len` bytes) has an entry named `name`.
fn tree_has_entry(tree: &[u8], name: &str, oid_len: usize) -> Option<bool> {
    let mut rest = tree;
    while !rest.is_empty() {
        let space = rest.iter().position(|&b| b == b' ')?;
        let nul = space + rest[space..].iter().position(|&b| b == 0)?;
        if &rest[space + 1..nul] == name.as_bytes() {
            return Some(true);
        }
        rest = rest.get(nul + 1 + oid_len..)?;
    }
    Some(false)
}

/// Reads the vault file at commits, once per distinct blob.
struct VaultReader<'a, F: Fn(&[u8]) -> Option<bool>> {
    name: &'a str,
    /// The vault's directory inside the checkout, as path components (empty
    /// at the root).
    prefix: Vec<String>,
    lists: F,
    check: CatFile,
    contents: CatFile,
    by_commit: std::collections::HashMap<String, Listing>,
    by_blob: std::collections::HashMap<String, Listing>,
    broken: bool,
}

impl<F: Fn(&[u8]) -> Option<bool>> VaultReader<'_, F> {
    fn at(&mut self, commit: &str) -> Listing {
        if let Some(&known) = self.by_commit.get(commit) {
            return known;
        }
        let listing = self.read(commit);
        self.by_commit.insert(commit.to_string(), listing);
        listing
    }

    fn read(&mut self, commit: &str) -> Listing {
        if self.broken {
            return Listing::Unreadable;
        }
        let Some(header) = self.check.ask(&format!("{commit}:./{}", self.name)) else {
            self.broken = true;
            return Listing::Unreadable;
        };
        match header.as_slice() {
            [oid, kind, size] if kind == "blob" => {
                let Ok(size) = size.parse::<u64>() else {
                    return Listing::Unreadable;
                };
                if let Some(&known) = self.by_blob.get(oid) {
                    return known;
                }
                let listing = if size > VAULT_BLOB_LIMIT {
                    Listing::Unreadable
                } else {
                    self.blob(oid)
                };
                self.by_blob.insert(oid.clone(), listing);
                listing
            }
            [.., last] if last == "missing" => self.missing(commit),
            _ => Listing::Unreadable,
        }
    }

    /// The vault blob `oid`, at most [`VAULT_BLOB_LIMIT`] bytes as
    /// `--batch-check` said.
    fn blob(&mut self, oid: &str) -> Listing {
        let Some(answer) = self.contents.ask(oid) else {
            self.broken = true;
            return Listing::Unreadable;
        };
        match answer.as_slice() {
            [_, kind, size] if kind == "blob" => {
                let Some(bytes) = size.parse().ok().and_then(|s| self.contents.body(s)) else {
                    self.broken = true;
                    return Listing::Unreadable;
                };
                (self.lists)(&bytes).map_or(Listing::Unreadable, Listing::Lists)
            }
            [.., last] if last == "missing" => Listing::Missing,
            _ => {
                self.broken = true;
                Listing::Unreadable
            }
        }
    }

    /// git answered `missing` for the vault file at `commit`: either the
    /// commit has no such file (the file, or a directory on its path, is not
    /// in the commit's tree) or the file's object is not here. Walking up the
    /// path from the vault's directory to the root, the first tree that is
    /// here tells which: no entry for the next path component means no vault
    /// file there ([`Listing::Absent`]; also a commit that deleted the whole
    /// vault directory, or one from before it existed); an entry means its
    /// object is missing ([`Listing::Missing`]).
    fn missing(&mut self, commit: &str) -> Listing {
        let mut path = self.prefix.clone();
        path.push(self.name.to_string());
        for depth in (0..path.len()).rev() {
            let spec = if depth == 0 {
                format!("{commit}^{{tree}}")
            } else {
                format!("{commit}:{}", path[..depth].join("/"))
            };
            let Some(header) = self.check.ask(&spec) else {
                self.broken = true;
                return Listing::Unreadable;
            };
            match header.as_slice() {
                [oid, kind, size] if kind == "tree" => {
                    let oid = oid.clone();
                    return match self.tree_has(&oid, size, &path[depth]) {
                        Some(true) => Listing::Missing,
                        Some(false) => Listing::Absent,
                        None => Listing::Unreadable,
                    };
                }
                [.., last] if last == "missing" => {}
                _ => return Listing::Unreadable,
            }
        }
        Listing::Missing
    }

    /// Whether tree `oid` (`size` bytes, as `--batch-check` said) has an
    /// entry named `name`. `None` when it cannot be read.
    fn tree_has(&mut self, oid: &str, size: &str, name: &str) -> Option<bool> {
        let size: usize = size.parse().ok()?;
        let Some(answer) = self.contents.ask(oid) else {
            self.broken = true;
            return None;
        };
        if answer.get(1).map(String::as_str) != Some("tree") {
            return None;
        }
        let Some(tree) = self.contents.body(size) else {
            self.broken = true;
            return None;
        };
        tree_has_entry(&tree, name, oid.len() / 2)
    }
}

/// The commits of `args` (a `git rev-list` command line, path-limited to the
/// vault file `name`), at most [`VAULT_HISTORY_CAP`], and whether there are
/// more. `None` when git fails.
fn vault_revisions(dir: &Path, name: &str, args: &[&str]) -> Option<(Vec<String>, bool)> {
    let cap = format!("--max-count={}", VAULT_HISTORY_CAP + 1);
    let path = format!("./{name}");
    let mut all = vec!["rev-list", &cap];
    all.extend_from_slice(args);
    all.extend_from_slice(&["--", &path]);
    let out = git_output(dir, &all)?;
    let mut revisions: Vec<String> = out
        .lines()
        .filter(|r| is_commit_id(r))
        .map(str::to_string)
        .collect();
    let more = revisions.len() > VAULT_HISTORY_CAP;
    revisions.truncate(VAULT_HISTORY_CAP);
    Some((revisions, more))
}

/// Each of `commits` with its parents, as committed (`git rev-list
/// --no-walk --parents --stdin`, no history simplification). `None` when git
/// fails or leaves one out.
fn parents_of(dir: &Path, commits: &[String]) -> Option<Vec<(String, Vec<String>)>> {
    use std::io::Write;
    let mut child = git_command()
        .args(["rev-list", "--no-walk=unsorted", "--parents", "--stdin"])
        .current_dir(dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let mut input = child.stdin.take()?;
    // git reads all of stdin before it writes, so this cannot fill both
    // pipes.
    let written = commits.iter().all(|c| writeln!(input, "{c}").is_ok());
    drop(input);
    let out = child.wait_with_output().ok()?;
    if !written || !out.status.success() {
        return None;
    }
    let parsed: Vec<(String, Vec<String>)> = String::from_utf8(out.stdout)
        .ok()?
        .lines()
        .filter_map(|line| {
            let mut ids = line.split_whitespace().map(str::to_string);
            Some((ids.next()?, ids.collect()))
        })
        .collect();
    (parsed.len() == commits.len()
        && parsed
            .iter()
            .all(|(c, ps)| is_commit_id(c) && ps.iter().all(|p| is_commit_id(p))))
    .then_some(parsed)
}

/// The shallow boundary of the repository holding `dir`: the commits listed
/// in its `shallow` file, whose parents this clone does not have. Empty for
/// a full clone; `None` when git fails.
fn shallow_commits(dir: &Path) -> Option<Vec<String>> {
    let path = git_output(dir, &["rev-parse", "--git-path", "shallow"])?;
    let path = dir.join(path);
    match fs::read_to_string(&path) {
        Ok(text) => Some(
            text.lines()
                .map(str::trim)
                .filter(|c| is_commit_id(c))
                .map(str::to_string)
                .collect(),
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(Vec::new()),
        Err(_) => None,
    }
}

/// Whether `commit` is in `range_top`'s history and not in `bound`'s: a
/// shallow boundary commit there means the walk from `range_top` back to
/// `bound` stopped early.
fn boundary_between(dir: &Path, boundary: &[String], bound: &str, range_top: &str) -> bool {
    boundary
        .iter()
        .any(|s| is_ancestor(dir, s, range_top) && !is_ancestor(dir, s, bound))
}

/// The promisor remote of a partial clone (`remote.<name>.promisor`, or the
/// older `extensions.partialClone`), if any.
fn promisor_remote(dir: &Path) -> Option<String> {
    // `--type=bool` makes git read every boolean spelling (true, yes, on, 1,
    // a bare key; any case) and print `true` or `false`.
    let listed = git_output(
        dir,
        &[
            "config",
            "--type=bool",
            "--get-regexp",
            r"^remote\..*\.promisor$",
        ],
    )
    .unwrap_or_default();
    listed
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(' ')?;
            (value.trim() == "true")
                .then(|| key.strip_prefix("remote.")?.strip_suffix(".promisor"))?
        })
        .map(str::to_string)
        .or_else(|| git_output(dir, &["config", "--get", "extensions.partialclone"]))
}

/// What to answer for an object the walk needed and did not find: a partial
/// clone did not download it, else the repository is damaged.
fn missing_object(dir: &Path) -> HistoryCheck {
    match promisor_remote(dir) {
        Some(remote) => HistoryCheck::Partial { remote },
        None => HistoryCheck::Unreadable,
    }
}

/// The walk's bound for [`vault_history_drops`]: `since` when its vault
/// lists the key, else the newest revision on `since`'s first-parent path
/// whose vault does. `Err` holds the answer when there is none to find.
fn walk_bound<F: Fn(&[u8]) -> Option<bool>>(
    reader: &mut VaultReader<'_, F>,
    dir: &Path,
    since: &str,
    boundary: &[String],
) -> Result<String, HistoryCheck> {
    match reader.at(since) {
        Listing::Lists(true) => return Ok(since.to_string()),
        Listing::Missing => return Err(missing_object(dir)),
        Listing::Unreadable => return Err(HistoryCheck::Unreadable),
        Listing::Lists(false) | Listing::Absent => {}
    }
    let Some((revisions, more)) = vault_revisions(dir, reader.name, &["--first-parent", since])
    else {
        return Err(HistoryCheck::Unreadable);
    };
    for r in revisions {
        match reader.at(&r) {
            Listing::Lists(true) => return Ok(r),
            Listing::Missing => return Err(missing_object(dir)),
            Listing::Unreadable => return Err(HistoryCheck::Unreadable),
            Listing::Lists(false) | Listing::Absent => {}
        }
    }
    Err(if more {
        HistoryCheck::TooLong
    } else if boundary.iter().any(|s| is_ancestor(dir, s, since)) {
        HistoryCheck::Shallow
    } else {
        HistoryCheck::Unreadable
    })
}

/// Whether HEAD's history holds a commit that dropped what `lists` looks for
/// from the vault file `abs_vault`: a commit whose vault `lists` answers
/// `Some(false)` for (or that has no vault file) while one of its parents'
/// vaults answers `Some(true)`. Every path of the history counts, not only
/// first parents, so a merge that makes another branch the first parent
/// does not hide the drop.
///
/// The walk is bounded below by a commit `B` that still lists it: `since`
/// (a full commit id) when its vault does, else the newest revision on
/// `since`'s own first-parent path whose vault does (for a removal accepted
/// at `since`, the vault just before the drop that `since` holds). It reads
/// `git rev-list --full-history B..HEAD -- <vault>` (every commit that
/// changes the vault file, reachable from HEAD and not from `B`), so a drop
/// already in `B`'s history (an older removal, undone before `since`) does
/// not count. Both walks read at most [`VAULT_HISTORY_CAP`] revisions.
///
/// It answers [`HistoryCheck::Found`] as soon as it sees a drop. Otherwise
/// anything it cannot decide makes the answer one of the other kinds,
/// never [`HistoryCheck::NotFound`]: a walk past the cap
/// ([`HistoryCheck::TooLong`]); a shallow clone whose boundary lies between
/// HEAD and `B`, or before the first listing revision on `since`'s path
/// ([`HistoryCheck::Shallow`]; a shallow clone whose fetched history holds
/// the whole walk is decided normally); a vault object a partial clone did
/// not download ([`HistoryCheck::Partial`]; one it did download is read
/// normally); `since` not in the repository ([`HistoryCheck::Gone`]); or a
/// revision that is not a vault, does not parse, is over
/// [`VAULT_BLOB_LIMIT`], or a git failure ([`HistoryCheck::Unreadable`]).
/// Lazy fetches are off (see [`git_command`]), so a missing object is never
/// downloaded here. Read-only: takes no `index.lock`.
pub fn vault_history_drops(
    abs_vault: &Path,
    since: &str,
    lists: impl Fn(&[u8]) -> Option<bool>,
) -> HistoryCheck {
    let (Some(dir), Some(name)) = (
        abs_vault.parent(),
        abs_vault.file_name().and_then(|n| n.to_str()),
    ) else {
        return HistoryCheck::Unreadable;
    };
    let Some(boundary) = shallow_commits(dir) else {
        return HistoryCheck::Unreadable;
    };
    let exists = |c: &str| {
        is_commit_id(c)
            && git_succeeds(
                dir,
                git_command().args(["cat-file", "-e", &format!("{c}^{{commit}}")]),
            )
    };
    if !exists(since) {
        return if boundary.is_empty() {
            HistoryCheck::Gone
        } else {
            HistoryCheck::Shallow
        };
    }
    let (Some(check), Some(contents)) = (
        CatFile::start(dir, "--batch-check"),
        CatFile::start(dir, "--batch"),
    ) else {
        return HistoryCheck::Unreadable;
    };
    let Some(prefix) = git_output(dir, &["rev-parse", "--show-prefix"]) else {
        return HistoryCheck::Unreadable;
    };
    let mut reader = VaultReader {
        name,
        prefix: prefix
            .split('/')
            .filter(|c| !c.is_empty())
            .map(str::to_string)
            .collect(),
        lists,
        check,
        contents,
        by_commit: std::collections::HashMap::new(),
        by_blob: std::collections::HashMap::new(),
        broken: false,
    };
    let bound = match walk_bound(&mut reader, dir, since, &boundary) {
        Ok(bound) => bound,
        Err(undecided) => return undecided,
    };
    let range = format!("{bound}..HEAD");
    let Some((revisions, more)) = vault_revisions(dir, name, &["--full-history", &range]) else {
        return HistoryCheck::Unreadable;
    };
    let Some(with_parents) = parents_of(dir, &revisions) else {
        return HistoryCheck::Unreadable;
    };
    let (mut missing, mut unreadable) = (false, false);
    let mut note = |l: Listing| match l {
        Listing::Missing => missing = true,
        Listing::Unreadable => unreadable = true,
        Listing::Lists(_) | Listing::Absent => {}
    };
    for (commit, parents) in &with_parents {
        let at = reader.at(commit);
        note(at);
        if !matches!(at, Listing::Lists(false) | Listing::Absent) {
            continue;
        }
        for parent in parents {
            match reader.at(parent) {
                Listing::Lists(true) => return HistoryCheck::Found,
                other => note(other),
            }
        }
    }
    if more {
        HistoryCheck::TooLong
    } else if boundary_between(dir, &boundary, &bound, "HEAD") {
        HistoryCheck::Shallow
    } else if missing {
        missing_object(dir)
    } else if unreadable || reader.broken {
        HistoryCheck::Unreadable
    } else {
        HistoryCheck::NotFound
    }
}

/// A path naming a vault the same way from every worktree of its repository:
/// the repository's common git directory joined with the vault's path inside
/// the checkout. `None` when the vault is not inside a git checkout.
///
/// The trust pin is keyed on this, so trusting a vault once covers every
/// worktree of the repository (an agent's throwaway checkout included).
pub(crate) fn repository_vault_identity(abs_vault: &Path) -> Option<PathBuf> {
    let root = worktree_root(abs_vault.parent()?)?;
    let relative = abs_vault.strip_prefix(&root).ok()?;
    let common = common_dir(&root)?;
    let common = fs::canonicalize(&common).unwrap_or(common);
    Some(common.join("murk-vault").join(relative))
}

/// The repository's common directory (the shared `.git` holding `objects/` and
/// `worktrees/`) for the checkout at `root`.
///
/// Resolved lexically, never through `fs::canonicalize`. Two callers compare
/// these values against each other — [`sibling_worktrees`] checks membership in
/// both directions — so both sides must live in one coordinate system. A
/// canonicalized path is a *different spelling* of the same directory: on
/// Windows it gains a `\\?\` verbatim prefix that no lexical path ever has, so
/// every genuine sibling compared unequal and worktree discovery rejected
/// everything. Lexical also matches how key lookup hashes a vault path
/// (`env::key_file_path`), which likewise does not resolve symlinks.
fn common_dir(root: &Path) -> Option<PathBuf> {
    let dotgit = root.join(".git");
    if dotgit.is_dir() {
        return Some(dotgit);
    }
    // A linked worktree's `.git` is a file pointing at `<common>/worktrees/<id>`,
    // which in turn records the common dir relative to itself.
    let pointer = fs::read_to_string(&dotgit).ok()?;
    let gitdir = root.join(pointer.trim().strip_prefix("gitdir:")?.trim());
    let common = match fs::read_to_string(gitdir.join("commondir")) {
        Ok(rel) => gitdir.join(rel.trim()),
        Err(_) => gitdir,
    };
    // Resolve the `../..` hop `commondir` spells it with, so the `.git` name
    // check in `sibling_worktrees` sees the directory itself.
    Some(lexical_normalize(&common))
}

/// Resolve `.` and `..` components textually, without touching the filesystem.
fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::CWD_LOCK;

    #[test]
    fn attribute_patterns_that_could_name_a_vault_are_found() {
        // (pattern, may match *.murk, may match .murk.*), the same with and
        // without core.ignorecase.
        for (pattern, suffix, prefix) in [
            ("*.murk", true, true),
            (".murk.*", true, true),
            ("*", true, true),
            ("**", true, true),
            ("a/**", true, true),
            ("prod.*", true, false),
            ("prod.murk", true, false),
            ("/config/.murk.prod", false, true),
            ("[!x].murk", true, false),
            ("[ps]rod.murk", true, false),
            ("*.mur?", true, true),
            ("*.[l-n]urk", true, true),
            ("*[[:alpha:]]", true, true),
            (".murk.prod", false, true),
            (".murk", true, false),
            ("*.txt", false, true),
            ("prod.txt", false, false),
            ("*.murkx", false, true),
            ("[!.]murk", false, false),
            ("*.mur[!k]", false, true),
            ("x.murk.*", true, false),
            ("prod.mur[!k]", false, false),
            ("*.murk/x", false, false),
            ("?", false, false),
            (".[a-z]urk", true, false),
            (".[!m]urk", false, false),
        ] {
            for fold in [false, true] {
                assert_eq!(
                    (
                        glob_may_match_vault(pattern, true, false, fold),
                        glob_may_match_vault(pattern, false, true, fold)
                    ),
                    (suffix, prefix),
                    "{pattern} fold={fold}"
                );
            }
        }
        // Case matters: (pattern, (*.murk, .murk.*) without core.ignorecase,
        // the same with it).
        for (pattern, exact, folded) in [
            ("PROD.MURK", (false, false), (true, false)),
            (".[!M]urk", (true, false), (true, false)),
            (".[^M]urk", (true, false), (true, false)),
            (".[!A-Z]urk", (true, false), (true, false)),
            (".[!M]urk.prod", (false, true), (false, true)),
            (".[M]urk", (false, false), (true, false)),
            (".[A-Z]urk", (false, false), (true, false)),
        ] {
            for (fold, want) in [(false, exact), (true, folded)] {
                assert_eq!(
                    (
                        glob_may_match_vault(pattern, true, false, fold),
                        glob_may_match_vault(pattern, false, true, fold)
                    ),
                    want,
                    "{pattern} fold={fold}"
                );
            }
        }
    }

    #[test]
    fn attribute_pattern_judgement_covers_everything_git_matches() {
        // git is the oracle: for each pattern and case mode, every name in
        // the table that git gives both the pattern's attribute and one of
        // murk's lines must be one the matcher reports.
        let patterns = [
            ".[!M]urk",
            ".[^M]urk",
            ".[!A-Z]urk",
            ".[!M]urk.prod",
            ".[!m]urk",
            ".[a-z]urk",
            ".[A-Z]urk",
            ".[M]urk",
            "[!a]rod.murk",
            "[!x].murk",
            "prod.*",
            "*.prod",
            "PROD.MURK",
            ".MURK",
            ".Murk.*",
            "*.MURK",
            "*.mur[!k]",
            "*.mur[!K]",
            "[[:upper:]]*.murk",
            "secrets/**",
            "?murk",
            "*urk",
            ".mur[a-l]",
        ];
        let names = [
            ".murk",
            ".Murk",
            ".MURK",
            ".mUrk",
            ".murK",
            "prod.murk",
            "Prod.murk",
            "prod.MURK",
            "arod.murk",
            "xrod.murk",
            "a.murk",
            "x.murk",
            ".murk.prod",
            ".Murk.prod",
            ".MURK.PROD",
            ".murk.PROD",
            "secrets/a.murk",
            "Q.murk",
            ".murk.murk",
            "murk.murk",
        ];
        let dir = tempfile::tempdir().unwrap();
        let git = |args: &[String]| {
            let out = std::process::Command::new("git")
                .args(args)
                .current_dir(dir.path())
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_ATTR_NOSYSTEM", "1")
                .output()
                .unwrap();
            assert!(out.status.success(), "{args:?}");
            String::from_utf8_lossy(&out.stdout).into_owned()
        };
        git(&["init".to_string(), "-q".to_string()]);
        for pattern in patterns {
            fs::write(
                dir.path().join(".gitattributes"),
                format!("*.murk vs\n.murk.* vp\n{pattern} merge=custom\n"),
            )
            .unwrap();
            for fold in [false, true] {
                let mut args: Vec<String> = [
                    "-c",
                    &format!("core.ignorecase={fold}"),
                    "check-attr",
                    "-z",
                    "vs",
                    "vp",
                    "merge",
                    "--",
                ]
                .iter()
                .map(ToString::to_string)
                .collect();
                args.extend(names.iter().map(ToString::to_string));
                let out = git(&args);
                let fields: Vec<&str> = out.split('\0').collect();
                let mut attrs = std::collections::HashMap::new();
                for f in fields.as_chunks::<3>().0 {
                    attrs.insert((f[0], f[1]), f[2]);
                }
                for name in names {
                    if attrs[&(name, "merge")] != "custom" {
                        continue;
                    }
                    if attrs[&(name, "vs")] == "set" {
                        assert!(
                            glob_may_match_vault(pattern, true, false, fold),
                            "{pattern} fold={fold}: git matches {name} (*.murk)"
                        );
                    }
                    if attrs[&(name, "vp")] == "set" {
                        assert!(
                            glob_may_match_vault(pattern, false, true, fold),
                            "{pattern} fold={fold}: git matches {name} (.murk.*)"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn attribute_lines_that_touch_merge_are_found() {
        let macros = BTreeSet::from(["binary".to_string(), "mine".to_string()]);
        for token in [
            "merge",
            "-merge",
            "!merge",
            "merge=custom",
            "binary",
            "-mine",
        ] {
            assert!(touches_merge(token, &macros), "{token}");
        }
        for token in ["merge=murk", "text", "-diff", "diff=merge"] {
            assert!(!touches_merge(token, &macros), "{token}");
        }
        assert_eq!(
            parse_attribute_line(r#""my vault.murk" merge=custom"#),
            Some((Some("my vault.murk".to_string()), vec!["merge=custom"]))
        );
        assert_eq!(
            parse_attribute_line("[attr]mine -merge -text"),
            Some((None, vec!["-merge", "-text"]))
        );
        assert_eq!(parse_attribute_line("  # note"), None);
        assert_eq!(
            parse_attribute_line(r#""prod.\155urk" merge=custom"#),
            Some((Some("prod.murk".to_string()), vec!["merge=custom"]))
        );
        assert_eq!(
            parse_attribute_line(r#""a\\b\"c" -merge"#),
            Some((Some("a\\b\"c".to_string()), vec!["-merge"]))
        );
        // Invalid quoting: git ignores the line.
        assert_eq!(parse_attribute_line(r#""a\qb" merge=x"#), None);
    }

    #[test]
    fn a_case_folded_head_maps_to_the_stored_branch_where_git_ignores_case() {
        // HEAD as `git checkout Main` leaves it on a case-insensitive
        // filesystem, where the branch is stored as `main`. Written by hand,
        // so this runs the same on any filesystem.
        let dir = tempfile::tempdir().unwrap();
        let git = dir.path().join(".git");
        std::fs::create_dir_all(git.join("refs/heads/team")).unwrap();
        std::fs::write(git.join("refs/heads/main"), "0\n").unwrap();
        std::fs::write(
            git.join("packed-refs"),
            "# pack-refs\n1 refs/heads/team/Feature\n",
        )
        .unwrap();
        let vault = dir.path().join(".murk");
        let head = |h: &str| {
            std::fs::write(git.join("HEAD"), format!("ref: refs/heads/{h}\n")).unwrap();
            head_state(&vault)
        };
        let branch = |b: &str| HeadState::Branch(b.into());
        // Without core.ignorecase the names are distinct branches.
        std::fs::write(git.join("config"), "[core]\n\tbare = false\n").unwrap();
        assert_eq!(head("Main"), branch("Main"));
        std::fs::write(git.join("config"), "[core]\n\tignorecase = true\n").unwrap();
        assert_eq!(head("Main"), branch("main"));
        assert_eq!(head("main"), branch("main"));
        assert_eq!(head("TEAM/feature"), branch("team/Feature"));
        // No ref matches: an unborn branch keeps HEAD's spelling.
        assert_eq!(head("Other"), branch("Other"));
        // Two refs match ignoring case (packed and loose): ambiguous, kept.
        std::fs::write(git.join("packed-refs"), "1 refs/heads/MAIN\n").unwrap();
        assert_eq!(head("Main"), branch("Main"));
    }

    #[test]
    fn setup_merge_driver_creates_gitattributes() {
        let _lock = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join("murk_test_git_setup");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Init a git repo so git config works.
        Command::new("git")
            .args(["init"])
            .current_dir(&dir)
            .output()
            .unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        let steps = setup_merge_driver().unwrap().steps;
        assert!(steps.contains(&MergeDriverSetupStep::GitattributesCreated));
        assert!(steps.contains(&MergeDriverSetupStep::GitConfigured));

        let contents = std::fs::read_to_string(dir.join(".gitattributes")).unwrap();
        assert!(contents.contains("*.murk merge=murk"));

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn setup_merge_driver_appends_gitattributes() {
        let _lock = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join("murk_test_git_append");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        Command::new("git")
            .args(["init"])
            .current_dir(&dir)
            .output()
            .unwrap();

        std::fs::write(dir.join(".gitattributes"), "*.txt text\n").unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        let steps = setup_merge_driver().unwrap().steps;
        assert!(steps.contains(&MergeDriverSetupStep::GitattributesAppended));

        let contents = std::fs::read_to_string(dir.join(".gitattributes")).unwrap();
        assert!(contents.contains("*.txt text"));
        assert!(contents.contains("*.murk merge=murk"));

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn setup_merge_driver_already_exists() {
        let _lock = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join("murk_test_git_exists");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        Command::new("git")
            .args(["init"])
            .current_dir(&dir)
            .output()
            .unwrap();

        std::fs::write(
            dir.join(".gitattributes"),
            "*.murk merge=murk\n.murk.* merge=murk\n",
        )
        .unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        let steps = setup_merge_driver().unwrap().steps;
        assert!(steps.contains(&MergeDriverSetupStep::GitattributesAlreadyExists));

        std::env::set_current_dir(original_dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn last_commit_signature_unsigned_commit() {
        let _lock = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();

        Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::fs::write(dir.join("vault.murk"), "data\n").unwrap();
        Command::new("git")
            .args(["add", "vault.murk"])
            .current_dir(dir)
            .output()
            .unwrap();
        // Explicit identity + gpgsign=false so the commit lands unsigned
        // regardless of the runner's global git config.
        Command::new("git")
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.com",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-m",
                "add vault",
            ])
            .current_dir(dir)
            .output()
            .unwrap();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir).unwrap();
        let sig = last_commit_signature("vault.murk", &[]);
        std::env::set_current_dir(original_dir).unwrap();

        assert_eq!(sig, Some(CommitSignature::Unsigned));
    }

    #[test]
    fn last_commit_signature_untracked_path_is_none() {
        let _lock = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();

        Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .output()
            .unwrap();
        // A commit exists, but for a *different* file — so `git log` succeeds
        // with empty output for the queried path: the "no anchor" branch.
        std::fs::write(dir.join("other.txt"), "x\n").unwrap();
        Command::new("git")
            .args(["add", "other.txt"])
            .current_dir(dir)
            .output()
            .unwrap();
        let commit = Command::new("git")
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.com",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-m",
                "seed",
            ])
            .current_dir(dir)
            .output()
            .unwrap();
        // If the seed commit fails, `git log` would error (not return empty) and
        // the None below would come from the wrong branch — assert it landed.
        assert!(
            commit.status.success(),
            "seed commit must succeed: {}",
            String::from_utf8_lossy(&commit.stderr)
        );

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir).unwrap();
        let sig = last_commit_signature("never-committed.murk", &[]);
        std::env::set_current_dir(original_dir).unwrap();

        assert_eq!(sig, None);
    }

    #[test]
    fn commit_signature_status_maps_to_what_git_vouches_for() {
        let signer = |key: &str, fp: &str| CommitSigner {
            key: key.into(),
            fingerprint: fp.into(),
        };
        let fp = "SHA256:abc";
        let line = |status: &str| format!("{status}\0{fp}\0{fp}");
        // G and U both mean the signature checked out; neither says whose key it is.
        for status in ["G", "U"] {
            assert_eq!(
                parse_commit_signature(&line(status)),
                Some(CommitSignature::Verified(signer(fp, fp))),
                "{status}"
            );
        }
        // X, Y and E are signatures git cannot vouch for, and keep their status.
        for status in ['X', 'Y', 'E'] {
            assert_eq!(
                parse_commit_signature(&line(&status.to_string())),
                Some(CommitSignature::Unverified {
                    status,
                    signer: signer(fp, fp)
                }),
                "{status}"
            );
        }
        assert_eq!(
            parse_commit_signature(&line("B")),
            Some(CommitSignature::Bad)
        );
        assert_eq!(
            parse_commit_signature(&line("R")),
            Some(CommitSignature::Bad)
        );
        assert_eq!(
            parse_commit_signature("N\0\0"),
            Some(CommitSignature::Unsigned)
        );
        // No commit touches the path, or a status git does not define.
        assert_eq!(parse_commit_signature(""), None);
        assert_eq!(parse_commit_signature(&line("Z")), None);
        assert_eq!(parse_commit_signature(&line("GG")), None);
    }

    #[test]
    fn commit_signer_id_prefers_the_fingerprint() {
        let both = CommitSigner {
            key: "KEYID".into(),
            fingerprint: "FINGERPRINT".into(),
        };
        assert_eq!(both.id(), Some("FINGERPRINT"));
        let key_only = CommitSigner {
            key: "KEYID".into(),
            fingerprint: String::new(),
        };
        assert_eq!(key_only.id(), Some("KEYID"));
        let neither = CommitSigner {
            key: String::new(),
            fingerprint: String::new(),
        };
        assert_eq!(neither.id(), None);
    }

    #[test]
    fn allowed_signers_file_lists_only_ssh_ed25519_keys_without_comments() {
        let key = crate::testutil::SSH_ED25519_PK;
        let keys = vec![
            format!("{key} someone@host"),
            "ssh-rsa AAAAB3xyz".to_string(),
            "age1abc".to_string(),
        ];
        let (dir, path) = write_allowed_signers(&keys).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("murk-trusted-signer namespaces=\"git\" {key}\n")
        );
        drop(dir);
        assert!(!path.exists(), "the temporary directory is removed");
    }

    #[test]
    fn setup_merge_driver_outside_repo_errors() {
        let _lock = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // No `git init`: there is no working tree to configure, so setup must
        // fail before writing anything, rather than leave a stray
        // .gitattributes or claim the merge driver was configured.
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir).unwrap();
        let result = setup_merge_driver();
        std::env::set_current_dir(original_dir).unwrap();

        let err = result.unwrap_err();
        assert!(
            err.contains("not inside a git working tree"),
            "expected not-a-repo guidance, got: {err}"
        );
        assert!(!dir.join(".gitattributes").exists());
    }

    // ── worktree layout ──

    /// Create a repo with one commit at `dir` and return its canonical path.
    /// `git worktree add` records canonical paths, so the fixture must use them
    /// too or the comparisons below drift on macOS (`/var` → `/private/var`).
    fn init_repo_with_commit(dir: &Path) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let dir = crate::testutil::real_path(dir);
        git_in(&dir, &["init"]);
        std::fs::write(dir.join("README"), "x\n").unwrap();
        git_in(&dir, &["add", "README"]);
        git_in(&dir, &["commit", "-m", "init"]);
        dir
    }

    fn git_in(dir: &Path, args: &[&str]) {
        let output = Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@test.com")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@test.com")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn worktree_root_finds_nearest_checkout() {
        let tmp = tempfile::TempDir::new().unwrap();
        let main = init_repo_with_commit(&tmp.path().join("main"));
        let nested = main.join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();

        assert_eq!(worktree_root(&nested), Some(main.clone()));
        assert_eq!(worktree_root(&main), Some(main));
    }

    #[test]
    fn worktree_root_outside_a_repo_is_none() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = crate::testutil::real_path(tmp.path());
        assert_eq!(worktree_root(&dir), None);
    }

    #[test]
    fn sibling_worktrees_sees_main_and_linked_checkouts() {
        let tmp = tempfile::TempDir::new().unwrap();
        let main = init_repo_with_commit(&tmp.path().join("main"));
        let root = crate::testutil::real_path(tmp.path());
        let first = root.join("wt-a");
        let second = root.join("wt-b");
        git_in(
            &main,
            &["worktree", "add", "--detach", first.to_str().unwrap()],
        );
        git_in(
            &main,
            &["worktree", "add", "--detach", second.to_str().unwrap()],
        );

        // From the main checkout: only the linked worktrees, sorted.
        assert_eq!(
            sibling_worktrees(&main),
            vec![first.clone(), second.clone()]
        );
        // From a linked worktree: the main checkout first, then the other link.
        // Main first is what makes the original checkout's key win when several
        // worktrees have one stored.
        assert_eq!(
            sibling_worktrees(&first),
            vec![main.clone(), second.clone()]
        );
        // A checkout never lists itself.
        assert!(!sibling_worktrees(&second).contains(&second));
    }

    #[test]
    fn sibling_worktrees_of_a_lone_repo_is_empty() {
        let tmp = tempfile::TempDir::new().unwrap();
        let main = init_repo_with_commit(&tmp.path().join("solo"));
        let found = sibling_worktrees(&main);
        assert!(found.is_empty(), "{found:?}");

        let bare = crate::testutil::real_path(tmp.path()).join("not-a-repo");
        std::fs::create_dir_all(&bare).unwrap();
        let found = sibling_worktrees(&bare);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn sibling_worktrees_of_a_bare_repo_layout_skips_the_container() {
        // The `.bare` + worktrees layout has no main working tree, so the
        // parent of the common dir is a plain directory, not a checkout — it
        // must not be offered as a sibling.
        let tmp = tempfile::TempDir::new().unwrap();
        let root = crate::testutil::real_path(tmp.path());
        let seed = init_repo_with_commit(&root.join("seed"));
        let bare = root.join("proj").join(".bare");
        std::fs::create_dir_all(root.join("proj")).unwrap();
        git_in(
            &root,
            &[
                "clone",
                "--bare",
                seed.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
        );

        let checkout = root.join("proj").join("main");
        git_in(
            &bare,
            &["worktree", "add", "--detach", checkout.to_str().unwrap()],
        );

        assert_eq!(sibling_worktrees(&checkout), Vec::<PathBuf>::new());
    }

    #[test]
    fn bare_repo_worktrees_still_see_each_other() {
        // The layout agent harnesses use: a bare repo plus N checkouts, none of
        // which is a main working tree. They are still siblings.
        let tmp = tempfile::TempDir::new().unwrap();
        let root = crate::testutil::real_path(tmp.path());
        let seed = init_repo_with_commit(&root.join("seed"));
        let bare = root.join("proj").join(".bare");
        std::fs::create_dir_all(root.join("proj")).unwrap();
        git_in(
            &root,
            &[
                "clone",
                "--bare",
                seed.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
        );

        let first = root.join("proj").join("a");
        let second = root.join("proj").join("b");
        git_in(
            &bare,
            &["worktree", "add", "--detach", first.to_str().unwrap()],
        );
        git_in(
            &bare,
            &["worktree", "add", "--detach", second.to_str().unwrap()],
        );

        assert_eq!(sibling_worktrees(&first), vec![second]);
    }

    #[test]
    fn planted_git_pointer_into_another_repo_lists_nothing() {
        // A directory is not a worktree just because it says so. Anyone who can
        // drop a `.git` file — an unpacked tarball, an agent writing files —
        // could otherwise nominate a victim repository and borrow its key.
        let tmp = tempfile::TempDir::new().unwrap();
        let root = crate::testutil::real_path(tmp.path());
        let main = init_repo_with_commit(&root.join("main"));
        let real = root.join("real-wt");
        git_in(
            &main,
            &["worktree", "add", "--detach", real.to_str().unwrap()],
        );

        // Point at the registered worktree's own git dir: maximally plausible,
        // and still not a checkout git knows about.
        let stolen = std::fs::read_to_string(real.join(".git")).unwrap();
        let evil = root.join("evil");
        std::fs::create_dir_all(&evil).unwrap();
        std::fs::write(evil.join(".git"), stolen).unwrap();

        assert_eq!(sibling_worktrees(&evil), Vec::<PathBuf>::new());
        // The genuine worktree is unaffected.
        assert_eq!(sibling_worktrees(&real), vec![main]);
    }

    #[test]
    fn planted_git_dir_naming_a_foreign_checkout_lists_nothing() {
        // The mirror image: a real (attacker-owned) repository whose
        // `worktrees/` entry names someone else's checkout. That checkout
        // points at its own common dir, so it is not a sibling.
        let tmp = tempfile::TempDir::new().unwrap();
        let root = crate::testutil::real_path(tmp.path());
        let victim = init_repo_with_commit(&root.join("victim"));
        let evil = init_repo_with_commit(&root.join("evil"));

        let forged = evil.join(".git").join("worktrees").join("x");
        std::fs::create_dir_all(&forged).unwrap();
        std::fs::write(
            forged.join("gitdir"),
            format!("{}\n", victim.join(".git").display()),
        )
        .unwrap();

        assert_eq!(sibling_worktrees(&evil), Vec::<PathBuf>::new());
    }
}
