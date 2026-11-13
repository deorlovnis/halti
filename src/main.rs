//! halti — macOS Keychain-backed secrets for humans and agents.
//!
//! Secrets are grouped by resource: one thing you sign in to (GitHub, AWS, …). A resource has
//! fields — token, user, password, … — each its own Keychain item. What may happen to them is
//! decided by the resource's policy, which counts only once approved with Touch ID: which
//! fields `halti run` exports, how fields refresh, and what an agent may do through `halti mcp`.
//! Agents never get the credentials themselves.

// `halti_dev` (the test hooks) comes from build.rs, for the debug profile only; every other
// profile gets `halti_release`. Both at once means `--cfg halti_dev` came from somewhere else.
#[cfg(all(halti_dev, any(halti_release, not(debug_assertions))))]
compile_error!("halti_dev is only for debug-profile builds: a release build or one without debug assertions must not have the test hooks");

mod approval;
mod approve;
mod audit;
mod boxes;
mod browse;
mod browser;
mod chain;
mod config;
mod door;
mod engine;
mod fetch;
mod index;
mod keychain;
// Mostly read by nothing until the migration of an install made under the old name exists.
#[allow(dead_code)]
mod legacy;
mod limits;
mod mask;
mod mcp;
mod names;
mod policy;
mod refresh;
#[cfg(all(halti_dev, target_os = "linux"))]
mod sandbox;
mod seal;
mod source;
mod util;
mod ws;

use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::sync::Arc;
use std::thread;

use aho_corasick::{AhoCorasick, MatchKind};
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use jiff::civil::Date;

use index::{Expiry, Field, Index, Meta, days_left, jwt_exp, store, warn_days};
use policy::Mode;
use refresh::{auto_resources, refresh_due};

const MASK: &[u8] = b"********";

/// The target check.sh builds and tests this source on. x86_64 Linux and macOS aren't, until
/// there is a machine to run them on.
const VERIFIED: &str = "linux-aarch64";

#[derive(Parser)]
#[command(name = "halti", version, about = "Keychain-backed secrets for humans and agents")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Store or rotate a field (hidden prompt); creates the resource and asks for what's missing
    Set {
        #[arg(value_parser = parse_resource)]
        resource: String,
        #[arg(value_parser = parse_field)]
        field: String,
        #[arg(long, value_parser = parse_date)]
        expires: Option<Date>,
        #[command(flatten)]
        meta: Meta,
    },
    /// Replace a field with the clipboard contents, then clear the clipboard
    #[command(visible_alias = "rotate")]
    Update {
        #[arg(value_parser = parse_resource)]
        resource: String,
        #[arg(value_parser = parse_field)]
        field: String,
        #[arg(long, value_parser = parse_date)]
        expires: Option<Date>,
    },
    /// Change a resource's link/description ("" clears; no flags = prompt)
    Describe {
        #[arg(value_parser = parse_resource)]
        resource: String,
        #[command(flatten)]
        meta: Meta,
    },
    /// Show, edit or approve a resource's policy (what may happen to its secrets)
    Policy {
        #[command(subcommand)]
        action: PolicyCmd,
    },
    /// Refresh fields due within the hour, as the policies say (all of them with --force)
    Refresh {
        #[arg(value_parser = parse_resource)]
        resources: Vec<String>,
        #[arg(long)]
        force: bool,
    },
    /// Show a resource, its policy and its fields (never values)
    Info {
        #[arg(value_parser = parse_resource)]
        resource: String,
    },
    /// List resources (never values)
    #[command(visible_alias = "list")]
    Ls,
    /// List expired/expiring fields; exit 1 if any
    Check {
        /// Warning window in days [default: $HALTI_WARN_DAYS or 14]
        days: Option<i64>,
    },
    /// Delete one field, or the whole resource
    #[command(visible_alias = "delete")]
    Rm {
        #[arg(value_parser = parse_resource)]
        resource: String,
        #[arg(value_parser = parse_field)]
        field: Option<String>,
    },
    /// Copy a field's value to the clipboard (asks for Touch ID)
    Copy {
        #[arg(value_parser = parse_resource)]
        resource: String,
        #[arg(value_parser = parse_field)]
        field: String,
    },
    /// Run CMD with the fields the policies export, values masked in its output
    #[command(after_help = "Name each resource with -s RESOURCE (at least one; repeat for more). \
                            Each resource's policy decides: [run] mode = allow, ask (Touch ID) or deny.")]
    Run {
        #[arg(short = 's', long = "secret", value_name = "RESOURCE", required = true, value_parser = parse_resource)]
        resources: Vec<String>,
        #[arg(last = true, required = true, value_name = "CMD")]
        command: Vec<String>,
    },
    /// Serve agents over MCP (stdio): requests and site tools, credentials added by halti
    Mcp,
    /// Show what agents did through `halti mcp` (never values); --verify checks nothing was altered
    Audit {
        /// How many of the latest entries to show
        #[arg(short = 'n', long, default_value_t = 20)]
        last: usize,
        /// Check the whole log against its Keychain-held HMAC chain
        #[arg(long)]
        verify: bool,
    },
    /// Re-create Keychain items so only the running halti may read them (after re-signing halti)
    Reseal {
        #[arg(value_parser = parse_resource)]
        resources: Vec<String>,
    },
    /// Boxes: isolated, encrypted places where an agent works, with halti as its only door
    #[command(name = "box")]
    Box {
        #[command(subcommand)]
        action: BoxCmd,
    },
    /// Edit halti's settings and approve them (--show: the settings in effect, --default: the template)
    Config {
        /// Show the settings in effect and change nothing
        #[arg(long, conflicts_with = "default")]
        show: bool,
        /// Print halti's template and change nothing
        #[arg(long)]
        default: bool,
    },
    /// Workspaces, each opened with its own passphrase: create, list and delete them, store secrets in them, approve their policies, and run their boxes
    Ws {
        #[command(subcommand)]
        action: WsCmd,
    },
    /// Check a workspace's passphrase and files (workspaces can't stay open yet)
    Open {
        /// The workspace; may be left out when there is only one
        name: Option<String>,
        /// Type the passphrase, whatever halti config says
        #[arg(long = "type")]
        type_it: bool,
    },
    /// Close a workspace (workspaces can't stay open yet, so there is nothing to close)
    Close {
        /// The workspace; may be left out when there is only one
        name: Option<String>,
    },
    /// How this binary was built: whether it has the test hooks, its target, and where it keeps its files
    #[command(name = "build-info", hide = true)]
    BuildInfo,
    /// Makes a sandbox's namespaces and runs CMD in it: what `box sh --engine sandbox` starts
    #[cfg(all(halti_dev, target_os = "linux"))]
    #[command(name = "__sandbox-init", hide = true)]
    SandboxInit {
        /// The pid of the `box sh` that started it
        #[arg(long)]
        parent: libc::pid_t,
        #[arg(long = "tool", value_name = "PATH")]
        tools: Vec<PathBuf>,
        #[arg(last = true, required = true, value_name = "CMD")]
        command: Vec<String>,
    },
}

#[derive(Subcommand)]
enum BoxCmd {
    /// Make a box: edit its policy from a template, create its key and an empty encrypted store
    New {
        #[arg(value_parser = boxes::parse_name)]
        name: String,
    },
    /// Open a box's policy in $EDITOR; shows what changed from the approved one
    Edit {
        #[arg(value_parser = boxes::parse_name)]
        name: String,
    },
    /// Approve box policies with one Touch ID (all of them if none named); until then they have no effect
    Approve {
        #[arg(value_parser = boxes::parse_name)]
        names: Vec<String>,
    },
    /// Open a box (Touch ID) and work in it; joins it if it runs already
    #[command(after_help = "Without CMD, runs the policy's `run` (claude). --temp makes a throwaway box with the \
                            same policy, shredded when it stops. Ctrl-C or closing the terminal stops the box.")]
    Run {
        /// A throwaway box: new store, key never written down, gone when it stops
        #[arg(long)]
        temp: bool,
        #[arg(value_parser = boxes::parse_name)]
        name: String,
        #[arg(last = true, value_name = "CMD")]
        command: Vec<String>,
    },
    /// List boxes: open or locked, policy status, size, sites, last used
    #[command(visible_alias = "list")]
    Ls,
    /// Show what went through a box's door (Touch ID unless it is open)
    Log {
        #[arg(value_parser = boxes::parse_name)]
        name: String,
        /// How many of the latest lines to show
        #[arg(short = 'n', long, default_value_t = 50)]
        last: usize,
        /// Check the whole log against its chain instead: fails at the first line that was changed or removed
        #[arg(long)]
        verify: bool,
    },
    /// Stop a running box and lock it
    Stop { name: String },
    /// Copy a file or folder out of a box (Touch ID); lists each file with its size and sha256
    Export {
        #[arg(value_parser = boxes::parse_name)]
        name: String,
        /// Path inside the box, e.g. work/report.md
        path: String,
        /// Folder on this Mac to copy it into
        #[arg(long, value_name = "DIR")]
        to: PathBuf,
    },
    /// Copy a file or folder into a box's work/ folder (box stopped)
    Import {
        #[arg(value_parser = boxes::parse_name)]
        name: String,
        path: String,
    },
    /// Sign in to a box's sites by hand, in a window on this Mac; halti seals each session into the box (Touch ID, box stopped)
    #[command(after_help = "Without SITE, goes through the box's sites that allow browsing and have no sealed session yet, one window after another. \
Closing a window (or Enter) takes the session; Ctrl-C skips that site. --all signs in again to the ones that have a session.")]
    Login {
        #[arg(value_parser = boxes::parse_name)]
        name: String,
        #[arg(value_parser = parse_resource)]
        site: Option<String>,
        /// Include sites that already have a sealed session
        #[arg(long)]
        all: bool,
    },
    /// Delete a box for good: its key first, then its store (Touch ID)
    Rm {
        #[arg(value_parser = boxes::parse_name)]
        name: String,
    },
    /// A shell, or CMD, in a new sandbox with no store, door or policy (debug builds on Linux)
    #[cfg(all(halti_dev, target_os = "linux"))]
    Sh {
        /// The only one yet: a rootless kernel sandbox
        #[arg(long, value_parser = ["sandbox"])]
        engine: String,
        /// A host file or folder the box may run, read-only at the same path (claude is one already)
        #[arg(long = "tool", value_name = "PATH")]
        tools: Vec<PathBuf>,
        #[arg(last = true, value_name = "CMD")]
        command: Vec<String>,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Print the policy and whether it is approved
    Show {
        #[arg(value_parser = parse_resource)]
        resource: String,
    },
    /// Open the policy in $EDITOR (a template if new); approve it afterwards
    Edit {
        #[arg(value_parser = parse_resource)]
        resource: String,
    },
    /// Approve policies with one Touch ID (all of them if none named); until then they have no effect
    Approve {
        #[arg(value_parser = parse_resource)]
        resources: Vec<String>,
    },
}

#[derive(Subcommand)]
enum WsCmd {
    /// Create a workspace with its own passphrase (yours, or one halti makes: as halti config says, unless --own or --generate)
    New {
        name: String,
        /// Type a passphrase of your own
        #[arg(long, conflicts_with = "generate")]
        own: bool,
        /// Have halti make the passphrase and show it once
        #[arg(long)]
        generate: bool,
    },
    /// Store a secret in a workspace, typed unseen or piped in (asks as halti config says)
    Set {
        #[arg(value_name = "WS/RESOURCE", value_parser = parse_ws_resource)]
        target: String,
        #[arg(value_parser = parse_field)]
        field: String,
        /// Type the passphrase, whatever halti config says
        #[arg(long = "type")]
        type_it: bool,
    },
    /// List workspaces (asks for nothing), or the secrets in one (asks as halti config says for open)
    #[command(visible_alias = "list")]
    Ls {
        name: Option<String>,
        /// Type the passphrase, whatever halti config says
        #[arg(long = "type", requires = "name")]
        type_it: bool,
    },
    /// Remove one field of a resource, or the whole resource, from a workspace (asks as halti config says)
    Rm {
        #[arg(value_name = "WS/RESOURCE", value_parser = parse_ws_resource)]
        target: String,
        #[arg(value_parser = parse_field)]
        field: Option<String>,
        /// Type the passphrase, whatever halti config says
        #[arg(long = "type")]
        type_it: bool,
    },
    /// Delete a workspace and everything in it; it can't be undone (asks as halti config says)
    Delete {
        name: String,
        /// Type the passphrase, whatever halti config says
        #[arg(long = "type")]
        type_it: bool,
    },
    /// Edit, approve or show a workspace's policies
    Policy {
        #[command(subcommand)]
        action: WsPolicyCmd,
    },
    /// Make, change, approve, list or remove a workspace's boxes, or show a box's log
    #[command(name = "box")]
    Box {
        #[command(subcommand)]
        action: WsBoxCmd,
    },
    /// Start a box of a workspace (asks as halti config says for open), or join it if it runs (asks nothing)
    #[command(after_help = "Without CMD, runs the box policy's `run` (claude). Ctrl-C or closing the terminal stops the box.")]
    Run {
        #[arg(value_name = "WS/BOX", value_parser = parse_ws_box)]
        target: String,
        /// Type the passphrase, whatever halti config says
        #[arg(long = "type")]
        type_it: bool,
        #[arg(last = true, value_name = "CMD")]
        command: Vec<String>,
    },
    /// Stop a box of a workspace (asks nothing)
    Stop {
        #[arg(value_name = "WS/BOX", value_parser = parse_ws_box)]
        target: String,
    },
}

#[derive(Subcommand)]
enum WsBoxCmd {
    /// Make a box: its policy in $EDITOR (a template if new), then its key, its approval and an empty encrypted store (asks as halti config says for policy)
    New {
        #[arg(value_name = "WS/BOX", value_parser = parse_ws_box)]
        target: String,
        /// Type the passphrase, whatever halti config says
        #[arg(long = "type")]
        type_it: bool,
    },
    /// Open a box's policy in $EDITOR; shows what changed from the approved one, and approve it afterwards
    Edit {
        #[arg(value_name = "WS/BOX", value_parser = parse_ws_box)]
        target: String,
    },
    /// Approve a box's policy (asks as halti config says for policy); until then the box can't start
    Approve {
        #[arg(value_name = "WS/BOX", value_parser = parse_ws_box)]
        target: String,
        /// Type the passphrase, whatever halti config says
        #[arg(long = "type")]
        type_it: bool,
    },
    /// List a workspace's boxes: open or locked, size, last used, sites (asks nothing)
    #[command(visible_alias = "list")]
    Ls { name: String },
    /// Delete a box for good: its key, then its store; its policy file stays (asks as halti config says for rm)
    Rm {
        #[arg(value_name = "WS/BOX", value_parser = parse_ws_box)]
        target: String,
        /// Type the passphrase, whatever halti config says
        #[arg(long = "type")]
        type_it: bool,
    },
    /// Show what went through a box's door (asks as halti config says for open, unless the box runs)
    Log {
        #[arg(value_name = "WS/BOX", value_parser = parse_ws_box)]
        target: String,
        /// How many of the latest lines to show
        #[arg(short = 'n', long, default_value_t = 50)]
        last: usize,
        /// Type the passphrase, whatever halti config says
        #[arg(long = "type")]
        type_it: bool,
    },
}

#[derive(Subcommand)]
enum WsPolicyCmd {
    /// Open a resource's policy in $EDITOR (a template if new); approve it afterwards
    Edit {
        #[arg(value_name = "WS/RESOURCE", value_parser = parse_ws_resource)]
        target: String,
    },
    /// Approve one policy, or every policy in the workspace (asks as halti config says for policy)
    Approve {
        #[arg(value_name = "WS[/RESOURCE]", value_parser = parse_ws_maybe_resource)]
        target: String,
        /// Type the passphrase, whatever halti config says
        #[arg(long = "type")]
        type_it: bool,
    },
    /// Print a policy and whether it is approved, or list them all (asks as halti config says for open)
    Show {
        #[arg(value_name = "WS[/RESOURCE]", value_parser = parse_ws_maybe_resource)]
        target: String,
        /// Type the passphrase, whatever halti config says
        #[arg(long = "type")]
        type_it: bool,
    },
}

/// Whose passphrase `ws new` gives the workspace, if its flags say.
fn passphrase_choice(own: bool, generate: bool) -> Option<config::PassphraseMode> {
    match (own, generate) {
        (true, _) => Some(config::PassphraseMode::Own),
        (_, true) => Some(config::PassphraseMode::Generate),
        _ => None,
    }
}

fn parse_resource(s: &str) -> Result<String, String> {
    let mut chars = s.chars();
    let ok = chars.next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if ok { Ok(s.to_string()) } else { Err("use lowercase letters, digits and -, e.g. github".into()) }
}

fn parse_field(s: &str) -> Result<String, String> {
    let mut chars = s.chars();
    let ok = chars.next().is_some_and(|c| c.is_ascii_lowercase()) && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if ok { Ok(s.to_string()) } else { Err("use lowercase letters, digits and _, e.g. token".into()) }
}

/// `acme/github`: a workspace, one `/`, then a resource.
fn parse_ws_resource(s: &str) -> Result<String, String> {
    match ws::target(s) {
        Ok(_) => Ok(s.to_string()),
        Err(_) => Err("use a workspace and a resource, e.g. acme/github".into()),
    }
}

/// `acme/dev`: a workspace, one `/`, then a box.
fn parse_ws_box(s: &str) -> Result<String, String> {
    match ws::boxes::target(s) {
        Ok(_) => Ok(s.to_string()),
        Err(_) => Err("use a workspace and a box, e.g. acme/dev".into()),
    }
}

/// `acme`, or `acme/github`: a workspace, and maybe one of its resources.
fn parse_ws_maybe_resource(s: &str) -> Result<String, String> {
    let ok = if s.contains('/') { ws::target(s).is_ok() } else { halti_core::ids::WsName::parse(s).is_ok() };
    if ok { Ok(s.to_string()) } else { Err("use a workspace, or a workspace and a resource, e.g. acme/github".into()) }
}

fn parse_env(s: &str) -> Result<String, String> {
    let mut chars = s.chars();
    let ok = chars.next().is_some_and(|c| c.is_ascii_uppercase() || c == '_') && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    if ok { Ok(s.to_string()) } else { Err("use ENV_VAR style, e.g. GITHUB_TOKEN".into()) }
}

fn parse_date(s: &str) -> Result<Date, String> {
    match s.parse::<Date>() {
        Ok(d) if s.len() == 10 => Ok(d),
        _ => Err("must be YYYY-MM-DD".into()),
    }
}

// --- clipboard, terminal ---

fn pbpaste() -> Result<String> {
    let out = Command::new("pbpaste").output().context("running pbpaste")?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn pbcopy(data: &str) -> Result<()> {
    let mut child = Command::new("pbcopy").stdin(Stdio::piped()).spawn().context("running pbcopy")?;
    child.stdin.take().expect("piped stdin").write_all(data.as_bytes())?;
    child.wait()?;
    Ok(())
}

fn interactive() -> bool {
    io::stdin().is_terminal()
}

fn ask(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

// --- commands ---

fn cmd_set(res: &str, field: &str, expires: Option<Date>, mut meta: Meta) -> Result<()> {
    if !interactive() {
        bail!("set needs an interactive terminal (value is read with hidden input)");
    }
    let value = rpassword::prompt_password(format!("Value for {res}/{field}: "))?;
    if value.is_empty() {
        bail!("empty value, nothing stored");
    }
    // Ask only for what is still missing, so rotating a set-up field stays one prompt.
    let idx = Index::load()?;
    let r = idx.map.get(res);
    if meta.url.is_none() && r.is_none_or(|r| r.url.is_empty()) {
        meta.url = Some(ask(&format!("Resource link for {res} (Enter to leave empty): "))?);
    }
    if meta.desc.is_none() && r.is_none_or(|r| r.description.is_empty()) {
        meta.desc = Some(ask(&format!("Description of {res} (Enter to leave empty): "))?);
    }
    let suffix = store(res, field, &value, expires.map_or(Expiry::Keep, Expiry::Set), &meta)?;
    println!("stored {res}/{field}{suffix}");
    if policy::path(res).exists() {
        return Ok(());
    }
    println!("{res} has no policy, so nothing can use it yet (halti policy edit {res})");
    Ok(())
}

fn cmd_update(res: &str, field: &str, expires: Option<Date>) -> Result<()> {
    let Some(current) = source::current().value(res, field) else {
        bail!("{res}/{field} is not stored yet (add it with: halti set {res} {field})");
    };
    // Strip surrounding whitespace and newlines that come along when copying from a web page.
    let value = pbpaste()?.trim().to_string();
    if value.is_empty() {
        bail!("clipboard is empty — copy the new value first");
    }
    if value.contains(char::is_whitespace) {
        bail!("clipboard contains whitespace inside the value — copy just the token");
    }
    if value == current {
        bail!("clipboard matches the stored {res}/{field} — copy the new value first");
    }

    // A rotated token has a new expiry; the old date would be wrong, so ask instead of keeping it.
    let expiry = match expires {
        Some(d) => Expiry::Set(d),
        None if jwt_exp(&value).is_some() => Expiry::Keep,
        None if interactive() => {
            let old = Index::load()?.map.get(res).and_then(|r| r.fields.get(field)).and_then(|f| f.expires).map_or("none".to_string(), |d| d.to_string());
            let answer = ask(&format!("New expiry for {res}/{field}, YYYY-MM-DD (was {old}; blank = no expiry): "))?;
            if answer.is_empty() { Expiry::Clear } else { Expiry::Set(parse_date(&answer).map_err(|e| anyhow::anyhow!("expiry {e}"))?) }
        }
        None => Expiry::Clear,
    };

    let suffix = store(res, field, &value, expiry, &Meta::default())?;
    println!("stored {res}/{field}{suffix}");
    pbcopy("")?;
    println!("clipboard cleared");
    Ok(())
}

fn cmd_describe(res: &str, mut meta: Meta) -> Result<()> {
    let mut idx = Index::load()?;
    idx.get(res)?;
    let r = idx.map.get_mut(res).expect("checked above");
    if meta.url.is_none() && meta.desc.is_none() {
        if !interactive() {
            bail!("give --url and/or --desc, or run in a terminal to be prompted");
        }
        // Enter keeps the current value, "-" clears it.
        let keep_or_clear = |a: String| match a.as_str() {
            "" => None,
            "-" => Some(String::new()),
            _ => Some(a),
        };
        let shown = |s: &str| if s.is_empty() { "empty".to_string() } else { s.to_string() };
        eprintln!("Enter keeps the current value, a single - clears it.");
        meta.url = keep_or_clear(ask(&format!("Resource link [{}]: ", shown(&r.url)))?);
        meta.desc = keep_or_clear(ask(&format!("Description [{}]: ", shown(&r.description)))?);
    }
    r.apply(&meta);
    idx.save()?;
    println!("updated {res}");
    Ok(())
}

fn cmd_refresh(resources: Vec<String>, force: bool) -> Result<u8> {
    let resources = if resources.is_empty() { auto_resources() } else { resources };
    if resources.is_empty() {
        println!("nothing refreshes (add a [refresh.FIELD] section to a policy)");
        return Ok(0);
    }
    for res in &resources {
        if policy::load(res)?.policy.refresh.is_empty() {
            bail!("the policy for {res} refreshes nothing (add a [refresh.FIELD] section)");
        }
    }
    Ok(if refresh_due(&resources, force, true) { 0 } else { 1 })
}

fn cmd_info(res: &str) -> Result<()> {
    let idx = Index::load()?;
    let r = idx.get(res)?;
    let approved = policy::load(res).ok();
    println!("{:<12} {res}", "name");
    println!("{:<12} {}", "url", r.url);
    println!("{:<12} {}", "description", r.description);
    let status = policy::status(res);
    println!("{:<12} {} ({})", "policy", status.text(), policy::path(res).display());
    match &approved {
        // Lines about what agents may do. Further ones (e.g. blocked browser writes) go here.
        Some(a) => {
            for (label, text) in a.policy.rules() {
                println!("  {label:<10} {text}");
            }
        }
        None if !matches!(status, policy::Status::Missing) => {
            println!("  nothing in it applies until approved (halti policy approve {res})");
        }
        None => {}
    }
    for (name, f) in &r.fields {
        let mut parts = vec![if source::current().has_value(res, name) { "stored" } else { "MISSING" }.to_string()];
        let export = approved.as_ref().and_then(|a| a.policy.run.export.get(name));
        parts.push(export.map_or("inside halti".to_string(), |v| format!("exported as {v}")));
        if let Some(t) = f.expiry_text() {
            parts.push(format!("expires {t}"));
        }
        if let Some(u) = f.updated {
            parts.push(format!("updated {u}"));
        }
        println!("{name:<12} {}", parts.join(", "));
        if let Some(r) = approved.as_ref().and_then(|a| a.policy.refresh.get(name)) {
            let how = r.from.as_ref().map_or_else(|| format!("run {}", r.run.as_deref().unwrap_or("")), |f| format!("from {f}"));
            println!("{:<12}   auto-refresh: {how}", "");
        }
    }
    let allowed = approved.as_ref().and_then(|a| a.policy.browse.as_ref()).map_or(&[][..], |b| &b.allow_writes[..]);
    let writes = browse::blocked_writes(res, allowed);
    if !writes.is_empty() {
        println!("{:<12} writes pages tried without an allow_writes rule (add a URL prefix under [browse] to allow one):", "browser");
        for (what, count, last) in writes {
            println!("{:<12}   {what} (x{count}, last {last})", "");
        }
    }
    Ok(())
}

/// A field's status label and how urgent it is (higher = worse), for picking a resource's status.
fn field_status(res: &str, name: &str, f: &Field, auto: bool, warn: i64) -> (i64, String) {
    if !source::current().has_value(res, name) {
        return (i64::MAX, "MISSING".into());
    }
    if f.expired() {
        return (i64::MAX - 1, "EXPIRED".into());
    }
    if auto {
        return (1, "auto".into());
    }
    match f.expires.map(days_left) {
        // Fewer days left is more urgent.
        Some(d) if d <= warn => (1000 - d, format!("{d}d left")),
        _ => (0, "ok".into()),
    }
}

fn cmd_ls() -> Result<()> {
    let idx = Index::load()?;
    let warn = warn_days();
    println!("{:<20} {:<9} {:<17} {:<34} {:<26} DESCRIPTION", "RESOURCE", "STATUS", "EXPIRES", "FIELDS", "POLICY");
    for (res, r) in &idx.map {
        let approved = policy::load(res).ok();
        let auto = |n: &str| approved.as_ref().is_some_and(|a| a.policy.refresh.contains_key(n));
        let status = r.fields.iter().map(|(n, f)| field_status(res, n, f, auto(n), warn)).max_by_key(|(rank, _)| *rank).map_or("empty".to_string(), |(_, s)| s);
        let expires = r.fields.values().filter_map(|f| Some((f.expiry_key()?, f.expiry_text()?))).min_by_key(|(key, _)| *key).map_or("-".to_string(), |(_, text)| text);
        let fields: Vec<String> = r
            .fields
            .keys()
            .map(|n| match approved.as_ref().and_then(|a| a.policy.run.export.get(n)) {
                Some(v) => format!("{n}→{v}"),
                None => n.clone(),
            })
            .collect();
        let policy = match &approved {
            Some(a) => a.policy.summary(),
            None => policy::status(res).text().to_string(),
        };
        println!("{res:<20} {status:<9} {expires:<17} {:<34} {policy:<26} {}", fields.join(", "), r.description);
    }
    Ok(())
}

fn cmd_check(days: Option<i64>) -> Result<u8> {
    let within = days.unwrap_or_else(warn_days);
    // Renew what can renew itself first; those are only reported if still expired afterwards.
    refresh_due(&auto_resources(), false, false);
    let mut bad = 0;
    for (res, r) in &Index::load()?.map {
        let approved = policy::load(res).ok();
        for (name, f) in &r.fields {
            let Some(exp) = f.expires else { continue };
            let d = days_left(exp);
            let msg = if approved.as_ref().is_some_and(|a| a.policy.refresh.contains_key(name)) {
                if !f.expired() {
                    continue;
                }
                format!("{res}/{name} expired and auto-refresh failed (halti refresh {res})")
            } else if d < 0 {
                format!("{res}/{name} expired {}d ago ({exp})", -d)
            } else if d <= within {
                format!("{res}/{name} expires in {d}d ({exp})")
            } else {
                continue;
            };
            let rotate = if r.url.is_empty() { String::new() } else { format!(" — rotate at {}", r.url) };
            println!("{msg}{rotate}");
            bad = 1;
        }
    }
    Ok(bad)
}

fn cmd_rm(res: &str, field: Option<String>) -> Result<()> {
    let mut idx = Index::load()?;
    let names: Vec<String> = match &field {
        Some(f) => vec![f.clone()],
        None => idx.get(res)?.fields.keys().cloned().collect(),
    };
    for name in &names {
        if !source::current().remove_value(res, name) {
            eprintln!("halti: {res}/{name} not in Keychain");
        }
    }
    match field {
        Some(f) => {
            if let Some(r) = idx.map.get_mut(res) {
                r.fields.remove(&f);
            }
            println!("removed {res}/{f}");
        }
        None => {
            idx.map.remove(res);
            policy::revoke(res)?;
            println!("removed {res}");
        }
    }
    idx.save()
}

fn cmd_copy(res: &str, field: &str) -> Result<()> {
    let Some(v) = source::current().value(res, field) else { bail!("{res}/{field} not found") };
    approve::confirm(&format!("copy {res}/{field} to the clipboard"))?;
    pbcopy(v.trim_end_matches('\n'))?;
    println!("copied {res}/{field} to clipboard");
    Ok(())
}

fn cmd_reseal(resources: Vec<String>) -> Result<()> {
    let idx = Index::load()?;
    let resources = if resources.is_empty() { idx.map.keys().cloned().collect() } else { resources };
    for res in &resources {
        for name in idx.get(res)?.fields.keys() {
            // Reading may ask for Keychain access once; the new item needs no approval.
            let Some(value) = source::current().value(res, name) else {
                eprintln!("halti: {res}/{name} not in Keychain, skipped");
                continue;
            };
            source::current().reseal_value(res, name, &value).with_context(|| format!("{res}/{name} was removed but not stored again: set it with halti set {res} {name}"))?;
            println!("resealed {res}/{name}");
        }
        // Approvals aren't carried over: one planted by another program must not become trusted.
        if policy::path(res).exists() && !matches!(policy::status(res), policy::Status::Approved) {
            println!("approve {res}'s policy again: halti policy approve {res}");
        }
    }
    Ok(())
}

/// Copy src to dst line by line, replacing every secret value with ********.
fn pump(src: impl Read, mut dst: impl Write, ac: &AhoCorasick) {
    let reps = vec![MASK; ac.patterns_len()];
    let mut r = BufReader::new(src);
    let mut line = Vec::new();
    loop {
        line.clear();
        match r.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if dst.write_all(&ac.replace_all_bytes(&line, &reps)).and_then(|_| dst.flush()).is_err() {
            break;
        }
    }
}

fn cmd_run(resources: Vec<String>, command: Vec<String>) -> Result<u8> {
    // A failed refresh is reported; the stored value is still tried.
    refresh_due(&resources, false, false);

    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut masks = Vec::new();
    for res in &resources {
        let approved = policy::load(res).with_context(|| format!("halti run needs an approved policy for {res}"))?;
        let run = &approved.policy.run;
        if run.export.is_empty() {
            bail!("the policy for {res} exports no fields to halti run");
        }
        let fields: Vec<&str> = run.export.keys().map(String::as_str).collect();
        match run.mode {
            Mode::Deny => bail!("the policy for {res} doesn't allow halti run (agents can use halti mcp)"),
            Mode::Ask => approve::confirm(&format!("run {} with {res}'s {}", command[0], fields.join(", ")))?,
            Mode::Allow => {}
        }
        for (name, var) in &run.export {
            let Some(v) = source::current().value(res, name) else { bail!("{res}/{name} not found in Keychain (add it with: halti set {res} {name})") };
            cmd.env(var, &v);
            if !v.is_empty() {
                masks.push(v);
            }
        }
    }
    let ac = Arc::new(AhoCorasick::builder().match_kind(MatchKind::LeftmostLongest).build(&masks)?);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("halti: {}: {e}", command[0]);
            return Ok(127);
        }
    };
    // Mask stdout and stderr so a value never reaches a log or an agent transcript by accident.
    let (out, err) = (child.stdout.take().expect("piped"), child.stderr.take().expect("piped"));
    let a = Arc::clone(&ac);
    let t_out = thread::spawn(move || pump(out, io::stdout(), &a));
    let t_err = thread::spawn(move || pump(err, io::stderr(), &ac));
    let status = child.wait()?;
    let _ = (t_out.join(), t_err.join());
    let code = status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
    Ok(code as u8)
}

/// Where a command finds and keeps secrets. Workspaces, the settings and how halti was built reach
/// only the machine's own items, so they choose no place here: a lookup there fails instead of
/// reading the Keychain. `ws run` chooses its workspace itself, once it is opened, when it starts a
/// box; no other workspace command chooses one. Every other command keeps its secrets in the
/// Keychain.
fn source_for(cmd: &Cmd) -> Option<source::Source> {
    match cmd {
        Cmd::Ws { .. } | Cmd::Open { .. } | Cmd::Close { .. } | Cmd::Config { .. } | Cmd::BuildInfo => None,
        #[cfg(all(halti_dev, target_os = "linux"))]
        Cmd::SandboxInit { .. } => None,
        Cmd::Set { .. }
        | Cmd::Update { .. }
        | Cmd::Describe { .. }
        | Cmd::Policy { .. }
        | Cmd::Refresh { .. }
        | Cmd::Info { .. }
        | Cmd::Ls
        | Cmd::Check { .. }
        | Cmd::Rm { .. }
        | Cmd::Copy { .. }
        | Cmd::Run { .. }
        | Cmd::Mcp
        | Cmd::Audit { .. }
        | Cmd::Reseal { .. }
        | Cmd::Box { .. } => Some(source::Source::keychain()),
    }
}

/// For installers and check.sh: a build to install must say that both flags are false.
fn cmd_build_info() {
    println!("debug_assertions={} halti_dev={}", cfg!(debug_assertions), cfg!(halti_dev));
    println!("target={}", env!("BUILD_TARGET"));
    println!("verified: {VERIFIED}");
    println!("home={}", util::home().display());
    println!("config={}", util::config_dir().display());
    println!("store={}", util::store_root().display());
}

fn main() -> ExitCode {
    util::blocking_stdio();
    // Without an absolute home, every path halti uses would be relative to the current folder.
    if !util::home().is_absolute() {
        eprintln!("halti: no home folder in your passwd entry");
        return ExitCode::FAILURE;
    }
    // Always, so a debug build can't pass for an installed one.
    #[cfg(halti_dev)]
    eprintln!("halti: [DEV, not protected] a debug build: test variables can answer its prompts, and it keeps its files in {}", util::config_dir().display());
    let ok = |r: Result<()>| r.map(|_| 0);
    let cmd = Cli::parse().cmd;
    if let Some(source) = source_for(&cmd) {
        source::choose(source).expect("halti chose where secrets are kept once");
    }
    let result = match cmd {
        Cmd::Set { resource, field, expires, meta } => ok(cmd_set(&resource, &field, expires, meta)),
        Cmd::Update { resource, field, expires } => ok(cmd_update(&resource, &field, expires)),
        Cmd::Describe { resource, meta } => ok(cmd_describe(&resource, meta)),
        Cmd::Policy { action } => ok(match action {
            PolicyCmd::Show { resource } => policy::show(&resource),
            PolicyCmd::Edit { resource } => policy::edit(&resource),
            PolicyCmd::Approve { resources } => policy::approve(&resources),
        }),
        Cmd::Refresh { resources, force } => cmd_refresh(resources, force),
        Cmd::Info { resource } => ok(cmd_info(&resource)),
        Cmd::Ls => ok(cmd_ls()),
        Cmd::Check { days } => cmd_check(days),
        Cmd::Rm { resource, field } => ok(cmd_rm(&resource, field)),
        Cmd::Copy { resource, field } => ok(cmd_copy(&resource, &field)),
        Cmd::Run { resources, command } => cmd_run(resources, command),
        Cmd::Mcp => ok(mcp::serve()),
        Cmd::Audit { last, verify } => ok(audit::show(last, verify)),
        Cmd::Reseal { resources } => ok(cmd_reseal(resources)),
        Cmd::Box { action } => match action {
            BoxCmd::Run { temp, name, command } => boxes::run(&name, temp, command),
            BoxCmd::New { name } => ok(boxes::new(&name)),
            BoxCmd::Edit { name } => ok(boxes::edit(&name)),
            BoxCmd::Approve { names } => ok(boxes::approve(&names)),
            BoxCmd::Ls => ok(boxes::ls()),
            BoxCmd::Log { name, last, verify } => ok(boxes::log(&name, last, verify)),
            BoxCmd::Stop { name } => ok(boxes::stop(&name)),
            BoxCmd::Export { name, path, to } => ok(boxes::export(&name, &path, &to)),
            BoxCmd::Import { name, path } => ok(boxes::import(&name, &path)),
            BoxCmd::Login { name, site, all } => ok(boxes::login(&name, site.as_deref(), all)),
            BoxCmd::Rm { name } => ok(boxes::rm(&name)),
            #[cfg(all(halti_dev, target_os = "linux"))]
            BoxCmd::Sh { engine: _, tools, command } => sandbox::sh(tools, command),
        },
        Cmd::Config { show, default } => ok(config::command(show, default)),
        Cmd::Ws { action: WsCmd::Run { target, type_it, command } } => match ws::boxes::run(&target, command, type_it) {
            Ok(ws::boxes::Run::Join(join)) => boxes::join_in(*join),
            Ok(ws::boxes::Run::Start { source, start }) => {
                source::choose(*source).expect("ws run chose where secrets are kept once");
                boxes::run_in(*start)
            }
            Err(e) => Err(e),
        },
        Cmd::Ws { action } => ok(match action {
            WsCmd::New { name, own, generate } => ws::new(&name, passphrase_choice(own, generate)),
            WsCmd::Set { target, field, type_it } => ws::set(&target, &field, type_it),
            WsCmd::Ls { name, type_it } => ws::ls(name.as_deref(), type_it),
            WsCmd::Rm { target, field, type_it } => ws::rm(&target, field.as_deref(), type_it),
            WsCmd::Delete { name, type_it } => ws::delete(&name, type_it),
            WsCmd::Policy { action } => match action {
                WsPolicyCmd::Edit { target } => ws::policies::edit(&target),
                WsPolicyCmd::Approve { target, type_it } => ws::policies::approve(&target, type_it),
                WsPolicyCmd::Show { target, type_it } => ws::policies::show(&target, type_it),
            },
            WsCmd::Box { action } => match action {
                WsBoxCmd::New { target, type_it } => ws::boxes::new(&target, type_it),
                WsBoxCmd::Edit { target } => ws::boxes::edit(&target),
                WsBoxCmd::Approve { target, type_it } => ws::boxes::approve(&target, type_it),
                WsBoxCmd::Ls { name } => ws::boxes::ls(&name),
                WsBoxCmd::Rm { target, type_it } => ws::boxes::rm(&target, type_it),
                WsBoxCmd::Log { target, last, type_it } => ws::boxes::log(&target, last, type_it),
            },
            WsCmd::Stop { target } => ws::boxes::stop(&target),
            WsCmd::Run { .. } => unreachable!("ws run returns its command's exit code, above"),
        }),
        Cmd::Open { name, type_it } => ok(ws::open(name.as_deref(), type_it)),
        Cmd::Close { name } => ok(ws::close(name.as_deref())),
        Cmd::BuildInfo => {
            cmd_build_info();
            Ok(0)
        }
        #[cfg(all(halti_dev, target_os = "linux"))]
        Cmd::SandboxInit { parent, tools, command } => sandbox::init(parent, &tools, &command),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("halti: {e:#}");
            ExitCode::FAILURE
        }
    }
}
