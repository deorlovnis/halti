//! End-to-end tests: the built `halti` binary, driven the way a person and an agent drive it.
//!
//! The debug binary keeps Keychain items in a temp folder (HALTI_TEST_KEYCHAIN), answers Touch ID
//! prompts from HALTI_TEST_APPROVE and sudo from HALTI_TEST_SUDO (it never runs sudo, and keeps the
//! approved settings in the test's home), so these tests need no human and never touch the real
//! Keychain or the system's folders. Run them with `mise run e2e`. Two groups need more, and are opt-in:
//!
//!   HALTI_E2E_BROWSER=1      the sandboxed browser (needs `npm ci` in runner/ and Chromium)
//!   HALTI_E2E_INTERACTIVE=1  a real Touch ID approval in the real Keychain (a human taps)
//!
//! Run those with `mise run e2e-opt-in`; they are #[ignore]d otherwise.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::{env, fs, thread};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[path = "../src/legacy.rs"]
#[allow(dead_code)] // the tests use a few
mod legacy;

const HALTI: &str = env!("CARGO_BIN_EXE_halti");
const TOKEN: &str = "s3cret-token-value";
/// Where a debug build keeps box stores under its home (`util::DEV_STORE_ROOT`).
const DEV_STORE_ROOT: &str = "Library/Application Support/halti-dev";
/// Where a debug build keeps its config under its home (`util::DEV_CONFIG_DIR`): never an
/// installed halti's `.config/halti`, and in these tests always under the test's own home.
const DEV_CONFIG_DIR: &str = ".config/halti-dev";

/// A private home for one test: index, policies and fake Keychain, removed when dropped.
struct Env {
    dir: PathBuf,
}

impl Env {
    fn new() -> Self {
        // Only debug-profile builds honor the test variables; a release build would use the real
        // Keychain.
        if !cfg!(halti_dev) {
            panic!("run the e2e tests with a debug build (no --release)");
        }
        static COUNT: AtomicUsize = AtomicUsize::new(0);
        let dir = env::temp_dir().join(format!("halti-e2e-{}-{}", std::process::id(), COUNT.fetch_add(1, Ordering::Relaxed)));
        let _ = fs::remove_dir_all(&dir);
        for sub in ["keychain", "policy", "box", "home"] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        Self { dir }
    }

    /// `halti ARGS` with every path pointing into this test's folder; Touch ID answers yes.
    fn command(&self) -> Command {
        let mut cmd = Command::new(HALTI);
        cmd.env("HOME", self.dir.join("home"))
            .env("HALTI_INDEX", self.dir.join("index.json"))
            .env("HALTI_POLICY_DIR", self.dir.join("policy"))
            .env("HALTI_BOX_DIR", self.dir.join("box"))
            .env("HALTI_TEST_KEYCHAIN", self.dir.join("keychain"))
            .env("HALTI_TEST_APPROVE", "yes")
            .env_remove("HALTI_REFRESHING")
            .env_remove(format!("{}REFRESHING", legacy::ENV_PREFIX))
            .current_dir(&self.dir)
            .stdin(Stdio::null());
        cmd
    }

    fn halti(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }

    /// Store a field as `halti set` would (which needs a terminal for the hidden prompt).
    fn store(&self, res: &str, field: &str, value: &str) {
        fs::write(self.dir.join("keychain").join(format!("{res}.{field}")), value).unwrap();
        let index = self.dir.join("index.json");
        let mut map: Value = fs::read_to_string(&index).map_or(json!({}), |s| serde_json::from_str(&s).unwrap());
        map[res]["description"] = json!(format!("the {res} test site"));
        map[res]["fields"][field] = json!({});
        fs::write(index, map.to_string()).unwrap();
    }

    fn write_policy(&self, res: &str, toml: &str) {
        fs::write(self.dir.join("policy").join(format!("{res}.toml")), toml).unwrap();
    }

    /// Write a policy and approve it through `halti policy approve`.
    fn policy(&self, res: &str, toml: &str) {
        self.write_policy(res, toml);
        let out = self.halti(&["policy", "approve", res]);
        assert!(out.status.success(), "approve failed: {}", text(&out.stderr));
    }

    fn mcp(&self) -> Mcp {
        Mcp::start(self.command().arg("mcp"))
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn stdout(out: &Output) -> String {
    text(&out.stdout)
}

/// What a command said on stderr, without the banner every debug build starts with.
fn stderr(out: &Output) -> String {
    text(&out.stderr).lines().filter(|l| !l.starts_with("halti: [DEV, not protected]")).map(|l| format!("{l}\n")).collect()
}

// --- an MCP client, as an agent's would talk to `halti mcp` ---

struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Mcp {
    fn start(cmd: &mut Command) -> Self {
        let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let (stdin, stdout) = (child.stdin.take().unwrap(), BufReader::new(child.stdout.take().unwrap()));
        Self { child, stdin: Some(stdin), stdout, next_id: 0 }
    }

    fn send(&mut self, message: &Value) {
        writeln!(self.stdin.as_mut().unwrap(), "{message}").unwrap();
    }

    /// A request and its result (or the error object).
    fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let request = json!({ "jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params });
        self.send(&request);
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        let reply: Value = serde_json::from_str(&line).unwrap_or_else(|_| panic!("not JSON: {line:?}"));
        assert_eq!(reply["id"], json!(self.next_id));
        reply.get("result").cloned().unwrap_or_else(|| reply["error"].clone())
    }

    fn handshake(&mut self) -> Value {
        let init = self.rpc("initialize", json!({ "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "e2e", "version": "0" } }));
        self.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        init
    }

    fn tool_names(&mut self) -> Vec<String> {
        let list = self.rpc("tools/list", json!({}));
        list["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect()
    }

    /// Call a tool; returns (is_error, text).
    fn call(&mut self, name: &str, args: Value) -> (bool, String) {
        let result = self.rpc("tools/call", json!({ "name": name, "arguments": args }));
        (result["isError"].as_bool().unwrap(), result["content"][0]["text"].as_str().unwrap().to_string())
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        // Closing stdin lets halti exit on its own and close any browser it started.
        drop(self.stdin.take());
        let _ = self.child.wait();
    }
}

// --- a local web site ---

/// Serves on 127.0.0.1 and keeps every request it gets (head only, header names lowercased).
struct Site {
    port: u16,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Site {
    /// `/echo` says which Authorization it got, `/redirect` redirects to `/echo`, `/page` is
    /// an HTML page showing its Cookie header, anything else is "ok".
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let seen = Arc::clone(&seen);
                thread::spawn(move || answer(stream, port, &seen));
            }
        });
        Self { port, requests }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn origin(&self) -> String {
        self.url("")
    }

    /// The requests seen so far, as "METHOD /path" followed by the lowercased headers.
    fn seen(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

fn answer(mut stream: TcpStream, port: u16, seen: &Mutex<Vec<String>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut head = String::new();
    let mut length = 0;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        if line == "\r\n" {
            break;
        }
        if let Some(n) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = n.trim().parse().unwrap_or(0);
        }
        match line.split_once(':') {
            Some((name, value)) if !head.is_empty() => head += &format!("{}:{value}", name.to_ascii_lowercase()),
            _ => head += &line,
        }
    }
    let mut body = vec![0; length];
    let _ = reader.read_exact(&mut body);
    seen.lock().unwrap().push(head.clone());

    let header = |name: &str| head.lines().find_map(|l| l.strip_prefix(&format!("{name}: "))).unwrap_or("none").to_string();
    let (status, extra, content_type, body) = match head.split_whitespace().nth(1).unwrap_or("/") {
        "/echo" => ("200 OK", String::new(), "text/plain", format!("authorization: {}", header("authorization"))),
        "/redirect" => ("302 Found", format!("Location: http://127.0.0.1:{port}/echo\r\n"), "text/plain", String::new()),
        "/page" => ("200 OK", String::new(), "text/html", format!("<html><body><h1>Hello e2e</h1><p>cookie: {}</p></body></html>", header("cookie"))),
        _ => ("200 OK", String::new(), "text/plain", "ok".into()),
    };
    let _ = write!(stream, "HTTP/1.1 {status}\r\n{extra}Content-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
}

fn fetch_policy(site: &Site) -> String {
    format!(
        r#"
        [fetch]
        hosts = ["{}"]
        auth = "Bearer {{token}}"

        [[tool]]
        name = "echo"
        about = "Echo the authorization"
        request = "GET {}/{{what}}"
        "#,
        site.origin(),
        site.origin()
    )
}

// --- halti run ---

#[test]
fn run_exports_fields_and_masks_them_in_output() {
    let env = Env::new();
    env.store("app", "token", TOKEN);
    env.policy("app", "[run]\nmode = \"allow\"\nexport = { token = \"APP_TOKEN\" }\n");
    let out = env.halti(&["run", "-s", "app", "--", "sh", "-c", "echo \"out=$APP_TOKEN\"; echo \"err=$APP_TOKEN\" >&2; exit 3"]);
    assert_eq!(out.status.code(), Some(3), "the command's exit code is passed on");
    assert_eq!(stdout(&out), "out=********\n");
    assert_eq!(stderr(&out), "err=********\n");
}

#[test]
fn run_refuses_policies_that_are_not_approved_or_not_permissive() {
    let env = Env::new();
    env.store("app", "token", TOKEN);
    let run = |env: &Env| env.halti(&["run", "-s", "app", "--", "true"]);

    env.write_policy("app", "[run]\nmode = \"allow\"\nexport = { token = \"APP_TOKEN\" }\n");
    let out = run(&env);
    assert!(!out.status.success() && stderr(&out).contains("isn't approved"), "{}", stderr(&out));

    env.halti(&["policy", "approve", "app"]);
    assert!(run(&env).status.success());

    env.write_policy("app", "[run]\nmode = \"allow\"\nexport = { token = \"OTHER_VAR\" }\n");
    let out = run(&env);
    assert!(!out.status.success() && stderr(&out).contains("changed since it was approved"), "{}", stderr(&out));

    env.policy("app", "[run]\nmode = \"deny\"\nexport = { token = \"APP_TOKEN\" }\n");
    let out = run(&env);
    assert!(!out.status.success() && stderr(&out).contains("doesn't allow halti run"), "{}", stderr(&out));
}

#[test]
fn run_in_ask_mode_follows_the_touch_id_answer() {
    let env = Env::new();
    env.store("app", "token", TOKEN);
    env.policy("app", "[run]\nmode = \"ask\"\nexport = { token = \"APP_TOKEN\" }\n");
    let args = ["run", "-s", "app", "--", "sh", "-c", "echo $APP_TOKEN"];
    assert!(env.halti(&args).status.success());
    let out = env.command().args(args).env("HALTI_TEST_APPROVE", "no").output().unwrap();
    assert!(!out.status.success() && stdout(&out).is_empty(), "nothing runs when Touch ID is refused");
}

#[test]
fn run_needs_a_resource_and_ignores_a_cred_file() {
    let env = Env::new();
    env.store("app", "token", TOKEN);
    env.policy("app", "[run]\nmode = \"allow\"\nexport = { token = \"APP_TOKEN\" }\n");
    // A repo file named resources for `run` before the rename; it's read no more.
    fs::write(env.dir.join(".cred"), "app\n").unwrap();
    let out = env.halti(&["run", "--", "sh", "-c", "echo $APP_TOKEN"]);
    assert!(!out.status.success() && stderr(&out).contains("--secret <RESOURCE>"), "{}", stderr(&out));
    assert!(stdout(&out).is_empty());
}

// --- halti refresh ---

#[test]
fn refresh_scripts_get_the_fields_under_both_names() {
    let env = Env::new();
    env.store("app", "login", "someone");
    env.store("app", "token", "old");
    // Scripts approved before the rename read the old names; their bytes are pinned.
    let old = |suffix: &str| format!("{}{suffix}", legacy::ENV_PREFIX);
    let script = env.dir.join("refresh.sh");
    fs::write(&script, format!("#!/bin/sh\nprintf '%s-%s-%s-%s' \"$HALTI_LOGIN\" \"${}\" \"$HALTI_REFRESHING\" \"${}\"\n", old("LOGIN"), old("REFRESHING"))).unwrap();
    env.policy("app", &format!("[refresh.token]\nrun = \"{}\"\n", script.display()));
    let token = || fs::read_to_string(env.dir.join("keychain/app.token")).unwrap();

    // A halti inside a refresh script refreshes nothing, whichever name says so.
    for var in ["HALTI_REFRESHING".to_string(), old("REFRESHING")] {
        let out = env.command().args(["refresh", "app", "--force"]).env(&var, "app").output().unwrap();
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(token(), "old", "refreshed inside {var}");
    }

    let out = env.halti(&["refresh", "app", "--force"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(token(), "someone-someone-app-app");
}

// --- info, ls and policy edit ---

#[test]
fn info_and_ls_show_the_approved_rules() {
    let env = Env::new();
    env.store("app", "token", TOKEN);
    let toml = "[run]\nmode = \"ask\"\nexport = { token = \"APP_TOKEN\" }\n[fetch]\nhosts = [\"https://api.example.com\"]\nwrites = \"ask\"\nauth = \"Bearer {token}\"\n\
                [[tool]]\nname = \"item\"\nabout = \"One item\"\nrequest = \"GET https://api.example.com/items/{id}\"\n\
                [browse]\norigins = [\"https://app.example.com\"]\nscreenshots = true\n";
    env.write_policy("app", toml);

    let info = stdout(&env.halti(&["info", "app"]));
    assert!(info.contains("not approved") && info.contains("nothing in it applies until approved"), "{info}");
    assert!(!info.contains("api.example.com"), "unapproved rules aren't shown:\n{info}");
    assert!(stdout(&env.halti(&["ls"])).contains("not approved"));

    env.halti(&["policy", "approve", "app"]);
    let info = stdout(&env.halti(&["info", "app"]));
    for expected in [
        "approved",
        "hosts https://api.example.com; writes ask; auth in Authorization",
        "item: GET https://api.example.com/items/{id}",
        "pages on https://app.example.com; writes deny; screenshots",
        "exported as APP_TOKEN",
    ] {
        assert!(info.contains(expected), "missing {expected:?}:\n{info}");
    }
    assert!(!info.contains(TOKEN));
    let ls = stdout(&env.halti(&["ls"]));
    assert!(ls.contains("run:ask fetch:ask browse"), "{ls}");

    env.write_policy("app", &format!("{toml}\n# edited\n"));
    let info = stdout(&env.halti(&["info", "app"]));
    assert!(info.contains("changed since approval") && !info.contains("api.example.com"), "{info}");
    assert!(stdout(&env.halti(&["ls"])).contains("changed since approval"));
}

#[test]
fn policy_edit_shows_a_diff_against_the_approved_version() {
    let env = Env::new();
    env.policy("app", "[run]\nmode = \"ask\"\n");
    let edited = env.dir.join("edited.toml");
    fs::write(&edited, "[run]\nmode = \"allow\"\n").unwrap();

    // The "editor" replaces the file with the edited copy.
    let edit = |env: &Env| env.command().args(["policy", "edit", "app"]).env("EDITOR", format!("cp {}", edited.display())).output().unwrap();
    let out = edit(&env);
    let shown = stdout(&out);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(shown.contains("-mode = \"ask\"\n+mode = \"allow\"\n"), "{shown}");
    assert!(!shown.contains('\x1b'), "no colors when stdout isn't a terminal");
    assert!(shown.contains("takes effect once approved"), "{shown}");
    assert!(stdout(&env.halti(&["policy", "show", "app"])).contains("changed since approval"));

    env.halti(&["policy", "approve", "app"]);
    assert!(stdout(&edit(&env)).contains("no change from the approved policy"));
}

// --- halti mcp ---

#[test]
fn mcp_handshake_and_tool_list() {
    let env = Env::new();
    let site = Site::start();
    env.store("app", "token", TOKEN);
    env.policy("app", &fetch_policy(&site));
    env.store("draft", "token", TOKEN);
    env.write_policy("draft", &fetch_policy(&site));

    let mut mcp = env.mcp();
    let init = mcp.handshake();
    assert_eq!(init["serverInfo"]["name"], "halti");
    assert_eq!(init["protocolVersion"], "2025-06-18");
    assert!(init["instructions"].as_str().unwrap().contains("without ever revealing"));
    assert_eq!(mcp.rpc("ping", json!({})), json!({}));
    assert_eq!(mcp.rpc("nope", json!({}))["code"], -32601);

    let names = mcp.tool_names();
    assert_eq!(names, ["sites", "fetch", "app_echo"], "unapproved policies and absent browse sections add nothing");
    let (is_error, sites) = mcp.call("sites", json!({}));
    assert!(!is_error && sites.contains("app: the app test site") && !sites.contains("draft"), "{sites}");
}

#[test]
fn mcp_fetch_adds_credentials_and_masks_the_response() {
    let env = Env::new();
    let site = Site::start();
    env.store("app", "token", TOKEN);
    env.policy("app", &fetch_policy(&site));

    let mut mcp = env.mcp();
    mcp.handshake();
    let (is_error, reply) = mcp.call("fetch", json!({ "site": "app", "method": "GET", "url": site.url("/echo") }));
    assert!(!is_error, "{reply}");
    assert!(reply.contains("HTTP 200") && reply.contains("authorization: Bearer ********"), "{reply}");
    assert!(!reply.contains(TOKEN));
    assert!(site.seen().iter().any(|r| r.contains(&format!("authorization: Bearer {TOKEN}"))), "{:?}", site.seen());

    let (is_error, reply) = mcp.call("app_echo", json!({ "what": "echo" }));
    assert!(!is_error && reply.contains("authorization: Bearer ********"), "{reply}");
}

#[test]
fn mcp_fetch_enforces_the_policy() {
    let env = Env::new();
    let site = Site::start();
    env.store("app", "token", TOKEN);
    env.policy("app", &fetch_policy(&site));
    let mut mcp = env.mcp();
    mcp.handshake();
    let before = site.seen().len();

    let (is_error, reply) = mcp.call("fetch", json!({ "site": "app", "method": "GET", "url": "http://127.0.0.2:1/x" }));
    assert!(is_error && reply.contains("isn't one of this site's hosts"), "{reply}");
    let (is_error, reply) = mcp.call("fetch", json!({ "site": "app", "method": "POST", "url": site.url("/echo"), "body": "{}" }));
    assert!(is_error && reply.contains("doesn't allow POST"), "{reply}");
    let (is_error, reply) = mcp.call("fetch", json!({ "site": "other", "method": "GET", "url": site.url("/echo") }));
    assert!(is_error && reply.contains("unknown site"), "{reply}");
    assert_eq!(site.seen().len(), before, "refused requests never reach the site");

    // A redirect is reported, not followed: the credentials would go wherever it points.
    let (is_error, reply) = mcp.call("fetch", json!({ "site": "app", "method": "GET", "url": site.url("/redirect") }));
    assert!(!is_error && reply.contains("HTTP 302") && reply.contains("location:"), "{reply}");
    assert_eq!(site.seen().len(), before + 1);

    // The policy is checked again on every call.
    env.write_policy("app", &format!("{}\n# edited\n", fetch_policy(&site)));
    let (is_error, reply) = mcp.call("fetch", json!({ "site": "app", "method": "GET", "url": site.url("/echo") }));
    assert!(is_error && reply.contains("changed since it was approved"), "{reply}");
}

#[test]
fn mcp_asks_for_consent_and_for_writes() {
    let env = Env::new();
    let site = Site::start();
    env.store("app", "token", TOKEN);
    env.policy("app", &fetch_policy(&site));
    let get = json!({ "site": "app", "method": "GET", "url": site.url("/echo") });

    // The default policy asks for Touch ID when an agent first uses the site; refused here.
    let mut mcp = Mcp::start(env.command().arg("mcp").env("HALTI_TEST_APPROVE", "no"));
    mcp.handshake();
    let (is_error, reply) = mcp.call("fetch", get.clone());
    assert!(is_error && reply.contains("not approved"), "{reply}");

    // Without consent, writes still follow their own rule: ask means Touch ID.
    let policy = format!("[agent]\nconsent = \"none\"\n[fetch]\nhosts = [\"{}\"]\nwrites = \"ask\"\n", site.origin());
    env.policy("app", &policy);
    let post = json!({ "site": "app", "method": "POST", "url": site.url("/echo"), "body": "{}" });
    let mut refused = Mcp::start(env.command().arg("mcp").env("HALTI_TEST_APPROVE", "no"));
    refused.handshake();
    assert!(!refused.call("fetch", get).0, "reads need no consent here");
    let (is_error, reply) = refused.call("fetch", post.clone());
    assert!(is_error && reply.contains("not approved"), "{reply}");
    let mut allowed = env.mcp();
    allowed.handshake();
    let (is_error, reply) = allowed.call("fetch", post);
    assert!(!is_error && reply.contains("HTTP 200"), "{reply}");
}

// --- halti box (the parts that need no VM) ---

impl Env {
    /// `halti box ARGS`, with `editor` as $EDITOR.
    fn boxed(&self, editor: &str, args: &[&str]) -> Output {
        self.command().arg("box").args(args).env("EDITOR", editor).output().unwrap()
    }

    fn box_policy_path(&self, name: &str) -> PathBuf {
        self.dir.join("box").join(format!("{name}.toml"))
    }

    fn box_key_path(&self, name: &str) -> PathBuf {
        self.dir.join("keychain").join(format!("box.{name}._key"))
    }

    /// The store of a box; the test's HOME holds it, so nothing lands in the real Library.
    fn box_store(&self, name: &str) -> PathBuf {
        self.dir.join("home").join(DEV_STORE_ROOT).join("box").join(format!("{name}.sparsebundle"))
    }

    /// An "editor" that replaces the policy with `toml`.
    fn editor_writing(&self, toml: &str) -> String {
        let file = self.dir.join("edited-box.toml");
        fs::write(&file, toml).unwrap();
        format!("cp {}", file.display())
    }

    /// Make a box with the default template and approve it.
    fn new_box(&self, name: &str) {
        let out = self.boxed("true", &["new", name]);
        assert!(out.status.success(), "new failed: {}", stderr(&out));
        let out = self.boxed("true", &["approve", name]);
        assert!(out.status.success(), "approve failed: {}", stderr(&out));
    }
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
fn box_new_makes_a_policy_a_key_and_an_encrypted_store() {
    let env = Env::new();
    let out = env.boxed("true", &["new", "research"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("takes effect once approved"), "{}", stdout(&out));

    let policy = fs::read_to_string(env.box_policy_path("research")).unwrap();
    assert!(policy.contains("halti box approve research"), "{policy}");
    let key = fs::read_to_string(env.box_key_path("research")).unwrap();
    assert!(key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()), "256 random bits as hex");
    let store = env.box_store("research");
    assert!(store.join("bands").is_dir(), "a sparse bundle");

    let out = env.boxed("true", &["new", "research"]);
    assert!(!out.status.success() && stderr(&out).contains("exists"), "{}", stderr(&out));

    let ls = stdout(&env.boxed("true", &["ls"]));
    assert!(ls.contains("research") && ls.contains("locked") && ls.contains("not approved"), "{ls}");
    let out = env.boxed("true", &["run", "research"]);
    assert!(!out.status.success() && stderr(&out).contains("isn't approved"), "nothing starts before approval: {}", stderr(&out));
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
fn box_policies_are_approved_edited_and_blocked_like_resource_policies() {
    let env = Env::new();
    env.new_box("research");
    let ls = stdout(&env.boxed("true", &["ls"]));
    assert!(ls.contains("research") && ls.contains("approved") && !ls.contains("not approved"), "{ls}");

    // An edit shows a diff against the approved text and blocks the box until approved again.
    let editor = env.editor_writing(&fs::read_to_string(env.box_policy_path("research")).unwrap().replace("cpus = 4", "cpus = 2"));
    let out = env.boxed(&editor, &["edit", "research"]);
    let shown = stdout(&out);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(shown.contains("-cpus = 4\n+cpus = 2\n") && !shown.contains('\x1b'), "{shown}");
    assert!(stdout(&env.boxed("true", &["ls"])).contains("changed since approval"));
    let out = env.boxed("true", &["run", "research"]);
    assert!(!out.status.success() && stderr(&out).contains("changed since it was approved"), "{}", stderr(&out));

    assert!(env.boxed("true", &["approve", "research"]).status.success());
    assert!(stdout(&env.boxed("true", &["edit", "research"])).contains("no change from the approved policy for box research"));
}

#[test]
fn box_policy_approve_with_no_names_covers_boxes_too() {
    let env = Env::new();
    env.boxed("true", &["new", "alpha"]);
    env.boxed("true", &["new", "beta"]);
    env.policy("app", "[run]\nmode = \"deny\"\n");
    fs::write(env.box_policy_path("app-box"), "").unwrap();

    let out = env.halti(&["policy", "approve"]);
    if cfg!(not(target_os = "macos")) {
        // No box runs here, so nothing can approve a box's policy, and halti says so.
        let said = stderr(&out);
        assert!(!out.status.success() && said.contains("approving a changed box policy needs an approval this system can't give"), "{said}");
        assert!(!stdout(&out).contains("approved the policy"), "nothing is approved");
        return;
    }
    let shown = stdout(&out);
    assert!(out.status.success(), "{}", stderr(&out));
    for expected in ["approved the policy for app\n", "approved the policy for box alpha", "approved the policy for box beta", "approved the policy for box app-box"] {
        assert!(shown.contains(expected), "missing {expected:?}:\n{shown}");
    }
    let ls = stdout(&env.boxed("true", &["ls"]));
    assert!(!ls.contains("not approved"), "{ls}");
    // Resource names and box names don't collide: the resource list has no boxes in it.
    assert!(!stdout(&env.halti(&["ls"])).contains("alpha"));

    let out = env.command().args(["policy", "approve"]).env("HALTI_TEST_APPROVE", "no").output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn box_new_refuses_policies_the_door_cannot_keep() {
    let env = Env::new();
    for (toml, why) in [
        ("[net]\nallow_writes = [\"http://a.example.com/x\"]\n", "allow_writes"),
        ("standins = [\"HTTPS_PROXY\"]\n", "set by halti already"),
        ("[browser]\nkeep_session = true\n", "unknown field"),
        ("[[mount]]\npath = \"/opt/data\"\nmode = \"rw\"\n", "rw isn't available"),
        ("nope = 1\n", "unknown field"),
    ] {
        let out = env.boxed(&env.editor_writing(toml), &["new", "bad"]);
        assert!(!out.status.success() && stderr(&out).contains(why), "{toml}: {}", stderr(&out));
        assert!(!env.box_key_path("bad").exists() && !env.box_store("bad").exists(), "nothing is made for a bad policy");
        fs::remove_file(env.box_policy_path("bad")).unwrap();
    }
}

/// `halti box login` with a stand-in for the window (see tests/fixtures/fake-runner.mjs). `enter_at`
/// is a line of its output after which the "person" presses Enter in the terminal.
fn box_login(env: &Env, args: &[&str], enter_at: Option<&str>) -> (Output, String) {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-runner.mjs");
    let mut child =
        env.command().args(["box", "login"]).args(args).env("HALTI_TEST_LOGIN_RUNNER", script).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut shown = String::new();
    let mut lines = BufReader::new(child.stdout.take().unwrap());
    loop {
        let mut line = String::new();
        if lines.read_line(&mut line).unwrap() == 0 {
            break;
        }
        shown += &line;
        if enter_at.is_some_and(|at| line.contains(at)) {
            // The window is open by now; Enter typed before it opened would not count.
            thread::sleep(std::time::Duration::from_millis(700));
            let _ = writeln!(stdin);
        }
    }
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    (out, shown)
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
fn box_login_signs_in_site_by_site_and_seals_each_session_in_the_box() {
    let env = Env::new();
    let origin = "http://127.0.0.1:9";
    // Sites that can be signed in to (the first window closes itself, the second waits for Enter,
    // the third is closed without signing in), one that has no browser, one that is not the box's.
    env.policy("app", &format!("[browse]\norigins = [\"{origin}\"]\nstart = \"{origin}/autoclose?site=app\"\n"));
    env.policy("docs", &format!("[browse]\norigins = [\"{origin}\"]\nstart = \"{origin}/wait?site=docs\"\n"));
    env.policy("plain", &format!("[fetch]\nhosts = [\"{origin}\"]\nauth = \"Bearer {{token}}\"\n"));
    env.policy("blank", &format!("[browse]\norigins = [\"{origin}\"]\nstart = \"{origin}/nothing\"\n"));
    env.policy("elsewhere", &format!("[browse]\norigins = [\"{origin}\"]\nstart = \"{origin}/autoclose?site=elsewhere\"\n"));
    let editor = env.editor_writing("sites = [\"app\", \"docs\", \"plain\", \"blank\"]\n");
    assert!(env.boxed(&editor, &["new", "research"]).status.success());
    assert!(env.boxed("true", &["approve", "research"]).status.success());

    // Touch ID is asked first, and a refusal opens nothing.
    let out = env.command().args(["box", "login", "research"]).env("HALTI_TEST_APPROVE", "no").output().unwrap();
    assert!(!out.status.success() && stderr(&out).contains("not approved"), "{}", stderr(&out));
    assert!(!stdout(&out).contains("signing in"));

    // A running box can't be signed in to: nothing may change a folder its VM has mounted.
    let open_dir = env.dir.join("home").join(DEV_STORE_ROOT).join("box/open");
    fs::create_dir_all(&open_dir).unwrap();
    let held = fs::OpenOptions::new().create(true).truncate(false).write(true).open(open_dir.join("research.lock")).unwrap();
    held.lock().unwrap();
    let (out, shown) = box_login(&env, &["research"], None);
    assert!(!out.status.success() && stderr(&out).contains("is running: stop it first"), "{}", stderr(&out));
    assert!(!shown.contains("signing in"));
    held.unlock().unwrap();
    drop(held);

    // Not the box's site, a site with no browser: refused before anything opens.
    for (site, why) in [("elsewhere", "isn't one of box research's sites"), ("plain", "doesn't allow browsing")] {
        let (out, shown) = box_login(&env, &["research", site], None);
        assert!(!out.status.success() && stderr(&out).contains(why), "{site}: {}", stderr(&out));
        assert!(!shown.contains("signing in"));
    }

    // Every site that can be signed in to, one window after another.
    let (out, shown) = box_login(&env, &["research"], Some("docs (2 of 3)"));
    assert!(out.status.success(), "{}\n{}", shown, stderr(&out));
    for line in [
        "signing in to app (1 of 3): close the window when done",
        "sealed the session for app in the box",
        "signing in to docs (2 of 3): close the window when done",
        "sealed the session for docs in the box",
        "signing in to blank (3 of 3): close the window when done",
        "blank: nothing signed in, so nothing sealed",
        "2 of 3 sites signed in",
    ] {
        assert!(shown.contains(line), "missing {line:?} in:\n{shown}");
    }
    assert!(!shown.contains("plain"), "a site without a browser isn't offered: {shown}");
    // The session itself is never shown.
    let everything = format!("{shown}{}", stderr(&out));
    for secret in ["signed-in-to", "by-hand", "local-app", "local-docs"] {
        assert!(!everything.contains(secret), "{secret} was printed:\n{everything}");
    }
    let ls = stdout(&env.boxed("true", &["ls"]));
    assert!(ls.contains("SESSIONS") && ls.contains("app, docs"), "{ls}");

    // The sessions are in the store, sealed.
    let out_dir = env.dir.join("out");
    fs::create_dir(&out_dir).unwrap();
    for site in ["app", "docs"] {
        let out = env.boxed("true", &["export", "research", &format!("browser/{site}.sealed"), "--to", out_dir.to_str().unwrap()]);
        assert!(out.status.success(), "{}", stderr(&out));
        let file = fs::read(out_dir.join(format!("{site}.sealed"))).unwrap();
        assert!(file.len() > 100 && !text(&file).contains("signed-in-to"), "{site}: sealed, not plain");
    }
    assert!(!out_dir.join("blank.sealed").exists());

    // Run again: only the site that got no session is offered; --all asks for every site again.
    let (out, shown) = box_login(&env, &["research"], None);
    assert!(out.status.success() && shown.contains("signing in to blank (1 of 1)") && !shown.contains("app"), "{shown}{}", stderr(&out));
    assert!(shown.contains("0 of 1 sites signed in"), "{shown}");
    let (out, shown) = box_login(&env, &["research", "--all"], Some("docs (2 of 3)"));
    assert!(out.status.success() && shown.contains("signing in to app (1 of 3)") && shown.contains("2 of 3 sites signed in"), "{shown}{}", stderr(&out));

    // One named site goes straight to it, even with a session already.
    let (out, shown) = box_login(&env, &["research", "app"], None);
    assert!(out.status.success() && shown.contains("signing in to app (1 of 1)") && shown.contains("1 of 1 sites signed in"), "{shown}{}", stderr(&out));
}

#[test]
fn a_box_that_is_not_kept_has_no_key_and_no_store() {
    let env = Env::new();
    let out = env.boxed(&env.editor_writing("keep = false\n"), &["new", "scratch"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("keep = false"));
    assert!(!env.box_key_path("scratch").exists() && !env.box_store("scratch").exists());
    assert!(stdout(&env.boxed("true", &["ls"])).contains("shredded"));
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
fn box_import_export_and_log_go_through_touch_id_and_stay_in_the_box() {
    let env = Env::new();
    env.new_box("research");
    let note = env.dir.join("note.txt");
    fs::write(&note, "hello box\n").unwrap();
    let out = env.boxed("true", &["import", "research", note.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("work/note.txt"), "{}", stdout(&out));
    assert!(!env.dir.join("home").join(DEV_STORE_ROOT).join("box/open/research").exists(), "the store is closed again");
    assert!(
        !fs::read_dir(env.box_store("research").join("bands")).unwrap().any(|b| fs::read(b.unwrap().path()).unwrap().windows(9).any(|w| w == b"hello box")),
        "ciphertext at rest"
    );

    let out_dir = env.dir.join("out");
    fs::create_dir(&out_dir).unwrap();
    let export = |env: &Env, args: &[&str]| env.boxed("true", &[&["export", "research"], args].concat());
    let out = export(&env, &["work/note.txt", "--to", out_dir.to_str().unwrap()]);
    let shown = stdout(&out);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(shown.contains("10 B") && shown.contains("work/note.txt") && shown.contains(&sha256(b"hello box\n")), "{shown}");
    assert_eq!(fs::read_to_string(out_dir.join("note.txt")).unwrap(), "hello box\n");

    // What leaves is logged in the box.
    let log = stdout(&env.boxed("true", &["log", "research"]));
    assert!(log.contains("\"kind\":\"export\"") && log.contains("work/note.txt") && log.contains("\"kind\":\"import\""), "{log}");

    // Paths that lead out of the box, and a refused Touch ID, export nothing.
    for bad in ["../note.txt", "/etc/passwd", "work/missing"] {
        let out = export(&env, &[bad, "--to", out_dir.to_str().unwrap()]);
        assert!(!out.status.success(), "exported {bad}");
    }
    fs::remove_file(out_dir.join("note.txt")).unwrap();
    let out = env.command().args(["box", "export", "research", "work/note.txt", "--to"]).arg(&out_dir).env("HALTI_TEST_APPROVE", "no").output().unwrap();
    assert!(!out.status.success() && !out_dir.join("note.txt").exists());
}

impl Env {
    /// Open the box's store as halti does (the key from the test Keychain on hdiutil's stdin), change
    /// its log the way someone with the store open could, and close it again.
    fn tamper_with_log(&self, name: &str, change: impl FnOnce(&str) -> String) {
        struct Detach(PathBuf);
        impl Drop for Detach {
            fn drop(&mut self) {
                let _ = Command::new("hdiutil").args(["detach", "-force"]).arg(&self.0).output();
            }
        }
        let mnt = self.dir.join("tamper-mnt");
        fs::create_dir_all(&mnt).unwrap();
        let key = fs::read_to_string(self.box_key_path(name)).unwrap();
        let mut attach = Command::new("hdiutil")
            .args(["attach", "-stdinpass", "-nobrowse", "-noautoopen", "-owners", "on", "-mountpoint"])
            .arg(&mnt)
            .arg(self.box_store(name))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        attach.stdin.take().unwrap().write_all(&[key.as_bytes(), &[0]].concat()).unwrap();
        let out = attach.wait_with_output().unwrap();
        assert!(out.status.success(), "attach: {}", String::from_utf8_lossy(&out.stderr));
        let _detach = Detach(mnt.clone());
        let log = mnt.join("log/door.log");
        let text = fs::read_to_string(&log).unwrap();
        fs::write(&log, change(&text)).unwrap();
    }
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
fn box_log_verify_finds_a_changed_line_and_a_missing_one() {
    let env = Env::new();
    env.new_box("research");
    let empty = stdout(&env.boxed("true", &["log", "research", "--verify"]));
    assert!(empty.contains("0 lines, chain intact"), "{empty}");

    // Three things happen to the box: one import and two exports, each one line in its log.
    let note = env.dir.join("note.txt");
    fs::write(&note, "hello box\n").unwrap();
    assert!(env.boxed("true", &["import", "research", note.to_str().unwrap()]).status.success());
    for n in 1..=2 {
        let to = env.dir.join(format!("out{n}"));
        fs::create_dir(&to).unwrap();
        let out = env.boxed("true", &["export", "research", "work/note.txt", "--to", to.to_str().unwrap()]);
        assert!(out.status.success(), "{}", stderr(&out));
    }
    let shown = stdout(&env.boxed("true", &["log", "research"]));
    assert!(shown.lines().all(|l| l.contains("\"mac\":\"")), "every line is chained:\n{shown}");
    let verified = env.boxed("true", &["log", "research", "--verify"]);
    assert!(verified.status.success() && stdout(&verified).contains("3 lines, chain intact"), "{} {}", stdout(&verified), stderr(&verified));

    // An edited line is found, and named.
    env.tamper_with_log("research", |text| text.replace("\"kind\":\"import\"", "\"kind\":\"imported\""));
    let out = env.boxed("true", &["log", "research", "--verify"]);
    assert!(!out.status.success() && stderr(&out).contains("chain breaks at line 1"), "{}", stderr(&out));
    env.tamper_with_log("research", |text| text.replace("\"kind\":\"imported\"", "\"kind\":\"import\""));
    assert!(env.boxed("true", &["log", "research", "--verify"]).status.success(), "restoring the line restores the chain");

    // So is a line taken out of the middle.
    env.tamper_with_log("research", |text| text.lines().enumerate().filter(|(i, _)| *i != 1).map(|(_, l)| format!("{l}\n")).collect());
    let out = env.boxed("true", &["log", "research", "--verify"]);
    assert!(!out.status.success() && stderr(&out).contains("chain breaks at line 2"), "{}", stderr(&out));
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
fn box_rm_deletes_the_key_then_the_store_and_warns_about_backups() {
    let env = Env::new();
    env.new_box("research");
    let store = env.box_store("research");
    assert!(store.exists() && env.box_key_path("research").exists());

    let out = env.command().args(["box", "rm", "research"]).env("HALTI_TEST_APPROVE", "no").output().unwrap();
    assert!(!out.status.success());
    assert!(store.exists() && env.box_key_path("research").exists(), "nothing is deleted without Touch ID");

    let out = env.boxed("true", &["rm", "research"]);
    let shown = stdout(&out);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(shown.contains("Time Machine") && shown.contains("old key"), "{shown}");
    assert!(!store.exists() && !env.box_key_path("research").exists());
    assert!(!env.dir.join("keychain/box.research._policy").exists(), "the approval goes too");
    assert!(env.box_policy_path("research").exists(), "the policy file stays");
    assert!(stdout(&env.boxed("true", &["ls"])).contains("no store"));
    let out = env.boxed("true", &["run", "research"]);
    assert!(!out.status.success() && stderr(&out).contains("isn't approved"));
    assert!(!env.boxed("true", &["rm", "nothing"]).status.success());
}

// --- workspaces ---

/// What the passphrase tests type.
const PASSPHRASE: &str = "acme passphrase one";

/// `halti ARGS`, with HALTI_TEST_PASSPHRASE answering every passphrase question.
fn ws(env: &Env, passphrase: &str, args: &[&str]) -> Output {
    env.command().env("HALTI_TEST_PASSPHRASE", passphrase).args(args).output().unwrap()
}

/// The `ws` folder of a test's debug-build home.
fn ws_dir(env: &Env) -> PathBuf {
    env.dir.join("home").join(DEV_STORE_ROOT).join("ws")
}

/// A workspace's id, as its directory record holds it.
fn ws_id(env: &Env, name: &str) -> String {
    fs::read(ws_dir(env).join("dir").join(name)).unwrap()[1..17].iter().map(|b| format!("{b:02x}")).collect()
}

/// How many passphrase questions a command asked: the test variable says each on stderr.
fn asked(out: &Output) -> usize {
    stderr(out).matches("halti: [test] asked: ").count()
}

/// How many passphrase prompts a command showed: the test variable says core's words for each, once
/// each time core asked the key holder, however many questions followed.
fn prompted(out: &Output) -> usize {
    stderr(out).lines().filter(|line| line.starts_with("halti: [test] ") && !line.starts_with("halti: [test] asked: ")).count()
}

#[test]
fn a_workspace_is_made_listed_opened_closed_and_deleted_with_one_passphrase_each() {
    let env = Env::new();
    let made = ws(&env, PASSPHRASE, &["ws", "new", "acme"]);
    assert!(made.status.success(), "{}", stderr(&made));
    // Nothing on stdout until it is created; then that it was, how to open it, and that a debug build made it. Never the passphrase.
    let said = stdout(&made);
    assert_eq!(said, "created workspace acme\nopen it with: halti open acme\ndebug build: this workspace opens only with a debug build\n");
    assert!(!said.contains(PASSPHRASE) && !stderr(&made).contains(PASSPHRASE));
    // A passphrase of one's own is the default: asked for, then typed again.
    assert_eq!((prompted(&made), asked(&made)), (1, 2));
    for question in ["asked: new passphrase for workspace acme (at least 14 characters): \n", "asked: type it again to confirm: \n"] {
        assert!(stderr(&made).contains(question), "{question}: {}", stderr(&made));
    }
    assert!(stderr(&made).contains("halti: [test] [DEV, not protected] create workspace acme\n"), "{}", stderr(&made));
    // The record names no client; the key file is the passphrase record; only this user can read any of it.
    let (dir, id) = (ws_dir(&env), ws_id(&env, "acme"));
    let record = fs::read(dir.join("dir/acme")).unwrap();
    assert_eq!((record.len(), record[0], &record[17..]), (19, 0x01, &[0x05, 0x02][..]));
    assert_eq!((fs::read(dir.join(&id).join("key")).unwrap().len(), fs::read(dir.join("pins").join(&id)).unwrap().len()), (1855, 153));
    let mode = |p: PathBuf| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let pin = dir.join("pins").join(&id);
    assert_eq!([mode(dir.clone()), mode(dir.join(&id)), mode(dir.join("dir/acme")), mode(pin)], [0o700, 0o700, 0o600, 0o600]);
    assert!(!dir.join("mark").exists(), "no prompt mark is made");

    // The table, with the id last, and nothing else; listing asks nothing, and there is no --labels.
    let listing = ws(&env, PASSPHRASE, &["ws", "list"]);
    let listed = stdout(&listing);
    assert!(listed.starts_with("WORKSPACE        STATE      KEY        ID\n"), "{listed}");
    assert!(listed.lines().any(|l| l.starts_with("acme ") && l.contains(" closed ") && l.contains(" passphrase ") && l.ends_with(&id)), "{listed}");
    assert!(listed.lines().count() == 2 && prompted(&listing) == 0, "{listed}");
    let labels = ws(&env, PASSPHRASE, &["ws", "ls", "--labels"]);
    assert!(!labels.status.success() && stdout(&labels).is_empty(), "{}", stderr(&labels));
    for args in [&["open", "acme"][..], &["open"]] {
        let opened = ws(&env, PASSPHRASE, args);
        let said = stdout(&opened);
        assert!(opened.status.success() && said == "passphrase correct\nworkspaces can't stay open yet, so acme was closed again\n", "{said}{}", stderr(&opened));
        assert_eq!((prompted(&opened), asked(&opened)), (1, 1), "{args:?}");
        assert!(stderr(&opened).contains("halti: [test] asked: passphrase for workspace acme: \n"), "{}", stderr(&opened));
    }
    let closed = ws(&env, PASSPHRASE, &["close", "acme"]);
    assert!(closed.status.success() && stdout(&closed) == "acme isn't open\n" && prompted(&closed) == 0);

    let deleted = ws(&env, PASSPHRASE, &["ws", "delete", "acme"]);
    assert!(deleted.status.success() && stdout(&deleted) == "deleted workspace acme\n", "{}", stderr(&deleted));
    assert!(stderr(&deleted).contains("[test] [DEV, not protected] delete workspace acme") && asked(&deleted) == 1);
    assert!(stderr(&deleted).contains("halti: [test] asked: passphrase for workspace acme: \n"), "{}", stderr(&deleted));
    assert!(!dir.join("dir/acme").exists() && !dir.join(&id).exists() && !dir.join("pins").join(&id).exists());
    assert_eq!(stdout(&ws(&env, PASSPHRASE, &["ws", "ls"])), "no workspaces yet. create one with: halti ws new NAME\n");
}

#[test]
fn a_wrong_passphrase_or_a_changed_file_opens_nothing_and_deletes_nothing() {
    let env = Env::new();
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    let (dir, id) = (ws_dir(&env), ws_id(&env, "acme"));
    let files = [dir.join("dir/acme"), dir.join(&id).join("key"), dir.join(&id).join("wrap"), dir.join(&id).join("manifest"), dir.join("pins").join(&id)];
    let before: Vec<Vec<u8>> = files.iter().map(|file| fs::read(file).unwrap()).collect();
    // Another passphrase, and one too short to be any: each is a wrong one, asked once and not again.
    for wrong in ["acme passphrase two", "short"] {
        let out = ws(&env, wrong, &["open", "acme"]);
        assert!(!out.status.success() && stderr(&out).contains("halti: that can't be opened (wrong key, or it was changed)"), "{wrong}: {}", stderr(&out));
        assert_eq!((prompted(&out), asked(&out)), (1, 1), "{wrong}: asked once, and not again");
        let out = ws(&env, wrong, &["ws", "delete", "acme"]);
        let said = stderr(&out);
        assert!(!out.status.success() && said.contains("halti: nothing was deleted: that can't be opened (wrong key"), "{wrong}: {said}");
        assert!(said.contains("halti: [test] [DEV, not protected] delete workspace acme") && asked(&out) == 1, "{wrong}: {said}");
        let after: Vec<Vec<u8>> = files.iter().map(|file| fs::read(file).unwrap()).collect();
        assert!(after == before, "{wrong}: every file is as it was");
    }
    // One byte of the wrap changed: refused before anything is asked, and a delete removes nothing.
    let wrap = dir.join(&id).join("wrap");
    let mut bytes = fs::read(&wrap).unwrap();
    bytes[1682] ^= 0x01;
    fs::write(&wrap, &bytes).unwrap();
    for args in [&["open", "acme"][..], &["ws", "delete", "acme"]] {
        let out = ws(&env, PASSPHRASE, args);
        assert!(!out.status.success() && stderr(&out).contains("can't be opened") && prompted(&out) == 0, "{args:?}: {}", stderr(&out));
    }
    assert!(stderr(&ws(&env, PASSPHRASE, &["ws", "delete", "acme"])).contains("halti: nothing was deleted: "));
    assert!(ws_dir(&env).join("dir/acme").exists() && wrap.exists());
}

#[test]
fn names_are_checked_never_swapped_and_an_unfinished_workspace_is_cleared() {
    let env = Env::new();
    let refused = ws(&env, PASSPHRASE, &["ws", "new", "Bad\x1b[2J"]);
    assert!(stderr(&refused).contains("isn't a workspace name") && !stderr(&refused).contains("Bad"), "{}", stderr(&refused));
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    let again = ws(&env, PASSPHRASE, &["ws", "new", "acme"]);
    let said = stderr(&again);
    assert!(said.contains("there is already a workspace named acme") && !said.contains("ws delete") && prompted(&again) == 0, "{said}");
    assert!(stderr(&ws(&env, PASSPHRASE, &["open", "initech"])).contains("there is no workspace named initech"));
    // A passphrase of one's own that is too short makes nothing, frees the name, and leaves no lock file for the id it drew.
    let locks = || fs::read_dir(ws_dir(&env).join("locks")).unwrap().count();
    assert_eq!(locks(), 1, "acme's");
    let short = ws(&env, "short", &["ws", "new", "globex"]);
    assert!(stderr(&short).contains("halti: workspace globex was not created: a passphrase has at least 14 characters"), "{}", stderr(&short));
    assert_eq!((prompted(&short), asked(&short), locks()), (1, 3, 1), "asked three times, and only acme's lock file is left");
    // One made by halti: the test variable is the passphrase made, so nothing is typed back.
    let generated = ws(&env, PASSPHRASE, &["ws", "new", "globex", "--generate"]);
    assert!(generated.status.success(), "{}", stderr(&generated));
    assert_eq!((prompted(&generated), asked(&generated)), (1, 0));
    assert_eq!(stdout(&generated), "created workspace globex\nopen it with: halti open globex\ndebug build: this workspace opens only with a debug build\n");
    // One's own is the default: typed, then typed again.
    let own = ws(&env, PASSPHRASE, &["ws", "new", "initech"]);
    assert!(own.status.success(), "{}", stderr(&own));
    assert_eq!((prompted(&own), asked(&own)), (1, 2));
    assert!(stderr(&ws(&env, PASSPHRASE, &["open"])).contains("there is more than one workspace (name one)"));
    // globex's pin removed, as a program running as you could, or as a create cut short leaves it: listed as unfinished, its
    // name says how to remove it, and its files go without a passphrase.
    let (dir, id) = (ws_dir(&env), ws_id(&env, "globex"));
    fs::remove_file(dir.join("pins").join(&id)).unwrap();
    let listed = stdout(&ws(&env, PASSPHRASE, &["ws", "ls"]));
    assert!(listed.lines().any(|l| l.starts_with("globex ") && l.contains(" unfinished ")), "{listed}");
    assert!(listed.lines().any(|l| l == "globex was never fully created. remove it with: halti ws delete globex"), "{listed}");
    let again = ws(&env, PASSPHRASE, &["ws", "new", "globex"]);
    let said = stderr(&again);
    let hint = "halti: globex was never fully created. remove it with: halti ws delete globex: there is already a workspace named globex";
    assert!(said.contains(hint) && prompted(&again) == 0, "{said}");
    let cleared = ws(&env, PASSPHRASE, &["ws", "delete", "globex"]);
    let said = stdout(&cleared);
    assert!(said == "removed workspace globex. it was never fully created, so no passphrase was asked\n" && prompted(&cleared) == 0, "{said}");
    assert!(!dir.join("dir/globex").exists() && !dir.join(&id).exists());
}

// --- halti config ---

/// The person's settings file in a test's debug-build home.
fn config_file(env: &Env) -> PathBuf {
    env.dir.join("home").join(DEV_CONFIG_DIR).join("config.toml")
}

/// The approved copy of the settings: a debug build keeps it in its own config folder, where its
/// hook writes it as sudo would.
fn approved_copy(env: &Env) -> PathBuf {
    let uid = fs::metadata(&env.dir).unwrap().uid();
    env.dir.join("home").join(DEV_CONFIG_DIR).join("approved").join(format!("{uid}.toml"))
}

/// The box sections of a Mac's template. No box runs on Linux, so its template has none.
const BOX_SECTIONS: &str = "\n[box]\nengine = \"container\"          # container\nkeys   = \"keychain\"           # where a box's key is kept: keychain\n\n\
                            [box.approval]\nrun    = \"touchid\"            # opening a box: touchid | sudo | none\n\
                            policy = \"touchid\"            # approving a changed box policy: touchid | sudo | none\n\
                            write  = \"touchid\"            # a write the box's policy says to ask about: touchid | none\n\
                            export = \"touchid\"            # copying files out of a box: touchid | sudo | none\n\
                            delete = \"touchid\"            # deleting a box: touchid | sudo | none\n";

/// The template a debug build has on this system.
fn template() -> String {
    let (default, config, boxes) = if cfg!(target_os = "macos") { ("sudo | touchid | passphrase", "sudo | touchid", BOX_SECTIONS) } else { ("sudo | passphrase", "sudo", "") };
    let (managers, ws) = if cfg!(target_os = "macos") { ("none | keychain", "passphrase | sudo | touchid | none") } else { ("none", "passphrase") };
    format!(
        "# halti config. edit with: halti config\n\n[approval]\ndefault = \"sudo\"              # {default}\nconfig  = \"sudo\"              # a change to this file: {config}\n\n\
         [paths]\nworkspaces = \"~/{DEV_STORE_ROOT}/ws\"\n\n[passwords]\nmanager = \"none\"              # {managers}\n\n[secrets]\nstore = \"files\"               # files\n\n\
         [workspace]\npassphrase = \"own\"            # own | generate\n\n[workspace.approval]\n\
         open   = \"passphrase\"         # opening a workspace: {ws}\ndelete = \"passphrase\"         # deleting a workspace: {ws}\n{boxes}"
    )
}

/// The template with one line changed.
fn edited(from: &str, to: &str) -> String {
    let text = template();
    assert!(text.contains(from), "{from}");
    text.replace(from, to)
}

/// `halti config` with an "editor" that writes `text` into the file, and the sudo hook answering
/// `sudo` (yes or no). No test runs the real sudo: a debug build refuses to.
fn config(env: &Env, text: &str, sudo: &str) -> Output {
    let file = env.dir.join("edited-config.toml");
    fs::write(&file, text).unwrap();
    env.command().arg("config").env("EDITOR", format!("cp {}", file.display())).env_remove("VISUAL").env("HALTI_TEST_SUDO", sudo).output().unwrap()
}

const WORKSPACES: &str = "workspaces = \"~/Library/Application Support/halti-dev/ws\"";

#[test]
fn config_shows_the_template_and_what_is_in_effect() {
    let env = Env::new();
    let out = env.halti(&["config", "--default"]);
    assert!(out.status.success() && stdout(&out) == template() && stderr(&out).is_empty(), "{}{}", stdout(&out), stderr(&out));
    let shown = env.halti(&["config", "--show"]);
    let settings = "\n[approval]\ndefault = \"sudo\"\nconfig  = \"sudo\"\n\n[paths]\n";
    let expected = format!("no settings of yours are approved yet, so halti uses its template\n{settings}{WORKSPACES}\n\n[passwords]\nmanager = \"none\"\n");
    assert!(shown.status.success() && stdout(&shown).starts_with(&expected) && stderr(&shown).is_empty(), "{}{}", stdout(&shown), stderr(&shown));
    let last = if cfg!(target_os = "macos") {
        "\n[box.approval]\nrun    = \"touchid\"\npolicy = \"touchid\"\nwrite  = \"touchid\"\nexport = \"touchid\"\ndelete = \"touchid\"\n"
    } else {
        "\n[workspace.approval]\nopen   = \"passphrase\"\ndelete = \"passphrase\"\n"
    };
    assert!(stdout(&shown).ends_with(last), "{}", stdout(&shown));
    assert!(!config_file(&env).exists() && !approved_copy(&env).exists(), "showing writes nothing");
    assert!(!env.halti(&["config", "--show", "--default"]).status.success());
    // halti setup is gone, and a setup.toml an earlier build left is never read.
    assert!(!env.halti(&["setup"]).status.success());
    fs::create_dir_all(env.dir.join("home").join(DEV_CONFIG_DIR)).unwrap();
    fs::write(env.dir.join("home").join(DEV_CONFIG_DIR).join("setup.toml"), "version = 1\npassphrase = \"/bin/sh\"\n").unwrap();
    let made = ws(&env, PASSPHRASE, &["ws", "new", "acme"]);
    assert!(made.status.success() && !stderr(&made).contains("setup"), "{}", stderr(&made));
    assert!(ws_dir(&env).join("dir/acme").exists());
}

#[test]
fn config_approved_with_sudo_moves_where_workspaces_are() {
    let env = Env::new();
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    let home = env.dir.join("home");
    let moved = edited(WORKSPACES, "workspaces = \"~/work/ws\"");
    let out = config(&env, &moved, "yes");
    let said = stdout(&out);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(said.starts_with("--- template\n+++ now\n") && !said.contains('\x1b'), "{said}");
    assert!(said.contains(&format!("-{WORKSPACES}\n+workspaces = \"~/work/ws\"\n")), "{said}");
    let moving = format!(
        "workspaces in {} won't be listed after this: acme. to keep using them, move them to {}\n",
        home.join(DEV_STORE_ROOT).join("ws").display(),
        home.join("work/ws").display()
    );
    assert!(said.ends_with(&format!("{moving}approved. these settings are in effect now\n")), "{said}");
    assert_eq!(stderr(&out), "halti: [test] sudo: yes\n");
    // The file was made from the template, private; the approved copy holds exactly what was approved.
    assert_eq!(fs::read_to_string(config_file(&env)).unwrap(), moved);
    assert_eq!(fs::metadata(config_file(&env)).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(fs::read_to_string(approved_copy(&env)).unwrap(), moved);
    assert_eq!(fs::metadata(approved_copy(&env)).unwrap().permissions().mode() & 0o022, 0);

    // New workspaces go there now, and acme, left where it was, isn't listed.
    let made = ws(&env, PASSPHRASE, &["ws", "new", "globex"]);
    assert!(made.status.success() && stderr(&made).lines().all(|l| l.starts_with("halti: [test] ")), "{}", stderr(&made));
    assert!(home.join("work/ws/dir/globex").exists());
    let listed = stdout(&ws(&env, PASSPHRASE, &["ws", "ls"]));
    assert!(listed.contains("globex") && !listed.contains("acme"), "{listed}");
    let shown = stdout(&env.halti(&["config", "--show"]));
    assert!(shown.starts_with(&format!("your settings, approved with sudo ({})\n\n", approved_copy(&env).display())), "{shown}");
    assert!(shown.contains("\nworkspaces = \"~/work/ws\"\n"), "{shown}");

    // The same again, or with a comment changed: nothing to approve, and sudo isn't asked.
    for text in [moved.clone(), format!("# mine\n{moved}")] {
        let out = config(&env, &text, "yes");
        assert!(out.status.success() && stdout(&out) == "no change to the settings in effect\n" && stderr(&out).is_empty(), "{}{}", stdout(&out), stderr(&out));
    }
}

#[test]
fn a_config_not_approved_or_refused_changes_nothing() {
    let env = Env::new();
    let file = config_file(&env);
    let moved = edited(WORKSPACES, "workspaces = \"~/work/ws\"");
    let out = config(&env, &moved, "no");
    let declined = format!("halti: [test] sudo: no\nhalti: not approved, so nothing changed. your edits stay in {}. approve them with: halti config\n", file.display());
    assert!(!out.status.success() && stderr(&out) == declined, "{}", stderr(&out));
    assert!(!stdout(&out).contains("approved."), "{}", stdout(&out));
    assert!(!approved_copy(&env).exists());
    // Until approved, the edit has no effect, and every workspace command says so.
    let pending = format!("halti: changes in {} aren't approved yet, so they have no effect. approve them with: halti config\n", file.display());
    let listed = ws(&env, PASSPHRASE, &["ws", "ls"]);
    assert_eq!(stderr(&listed), pending);
    let made = ws(&env, PASSPHRASE, &["ws", "new", "acme"]);
    assert!(made.status.success() && stderr(&made).starts_with(&pending) && ws_dir(&env).join("dir/acme").exists(), "{}", stderr(&made));
    let shown = env.halti(&["config", "--show"]);
    assert!(stderr(&shown) == pending && stdout(&shown).starts_with("no settings of yours are approved yet"), "{}", stderr(&shown));

    // A setting that can't be: refused with its line, and nothing is asked.
    let can = if cfg!(target_os = "macos") { "can be sudo or touchid" } else { "can only be sudo" };
    let out = config(&env, &edited("config  = \"sudo\"", "config  = \"none\""), "yes");
    let refused = format!("halti: {}, line 5: config can't be none. it {can}\nnothing was approved. fix it with: halti config\n", file.display());
    assert!(!out.status.success() && stderr(&out) == refused && stdout(&out).is_empty(), "{}", stderr(&out));
    let out = config(&env, "[approval\n", "yes");
    let said = stderr(&out);
    assert!(said.starts_with(&format!("halti: {}, line ", file.display())), "{said}");
    assert!(said.ends_with(": this line isn't valid toml\nnothing was approved. fix it with: halti config\n"), "{said}");
    // The broken file is said to be so, and the settings stay as they were.
    let listed = ws(&env, PASSPHRASE, &["ws", "ls"]);
    assert!(stderr(&listed).contains("can't be used (line ") && stderr(&listed).contains("so the settings stay as they were. fix it with: halti config"));
    assert!(stdout(&listed).contains("acme"), "{}", stdout(&listed));
    assert!(!approved_copy(&env).exists());
}

#[test]
fn a_copy_others_could_change_is_not_used() {
    let env = Env::new();
    let moved = edited(WORKSPACES, "workspaces = \"~/work/ws\"");
    assert!(config(&env, &moved, "yes").status.success());
    assert!(stdout(&env.halti(&["config", "--show"])).starts_with("your settings, approved with sudo"));
    fs::set_permissions(approved_copy(&env), fs::Permissions::from_mode(0o664)).unwrap();
    let shown = env.halti(&["config", "--show"]);
    let copy = approved_copy(&env).display().to_string();
    let not_used = format!("halti: {copy} isn't used, because someone other than you could change it or a folder above it. halti's template is in effect\n");
    assert!(stderr(&shown).starts_with(&not_used), "{}", stderr(&shown));
    assert!(stdout(&shown).starts_with("no settings of yours are approved yet") && stdout(&shown).contains(WORKSPACES), "{}", stdout(&shown));
    // So new workspaces are where the template says.
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    assert!(ws_dir(&env).join("dir/acme").exists() && !env.dir.join("home/work/ws").exists());

    // A copy that isn't settings: approving the template's own writes it again, and then nothing more
    // is said of it. The real tee keeps the mode of a copy already there, so only the hook mends one others could change.
    fs::set_permissions(approved_copy(&env), fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(approved_copy(&env), "[approval]\nconfig = \"none\"\n").unwrap();
    let out = config(&env, &template(), "yes");
    let again = format!("{copy} can't be used, so approving these settings writes it again\n");
    let said = stdout(&out);
    assert!(out.status.success() && said.starts_with(&again) && said.ends_with("approved. these settings are in effect now\n"), "{said}{}", stderr(&out));
    let shown = env.halti(&["config", "--show"]);
    assert!(stderr(&shown).is_empty() && stdout(&shown).starts_with("your settings, approved with sudo"), "{}{}", stdout(&shown), stderr(&shown));
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs hdiutil")]
fn a_box_asks_as_its_approval_settings_say() {
    let env = Env::new();
    env.new_box("research");
    let note = env.dir.join("note.txt");
    fs::write(&note, "hello box\n").unwrap();
    assert!(env.boxed("true", &["import", "research", note.to_str().unwrap()]).status.success());

    // Copying out asks nothing, and deleting asks for sudo: settings approved with sudo, as any change.
    let changed = edited("export = \"touchid\"", "export = \"none\"").replace("delete = \"touchid\"", "delete = \"sudo\"");
    let out = config(&env, &changed, "yes");
    assert!(out.status.success(), "{}", stderr(&out));
    let shown = stdout(&env.halti(&["config", "--show"]));
    assert!(shown.contains("\nwrite  = \"touchid\"\nexport = \"none\"\ndelete = \"sudo\"\n"), "{shown}");

    // Touch ID would say no, but nothing asks it: the file comes out.
    let out_dir = env.dir.join("out");
    fs::create_dir(&out_dir).unwrap();
    let out = env.command().args(["box", "export", "research", "work/note.txt", "--to"]).arg(&out_dir).env("HALTI_TEST_APPROVE", "no").output().unwrap();
    assert!(out.status.success() && !stderr(&out).contains("[test] export"), "{}", stderr(&out));
    assert_eq!(fs::read_to_string(out_dir.join("note.txt")).unwrap(), "hello box\n");

    // Deleting asks sudo, not Touch ID: a no keeps the box, a yes deletes it.
    let rm = |sudo: &str| env.command().args(["box", "rm", "research"]).env("HALTI_TEST_APPROVE", "no").env("HALTI_TEST_SUDO", sudo).output().unwrap();
    let out = rm("no");
    assert!(!out.status.success() && stderr(&out).contains("halti: [test] sudo: no"), "{}", stderr(&out));
    assert!(!stderr(&out).contains("[test] delete box"), "Touch ID isn't asked: {}", stderr(&out));
    assert!(env.box_key_path("research").exists() && env.box_store("research").exists(), "nothing is deleted");
    let out = rm("yes");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!env.box_key_path("research").exists() && !env.box_store("research").exists());
}

#[test]
fn a_folder_halti_did_not_make_is_never_taken_for_workspaces() {
    let env = Env::new();
    let mine = env.dir.join("home/work/ws");
    fs::create_dir_all(&mine).unwrap();
    fs::write(mine.join("notes.txt"), "mine").unwrap();
    let moved = edited(WORKSPACES, "workspaces = \"~/work/ws\"");
    let refused = |why: &str| format!("halti: the workspaces folder {why}, so halti won't use it\nnothing was approved. fix it with: halti config\n");
    // Open to others, or holding files of someone else's: refused, and the folder is left as it is.
    fs::set_permissions(&mine, fs::Permissions::from_mode(0o755)).unwrap();
    let out = config(&env, &moved, "yes");
    assert!(!out.status.success() && stderr(&out) == refused("is open to other users"), "{}", stderr(&out));
    assert_eq!(fs::metadata(&mine).unwrap().permissions().mode() & 0o777, 0o755);
    fs::set_permissions(&mine, fs::Permissions::from_mode(0o700)).unwrap();
    let out = config(&env, &moved, "yes");
    assert!(!out.status.success() && stderr(&out) == refused("holds files that aren't halti's"), "{}", stderr(&out));
    assert!(!approved_copy(&env).exists() && fs::read_dir(&mine).unwrap().count() == 1);

    // Empty, it is taken, and workspaces are made there.
    fs::remove_file(mine.join("notes.txt")).unwrap();
    assert!(config(&env, &moved, "yes").status.success());
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    assert!(mine.join("dir/acme").exists());
    // A file of someone else's put there later: nothing more is written in it.
    fs::write(mine.join("notes.txt"), "mine").unwrap();
    let made = ws(&env, PASSPHRASE, &["ws", "new", "globex"]);
    let said = stderr(&made);
    assert!(!made.status.success() && said.contains("the workspaces folder holds files that aren't halti's, so halti didn't write in it"), "{said}");
    assert!(!mine.join("dir/globex").exists() && stdout(&ws(&env, PASSPHRASE, &["ws", "ls"])).contains("acme"));
}

#[test]
fn ws_new_takes_whose_passphrase_from_the_settings_unless_told() {
    let env = Env::new();
    let generate = edited("passphrase = \"own\"   ", "passphrase = \"generate\"");
    assert!(config(&env, &generate, "yes").status.success());
    // A made passphrase: the test variable is the one made, so nothing is typed back.
    let made = ws(&env, PASSPHRASE, &["ws", "new", "acme"]);
    assert!(made.status.success() && (prompted(&made), asked(&made)) == (1, 0), "{}", stderr(&made));
    let own = ws(&env, PASSPHRASE, &["ws", "new", "globex", "--own"]);
    assert!(own.status.success() && (prompted(&own), asked(&own)) == (1, 2), "{}", stderr(&own));
    let both = ws(&env, PASSPHRASE, &["ws", "new", "initech", "--own", "--generate"]);
    assert!(!both.status.success() && prompted(&both) == 0);

    assert!(config(&env, &template(), "yes").status.success());
    let own = ws(&env, PASSPHRASE, &["ws", "new", "initech"]);
    assert!(own.status.success() && (prompted(&own), asked(&own)) == (1, 2), "{}", stderr(&own));
    let made = ws(&env, PASSPHRASE, &["ws", "new", "umbrella", "--generate"]);
    assert!(made.status.success() && (prompted(&made), asked(&made)) == (1, 0), "{}", stderr(&made));
}

/// The template with the keychain as the password manager, and opening and deleting a workspace
/// approved by `open` and `delete`.
fn with_keychain(open: &str, delete: &str) -> String {
    edited("manager = \"none\"   ", "manager = \"keychain\"")
        .replace("open   = \"passphrase\"", &format!("open   = \"{open}\""))
        .replace("delete = \"passphrase\"", &format!("delete = \"{delete}\""))
}

/// Where the debug build's fake Keychain keeps the saved passphrase of the workspace `name`.
fn saved_copy(env: &Env, name: &str) -> PathBuf {
    env.dir.join("keychain").join(format!("halti-ws.{}", ws_id(env, name)))
}

/// Whether neither stdout nor stderr holds `passphrase`.
fn keeps_quiet(out: &Output, passphrase: &str) -> bool {
    !text(&out.stdout).contains(passphrase) && !text(&out.stderr).contains(passphrase)
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "the keychain is only on a mac")]
fn a_saved_passphrase_is_taken_from_the_keychain_after_the_approval_in_effect() {
    let env = Env::new();
    let out = config(&env, &with_keychain("touchid", "sudo"), "yes");
    assert!(out.status.success(), "{}", stderr(&out));
    let made = ws(&env, PASSPHRASE, &["ws", "new", "acme"]);
    assert!(made.status.success() && keeps_quiet(&made, PASSPHRASE), "{}", stderr(&made));
    let said = "created workspace acme\nits passphrase is saved in the keychain\nopen it with: halti open acme\ndebug build: this workspace opens only with a debug build\n";
    assert_eq!(stdout(&made), said);
    let copy = saved_copy(&env, "acme");
    assert_eq!(fs::read_to_string(&copy).unwrap(), PASSPHRASE);
    let opened = "passphrase correct\nworkspaces can't stay open yet, so acme was closed again\n";

    // Touch ID, then the copy: no passphrase is given, and none is asked for.
    let open = |approve: &str| env.command().args(["open", "acme"]).env("HALTI_TEST_APPROVE", approve).output().unwrap();
    let out = open("yes");
    assert!(out.status.success() && stdout(&out) == opened && keeps_quiet(&out, PASSPHRASE), "{}{}", stdout(&out), stderr(&out));
    assert_eq!(stderr(&out), "halti: [test] [DEV, not protected] open workspace acme: yes\n");
    // Touch ID says no: nothing opens, and halti says how to type it instead.
    let out = open("no");
    assert!(!out.status.success() && stdout(&out).is_empty(), "{}", stdout(&out));
    assert!(stderr(&out).ends_with("halti: acme was not opened. to type the passphrase instead: halti open acme --type\n"), "{}", stderr(&out));
    // With --type it is typed, and Touch ID isn't asked.
    let out = env.command().args(["open", "acme", "--type"]).env("HALTI_TEST_APPROVE", "no").env("HALTI_TEST_PASSPHRASE", PASSPHRASE).output().unwrap();
    assert!(out.status.success() && stdout(&out) == opened && asked(&out) == 1, "{}", stderr(&out));
    assert!(!stderr(&out).contains("open workspace acme: ") && keeps_quiet(&out, PASSPHRASE), "{}", stderr(&out));

    // A copy that can't be used: said, typed once, and saved again. Then one that is gone: nothing to approve, and the
    // usual question.
    for change in [Some("acme passphrase two"), None] {
        match change {
            Some(other) => fs::write(&copy, other).unwrap(),
            None => fs::remove_file(&copy).unwrap(),
        }
        let out = ws(&env, PASSPHRASE, &["open", "acme"]);
        assert!(out.status.success() && asked(&out) == 1 && keeps_quiet(&out, PASSPHRASE), "{change:?}: {}", stderr(&out));
        let once = stderr(&out).contains("\nthe saved passphrase of acme can't be read. type it once.\n");
        assert_eq!(once, change.is_some(), "{change:?}: {}", stderr(&out));
        assert_eq!(stderr(&out).contains("open workspace acme: yes"), change.is_some(), "{change:?}: {}", stderr(&out));
        let again = "passphrase correct\nsaved the passphrase of acme in the keychain again\nworkspaces can't stay open yet, so acme was closed again\n";
        assert_eq!(stdout(&out), again, "{change:?}");
        assert_eq!(fs::read_to_string(&copy).unwrap(), PASSPHRASE, "{change:?}");
    }

    // Deleting asks sudo: a no keeps the workspace and its copy, a yes takes both. Nothing is typed.
    let delete = |sudo: &str| {
        let mut command = env.command();
        command.args(["ws", "delete", "acme"]).env("HALTI_TEST_APPROVE", "no").env("HALTI_TEST_SUDO", sudo).env("HALTI_TEST_PASSPHRASE", "not the passphrase");
        command.output().unwrap()
    };
    let out = delete("no");
    let refused = "halti: acme was not deleted. to type the passphrase instead: halti ws delete acme --type\n";
    assert!(!out.status.success() && stderr(&out).ends_with(refused), "{}", stderr(&out));
    assert!(ws_dir(&env).join("dir/acme").exists() && copy.exists());
    let out = delete("yes");
    assert!(out.status.success() && stdout(&out) == "deleted workspace acme\n" && asked(&out) == 0, "{}", stderr(&out));
    let said = stderr(&out);
    assert!(said.contains("this deletes workspace acme and everything in it. it can't be undone.\nhalti: [test] sudo: yes\n"), "{said}");
    assert!(!ws_dir(&env).join("dir/acme").exists() && !copy.exists() && keeps_quiet(&out, PASSPHRASE));
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "the keychain is only on a mac")]
fn a_workspace_made_before_the_manager_is_typed_and_a_passphrase_line_types_it() {
    let env = Env::new();
    // Made while nothing kept a passphrase, as every workspace before the manager was.
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    assert!(config(&env, &with_keychain("touchid", "touchid"), "yes").status.success());
    let out = ws(&env, PASSPHRASE, &["open", "acme"]);
    assert!(out.status.success() && asked(&out) == 1 && !stderr(&out).contains("open workspace acme: "), "{}", stderr(&out));
    assert!(!stderr(&out).contains("saved passphrase"), "no copy, so the usual question: {}", stderr(&out));
    let each_time = "passphrase correct\nacme was made without a saved passphrase, so it is typed each time\nworkspaces can't stay open yet, so acme was closed again\n";
    assert_eq!(stdout(&out), each_time);
    assert!(!saved_copy(&env, "acme").exists(), "nothing is saved for it");

    // Lines back to passphrase: a new workspace's passphrase is still saved, and opening and deleting type it.
    assert!(config(&env, &with_keychain("passphrase", "passphrase"), "yes").status.success());
    let globex = "globex passphrase one";
    let made = ws(&env, globex, &["ws", "new", "globex"]);
    assert!(made.status.success() && stdout(&made).contains("\nits passphrase is saved in the keychain\n"), "{}", stdout(&made));
    let copy = saved_copy(&env, "globex");
    let typed = |args: &[&str]| env.command().args(args).env("HALTI_TEST_APPROVE", "no").env("HALTI_TEST_PASSPHRASE", globex).output().unwrap();
    let out = typed(&["open", "globex"]);
    assert!(out.status.success() && asked(&out) == 1 && !stderr(&out).contains("open workspace globex: "), "{}", stderr(&out));
    assert!(!stderr(&out).contains("saved passphrase") && copy.exists());
    let out = typed(&["ws", "delete", "globex"]);
    assert!(out.status.success() && stdout(&out) == "deleted workspace globex\n" && asked(&out) == 1, "{}", stderr(&out));
    assert!(!copy.exists(), "the copy goes with the workspace");
}

#[test]
fn a_workspace_line_that_needs_a_password_manager_is_refused_without_one() {
    let env = Env::new();
    let (to, why) = if cfg!(target_os = "macos") {
        ("open   = \"touchid\"", "line 20: open can't be touchid while [passwords] manager is none")
    } else {
        ("open   = \"sudo\"", "line 20: open can't be sudo. it can only be passphrase")
    };
    let out = config(&env, &edited("open   = \"passphrase\"", to), "yes");
    let refused = format!("halti: {}, {why}\nnothing was approved. fix it with: halti config\n", config_file(&env).display());
    assert!(!out.status.success() && stderr(&out) == refused && stdout(&out).is_empty(), "{}", stderr(&out));
    assert!(!approved_copy(&env).exists());
    // Nothing changed: a workspace is made, opened and deleted with its passphrase, as before.
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    let out = ws(&env, PASSPHRASE, &["open", "acme"]);
    assert!(out.status.success() && asked(&out) == 1 && stdout(&out).starts_with("passphrase correct\n"), "{}", stderr(&out));
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "Touch ID is only on a mac")]
fn config_approved_with_touch_id_keeps_its_record_under_the_sudo_copy() {
    let env = Env::new();
    let touch_id = edited("config  = \"sudo\"", "config  = \"touchid\"");
    let out = config(&env, &touch_id, "yes");
    assert!(out.status.success(), "{}", stderr(&out));
    let record = env.dir.join("keychain").join(format!("config.{}._policy", &sha256(touch_id.as_bytes())[..16]));
    assert!(record.exists(), "sudo approved this text, so its record is made at once");
    assert_eq!(fs::read_to_string(approved_copy(&env)).unwrap(), touch_id);

    // Now Touch ID approves a change, sudo isn't asked, and the copy stays as sudo wrote it.
    let moved = touch_id.replace(WORKSPACES, "workspaces = \"~/work/ws\"");
    let out = config(&env, &moved, "no");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stderr(&out), "halti: [test] approve your changed settings: yes\n");
    assert_eq!(fs::read_to_string(approved_copy(&env)).unwrap(), touch_id);
    assert!(fs::read_to_string(&record).unwrap().contains("work/ws"));
    let shown = stdout(&env.halti(&["config", "--show"]));
    assert!(shown.starts_with("your settings, approved with touch id\n\n") && shown.contains("\nworkspaces = \"~/work/ws\"\n"), "{shown}");

    // The record removed: the copy sudo approved is in effect again, and halti says so.
    fs::remove_file(&record).unwrap();
    let shown = env.halti(&["config", "--show"]);
    assert!(stderr(&shown).starts_with("halti: the touch id approval of your settings is missing, so the settings last approved with sudo are in effect."));
    assert!(stdout(&shown).starts_with("your settings, approved with sudo") && stdout(&shown).contains(WORKSPACES), "{}", stdout(&shown));
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "Touch ID is there on a mac")]
fn config_refuses_touch_id_where_there_is_none() {
    let env = Env::new();
    let out = config(&env, &edited("config  = \"sudo\"", "config  = \"touchid\""), "yes");
    let refused = format!("halti: {}, line 5: touchid is only on a mac\nnothing was approved. fix it with: halti config\n", config_file(&env).display());
    assert!(!out.status.success() && stderr(&out) == refused, "{}", stderr(&out));
    assert!(!approved_copy(&env).exists());
}

// --- opt-in: the browser and the real Touch ID ---

fn opt_in(name: &str) -> bool {
    let on = env::var_os(name).is_some();
    if !on {
        eprintln!("skipped: set {name}=1 to run this test");
    }
    on
}

#[test]
#[ignore = "needs Node, the runner's dependencies and Chromium: HALTI_E2E_BROWSER=1"]
fn browser_opens_a_page_signed_in_and_masks_it() {
    if !opt_in("HALTI_E2E_BROWSER") {
        return;
    }
    let env = Env::new();
    let site = Site::start();
    env.store("app", "token", TOKEN);
    env.policy(
        "app",
        &format!(
            "[agent]\nconsent = \"none\"\n[browse]\norigins = [\"{0}\"]\nstart = \"{0}/page\"\ncookies = [{{ name = \"session\", field = \"token\", domain = \"127.0.0.1\" }}]\n",
            site.origin()
        ),
    );
    let runner = env::var("HALTI_RUNNER_DIR").unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("runner").display().to_string());
    // The test's HOME is empty, so Playwright must be told where the real one keeps Chromium.
    let browsers = env::var("PLAYWRIGHT_BROWSERS_PATH").unwrap_or_else(|_| format!("{}/Library/Caches/ms-playwright", env::var("HOME").unwrap()));
    let mut mcp = Mcp::start(env.command().arg("mcp").env("HALTI_RUNNER_DIR", runner).env("PLAYWRIGHT_BROWSERS_PATH", browsers));
    mcp.handshake();
    assert!(mcp.tool_names().contains(&"browse_open".to_string()));

    let (is_error, page) = mcp.call("browse_open", json!({ "site": "app" }));
    assert!(!is_error, "{page}");
    assert!(page.contains("Hello e2e"), "{page}");
    assert!(page.contains("cookie: session=********"), "the page got the session, masked for the agent:\n{page}");
    assert!(!page.contains(TOKEN));
    assert!(site.seen().iter().any(|r| r.contains(&format!("session={TOKEN}"))), "{:?}", site.seen());

    let (is_error, reply) = mcp.call("browse_goto", json!({ "url": "https://elsewhere.example.com/" }));
    assert!(is_error || reply.to_lowercase().contains("blocked"), "{reply}");
    assert_eq!(mcp.call("browse_close", json!({})), (false, "browser closed".to_string()));
}

#[test]
#[ignore = "asks a human for Touch ID and uses the real Keychain: HALTI_E2E_INTERACTIVE=1"]
fn touch_id_approval_pins_the_policy_in_the_real_keychain() {
    if !opt_in("HALTI_E2E_INTERACTIVE") {
        return;
    }
    let env = Env::new();
    // A throwaway resource name; its only Keychain item is the approval, removed at the end.
    let res = format!("e2e-touchid-{}", std::process::id());
    fs::write(env.dir.join("index.json"), json!({ res.clone(): { "fields": { "token": {} } } }).to_string()).unwrap();
    env.write_policy(&res, "[run]\nmode = \"deny\"\n");
    let real = || {
        let mut cmd = env.command();
        cmd.env("HOME", env::var("HOME").unwrap()).env_remove("HALTI_TEST_KEYCHAIN").env_remove("HALTI_TEST_APPROVE");
        cmd
    };

    eprintln!("Touch ID prompt: approve the policy for {res}");
    let out = real().args(["policy", "approve", &res]).output().unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let shown = stdout(&real().args(["policy", "show", &res]).output().unwrap());
    let removed = real().args(["rm", &res]).output().unwrap();
    assert!(shown.contains("(approved)"), "{shown}");
    assert!(removed.status.success(), "{}", stderr(&removed));
}
