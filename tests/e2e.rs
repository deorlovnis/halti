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

use std::collections::BTreeMap;
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

// --- rm, reseal, check and describe ---

/// Every item in the fake Keychain, by its file name, with its bytes.
fn keychain_items(env: &Env) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(env.dir.join("keychain")).unwrap().map(|e| e.unwrap()).map(|e| (e.file_name().into_string().unwrap(), fs::read(e.path()).unwrap())).collect()
}

fn index_text(env: &Env) -> String {
    fs::read_to_string(env.dir.join("index.json")).unwrap()
}

/// The index entry `Env::store` makes, as `halti` writes it back: fields with no dates.
fn stored_entry(res: &str, fields: &[&str]) -> String {
    let fields: Vec<String> = fields.iter().map(|f| format!("      \"{f}\": {{}}")).collect();
    format!("  \"{res}\": {{\n    \"url\": \"\",\n    \"description\": \"the {res} test site\",\n    \"fields\": {{\n{}\n    }}\n  }}", fields.join(",\n"))
}

/// Exit code 1, and on stderr only what the error says.
fn failed_with(out: &Output, error: &str) {
    assert_eq!(out.status.code(), Some(1), "{}", stderr(out));
    assert_eq!(stderr(out), format!("halti: {error}\n"));
    assert_eq!(stdout(out), "");
}

#[test]
fn rm_removes_the_values_and_the_approval() {
    let env = Env::new();
    env.store("app", "login", "someone");
    env.store("app", "token", TOKEN);
    env.store("other", "token", "other-token");
    env.policy("app", "[run]\nmode = \"allow\"\nexport = { token = \"APP_TOKEN\" }\n");
    let keychain = env.dir.join("keychain");
    let item = |name: &str| keychain.join(name).exists();
    assert!(item("app._policy"));

    // One field: its value and its line go, and the policy stays approved.
    let out = env.halti(&["rm", "app", "login"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "removed app/login\n");
    assert_eq!(stderr(&out), "");
    assert!(!item("app.login") && item("app.token") && item("app._policy"));
    assert_eq!(index_text(&env), format!("{{\n{},\n{}\n}}\n", stored_entry("app", &["token"]), stored_entry("other", &["token"])));

    // A field with no value is said on stderr, and the command still succeeds.
    let out = env.halti(&["rm", "app", "nothing"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "removed app/nothing\n");
    assert_eq!(stderr(&out), "halti: app/nothing not in Keychain\n");

    // The whole resource: every value it lists, its approval and its line; its policy file stays.
    env.store("app", "session", "gone already");
    fs::remove_file(keychain.join("app.session")).unwrap();
    let out = env.halti(&["rm", "app"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "removed app\n");
    assert_eq!(stderr(&out), "halti: app/session not in Keychain\n");
    assert!(!item("app.token") && !item("app._policy"));
    assert!(env.dir.join("policy/app.toml").exists());
    assert_eq!(keychain_items(&env), BTreeMap::from([("other.token".to_string(), b"other-token".to_vec())]));
    assert_eq!(index_text(&env), format!("{{\n{}\n}}\n", stored_entry("other", &["token"])));
    assert!(stdout(&env.halti(&["policy", "show", "app"])).contains("(not approved)\n"));

    // A resource the index doesn't list can't be removed whole; a field of it is tried anyway.
    failed_with(&env.halti(&["rm", "app"]), "app doesn't exist (create it with: halti set app FIELD)");
    let out = env.halti(&["rm", "app", "token"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "removed app/token\n");
    assert_eq!(stderr(&out), "halti: app/token not in Keychain\n");
    assert_eq!(index_text(&env), format!("{{\n{}\n}}\n", stored_entry("other", &["token"])));
}

#[test]
fn reseal_keeps_every_value() {
    let env = Env::new();
    env.store("app", "login", "someone\non two lines\n");
    env.store("app", "token", TOKEN);
    env.store("draft", "token", "draft-token");
    env.store("gone", "token", "removed by hand");
    fs::remove_file(env.dir.join("keychain/gone.token")).unwrap();
    env.policy("app", "[run]\nmode = \"allow\"\nexport = { token = \"APP_TOKEN\" }\n");
    env.write_policy("draft", "[run]\nmode = \"allow\"\nexport = { token = \"DRAFT_TOKEN\" }\n");
    let (items, index) = (keychain_items(&env), index_text(&env));

    // Every resource the index lists, field by field; a policy that isn't approved is named.
    let out = env.halti(&["reseal"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "resealed app/login\nresealed app/token\nresealed draft/token\napprove draft's policy again: halti policy approve draft\n");
    assert_eq!(stderr(&out), "halti: gone/token not in Keychain, skipped\n");
    assert_eq!(keychain_items(&env), items, "every value and approval keeps its bytes");
    assert_eq!(index_text(&env), index);

    // Only the ones named.
    let out = env.halti(&["reseal", "app"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "resealed app/login\nresealed app/token\n");
    assert_eq!(stderr(&out), "");
    assert_eq!(keychain_items(&env), items);
    assert!(stdout(&env.halti(&["policy", "show", "app"])).contains("(approved)\n"));

    failed_with(&env.halti(&["reseal", "nope"]), "nope doesn't exist (create it with: halti set nope FIELD)");
    assert_eq!(keychain_items(&env), items);
}

#[test]
fn check_reports_expiry_and_refreshes_what_is_due() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jiff::ToSpan;

    let env = Env::new();
    let today = jiff::Zoned::now().date();
    let day = |n: i64| today.checked_add(n.days()).unwrap().to_string();

    // A refreshed token that says when it expires, an hour from now.
    let exp = jiff::Timestamp::now().as_second() + 3600;
    let jwt = format!("e30.{}.sig", URL_SAFE_NO_PAD.encode(format!("{{\"exp\":{exp}}}")));
    let until = jiff::Timestamp::from_second(exp).unwrap().to_zoned(jiff::tz::TimeZone::system()).strftime("%Y-%m-%d %H:%M").to_string();
    let script = |name: &str, body: &str| {
        let path = env.dir.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        path.display().to_string()
    };
    let (fresh, fails, unused) = (script("fresh.sh", &format!("printf '%s' '{jwt}'")), script("fails.sh", "exit 1"), script("unused.sh", "printf 'not-due'"));

    for (res, field, value) in [("app", "later", "a1"), ("app", "old", "a2"), ("app", "token", "a3"), ("auto", "key", "k0"), ("auto", "token", "t0"), ("broken", "token", "b0")] {
        env.store(res, field, value);
    }
    let index = json!({
        "app": { "url": "https://app.example.com/tokens", "description": "", "fields": {
            "later": { "expires": day(30) }, "old": { "expires": day(-10) }, "token": { "expires": day(3) } } },
        "auto": { "url": "", "description": "", "fields": { "key": { "expires": day(5) }, "token": { "expires": day(-1) } } },
        "broken": { "url": "https://broken.example.com", "description": "", "fields": { "token": { "expires": day(-1) } } },
    });
    fs::write(env.dir.join("index.json"), index.to_string()).unwrap();
    env.policy("auto", &format!("[refresh.token]\nrun = \"{fresh}\"\n[refresh.key]\nrun = \"{unused}\"\n"));
    env.policy("broken", &format!("[refresh.token]\nrun = \"{fails}\"\n"));
    let value = |name: &str| fs::read_to_string(env.dir.join("keychain").join(name)).unwrap();

    // What refreshes and is due goes first, then whatever is still expired or due in 7 days is listed.
    let out = env.halti(&["check", "7"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(
        stdout(&out),
        format!(
            "app/old expired 10d ago ({}) — rotate at https://app.example.com/tokens\n\
             app/token expires in 3d ({}) — rotate at https://app.example.com/tokens\n\
             broken/token expired and auto-refresh failed (halti refresh broken) — rotate at https://broken.example.com\n",
            day(-10),
            day(3)
        )
    );
    assert_eq!(stderr(&out), format!("halti: refreshed auto/token (expires {until})\nhalti: refresh script for broken/token failed (exit status: 1)\n"));
    assert_eq!((value("auto.token"), value("auto.key"), value("broken.token")), (jwt.clone(), "k0".to_string(), "b0".to_string()));
    let saved: Value = serde_json::from_str(&index_text(&env)).unwrap();
    assert_eq!(saved["auto"]["fields"]["token"]["expires_at"], json!(jiff::Timestamp::from_second(exp).unwrap()));
    assert_eq!(saved["auto"]["fields"]["token"]["updated"], json!(day(0)));

    // A token refreshed a moment ago isn't due again; a narrower window lists less.
    let out = env.halti(&["check", "2"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(
        stdout(&out),
        format!(
            "app/old expired 10d ago ({}) — rotate at https://app.example.com/tokens\n\
             broken/token expired and auto-refresh failed (halti refresh broken) — rotate at https://broken.example.com\n",
            day(-10)
        )
    );
    assert_eq!(stderr(&out), "halti: refresh script for broken/token failed (exit status: 1)\n");
    assert_eq!(value("auto.token"), jwt);

    // Nothing due, nothing said.
    let env = Env::new();
    env.store("app", "token", TOKEN);
    let out = env.halti(&["check", "7"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!((stdout(&out), stderr(&out)), (String::new(), String::new()));
}

#[test]
fn describe_keeps_the_values() {
    let env = Env::new();
    env.store("app", "login", "someone");
    env.store("app", "token", TOKEN);
    env.policy("app", "[run]\nmode = \"allow\"\nexport = { token = \"APP_TOKEN\" }\n");
    let mut index: Value = serde_json::from_str(&index_text(&env)).unwrap();
    index["app"]["fields"]["token"] = json!({ "updated": "2026-01-02", "expires": "2027-01-02" });
    fs::write(env.dir.join("index.json"), index.to_string()).unwrap();
    let items = keychain_items(&env);
    let described = |url: &str, desc: &str| {
        format!(
            "{{\n  \"app\": {{\n    \"url\": \"{url}\",\n    \"description\": \"{desc}\",\n    \"fields\": {{\n      \"login\": {{}},\n      \"token\": {{\n        \
             \"updated\": \"2026-01-02\",\n        \"expires\": \"2027-01-02\"\n      }}\n    }}\n  }}\n}}\n"
        )
    };

    let out = env.halti(&["describe", "app", "--url", "https://app.example.com/tokens", "--desc", "The app"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!((stdout(&out), stderr(&out)), ("updated app\n".to_string(), String::new()));
    assert_eq!(index_text(&env), described("https://app.example.com/tokens", "The app"));

    // "" clears one, and the other stays.
    let out = env.halti(&["describe", "app", "--desc", ""]);
    assert_eq!((stdout(&out), stderr(&out)), ("updated app\n".to_string(), String::new()));
    assert_eq!(index_text(&env), described("https://app.example.com/tokens", ""));

    // With no flags and no terminal there is nothing to ask, and nothing changes.
    failed_with(&env.halti(&["describe", "app"]), "give --url and/or --desc, or run in a terminal to be prompted");
    failed_with(&env.halti(&["describe", "nope", "--desc", "x"]), "nope doesn't exist (create it with: halti set nope FIELD)");
    assert_eq!(index_text(&env), described("https://app.example.com/tokens", ""));
    assert_eq!(keychain_items(&env), items, "values and the approval keep their bytes");
    assert!(stdout(&env.halti(&["policy", "show", "app"])).contains("(approved)\n"));
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

// --- a workspace's secrets ---

/// What the secret tests store.
const VALUE: &str = "acme github token";

/// `halti ARGS` as `ws` runs it, with `input` piped to its standard input and closed.
fn ws_with(env: &Env, passphrase: &str, args: &[&str], input: &[u8]) -> Output {
    let mut child = env.command().env("HALTI_TEST_PASSPHRASE", passphrase).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    // halti may end before it reads, when it refuses first.
    let _ = child.stdin.take().unwrap().write_all(input);
    child.wait_with_output().unwrap()
}

/// The version of a workspace's pin.
fn pin_version(env: &Env, name: &str) -> u64 {
    let pin = fs::read(ws_dir(env).join("pins").join(ws_id(env, name))).unwrap();
    u64::from_be_bytes(pin[1..9].try_into().unwrap())
}

/// Every file of the workspaces folder, by path, with its bytes: lock files aside.
fn ws_files(env: &Env) -> Vec<(PathBuf, Vec<u8>)> {
    let mut files = Vec::new();
    let mut folders = vec![ws_dir(env)];
    while let Some(folder) = folders.pop() {
        for entry in fs::read_dir(&folder).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                if !path.ends_with("locks") {
                    folders.push(path);
                }
            } else {
                files.push((path.clone(), fs::read(&path).unwrap()));
            }
        }
    }
    files.sort();
    files
}

/// The files of a workspace's items folder.
fn items(env: &Env, name: &str) -> Vec<PathBuf> {
    let folder = ws_dir(env).join(ws_id(env, name)).join("items");
    let mut found: Vec<PathBuf> = fs::read_dir(folder).map(|entries| entries.map(|entry| entry.unwrap().path()).collect()).unwrap_or_default();
    found.sort();
    found
}

/// Whether neither stdout nor stderr holds `value`.
fn quiet(out: &Output, value: &str) -> bool {
    !text(&out.stdout).contains(value) && !text(&out.stderr).contains(value)
}

#[test]
fn a_secret_is_stored_listed_and_removed_with_one_passphrase_each() {
    let env = Env::new();
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    let version = pin_version(&env, "acme");
    let empty = ws(&env, PASSPHRASE, &["ws", "ls", "acme"]);
    assert_eq!(stdout(&empty), "acme has no secrets yet. add one with: halti ws set acme/RESOURCE FIELD\n");

    let stored = ws_with(&env, PASSPHRASE, &["ws", "set", "acme/github", "token"], format!("{VALUE}\n").as_bytes());
    assert!(stored.status.success(), "{}", stderr(&stored));
    assert_eq!(stdout(&stored), "stored github/token in acme\n");
    assert_eq!((prompted(&stored), asked(&stored)), (1, 1));
    assert!(stderr(&stored).contains("halti: [test] [DEV, not protected] store a secret in workspace acme\n"), "{}", stderr(&stored));
    assert!(stderr(&stored).contains("halti: [test] asked: passphrase for workspace acme: \n") && !stderr(&stored).contains("value for"), "{}", stderr(&stored));
    assert!(quiet(&stored, VALUE));
    assert_eq!(pin_version(&env, "acme"), version + 1);
    // One file, private, named by 64 hex characters, holding neither the name nor the value.
    let files = items(&env, "acme");
    assert_eq!(files.len(), 1);
    let file = files[0].file_name().unwrap().to_str().unwrap().to_string();
    assert!(file.len() == 64 && file.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()), "{file}");
    assert_eq!(fs::metadata(&files[0]).unwrap().permissions().mode() & 0o777, 0o600);
    let blob = fs::read(&files[0]).unwrap();
    assert_eq!(blob.len(), VALUE.len() + 29);
    for word in [&b"github"[..], b"token", VALUE.as_bytes()] {
        assert!(!blob.windows(word.len()).any(|w| w == word) && !file.as_bytes().windows(word.len()).any(|w| w == word));
    }
    let manifest = fs::read(ws_dir(&env).join(ws_id(&env, "acme")).join("manifest")).unwrap();
    assert!(!manifest.windows(6).any(|w| w == b"github"), "the list is sealed");

    // Again: replaced, at the next version, still one file. Then two more.
    let replaced = ws_with(&env, PASSPHRASE, &["ws", "set", "acme/github", "token"], b"acme github token two\r\n");
    assert!(replaced.status.success() && stdout(&replaced) == "replaced github/token in acme\n", "{}", stderr(&replaced));
    assert_eq!((pin_version(&env, "acme"), items(&env, "acme").len()), (version + 2, 1));
    for (target, field) in [("acme/github", "user"), ("acme/linear", "token")] {
        let out = ws_with(&env, PASSPHRASE, &["ws", "set", target, field], b"another value\n");
        assert!(out.status.success(), "{}", stderr(&out));
    }

    // Listed with one passphrase, nothing written.
    let before = ws_files(&env);
    let listed = ws(&env, PASSPHRASE, &["ws", "ls", "acme"]);
    assert!(listed.status.success(), "{}", stderr(&listed));
    assert_eq!(stdout(&listed), "RESOURCE         FIELDS\ngithub           token, user\nlinear           token\n");
    assert_eq!((prompted(&listed), asked(&listed)), (1, 1));
    assert!(stderr(&listed).contains("halti: [test] [DEV, not protected] open workspace acme\n"), "{}", stderr(&listed));
    assert!(ws_files(&env) == before, "listing writes nothing");
    // Without a name, the workspaces, asking nothing, as before.
    let all = ws(&env, PASSPHRASE, &["ws", "ls"]);
    assert!(stdout(&all).starts_with("WORKSPACE ") && prompted(&all) == 0, "{}", stdout(&all));

    // Removed: one field, then a resource.
    let version = pin_version(&env, "acme");
    let removed = ws(&env, PASSPHRASE, &["ws", "rm", "acme/github", "token"]);
    assert!(removed.status.success() && stdout(&removed) == "removed github/token from acme\n", "{}", stderr(&removed));
    assert_eq!((prompted(&removed), asked(&removed)), (1, 1));
    assert!(stderr(&removed).contains("halti: [test] [DEV, not protected] remove secrets from workspace acme\n"), "{}", stderr(&removed));
    assert_eq!((pin_version(&env, "acme"), items(&env, "acme").len()), (version + 1, 2));
    let removed = ws(&env, PASSPHRASE, &["ws", "rm", "acme/linear"]);
    assert!(removed.status.success() && stdout(&removed) == "removed linear from acme\n", "{}", stderr(&removed));
    assert_eq!(stdout(&ws(&env, PASSPHRASE, &["ws", "ls", "acme"])), "RESOURCE         FIELDS\ngithub           user\n");
    // Naming nothing stored: refused after the passphrase, nothing written.
    let before = ws_files(&env);
    let none = ws(&env, PASSPHRASE, &["ws", "rm", "acme/github", "token"]);
    assert!(!none.status.success() && stderr(&none).ends_with("halti: there is no github/token in acme\n"), "{}", stderr(&none));
    assert!(ws_files(&env) == before);
    // Deleting the workspace takes its secrets with it.
    assert!(ws(&env, PASSPHRASE, &["ws", "delete", "acme"]).status.success());
    assert!(fs::read_dir(ws_dir(&env)).unwrap().all(|entry| entry.unwrap().file_name().len() != 32), "no workspace folder is left");
}

#[test]
fn no_value_stores_nothing_and_a_value_is_never_an_argument() {
    let env = Env::new();
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    let before = ws_files(&env);
    // Nothing on stdin (null, as Env::command gives), or only a line break.
    for out in [ws(&env, PASSPHRASE, &["ws", "set", "acme/github", "token"]), ws_with(&env, PASSPHRASE, &["ws", "set", "acme/github", "token"], b"\n")] {
        assert!(!out.status.success() && stderr(&out).ends_with("halti: no value was given, so nothing was stored\n"), "{}", stderr(&out));
        assert!(stdout(&out).is_empty() && asked(&out) == 1);
        assert!(ws_files(&env) == before, "every file as it was");
    }
    // A value a secret can't hold: too long, or with a control character; never echoed.
    for value in [vec![b'a'; 65537], b"acme\x1b[2Jtoken\n".to_vec(), b"acme\0token".to_vec(), b"acme\xfftoken".to_vec()] {
        let out = ws_with(&env, PASSPHRASE, &["ws", "set", "acme/github", "token"], &value);
        let said = stderr(&out);
        assert!(!out.status.success() && said.ends_with("halti: that value can't be stored: a secret is text of up to 65536 bytes\n"), "{said}");
        assert!(!said.contains("acme\x1b") && !said.contains("token\n") && stdout(&out).is_empty(), "{said}");
        assert!(ws_files(&env) == before);
    }
    // The longest value is stored.
    let out = ws_with(&env, PASSPHRASE, &["ws", "set", "acme/github", "token"], &[b'a'; 65536]);
    assert!(out.status.success(), "{}", stderr(&out));
    // A value in the arguments is a usage error, and nothing is asked.
    let before = ws_files(&env);
    let out = ws_with(&env, PASSPHRASE, &["ws", "set", "acme/github", "token", VALUE], b"");
    assert!(!out.status.success() && stdout(&out).is_empty() && prompted(&out) == 0, "{}", stderr(&out));
    assert!(ws_files(&env) == before);
    // Names are checked before anything is asked, and none is said back.
    let out = ws_with(&env, PASSPHRASE, &["ws", "set", "Acme/github", "token"], VALUE.as_bytes());
    assert!(stderr(&out).contains("error: invalid value 'Acme/github' for '<WS/RESOURCE>': use a workspace and a resource, e.g. acme/github"), "{}", stderr(&out));
    let out = ws_with(&env, PASSPHRASE, &["ws", "set", "acme/github", "Token"], VALUE.as_bytes());
    assert!(stderr(&out).contains("use lowercase letters, digits and _, e.g. token") && prompted(&out) == 0, "{}", stderr(&out));
    let out = ws_with(&env, PASSPHRASE, &["ws", "set", "initech/github", "token"], VALUE.as_bytes());
    assert!(stderr(&out).ends_with("halti: there is no workspace named initech\n") && prompted(&out) == 0, "{}", stderr(&out));
    let out = ws(&env, PASSPHRASE, &["ws", "ls", "--type"]);
    assert!(!out.status.success() && prompted(&out) == 0, "--type needs a workspace");
}

#[test]
fn a_put_back_secret_file_is_listed_as_unreadable() {
    let env = Env::new();
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    // Of other lengths, so each file is known by its size.
    for (target, field, value) in [("acme/github", "token", VALUE), ("acme/linear", "token", "acme linear token one")] {
        assert!(ws_with(&env, PASSPHRASE, &["ws", "set", target, field], value.as_bytes()).status.success());
    }
    let linear = items(&env, "acme").into_iter().find(|file| fs::read(file).unwrap().len() == "acme linear token one".len() + 29).unwrap();
    let first = fs::read(&linear).unwrap();
    assert!(ws_with(&env, PASSPHRASE, &["ws", "set", "acme/linear", "token"], b"acme linear token 2").status.success());
    // Its file from before the last set put back: it can't be read, and the listing says how to set it again.
    fs::write(&linear, &first).unwrap();
    let hint = "linear/token can't be read. set it again with: halti ws set acme/linear token\n";
    let listed = ws(&env, PASSPHRASE, &["ws", "ls", "acme"]);
    assert_eq!(stdout(&listed), format!("RESOURCE         FIELDS\ngithub           token\nlinear           token\n{hint}"));
    // Removed altogether: the same.
    fs::remove_file(&linear).unwrap();
    assert!(stdout(&ws(&env, PASSPHRASE, &["ws", "ls", "acme"])).ends_with(hint));
    // Set again, it is read.
    assert!(ws_with(&env, PASSPHRASE, &["ws", "set", "acme/linear", "token"], b"acme linear token 3").status.success());
    assert!(!stdout(&ws(&env, PASSPHRASE, &["ws", "ls", "acme"])).contains("can't be read"));
}

#[test]
fn a_wrong_passphrase_stores_lists_and_removes_nothing() {
    let env = Env::new();
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    assert!(ws_with(&env, PASSPHRASE, &["ws", "set", "acme/github", "token"], VALUE.as_bytes()).status.success());
    let before = ws_files(&env);
    let wrong = "acme passphrase two";
    let tries: [(&[&str], &[u8]); 4] = [
        (&["ws", "set", "acme/github", "token"], b"another value"),
        (&["ws", "set", "acme/linear", "token"], b"another value"),
        (&["ws", "ls", "acme"], b""),
        (&["ws", "rm", "acme/github"], b""),
    ];
    for (args, input) in tries {
        let out = ws_with(&env, wrong, args, input);
        assert!(!out.status.success() && stderr(&out).ends_with("halti: that can't be opened (wrong key, or it was changed)\n"), "{args:?}: {}", stderr(&out));
        assert!(stdout(&out).is_empty() && (prompted(&out), asked(&out)) == (1, 1), "{args:?}: asked once, and not again");
        assert!(ws_files(&env) == before, "{args:?}: every file as it was");
    }
    // The manifest changed: refused before anything is asked.
    let manifest = ws_dir(&env).join(ws_id(&env, "acme")).join("manifest");
    let mut bytes = fs::read(&manifest).unwrap();
    bytes[20] ^= 0x01;
    fs::write(&manifest, &bytes).unwrap();
    for args in [&["ws", "set", "acme/github", "token"][..], &["ws", "ls", "acme"], &["ws", "rm", "acme/github"]] {
        let out = ws_with(&env, PASSPHRASE, args, VALUE.as_bytes());
        assert!(!out.status.success() && stderr(&out).contains("can't be opened") && prompted(&out) == 0, "{args:?}: {}", stderr(&out));
    }
}

/// A pseudo-terminal: the side a person types into, and the terminal a program is given.
fn pty() -> (fs::File, fs::File) {
    use std::os::fd::FromRawFd;
    let (mut person, mut terminal) = (0, 0);
    let made = unsafe { libc::openpty(&mut person, &mut terminal, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) };
    assert_eq!(made, 0, "openpty: {}", std::io::Error::last_os_error());
    unsafe { (fs::File::from_raw_fd(person), fs::File::from_raw_fd(terminal)) }
}

#[test]
fn a_value_pasted_in_more_lines_is_refused_and_the_shell_reads_none_of_it() {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let env = Env::new();
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    let before = ws_files(&env);
    let (person, terminal) = pty();
    let left = env.dir.join("left");
    // halti runs under a shell that owns the terminal, as a person's does, and that then reads whatever halti left there.
    let mut shell = Command::new("/bin/sh");
    shell.args(["-c", "\"$@\"; done=$?; stty -icanon min 0 time 0; cat > \"$LEFT\"; exit $done", "sh", HALTI, "ws", "set", "acme/github", "key"]);
    let halti = env.command();
    for (name, value) in halti.get_envs() {
        match value {
            Some(value) => shell.env(name, value),
            None => shell.env_remove(name),
        };
    }
    shell.env("HALTI_TEST_PASSPHRASE", PASSPHRASE).env("LEFT", &left).current_dir(&env.dir);
    shell.stdin(terminal.try_clone().unwrap()).stdout(Stdio::piped()).stderr(Stdio::piped());
    unsafe {
        shell.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = shell.spawn().unwrap();
    // What the terminal shows, read as it comes: a shell leaving a terminal waits for that.
    let mut shown = person.try_clone().unwrap();
    let screen = thread::spawn(move || {
        let mut seen = Vec::new();
        let mut buf = [0; 1024];
        while let Ok(n @ 1..) = shown.read(&mut buf) {
            seen.extend_from_slice(&buf[..n]);
        }
        seen
    });
    // Pasted once the value's question has turned echo off, as a person pastes after it.
    let echoing = || {
        let mut now: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(terminal.as_raw_fd(), &mut now) }, 0);
        now.c_lflag & libc::ECHO != 0
    };
    let start = std::time::Instant::now();
    while echoing() && child.try_wait().unwrap().is_none() && start.elapsed().as_secs() < 30 {
        thread::sleep(std::time::Duration::from_millis(10));
    }
    (&person).write_all(b"-----BEGIN TEST KEY-----\nYWNtZSBnaXRodWIga2V5\n-----END TEST KEY-----").unwrap();
    drop(terminal);
    let out = child.wait_with_output().unwrap();
    let refused = "halti: a value of more than one line can't be typed, so nothing was stored. pipe it in instead\n";
    assert!(!out.status.success() && stderr(&out).ends_with(refused) && stdout(&out).is_empty(), "{}{}", stdout(&out), stderr(&out));
    assert_eq!(text(&fs::read(&left).unwrap()), "", "the shell reads none of it");
    let screen = text(&screen.join().unwrap());
    assert!(screen.contains("value for github/key: ") && !screen.contains("TEST KEY") && !screen.contains("YWNt"), "{screen}");
    assert!(ws_files(&env) == before, "nothing was stored");
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "the keychain is only on a mac")]
fn a_saved_passphrase_stores_lists_and_removes_with_nothing_typed() {
    let env = Env::new();
    // Each line names its own means, so each command is seen to follow its own line.
    assert!(config(&env, &with_keychain_secrets("none", "touchid", "sudo", "passphrase"), "yes").status.success());
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    // No passphrase is given: Touch ID, sudo or nothing releases the saved copy.
    let run = |args: &[&str], approve: &str, sudo: &str, input: &[u8]| {
        let mut child = env
            .command()
            .args(args)
            .env("HALTI_TEST_APPROVE", approve)
            .env("HALTI_TEST_SUDO", sudo)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let _ = child.stdin.take().unwrap().write_all(input);
        child.wait_with_output().unwrap()
    };
    let out = run(&["ws", "set", "acme/github", "token"], "yes", "no", VALUE.as_bytes());
    assert!(out.status.success() && stdout(&out) == "stored github/token in acme\n" && asked(&out) == 0, "{}", stderr(&out));
    assert_eq!(stderr(&out), "halti: [test] [DEV, not protected] store a secret in workspace acme: yes\n");
    assert!(quiet(&out, VALUE) && quiet(&out, PASSPHRASE));
    // Listing follows the open line, which asks nothing.
    let out = run(&["ws", "ls", "acme"], "no", "no", b"");
    assert!(out.status.success() && stdout(&out) == "RESOURCE         FIELDS\ngithub           token\n" && asked(&out) == 0, "{}", stderr(&out));
    assert_eq!(stderr(&out), "");

    // Declined: nothing is read or stored, and halti says how to type the passphrase instead.
    let before = ws_files(&env);
    let out = run(&["ws", "set", "acme/github", "token"], "no", "no", b"another value");
    assert!(
        !out.status.success() && stderr(&out).ends_with("halti: github/token was not stored. to type the passphrase instead: halti ws set acme/github token --type\n"),
        "{}",
        stderr(&out)
    );
    let out = run(&["ws", "rm", "acme/github"], "yes", "no", b"");
    assert!(!out.status.success() && stderr(&out).ends_with("halti: github was not removed. to type the passphrase instead: halti ws rm acme/github --type\n"), "{}", stderr(&out));
    assert!(ws_files(&env) == before);
    // With --type it is typed, and nothing else is asked.
    let out = env.command().args(["ws", "ls", "acme", "--type"]).env("HALTI_TEST_APPROVE", "no").env("HALTI_TEST_PASSPHRASE", PASSPHRASE).output().unwrap();
    assert!(out.status.success() && asked(&out) == 1 && !stderr(&out).contains("open workspace acme: "), "{}", stderr(&out));
    let typed = |args: &[&str], input: &[u8]| {
        let mut child = env
            .command()
            .args(args)
            .env("HALTI_TEST_APPROVE", "no")
            .env("HALTI_TEST_SUDO", "no")
            .env("HALTI_TEST_PASSPHRASE", PASSPHRASE)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let _ = child.stdin.take().unwrap().write_all(input);
        child.wait_with_output().unwrap()
    };
    let out = typed(&["ws", "set", "acme/gitlab", "token", "--type"], b"acme gitlab token");
    assert!(out.status.success() && stdout(&out) == "stored gitlab/token in acme\n" && asked(&out) == 1, "{}", stderr(&out));
    assert!(!stderr(&out).contains("store a secret in workspace acme: "), "{}", stderr(&out));
    let out = typed(&["ws", "rm", "acme/gitlab", "--type"], b"");
    assert!(out.status.success() && stdout(&out) == "removed gitlab from acme\n" && asked(&out) == 1, "{}", stderr(&out));
    assert!(!stderr(&out).contains("sudo: "), "{}", stderr(&out));

    // A copy that can't be used: typed once, and left for `halti open` to save again.
    let copy = saved_copy(&env, "acme");
    fs::write(&copy, "acme passphrase two").unwrap();
    let out = ws_with(&env, PASSPHRASE, &["ws", "set", "acme/linear", "token"], b"acme linear token");
    assert!(out.status.success() && stdout(&out) == "stored linear/token in acme\n" && asked(&out) == 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("\nthe saved passphrase of acme can't be read. type it once.\n"), "{}", stderr(&out));
    assert_eq!(fs::read_to_string(&copy).unwrap(), "acme passphrase two");
    assert!(ws(&env, PASSPHRASE, &["open", "acme"]).status.success());
    assert_eq!(fs::read_to_string(&copy).unwrap(), PASSPHRASE);

    // Removed after sudo, nothing typed.
    let out = run(&["ws", "rm", "acme/github", "token"], "no", "yes", b"");
    assert!(out.status.success() && stdout(&out) == "removed github/token from acme\n" && asked(&out) == 0, "{}", stderr(&out));
    assert_eq!(stderr(&out), "halti: [test] sudo: yes\n");
}

#[test]
fn storing_a_secret_is_never_approved_by_nothing() {
    let env = Env::new();
    let (text, why) = if cfg!(target_os = "macos") {
        (with_keychain_secrets("touchid", "none", "none", "none"), "line 21: set can't be none. it can be passphrase, sudo or touchid")
    } else {
        (edited("set    = \"passphrase\"", "set    = \"none\""), "line 21: set can't be none. it can only be passphrase")
    };
    let out = config(&env, &text, "yes");
    let refused = format!("halti: {}, {why}\nnothing was approved. fix it with: halti config\n", config_file(&env).display());
    assert!(!out.status.success() && stderr(&out) == refused && stdout(&out).is_empty(), "{}", stderr(&out));
    assert!(!approved_copy(&env).exists());
    // So a store still asks for the passphrase.
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    let out = ws_with(&env, PASSPHRASE, &["ws", "set", "acme/github", "token"], VALUE.as_bytes());
    assert!(out.status.success() && asked(&out) == 1, "{}", stderr(&out));
}

// --- a workspace's policies ---

/// The policy the tests approve in acme, and the first 12 hex characters of its sha256.
const POLICY_TEXT: &str = "[fetch]\nhosts = [\"https://api.github.com\"]\n";
const POLICY_SHA: &str = "80982e4c451a";

/// A workspace's policies folder.
fn policies_dir(env: &Env, name: &str) -> PathBuf {
    ws_dir(env).join(ws_id(env, name)).join("policies")
}

/// The first 12 hex characters of the sha256 of `text`, as halti shows a policy's.
fn sha12(text: &str) -> String {
    sha256(text.as_bytes())[..12].to_string()
}

/// `halti ws policy edit TARGET` with an "editor" that writes `text` over the file. Standard input
/// isn't a terminal, so nothing is offered or asked.
fn ws_policy_edit(env: &Env, target: &str, text: &str) -> Output {
    let file = env.dir.join("edited-policy.toml");
    fs::write(&file, text).unwrap();
    let mut command = env.command();
    command.args(["ws", "policy", "edit", target]).env("EDITOR", format!("cp {}", file.display())).env_remove("VISUAL").env("HALTI_TEST_PASSPHRASE", PASSPHRASE);
    command.output().unwrap()
}

/// As `ws_policy_edit`, with standard input a terminal, as a person runs it: once halti asks
/// whether to approve, `meanwhile` runs, then "y" is typed.
fn ws_policy_edit_then_y(env: &Env, target: &str, text: &str, meanwhile: impl FnOnce()) -> Output {
    let file = env.dir.join("edited-policy.toml");
    fs::write(&file, text).unwrap();
    let (person, terminal) = pty();
    let mut command = env.command();
    command.args(["ws", "policy", "edit", target]).env("EDITOR", format!("cp {}", file.display())).env_remove("VISUAL").env("HALTI_TEST_PASSPHRASE", PASSPHRASE);
    let mut child = command.stdin(terminal).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut said = child.stderr.take().unwrap();
    let mut err = Vec::new();
    let mut byte = [0];
    while !err.ends_with(b"Approve it now? [y/N] ") && said.read(&mut byte).unwrap() == 1 {
        err.push(byte[0]);
    }
    meanwhile();
    (&person).write_all(b"y\n").unwrap();
    said.read_to_end(&mut err).unwrap();
    let out = child.wait_with_output().unwrap();
    Output { stderr: err, ..out }
}

/// Exit code 1, on stderr only `error` after what the passphrase questions say, and on stdout at
/// most what was shown to approve: never a line that says something was approved.
fn refused_with(out: &Output, error: &str) {
    assert_eq!(out.status.code(), Some(1), "{}", stderr(out));
    assert!(stderr(out).ends_with(&format!("halti: {error}\n")), "{}", stderr(out));
    let said = stdout(out);
    assert!(said.lines().all(|line| !line.starts_with("approved the policy") && !line.ends_with("was approved already")), "{said}");
}

#[test]
fn a_workspace_policy_is_edited_approved_and_shown() {
    let env = Env::new();
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    let version = pin_version(&env, "acme");
    let dir = policies_dir(&env, "acme");
    let file = dir.join("github.toml");
    let path = file.display();

    // Left as the template: saved, nothing asked, and the template is the workspace's own.
    let out = env.command().args(["ws", "policy", "edit", "acme/github"]).env("EDITOR", "true").env_remove("VISUAL").env("HALTI_TEST_PASSPHRASE", PASSPHRASE).output().unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), format!("saved {path} — it takes effect once approved: halti ws policy approve acme/github\n"));
    assert_eq!((prompted(&out), asked(&out)), (0, 0));
    let template = fs::read_to_string(&file).unwrap();
    assert!(template.starts_with("# halti policy for github in acme. It takes effect only once approved: halti ws policy approve acme/github\n\n# [fetch]\n"), "{template}");
    assert!(!template.contains("[run]") && !template.contains("[agent]") && !template.contains("refresh"), "{template}");
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!((mode(&dir), mode(&file)), (0o700, 0o600));
    assert_eq!(pin_version(&env, "acme"), version, "editing writes nothing sealed");

    // Edited, and approved with "y": what was read is shown whole, then the passphrase, once.
    let out = ws_policy_edit_then_y(&env, "acme/github", POLICY_TEXT, || {});
    assert!(out.status.success(), "{}", stderr(&out));
    let said = format!(
        "saved {path} — it takes effect once approved: halti ws policy approve acme/github\n\
         Policy for github in acme ({path}), new:\n\n[fetch]\nhosts = [\"https://api.github.com\"]\n\nsha256 {POLICY_SHA}\n\n\
         approved the policy for github in acme\n"
    );
    assert_eq!(stdout(&out), said);
    // On the terminal the question's answer ends its line; here the prompt follows it on the same line.
    assert_eq!((stderr(&out).matches("halti: [test] [DEV, not protected] approve policies in workspace acme\n").count(), asked(&out)), (1, 1), "{}", stderr(&out));
    assert_eq!(pin_version(&env, "acme"), version + 1);
    assert_eq!(fs::read_to_string(dir.join("approved/github.toml")).unwrap(), POLICY_TEXT);
    assert_eq!((mode(&dir.join("approved")), mode(&dir.join("approved/github.toml"))), (0o700, 0o600));

    // Shown: one passphrase, the status, and the bytes that were hashed. Nothing written.
    let before = ws_files(&env);
    let out = ws(&env, PASSPHRASE, &["ws", "policy", "show", "acme/github"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), format!("{path} (approved)\n\n[fetch]\nhosts = [\"https://api.github.com\"]\n"));
    assert_eq!((prompted(&out), asked(&out)), (1, 1));
    assert!(stderr(&out).contains("halti: [test] [DEV, not protected] open workspace acme\n"), "{}", stderr(&out));
    let out = ws(&env, PASSPHRASE, &["ws", "policy", "show", "acme"]);
    assert_eq!(stdout(&out), "RESOURCE         POLICY\ngithub           approved\n", "{}", stderr(&out));
    assert_eq!((prompted(&out), asked(&out)), (1, 1));
    assert!(ws_files(&env) == before && pin_version(&env, "acme") == version + 1, "showing writes nothing");

    // Edited to the same text: nothing to approve, and nothing more is said.
    let out = ws_policy_edit(&env, "acme/github", POLICY_TEXT);
    assert!(out.status.success() && stdout(&out) == "no change from the approved policy for github in acme\n" && prompted(&out) == 0, "{}{}", stdout(&out), stderr(&out));
    // Approving one shows its whole text, whatever its copy says.
    let out = ws(&env, PASSPHRASE, &["ws", "policy", "approve", "acme/github"]);
    let said =
        format!("Policy for github in acme ({path}), unchanged:\n\n{}\n\nsha256 {POLICY_SHA}\n\nthe policy for github in acme was approved already\n", POLICY_TEXT.trim_end());
    assert!(out.status.success() && stdout(&out) == said && asked(&out) == 1, "{}{}", stdout(&out), stderr(&out));
    assert!(ws_files(&env) == before, "approved already: nothing written");

    // No file: said, and nothing asked. A file asked for and missing is refused before anything is asked.
    let out = ws(&env, PASSPHRASE, &["ws", "policy", "show", "acme/slack"]);
    assert!(out.status.success() && stdout(&out) == "no policy file for slack in acme. write one with: halti ws policy edit acme/slack\n" && prompted(&out) == 0);
    let out = ws(&env, PASSPHRASE, &["ws", "policy", "approve", "acme/slack"]);
    refused_with(&out, "acme has no policy file for slack. write one with: halti ws policy edit acme/slack");
    assert_eq!(prompted(&out), 0);
    for args in [&["ws", "policy", "approve", "initech"][..], &["ws", "policy", "show", "initech/github"], &["ws", "policy", "edit", "initech/github"]] {
        let out = ws(&env, PASSPHRASE, args);
        refused_with(&out, "there is no workspace named initech");
        assert_eq!(prompted(&out), 0, "{args:?}");
    }
    let out = ws(&env, PASSPHRASE, &["ws", "policy", "edit", "acme"]);
    assert!(stderr(&out).contains("error: invalid value 'acme' for '<WS/RESOURCE>': use a workspace and a resource, e.g. acme/github"), "{}", stderr(&out));
    for target in ["acme/GitHub", "Acme", "acme/github/x"] {
        let out = ws(&env, PASSPHRASE, &["ws", "policy", "approve", target]);
        assert!(stderr(&out).contains("use a workspace, or a workspace and a resource, e.g. acme/github") && prompted(&out) == 0, "{target}: {}", stderr(&out));
    }
    // A file name a policy can't have is refused, not skipped.
    fs::write(dir.join("Linear.toml"), POLICY_TEXT).unwrap();
    for args in [&["ws", "policy", "approve", "acme"][..], &["ws", "policy", "show", "acme"]] {
        let out = ws(&env, PASSPHRASE, args);
        refused_with(&out, &format!("{} isn't a policy file name: use a-z, 0-9 and -", dir.join("Linear.toml").display()));
        assert_eq!(prompted(&out), 0, "{args:?}");
    }
}

#[test]
fn approve_all_shows_new_changed_and_unchanged() {
    let env = Env::new();
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    let dir = policies_dir(&env, "acme");
    let (linear, slack) = ("[fetch]\nhosts = [\"https://api.linear.example\"]\n", "[fetch]\nhosts = [\"https://slack.example\"]\n");
    let out = ws(&env, PASSPHRASE, &["ws", "policy", "approve", "acme"]);
    refused_with(&out, "acme has no policy files. write one with: halti ws policy edit acme/RESOURCE");
    let out = ws(&env, PASSPHRASE, &["ws", "policy", "show", "acme"]);
    assert_eq!(stdout(&out), "acme has no policy files. write one with: halti ws policy edit acme/RESOURCE\n");
    for (target, text) in [("acme/linear", linear), ("acme/slack", slack)] {
        assert!(ws_policy_edit(&env, target, text).status.success());
    }
    let out = ws(&env, PASSPHRASE, &["ws", "policy", "approve", "acme"]);
    assert!(out.status.success() && stdout(&out).ends_with("approved the policy for linear in acme\napproved the policy for slack in acme\n"), "{}", stderr(&out));

    // github new, linear changed, slack as approved.
    let wider = format!("{linear}writes = \"ask\"\n");
    assert!(ws_policy_edit(&env, "acme/github", POLICY_TEXT).status.success());
    assert!(ws_policy_edit(&env, "acme/linear", &wider).status.success());
    let version = pin_version(&env, "acme");
    let out = ws(&env, PASSPHRASE, &["ws", "policy", "approve", "acme"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let path = |resource: &str| dir.join(format!("{resource}.toml")).display().to_string();
    let said = format!(
        "Policy for github in acme ({}), new:\n\n[fetch]\nhosts = [\"https://api.github.com\"]\n\nsha256 {POLICY_SHA}\n\n\
         Policy for linear in acme ({}), changed:\n--- approved\n+++ now\n@@ -1,2 +1,3 @@\n [fetch]\n hosts = [\"https://api.linear.example\"]\n+writes = \"ask\"\nsha256 {}\n\n\
         Policy for slack in acme ({}), unchanged, sha256 {}\n\n\
         approved the policy for github in acme\napproved the policy for linear in acme\nthe policy for slack in acme was approved already\n",
        path("github"),
        path("linear"),
        sha12(&wider),
        path("slack"),
        sha12(slack)
    );
    assert_eq!(stdout(&out), said);
    assert_eq!((prompted(&out), asked(&out), pin_version(&env, "acme")), (1, 1, version + 1), "one passphrase, one change");

    // The approved copy of linear changed: shown against it, then refused after the passphrase, and nothing is written.
    let narrower = format!("{linear}writes = \"deny\"\n");
    assert!(ws_policy_edit(&env, "acme/linear", &narrower).status.success());
    fs::write(dir.join("approved/linear.toml"), linear).unwrap();
    let before = ws_files(&env);
    let out = ws(&env, PASSPHRASE, &["ws", "policy", "approve", "acme"]);
    refused_with(&out, "the approved copy of linear in acme isn't what was approved, so nothing was approved. approve it alone: halti ws policy approve acme/linear");
    assert_eq!(asked(&out), 1);
    assert!(ws_files(&env) == before, "nothing was written");
    // Approved alone, its whole text is shown, and the copy is written again.
    let out = ws(&env, PASSPHRASE, &["ws", "policy", "approve", "acme/linear"]);
    let said =
        format!("Policy for linear in acme ({}), changed:\n\n{}\n\nsha256 {}\n\napproved the policy for linear in acme\n", path("linear"), narrower.trim_end(), sha12(&narrower));
    assert!(out.status.success() && stdout(&out) == said, "{}{}", stdout(&out), stderr(&out));
    assert_eq!(fs::read_to_string(dir.join("approved/linear.toml")).unwrap(), narrower);
    let out = ws(&env, PASSPHRASE, &["ws", "policy", "show", "acme"]);
    assert_eq!(stdout(&out), "RESOURCE         POLICY\ngithub           approved\nlinear           approved\nslack            approved\n");
}

#[test]
fn edit_then_y_approves_the_bytes_it_diffed() {
    let env = Env::new();
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    assert!(ws_policy_edit_then_y(&env, "acme/github", POLICY_TEXT, || {}).status.success());
    let file = policies_dir(&env, "acme").join("github.toml");
    let path = file.display().to_string();
    let wider = format!("{POLICY_TEXT}writes = \"ask\"\n");
    // While halti asks, the file is changed again: what was diffed is what is approved.
    let planted = format!("{POLICY_TEXT}writes = \"allow\"\n");
    let out = ws_policy_edit_then_y(&env, "acme/github", &wider, || fs::write(&file, &planted).unwrap());
    assert!(out.status.success(), "{}", stderr(&out));
    let said = format!(
        "--- approved\n+++ now\n@@ -1,2 +1,3 @@\n [fetch]\n hosts = [\"https://api.github.com\"]\n+writes = \"ask\"\n\n\
         saved {path} — it takes effect once approved: halti ws policy approve acme/github\nsha256 {}\n\napproved the policy for github in acme\n",
        sha12(&wider)
    );
    assert_eq!(stdout(&out), said);
    assert_eq!(asked(&out), 1);
    let approved = policies_dir(&env, "acme").join("approved/github.toml");
    assert_eq!(fs::read_to_string(&approved).unwrap(), wider);
    let out = ws(&env, PASSPHRASE, &["ws", "policy", "show", "acme/github"]);
    assert!(stdout(&out).starts_with(&format!("{path} (changed since approval)\n\n")) && stdout(&out).contains("\"allow\""), "{}", stdout(&out));
    fs::write(&file, &wider).unwrap();
    let out = ws(&env, PASSPHRASE, &["ws", "policy", "show", "acme/github"]);
    assert!(stdout(&out).starts_with(&format!("{path} (approved)\n\n")), "{}", stdout(&out));
}

#[test]
fn an_edited_workspace_policy_reads_as_changed_until_approved_again() {
    let env = Env::new();
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    assert!(ws_policy_edit(&env, "acme/github", POLICY_TEXT).status.success());
    assert!(ws(&env, PASSPHRASE, &["ws", "policy", "approve", "acme/github"]).status.success());
    let path = policies_dir(&env, "acme").join("github.toml").display().to_string();
    let wider = format!("{POLICY_TEXT}writes = \"ask\"\n");
    let out = ws_policy_edit(&env, "acme/github", &wider);
    let said = format!(
        "--- approved\n+++ now\n@@ -1,2 +1,3 @@\n [fetch]\n hosts = [\"https://api.github.com\"]\n+writes = \"ask\"\n\n\
         saved {path} — it takes effect once approved: halti ws policy approve acme/github\n"
    );
    assert!(out.status.success() && stdout(&out) == said && prompted(&out) == 0, "{}{}", stdout(&out), stderr(&out));
    let out = ws(&env, PASSPHRASE, &["ws", "policy", "show", "acme/github"]);
    assert_eq!(stdout(&out), format!("{path} (changed since approval)\n\n{}\n", wider.trim_end()));
    assert_eq!(stdout(&ws(&env, PASSPHRASE, &["ws", "policy", "show", "acme"])), "RESOURCE         POLICY\ngithub           changed since approval\n");
    assert!(ws(&env, PASSPHRASE, &["ws", "policy", "approve", "acme"]).status.success());
    assert_eq!(stdout(&ws(&env, PASSPHRASE, &["ws", "policy", "show", "acme"])), "RESOURCE         POLICY\ngithub           approved\n");
}

#[test]
fn approving_twice_writes_nothing_the_second_time() {
    let env = Env::new();
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    assert!(ws_policy_edit(&env, "acme/github", POLICY_TEXT).status.success());
    assert!(ws(&env, PASSPHRASE, &["ws", "policy", "approve", "acme"]).status.success());
    let path = policies_dir(&env, "acme").join("github.toml").display().to_string();
    let before = ws_files(&env);
    let out = ws(&env, PASSPHRASE, &["ws", "policy", "approve", "acme"]);
    let said = format!("Policy for github in acme ({path}), unchanged, sha256 {POLICY_SHA}\n\nthe policy for github in acme was approved already\n");
    assert!(out.status.success() && stdout(&out) == said, "{}{}", stdout(&out), stderr(&out));
    assert_eq!(asked(&out), 1, "the passphrase is still asked");
    assert!(ws_files(&env) == before, "every file as it was, the pin too");
    // A removed copy: approving all of them can't show this one against it, so it is refused; approved alone, the copy is written again.
    let copy = policies_dir(&env, "acme").join("approved/github.toml");
    fs::remove_file(&copy).unwrap();
    let out = ws(&env, PASSPHRASE, &["ws", "policy", "approve", "acme"]);
    refused_with(&out, "the approved copy of github in acme isn't what was approved, so nothing was approved. approve it alone: halti ws policy approve acme/github");
    let out = ws(&env, PASSPHRASE, &["ws", "policy", "approve", "acme/github"]);
    assert!(out.status.success() && stdout(&out).ends_with("the policy for github in acme was approved already\n"), "{}", stderr(&out));
    assert!(ws_files(&env) == before, "the copy is back, and nothing else changed");
}

#[test]
fn a_workspace_policy_can_t_refresh() {
    let env = Env::new();
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    let file = policies_dir(&env, "acme").join("github.toml");
    let why = format!("{}: in a workspace, [refresh] can't be used yet, and [run] and [agent] must keep their defaults", file.display());
    let refreshing = format!("{POLICY_TEXT}\n[refresh.token]\nrun = \"~/refresh/github.sh\"\n");
    let out = ws_policy_edit(&env, "acme/github", &refreshing);
    refused_with(&out, &why);
    assert_eq!(fs::read_to_string(&file).unwrap(), refreshing, "the file stays as the editor left it");
    let before = ws_files(&env);
    for args in [&["ws", "policy", "approve", "acme/github"][..], &["ws", "policy", "approve", "acme"], &["ws", "policy", "show", "acme/github"]] {
        let out = ws(&env, PASSPHRASE, args);
        refused_with(&out, &why);
        assert_eq!(prompted(&out), 0, "{args:?}: nothing asked");
    }
    // Nor [run] or [agent] other than their defaults, nor a host in other letters.
    for (text, why) in [
        ("[run]\nmode = \"allow\"\n".to_string(), why.clone()),
        ("[agent]\nconsent = \"none\"\n".to_string(), why.clone()),
        (
            "[fetch]\nhosts = [\"https://\u{430}pi.github.com\"]\n".to_string(),
            format!("{}: line 2 has a character that isn't plain ASCII. write a host with other letters in its xn-- form", file.display()),
        ),
    ] {
        refused_with(&ws_policy_edit(&env, "acme/github", &text), &why);
        refused_with(&ws(&env, PASSPHRASE, &["ws", "policy", "approve", "acme/github"]), &why);
    }
    // One that doesn't parse gets today's error, with its path.
    let out = ws_policy_edit(&env, "acme/github", "[fetch]\nhosts = \"one\"\n");
    assert!(!out.status.success() && stderr(&out).starts_with(&format!("halti: {}: ", file.display())), "{}", stderr(&out));
    assert!(ws_files(&env).iter().filter(|(path, _)| !path.ends_with("github.toml")).eq(before.iter().filter(|(path, _)| !path.ends_with("github.toml"))));
}

#[test]
fn a_planted_or_copied_approval_approves_nothing() {
    let env = Env::new();
    // github approved in the Keychain, and its file copied into acme.
    env.policy("github", POLICY_TEXT);
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    assert!(ws_policy_edit(&env, "acme/github", POLICY_TEXT).status.success());
    let dir = policies_dir(&env, "acme");
    let show = || stdout(&ws(&env, PASSPHRASE, &["ws", "policy", "show", "acme/github"]));
    assert!(show().contains("(not approved)"), "{}", show());
    // A copy planted as the approved one: still not approved, and approving all is refused.
    fs::create_dir_all(dir.join("approved")).unwrap();
    fs::write(dir.join("approved/github.toml"), POLICY_TEXT).unwrap();
    assert!(show().contains("(not approved)"), "{}", show());
    let out = ws(&env, PASSPHRASE, &["ws", "policy", "approve", "acme"]);
    refused_with(&out, "the approved copy of github in acme isn't what was approved, so nothing was approved. approve it alone: halti ws policy approve acme/github");
    assert!(stdout(&out).contains(", unchanged, sha256 "), "shown against the planted copy: {}", stdout(&out));
    assert!(show().contains("(not approved)"));

    // globex's sealed manifest, with its approval, put over acme's: refused before anything is asked.
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "globex"]).status.success());
    assert!(ws_policy_edit(&env, "globex/github", POLICY_TEXT).status.success());
    assert!(ws(&env, PASSPHRASE, &["ws", "policy", "approve", "globex"]).status.success());
    let manifest = |name: &str| ws_dir(&env).join(ws_id(&env, name)).join("manifest");
    let acme_s = fs::read(manifest("acme")).unwrap();
    fs::copy(manifest("globex"), manifest("acme")).unwrap();
    for args in [&["ws", "policy", "show", "acme/github"][..], &["ws", "policy", "show", "acme"], &["ws", "policy", "approve", "acme/github"]] {
        let out = ws(&env, PASSPHRASE, args);
        assert!(!out.status.success() && stderr(&out).contains("can't be opened") && prompted(&out) == 0 && asked(&out) == 0, "{args:?}: {}", stderr(&out));
    }
    fs::write(manifest("acme"), acme_s).unwrap();
    // A policy file planted where the workspace's own would be: refused before anything is asked.
    let planted = ws_dir(&env).join(ws_id(&env, "acme")).join("policy");
    fs::write(&planted, POLICY_TEXT).unwrap();
    let out = ws(&env, PASSPHRASE, &["ws", "policy", "show", "acme/github"]);
    assert!(!out.status.success() && prompted(&out) == 0 && asked(&out) == 0, "{}", stderr(&out));
    fs::remove_file(&planted).unwrap();
    assert!(show().contains("(not approved)"), "{}", show());
}

#[test]
fn rm_of_a_resource_drops_its_policy_approval() {
    let env = Env::new();
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    assert!(ws_with(&env, PASSPHRASE, &["ws", "set", "acme/github", "token"], VALUE.as_bytes()).status.success());
    assert!(ws_policy_edit(&env, "acme/github", POLICY_TEXT).status.success());
    assert!(ws(&env, PASSPHRASE, &["ws", "policy", "approve", "acme/github"]).status.success());
    let dir = policies_dir(&env, "acme");
    let show = || stdout(&ws(&env, PASSPHRASE, &["ws", "policy", "show", "acme/github"]));
    // One field: the approval stays.
    assert!(ws(&env, PASSPHRASE, &["ws", "rm", "acme/github", "token"]).status.success());
    assert!(show().contains("(approved)"), "{}", show());
    // The whole resource, with no secret left: the approval goes, and its copy; the file stays.
    let version = pin_version(&env, "acme");
    let out = ws(&env, PASSPHRASE, &["ws", "rm", "acme/github"]);
    assert!(out.status.success() && stdout(&out) == "removed github from acme\n" && asked(&out) == 1, "{}", stderr(&out));
    assert_eq!(pin_version(&env, "acme"), version + 1);
    assert!(show().contains("(not approved)"), "{}", show());
    assert!(dir.join("github.toml").exists() && !dir.join("approved/github.toml").exists());
    // With neither a secret nor an approval, there is nothing to remove.
    refused_with(&ws(&env, PASSPHRASE, &["ws", "rm", "acme/github"]), "there is no github in acme");
}

#[test]
fn removing_the_file_revokes_nothing() {
    let env = Env::new();
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    assert!(ws_policy_edit(&env, "acme/github", POLICY_TEXT).status.success());
    assert!(ws(&env, PASSPHRASE, &["ws", "policy", "approve", "acme"]).status.success());
    let file = policies_dir(&env, "acme").join("github.toml");
    fs::remove_file(&file).unwrap();
    assert_eq!(stdout(&ws(&env, PASSPHRASE, &["ws", "policy", "show", "acme"])), "RESOURCE         POLICY\ngithub           approved, no file\n");
    let out = ws(&env, PASSPHRASE, &["ws", "policy", "show", "acme/github"]);
    assert!(stdout(&out) == "no policy file for github in acme. write one with: halti ws policy edit acme/github\n" && prompted(&out) == 0);
    // The same text written back is approved again.
    fs::write(&file, POLICY_TEXT).unwrap();
    assert!(stdout(&ws(&env, PASSPHRASE, &["ws", "policy", "show", "acme/github"])).contains("(approved)"));
}

#[test]
fn deleting_a_workspace_removes_its_policies() {
    let env = Env::new();
    for name in ["acme", "globex"] {
        assert!(ws(&env, PASSPHRASE, &["ws", "new", name]).status.success());
        assert!(ws_policy_edit(&env, &format!("{name}/github"), POLICY_TEXT).status.success());
    }
    assert!(ws(&env, PASSPHRASE, &["ws", "policy", "approve", "acme"]).status.success());
    let dir = policies_dir(&env, "acme");
    for left in [".github.toml.swp", "github.toml~", "4913"] {
        fs::write(dir.join(left), "left").unwrap();
    }
    let acme = ws_dir(&env).join(ws_id(&env, "acme"));
    // What an earlier delete cut short left: an id no record names, with only policies in it.
    let orphan = ws_dir(&env).join("0123456789abcdef0123456789abcdef");
    fs::create_dir_all(orphan.join("policies/approved")).unwrap();
    fs::write(orphan.join("policies/github.toml"), POLICY_TEXT).unwrap();
    let out = ws(&env, PASSPHRASE, &["ws", "delete", "acme"]);
    assert!(out.status.success() && stdout(&out) == "deleted workspace acme\n" && stderr(&out).lines().all(|l| !l.starts_with("halti: the policies")), "{}", stderr(&out));
    assert!(!acme.exists() && !orphan.exists(), "acme's folder and the orphan are gone");
    assert!(policies_dir(&env, "globex").join("github.toml").exists(), "globex's are its own");
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "the keychain is only on a mac")]
fn a_saved_passphrase_approves_a_policy_after_touch_id_and_never_after_nothing() {
    let env = Env::new();
    let text = with_keychain("passphrase", "passphrase").replace("policy = \"passphrase\"", "policy = \"touchid\"");
    assert!(config(&env, &text, "yes").status.success());
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    assert!(ws_policy_edit(&env, "acme/github", POLICY_TEXT).status.success());
    let approve = |answer: &str| env.command().args(["ws", "policy", "approve", "acme"]).env("HALTI_TEST_APPROVE", answer).output().unwrap();
    // Touch ID, whose window names the policy and its hash; then the saved copy. Nothing typed.
    let out = approve("yes");
    assert!(out.status.success() && stdout(&out).ends_with("approved the policy for github in acme\n") && asked(&out) == 0, "{}", stderr(&out));
    assert_eq!(stderr(&out), format!("halti: [test] [DEV, not protected] approve policies github {POLICY_SHA} in workspace acme: yes\n"));
    assert!(keeps_quiet(&out, PASSPHRASE));
    // A no: nothing is written, and halti says how to type the passphrase instead.
    assert!(ws_policy_edit(&env, "acme/github", &format!("{POLICY_TEXT}writes = \"ask\"\n")).status.success());
    let before = ws_files(&env);
    let out = approve("no");
    let declined = "halti: the policies in acme were not approved. to type the passphrase instead: halti ws policy approve acme --type\n";
    assert!(!out.status.success() && stderr(&out).ends_with(declined) && stdout(&out).contains("changed:\n--- approved\n"), "{}", stderr(&out));
    assert!(ws_files(&env) == before);
    // Approving a policy is never approved by nothing.
    let out = config(&env, &text.replace("policy = \"touchid\"         # approving a policy", "policy = \"none\"         # approving a policy"), "yes");
    let refused =
        format!("halti: {}, line 23: policy can't be none. it can be passphrase, sudo or touchid\nnothing was approved. fix it with: halti config\n", config_file(&env).display());
    assert!(!out.status.success() && stderr(&out) == refused, "{}", stderr(&out));
}

#[test]
fn a_wrong_passphrase_approves_nothing() {
    let env = Env::new();
    assert!(ws(&env, PASSPHRASE, &["ws", "new", "acme"]).status.success());
    assert!(ws_policy_edit(&env, "acme/github", POLICY_TEXT).status.success());
    let before = ws_files(&env);
    for args in [&["ws", "policy", "approve", "acme"][..], &["ws", "policy", "approve", "acme/github"], &["ws", "policy", "show", "acme/github"], &["ws", "policy", "show", "acme"]]
    {
        let out = ws(&env, "acme passphrase two", args);
        refused_with(&out, "that can't be opened (wrong key, or it was changed)");
        assert_eq!((prompted(&out), asked(&out)), (1, 1), "{args:?}: asked once, and not again");
        assert!(ws_files(&env) == before, "{args:?}: every file as it was");
    }
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
    let (managers, ws, set) =
        if cfg!(target_os = "macos") { ("none | keychain", "passphrase | sudo | touchid | none", "passphrase | sudo | touchid") } else { ("none", "passphrase", "passphrase") };
    format!(
        "# halti config. edit with: halti config\n\n[approval]\ndefault = \"sudo\"              # {default}\nconfig  = \"sudo\"              # a change to this file: {config}\n\n\
         [paths]\nworkspaces = \"~/{DEV_STORE_ROOT}/ws\"\n\n[passwords]\nmanager = \"none\"              # {managers}\n\n[secrets]\nstore = \"files\"               # files\n\n\
         [workspace]\npassphrase = \"own\"            # own | generate\n\n[workspace.approval]\n\
         open   = \"passphrase\"         # opening a workspace: {ws}\nset    = \"passphrase\"         # storing a secret in a workspace: {set}\n\
         rm     = \"passphrase\"         # removing secrets from a workspace: {ws}\npolicy = \"passphrase\"         # approving a policy in a workspace: {set}\n\
         delete = \"passphrase\"         # deleting a workspace: {ws}\n{boxes}"
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
        "\n[workspace.approval]\nopen   = \"passphrase\"\nset    = \"passphrase\"\nrm     = \"passphrase\"\npolicy = \"passphrase\"\ndelete = \"passphrase\"\n"
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

/// As `with_keychain`, and storing and removing secrets approved by `set` and `rm`.
fn with_keychain_secrets(open: &str, set: &str, rm: &str, delete: &str) -> String {
    with_keychain(open, delete).replace("set    = \"passphrase\"", &format!("set    = \"{set}\"")).replace("rm     = \"passphrase\"", &format!("rm     = \"{rm}\""))
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
