//! The browser tools inside a box: sessions sealed when a browser closes, used when the next one
//! opens, and kept out of the agent's sight. The box's browser is a stand-in that runs a runner
//! on the Mac (the fake one in tests/fixtures, or with HALTI_E2E_BROWSER=1 the real one), with the
//! sealed sessions of a real store folder.
//!
//! Like the door's scenarios, this runs in a copy of the test program with a private
//! environment (index, policies, Keychain, audit log).

use std::fs;
use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::*;
use crate::boxes::sessions::{InBox, Sessions};
use crate::util::TempDir;
use crate::{keychain, policy};

const KEYCHAIN_TOKEN: &str = "KEYCHAIN-TOKEN-0123456789";
const FAKE: &str = "mcp::tests::the_fake_runner_scenario";
const REAL: &str = "mcp::tests::a_rotating_session_survives_with_the_real_runner";

fn private_environment(test: &str, dir: &TempDir) -> Command {
    for sub in ["keychain", "policy", "home", "store/browser"] {
        fs::create_dir_all(dir.0.join(sub)).unwrap();
    }
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", test, "--nocapture", "--test-threads=1", "--include-ignored"])
        .env("HALTI_MCP_CHILD", "1")
        .env("HALTI_MCP_DIR", &dir.0)
        .env("HOME", dir.0.join("home"))
        .env("HALTI_INDEX", dir.0.join("index.json"))
        .env("HALTI_POLICY_DIR", dir.0.join("policy"))
        .env("HALTI_TEST_KEYCHAIN", dir.0.join("keychain"))
        .env("HALTI_TEST_APPROVE", "yes")
        .env("HALTI_AUDIT", dir.0.join("audit.log"))
        .env("HALTI_AUDIT_KEY", "test-key")
        .env("FAKE_RUNNER_LOG", dir.0.join("runner.log"));
    cmd
}

fn finished(cmd: &mut Command) {
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "scenario failed:\n{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("1 passed"), "the scenario didn't run:\n{}", String::from_utf8_lossy(&out.stdout));
}

fn node_available() -> bool {
    let found = Command::new("node").arg("--version").output().is_ok();
    if !found {
        eprintln!("skipped: needs node");
    }
    found
}

#[test]
fn the_fake_runner_scenario() {
    if let Some(dir) = std::env::var_os("HALTI_MCP_DIR") {
        return fake_scenario(Path::new(&dir));
    }
    if node_available() {
        finished(&mut private_environment(FAKE, &TempDir::new("halti-mcp").unwrap()));
    }
}

#[test]
#[ignore = "needs Node, the runner's dependencies and Chromium: HALTI_E2E_BROWSER=1"]
fn a_rotating_session_survives_with_the_real_runner() {
    if let Some(dir) = std::env::var_os("HALTI_MCP_DIR") {
        return real_scenario(Path::new(&dir));
    }
    if std::env::var_os("HALTI_E2E_BROWSER").is_none() {
        return eprintln!("skipped: set HALTI_E2E_BROWSER=1 to run this test");
    }
    let dir = TempDir::new("halti-mcp").unwrap();
    let browsers = std::env::var("PLAYWRIGHT_BROWSERS_PATH").unwrap_or_else(|_| format!("{}/Library/Caches/ms-playwright", std::env::var("HOME").unwrap()));
    let runner = std::env::var("HALTI_RUNNER_DIR").unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("runner").display().to_string());
    finished(private_environment(REAL, &dir).env("PLAYWRIGHT_BROWSERS_PATH", browsers).env("HALTI_RUNNER_DIR", runner));
}

#[test]
fn halti_mcp_without_all_offers_no_site_and_says_how_to_get_one() {
    let server = Server::start(Scope::nothing());
    assert!(server.sites.is_empty() && server.tools.is_empty() && server.browsable.is_empty());
    let names: Vec<String> = server.list().iter().map(|tool| tool["name"].as_str().unwrap().to_string()).collect();
    assert_eq!(names, ["sites", "fetch"]);
    assert!(server.scope.none.contains("`halti ws mcp WS`") && server.scope.none.contains("`halti mcp --all`"), "{}", server.scope.none);
    assert_eq!(Scope::all().none, NO_SITES);
}

#[test]
fn a_question_names_the_workspace_or_the_workspace_s_box_it_comes_from() {
    assert_eq!(Scope::workspace("acme", Arc::default()).asking(), "workspace acme: ");
    assert_eq!(Scope::boxed("acme/dev", &[], None).asking(), "box acme/dev: ");
    for scope in [Scope::all(), Scope::nothing(), Scope::boxed("research", &[], None)] {
        assert_eq!(scope.asking(), "");
    }
}

#[test]
fn an_open_workspace_s_agent_has_its_consent_from_the_open_and_its_questions_end_with_the_session() {
    let ended = Arc::new(AtomicBool::new(false));
    let scope = Scope::workspace("acme", ended.clone());
    // No consent is asked, as for the workspace's boxes: where nobody can answer one (Linux), its
    // sites would never be used.
    assert!(scope.consented);
    assert!(scope.ended.as_ref().is_some_and(|flag| Arc::ptr_eq(flag, &ended)));
    // Elsewhere consent is asked as the policy says, and nothing ends a question but its answer.
    for scope in [Scope::all(), Scope::nothing()] {
        assert!(!scope.consented && scope.ended.is_none());
    }
}

#[test]
fn a_line_that_isn_t_utf_8_is_answered_as_a_parse_error_and_the_session_goes_on() {
    let mut out = Vec::new();
    let input = b"\xff\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n".to_vec();
    serve_io(Cursor::new(input), &mut out, Scope::nothing()).unwrap();
    let replies: Vec<Value> = String::from_utf8(out).unwrap().lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    assert_eq!(replies.len(), 2, "{replies:?}");
    assert_eq!((replies[0]["id"].clone(), replies[0]["error"]["code"].clone()), (Value::Null, json!(-32700)));
    assert_eq!(replies[1], json!({ "jsonrpc": "2.0", "id": 1, "result": {} }));
}

// --- the pieces ---

fn write_site(dir: &Path, origin: &str, extra_browse: &str) {
    let text = format!(
        "[agent]\nconsent = \"none\"\n[browse]\norigins = [\"{origin}\"]\nstart = \"{origin}/page\"\ncookies = [{{ name = \"session\", field = \"token\", domain = \"127.0.0.1\" }}]\n{extra_browse}"
    );
    fs::write(policy::path("app"), text).unwrap();
    keychain::set("app", "token", KEYCHAIN_TOKEN).unwrap();
    fs::write(dir.join("index.json"), json!({ "app": { "fields": { "token": {} } } }).to_string()).unwrap();
    policy::approve(&["app".into()]).unwrap();
}

/// A box's browser whose runners are `launch`ed on the Mac, with real sealed sessions in `store/browser`.
struct Rig {
    sessions: Sessions,
    /// The proxy tokens handed out, one per runner.
    tokens: Arc<Mutex<Vec<String>>>,
    launch: Arc<dyn Fn() -> Child + Send + Sync>,
    keep: bool,
    /// Whether runners get a proxy token (false: the real runner on the Mac, which has no proxy).
    proxied: bool,
    dir: PathBuf,
}

impl Rig {
    fn new(dir: &Path, keep: bool, proxied: bool, launch: impl Fn() -> Child + Send + Sync + 'static) -> Self {
        let store = dir.join("store");
        Self { sessions: Sessions::new(&store, "the box key", keep), tokens: Arc::default(), launch: Arc::new(launch), keep, proxied, dir: store }
    }

    fn fake(dir: &Path, keep: bool) -> Self {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-runner.mjs");
        Self::new(dir, keep, true, move || Command::new("node").arg(&script).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap())
    }

    fn browser(&self) -> Arc<dyn BoxBrowser> {
        let (tokens, launch, proxied) = (self.tokens.clone(), self.launch.clone(), self.proxied);
        // The same sealed folder, as a new object each time: a restart of the box.
        let sessions = Sessions::new(&self.dir, "the box key", self.keep);
        Arc::new(InBox::new(
            sessions,
            Box::new(move |site| {
                let mut tokens = tokens.lock().unwrap();
                let token = if proxied { format!("token-{site}-{}", tokens.len() + 1) } else { String::new() };
                tokens.push(token.clone());
                Ok((launch(), token))
            }),
            false,
        ))
    }

    fn server(&self) -> Server {
        Server::start(Scope::boxed("research", &["app".to_string()], Some(self.browser())))
    }
}

fn call(server: &mut Server, name: &str, args: Value) -> (bool, String) {
    let request = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": name, "arguments": args } });
    let reply: Value = serde_json::from_str(&server.handle(&request.to_string()).unwrap()).unwrap();
    (reply["result"]["isError"].as_bool().unwrap(), reply["result"]["content"][0]["text"].as_str().unwrap().to_string())
}

fn open(server: &mut Server) -> String {
    let (is_error, text) = call(server, "browse_open", json!({ "site": "app" }));
    assert!(!is_error, "{text}");
    text
}

fn close(server: &mut Server) {
    assert_eq!(call(server, "browse_close", json!({})), (false, "browser closed".to_string()));
}

/// The cookie `session` as the stand-in runner was given it at its n-th start (counting from 0).
fn started_with(dir: &Path, n: usize) -> Value {
    let log = fs::read_to_string(dir.join("runner.log")).unwrap();
    let config: Value = serde_json::from_str(log.lines().nth(n).unwrap()).unwrap();
    config["storageState"]["cookies"][0]["value"].as_str().map_or_else(|| config["cookies"][0]["value"].clone(), |v| json!(v))
}

fn audit_lines(dir: &Path) -> Vec<Value> {
    fs::read_to_string(dir.join("audit.log")).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn sealed_cookie(rig: &Rig) -> Option<String> {
    let state: Value = serde_json::from_str(&rig.sessions.get("app").unwrap()?).unwrap();
    state["cookies"][0]["value"].as_str().map(str::to_string)
}

// --- with the stand-in runner ---

fn fake_scenario(dir: &Path) {
    write_site(dir, "http://127.0.0.1:9", "");

    // A session survives close, and again, and rotates each time.
    let rig = Rig::fake(dir, true);
    let mut server = rig.server();
    let page = open(&mut server);
    assert_eq!(started_with(dir, 0), json!(KEYCHAIN_TOKEN), "nothing sealed yet: the Keychain's field is the session");
    assert!(page.contains("cookies: session=********") && !page.contains(KEYCHAIN_TOKEN), "{page}");
    assert!(page.contains(r#""username":"app""#) && page.contains(&rig.tokens.lock().unwrap()[0]), "the runner is started as the site, with its token: {page}");
    close(&mut server);
    assert_eq!(sealed_cookie(&rig).as_deref(), Some(format!("{KEYCHAIN_TOKEN}#1").as_str()), "browse_close seals what it got back");
    let on_disk = fs::read(dir.join("store/browser/app.sealed")).unwrap();
    assert!(!String::from_utf8_lossy(&on_disk).contains("KEYCHAIN-TOKEN"));

    let page = open(&mut server);
    assert_eq!(started_with(dir, 1), json!(format!("{KEYCHAIN_TOKEN}#1")), "the sealed session, not the Keychain field, goes into the browser");
    assert!(page.contains("cookies: session=********") && !page.contains("#1"), "the sealed value is masked: {page}");
    close(&mut server);
    // The box restarts: a new server and a new sessions object over the same folder.
    drop(server);
    let mut server = rig.server();
    open(&mut server);
    assert_eq!(started_with(dir, 2), json!(format!("{KEYCHAIN_TOKEN}#2")));
    // Opening the site again seals the browser it replaces.
    open(&mut server);
    assert_eq!(started_with(dir, 3), json!(format!("{KEYCHAIN_TOKEN}#3")));
    assert_eq!(rig.tokens.lock().unwrap().len(), 4, "one runner, one token each");

    // The idle limit closes a browser and seals it too.
    server.close_expired_browser(Instant::now() + Duration::from_secs(11 * 60));
    assert!(server.browser.is_none());
    assert_eq!(sealed_cookie(&rig).as_deref(), Some(format!("{KEYCHAIN_TOKEN}#4").as_str()), "idle close seals");

    // The box stopping ends the connection: an open browser is closed and sealed.
    open(&mut server);
    drop(server);
    assert_eq!(sealed_cookie(&rig).as_deref(), Some(format!("{KEYCHAIN_TOKEN}#5").as_str()), "the end of the connection seals");
    let request = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "browse_open", "arguments": { "site": "app" } } });
    let mut out = Vec::new();
    serve_io(Cursor::new(format!("{request}\n").into_bytes()), &mut out, Scope::boxed("research", &["app".to_string()], Some(rig.browser()))).unwrap();
    assert_eq!(sealed_cookie(&rig).as_deref(), Some(format!("{KEYCHAIN_TOKEN}#6").as_str()), "serve_io ending seals");

    // Values only the sealed session has (not in the Keychain) are masked too.
    rig.sessions
        .put("app", &json!({ "cookies": [{ "name": "session", "value": "ONLY-IN-THE-SESSION-0123", "domain": "127.0.0.1", "path": "/" }], "origins": [{ "origin": "http://127.0.0.1:9", "localStorage": [{ "name": "jwt", "value": "LOCAL-STORAGE-VALUE-0123" }] }] }).to_string())
        .unwrap();
    let mut server = rig.server();
    let page = open(&mut server);
    assert!(page.contains("session=********") && page.contains("jwt=********"), "{page}");
    assert!(!page.contains("ONLY-IN-THE-SESSION") && !page.contains("LOCAL-STORAGE-VALUE"), "{page}");
    assert_eq!(server.browser.as_ref().unwrap().secrets.len(), 2);
    close(&mut server);
    drop(server);

    // A session that doesn't open is not used: the site's usual sources are, and the agent is told.
    let mut bytes = fs::read(dir.join("store/browser/app.sealed")).unwrap();
    bytes[40] ^= 1;
    fs::write(dir.join("store/browser/app.sealed"), bytes).unwrap();
    let runs = fs::read_to_string(dir.join("runner.log")).unwrap().lines().count();
    let mut server = rig.server();
    let page = open(&mut server);
    assert!(page.contains("couldn't be opened") && page.contains("signed in the usual way"), "{page}");
    assert_eq!(started_with(dir, runs), json!(KEYCHAIN_TOKEN), "the Keychain's field instead");
    let audit = fs::read_to_string(dir.join("audit.log")).unwrap();
    assert!(audit.contains("browse_session_unreadable") && audit.contains("\"box\":\"research\""), "{audit}");
    close(&mut server);
    assert_eq!(sealed_cookie(&rig).as_deref(), Some(format!("{KEYCHAIN_TOKEN}#1").as_str()), "the next close replaces the damaged file");
    let page = open(&mut server);
    assert!(!page.contains("couldn't be opened"));
    close(&mut server);

    // keep_sessions = false: nothing is ever written, and nothing already there is used.
    fs::remove_file(dir.join("store/browser/app.sealed")).unwrap();
    let rig = Rig::fake(dir, false);
    let mut server = rig.server();
    open(&mut server);
    close(&mut server);
    open(&mut server);
    close(&mut server);
    assert!(fs::read_dir(dir.join("store/browser")).unwrap().next().is_none(), "no session was written");
    assert_eq!(started_with(dir, fs::read_to_string(dir.join("runner.log")).unwrap().lines().count() - 1), json!(KEYCHAIN_TOKEN));

    // A page's write is audited as a request of its own, though its question came while a later
    // call ran, or while the browser closed: the calls' lines keep their own decisions.
    let rig = Rig::fake(dir, false);
    let mut server = rig.server();
    open(&mut server);
    let before = audit_lines(dir).len();
    assert!(!call(&mut server, "browse_click", json!({ "ref": "later-write" })).0);
    assert!(!call(&mut server, "browse_snapshot", json!({})).0);
    assert!(!call(&mut server, "browse_click", json!({ "ref": "later-write" })).0);
    server.close_expired_browser(Instant::now() + Duration::from_secs(11 * 60));
    let page_write = ("browse_page_write", Some("POST"), Some("http://127.0.0.1:9/later"), "asked:yes");
    let lines: Vec<_> = audit_lines(dir)[before..].iter().map(|l| (l["tool"].clone(), l["method"].clone(), l["url"].clone(), l["decision"].clone(), l["box"].clone())).collect();
    let line = |(tool, method, url, decision): (&str, Option<&str>, Option<&str>, &str)| (json!(tool), json!(method), json!(url), json!(decision), json!("research"));
    let expected = [("browse_click", None, None, "allowed"), page_write, ("browse_snapshot", None, None, "allowed"), ("browse_click", None, None, "allowed"), page_write];
    assert_eq!(lines, expected.map(line));
    drop(server);

    // A box without a browser VM has no browser at all, and never falls back to the Mac's.
    let mut server = Server::start(Scope::boxed("research", &["app".to_string()], None));
    let (is_error, text) = call(&mut server, "browse_open", json!({ "site": "app" }));
    assert!(is_error && text.contains("has no browser"), "{text}");
}

// --- with the real runner ---

/// A site that sets a new session cookie on every visit and remembers what cookie each visit brought.
fn rotating_site() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let visits: Arc<Mutex<Vec<String>>> = Arc::default();
    let seen = visits.clone();
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let seen = seen.clone();
            thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let (mut path, mut cookie) = (String::new(), "none".to_string());
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if path.is_empty() {
                        path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                    }
                    if let Some(c) = line.to_ascii_lowercase().strip_prefix("cookie:") {
                        cookie = c.trim().to_string();
                    }
                }
                let mut seen = seen.lock().unwrap();
                let set = if path == "/page" {
                    seen.push(cookie);
                    format!("Set-Cookie: session=rot{}; Path=/\r\n", seen.len())
                } else {
                    String::new()
                };
                let body = "<html><body><h1>rotating</h1></body></html>";
                let _ = write!(stream, "HTTP/1.1 200 OK\r\n{set}Content-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                let _ = stream.flush();
                let _ = reader.read(&mut [0u8; 1]);
            });
        }
    });
    (port, visits)
}

fn real_scenario(dir: &Path) {
    let (port, visits) = rotating_site();
    write_site(dir, &format!("http://127.0.0.1:{port}"), "");
    // The initial field is what the first visit brings.
    keychain::set("app", "token", "rot0").unwrap();
    let rig = Rig::new(dir, true, false, || crate::browse::mac_runner().unwrap());

    let mut server = rig.server();
    open(&mut server);
    close(&mut server);
    assert_eq!(*visits.lock().unwrap(), ["session=rot0"]);
    // The box stops and starts again: the session is in the store, not in the browser.
    drop(server);
    let mut server = rig.server();
    open(&mut server);
    close(&mut server);
    open(&mut server);
    drop(server);
    assert_eq!(*visits.lock().unwrap(), ["session=rot0", "session=rot1", "session=rot2"], "every visit brought the latest value");
}
