//! Checks on the source itself, for what the compiler can't see: that test hooks are keyed to
//! `halti_dev` (debug-profile builds, see build.rs) and never to debug assertions, that every
//! `HALTI_*` variable is on a reviewed list saying who reads it, that the macOS-only code
//! stays as it was while the Linux host is built (it can't be compiled or run here), and that the
//! core crate stays plain Rust: no I/O, no code for one OS, nothing kept between calls.

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Read by release builds, through `util::env_var` (and so also as `CRED_<name>`). None of them
/// picks where halti keeps its files, which adapter protects them, or what a prompt answers.
const RELEASE: &[(&str, &str)] = &[
    ("WARN_DAYS", "the warning window of `halti check` and `ls`"),
    ("REFRESHING", "set for refresh scripts, so a halti they run doesn't refresh again"),
    ("FIREFOX_PROFILE", "which of your Firefox profiles a `from` rule reads"),
    ("CHROME_PROFILE", "which of your Chrome profiles a `from` rule reads"),
];

/// Read only by debug-profile builds, through `util::dev_var`, which release builds don't have.
const DEV: &[&str] = &[
    "HALTI_TEST_APPROVE",
    "HALTI_TEST_KEYCHAIN",
    "HALTI_TEST_LOGIN_RUNNER",
    "HALTI_AUDIT",
    "HALTI_AUDIT_KEY",
    "HALTI_RUNNER_DIR",
    "HALTI_INDEX",
    "HALTI_POLICY_DIR",
    "HALTI_BOX_DIR",
    // Picks the engine the conformance suite runs against (not read yet).
    "HALTI_E2E_ENGINE",
];

/// Read only by tests.
const TEST: &[&str] = &[
    "HALTI_E2E_BOX",
    "HALTI_E2E_AGENT_IMAGE",
    "HALTI_E2E_JVM_IMAGE",
    "HALTI_E2E_BROWSER",
    "HALTI_E2E_INTERACTIVE",
    "HALTI_RELEASE_BIN",
    "HALTI_MCP_CHILD",
    "HALTI_MCP_DIR",
    "HALTI_INSPECT_DIR",
    "HALTI_PAGE_DIR",
    "HALTI_PAGE_VM_DIR",
    "HALTI_DOOR_CHILD",
    "HALTI_DOOR_DIR",
    "HALTI_DOOR_LIVE",
    "HALTI_DOOR_ALLOW",
    "HALTI_DOOR_SECONDS",
];

/// Never read by halti: set for other programs, or named in text.
const NOT_READ: &[&str] = &[
    // Passed to the browser runner by tests; a release build refuses them (`engine::runner_command`).
    "HALTI_RUNNER_DEBUG",
    "HALTI_RUNNER_DEBUG_NO_ROUTING",
    // Read by install.sh.
    "HALTI_SIGN_IDENTITY",
    // A refresh script's field (`HALTI_<FIELD>`), in a test's script.
    "HALTI_LOGIN",
];

/// The `HALTI_` string literals release code may hold that aren't a `dev_var` name.
const OTHER_LITERALS: &[&str] = &[
    // util::env_names, which builds the names `env_var` reads and refresh scripts get.
    "\"HALTI_{suffix}\"",
    // engine::runner_command, refusing these in what is passed to the runner.
    "\"HALTI_RUNNER_DEBUG\"",
];

/// Other variables release code reads directly, and why: each file's reads, as the text from
/// `env::var` up to the closing parenthesis.
const OTHER_VARIABLES: &[(&str, &str)] = &[
    // keychain: the account of the Keychain items.
    ("src/keychain.rs", "env::var(\"USER\")"),
    // policy edit and box edit: the editor to run.
    ("src/policy.rs", "env::var(\"VISUAL\")"),
    ("src/policy.rs", "env::var(\"EDITOR\")"),
    // sandbox: the terminal type a box's command is given.
    ("src/sandbox.rs", "env::var_os(\"TERM\")"),
    // util::home, in debug builds only (checked below).
    ("src/util.rs", "env::var_os(\"HOME\")"),
    // util::env_var, which reads the names on the release list.
    ("src/util.rs", "env::var_os)"),
    // util::dev_var, which only debug builds have.
    ("src/util.rs", "env::var_os(name)"),
];

/// Reads of that list only debug builds have: the code each must follow, `#[cfg(halti_dev)]` and all.
const DEV_ONLY_READS: &[(&str, &str, &str)] = &[
    ("src/util.rs", "env::var_os(\"HOME\")", "#[cfg(halti_dev)]\n    if let Some(home) = "),
    ("src/util.rs", "env::var_os(name)", "#[cfg(halti_dev)]\npub fn dev_var(name: &str) -> Option<OsString> {\n    "),
];

/// Names an install made by cred (halti's old name) holds: halti writes none of them, so they
/// appear only in `legacy`, which the migration of such an install reads.
const OLD_NAMES: &[&str] = &[
    "cred-agent",
    "cred-browser",
    "cred-shim",
    "cred-box",
    "cred-managed",
    "\"cred:",
    "/run/cred",
    ".config/cred",
    "Application Support/cred",
    "com.deorlovnis.cred",
    "cred code signing",
];

#[test]
fn the_old_names_stay_in_legacy() {
    let mut files = Vec::new();
    for dir in ["src", "tests", "box", "core"] {
        all_files(&root().join(dir), &mut files);
    }
    files.extend(["install.sh", "mise.toml", "check.sh"].map(|f| root().join(f)));
    let mut found = Vec::new();
    for path in files {
        let rel = path.strip_prefix(root()).unwrap().display().to_string();
        if rel == "src/legacy.rs" || rel == "tests/source.rs" || rel.contains("/target/") {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else { continue };
        for (n, line) in text.lines().enumerate() {
            if let Some(name) = OLD_NAMES.iter().find(|n| line.contains(*n)) {
                found.push(format!("{rel}:{}: {name}", n + 1));
            }
        }
    }
    assert!(found.is_empty(), "halti's own names are in src/names.rs; the old ones belong in src/legacy.rs only:\n{}", found.join("\n"));
}

fn all_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target" || n == "node_modules") {
                continue;
            }
            all_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every .rs file under these folders of the crate, with its path from the crate's root.
fn sources(dirs: &[&str]) -> Vec<(String, String)> {
    let mut files = Vec::new();
    for dir in dirs {
        rust_files(&root().join(dir), &mut files);
    }
    files.sort();
    files.into_iter().map(|p| (p.strip_prefix(root()).unwrap().display().to_string(), fs::read_to_string(&p).unwrap())).collect()
}

/// A source file without its tests: files of tests are dropped, and a `#[cfg(test)] mod tests`
/// block is cut out up to its closing brace.
fn release_code(path: &str, text: &str) -> Option<String> {
    let name = Path::new(path).file_name().unwrap().to_string_lossy();
    if name == "tests.rs" || name.ends_with("_tests.rs") {
        return None;
    }
    let lines: Vec<&str> = text.lines().collect();
    let mut kept = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i] == "#[cfg(test)]" && lines.get(i + 1).is_some_and(|l| l.starts_with("mod tests {")) {
            while i < lines.len() && lines[i] != "}" {
                i += 1;
            }
        } else {
            kept.push(lines[i]);
        }
        i += 1;
    }
    Some(kept.join("\n"))
}

/// The string literal at the start of `s` (which starts after its opening quote).
fn literal(s: &str) -> &str {
    &s[..s.find('"').unwrap_or(s.len())]
}

/// The name each call of `function` in the code reads: a string literal, or a `const` of this
/// file that holds one. Anything else reads as "?", which no list has.
fn names_read(code: &str, function: &str) -> Vec<String> {
    let call = format!("{function}(");
    let mut found = Vec::new();
    for (at, _) in code.match_indices(&call) {
        let before = &code[..at];
        if before.ends_with("fn ") || before.ends_with(|c: char| c.is_alphanumeric() || c == '_') {
            continue;
        }
        let arg = &code[at + call.len()..];
        let name = match arg.strip_prefix('"') {
            Some(rest) => Some(literal(rest).to_string()),
            None => {
                let ident = &arg[..arg.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(0)];
                let def = format!("const {ident}: &str = \"");
                code.find(&def).filter(|_| !ident.is_empty()).map(|d| literal(&code[d + def.len()..]).to_string())
            }
        };
        found.push(name.unwrap_or_else(|| "?".into()));
    }
    found
}

/// The `HALTI_` names in a text: upper-case letters, digits and underscores after the prefix,
/// without trailing underscores (`HALTI_<FIELD>` and `HALTI_RUNNER_DEBUG_*` name families).
fn names(text: &str) -> Vec<String> {
    text.match_indices("HALTI_")
        .map(|(at, _)| {
            let rest = &text[at..];
            let end = rest.find(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')).unwrap_or(rest.len());
            rest[..end].trim_end_matches('_').to_string()
        })
        .filter(|n| n != "HALTI")
        .collect()
}

#[test]
fn no_hook_is_keyed_to_debug_assertions() {
    // A release profile can turn debug assertions on; `halti_dev` only comes with the debug
    // profile. main.rs keeps two: the guard against `halti_dev` in a release-profile build or one
    // without debug assertions, and what `build-info` prints.
    let allowed = [
        ("src/main.rs", "#[cfg(all(halti_dev, any(halti_release, not(debug_assertions))))]"),
        ("src/main.rs", "println!(\"debug_assertions={} halti_dev={}\", cfg!(debug_assertions), cfg!(halti_dev));"),
    ];
    let mut found = Vec::new();
    for (path, text) in sources(&["src", "tests"]) {
        if path == "tests/source.rs" {
            continue;
        }
        // As a cfg, not as `debug_assertions=` in what `build-info` prints.
        for line in text.lines().filter(|l| l.contains("debug_assertions)") || l.contains("debug_assertions,")) {
            if !allowed.contains(&(path.as_str(), line.trim())) {
                found.push(format!("{path}: {}", line.trim()));
            }
        }
    }
    assert!(found.is_empty(), "use cfg(halti_dev) for these:\n{}", found.join("\n"));
}

#[test]
fn release_code_reads_only_the_listed_variables() {
    let mut problems = Vec::new();
    for (path, text) in sources(&["src"]) {
        let Some(code) = release_code(&path, &text) else { continue };
        for name in names_read(&code, "env_var") {
            if !RELEASE.iter().any(|(n, _)| *n == name) {
                problems.push(format!("{path}: env_var reads {name}, which isn't on the release list"));
            }
        }
        for name in names_read(&code, "dev_var") {
            if !DEV.contains(&name.as_str()) {
                problems.push(format!("{path}: dev_var reads {name}, which isn't on the dev list"));
            }
        }
        // A HALTI_ literal anywhere else could be read some other way.
        for (at, _) in code.match_indices("\"HALTI_") {
            let quoted = format!("\"{}\"", literal(&code[at + 1..]));
            if !code[..at].ends_with("dev_var(") && !OTHER_LITERALS.contains(&quoted.as_str()) {
                problems.push(format!("{path}: {quoted} isn't read through dev_var"));
            }
        }
        // The old CRED_ names are read only through util::env_var.
        if code.contains("ENV_PREFIX") && !["src/util.rs", "src/engine.rs", "src/legacy.rs"].contains(&path.as_str()) {
            problems.push(format!("{path}: uses legacy::ENV_PREFIX"));
        }
        // `env::var`, `var_os`, `vars` and `vars_os`, called or passed as a function.
        for (at, _) in code.match_indices("env::var") {
            let rest = &code[at..];
            let read = &rest[..rest.find(')').map_or(rest.len(), |end| end + 1)];
            if !OTHER_VARIABLES.contains(&(path.as_str(), read)) {
                problems.push(format!("{path}: {read}"));
            } else if let Some((.., before)) = DEV_ONLY_READS.iter().find(|(p, r, _)| (*p, *r) == (path.as_str(), read))
                && !code[..at].ends_with(before)
            {
                problems.push(format!("{path}: {read} isn't under #[cfg(halti_dev)] as listed"));
            }
        }
        for call in ["getenv(", "secure_getenv("] {
            if code.contains(call) {
                problems.push(format!("{path}: {call}"));
            }
        }
    }
    assert!(problems.is_empty(), "read variables only through util::env_var (release, listed) or util::dev_var (debug builds):\n{}", problems.join("\n"));
}

#[test]
fn every_halti_variable_is_sorted() {
    let mut unsorted: Vec<String> = Vec::new();
    for (path, text) in sources(&["src", "tests"]) {
        if path == "tests/source.rs" {
            continue;
        }
        for name in names(&text) {
            let known = RELEASE.iter().any(|(n, _)| name == format!("HALTI_{n}")) || [DEV, TEST, NOT_READ].iter().any(|list| list.contains(&name.as_str()));
            if !known {
                unsorted.push(format!("{path}: {name}"));
            }
        }
    }
    unsorted.dedup();
    assert!(unsorted.is_empty(), "add each to a list in tests/source.rs:\n{}", unsorted.join("\n"));
}

/// The lines of a top-level macOS-only item, from its cfg line to its closing brace.
fn macos_block(path: &str, starts: &str) -> String {
    let text = fs::read_to_string(root().join(path)).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let first = (0..lines.len()).find(|&i| lines[i] == "#[cfg(target_os = \"macos\")]" && lines.get(i + 1).is_some_and(|l| l.starts_with(starts)));
    let first = first.unwrap_or_else(|| panic!("{path} has no macOS-only `{starts}`"));
    let last = (first..lines.len()).find(|&i| lines[i] == "}").unwrap();
    lines[first..=last].join("\n")
}

#[test]
fn the_macos_only_code_is_frozen() {
    // Touch ID and the Keychain can't be built or run on the Linux host, so nothing changes them
    // until the Mac adapters are written on a Mac, which updates these hashes.
    for (path, starts, sha256) in [
        ("src/approve.rs", "fn ask_person(", "b7b125f8ba2dabaa2481bdfea29cfc6d779a96ab8f3542fe7c9dadfb55db2bdf"),
        ("src/keychain.rs", "mod backend {", "c3d98940a584a9742da7b7320e60843eca9ea2387779635ef6027c2b3442a3b8"),
    ] {
        let block = macos_block(path, starts);
        let digest: String = Sha256::digest(block.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(digest, sha256, "the macOS-only `{starts}` in {path} changed");
    }
}

#[test]
fn the_name_scan_finds_families_and_skips_the_bare_prefix() {
    assert_eq!(names("HALTI_RUNNER_DEBUG_* and HALTI_<FIELD>, HALTI_TEST_APPROVE=yes"), ["HALTI_RUNNER_DEBUG", "HALTI_TEST_APPROVE"]);
    let code = release_code("src/x.rs", "a\n#[cfg(test)]\nmod tests {\n    b\n}\nc").unwrap();
    assert_eq!(code, "a\nc");
    let code = "const NAME: &str = \"WARN_DAYS\";\npub fn env_var(s: &str) {}\nenv_var(NAME); util::env_var(\"X\"); env_var(name); my_env_var(\"Y\")";
    assert_eq!(names_read(code, "env_var"), ["WARN_DAYS", "X", "?"]);
}

/// What core's source may name from `std`: nothing that reaches outside the process. Of
/// `collections` only the ordered ones: the hashed ones seed from the OS and list in another order
/// each run.
const CORE_STD: &[&str] = &["fmt", "error", "collections", "cell", "rc"];

/// What core may be built from. A crate that does I/O for core would pass every other check here,
/// so a new one is added to this list by hand.
const CORE_DEPENDENCIES: &[(&str, &[&str])] =
    &[("[dependencies]", &["aes-gcm", "anyhow", "hkdf", "ml-kem", "p256", "serde", "sha2", "zeroize"]), ("[dev-dependencies]", &["serde_json"])];

/// Core is plain Rust with no I/O, no code for one OS and nothing kept between calls (see
/// core/src/lib.rs). Clippy's list in core/clippy.toml refuses the calls by name; this refuses the
/// ways around that list, tests included.
#[test]
fn the_core_crate_stays_pure() {
    const BANNED: &[&str] = &[
        "std::{",
        "use std;",
        "std as",
        "sync::",
        "extern ",
        "#[path",
        "include!",
        "include_str!",
        "include_bytes!",
        "env!(",
        "thread_local!",
        "print!(",
        "println!(",
        "eprint!(",
        "eprintln!(",
        "dbg!(",
        "HashMap",
        "HashSet",
        "hash_map",
        "hash_set",
        "RandomState",
        "HALTI_",
        "halti_dev",
        "debug_assertions",
        "target_",
        "rustfmt",
        // Randomness is an argument: core never draws its own, and the crates it is built on can.
        "getrandom",
        "OsRng",
        "SysRng",
        "_from_rng(",
        "generate(",
    ];
    let word = |c: char| c.is_alphanumeric() || c == '_';
    let files = sources(&["core"]);
    let forbids = files.iter().any(|(path, text)| path == "core/src/lib.rs" && text.lines().any(|l| l == "#![forbid(unsafe_code)]"));
    assert!(forbids, "core/src/lib.rs forbids unsafe code");
    let mut found = Vec::new();
    for (path, text) in &files {
        if !path.starts_with("core/src/") {
            found.push(format!("{path}: core's code is all under core/src"));
        }
        for (n, line) in text.lines().enumerate() {
            let mut why: Vec<&str> = BANNED.iter().copied().filter(|t| line.contains(t)).collect();
            // Only tests are conditional, and of `std` only what stays in the process is named.
            why.extend(line.match_indices("cfg").filter(|(i, _)| !line[*i..].starts_with("cfg(test)") && !line[*i..].starts_with("cfg_attr(not(test),")).map(|_| "cfg"));
            why.extend(line.match_indices("std::").filter(|(i, _)| !CORE_STD.iter().any(|m| line[i + 5..].starts_with(m))).map(|_| "std::"));
            // The keyword, wherever it stands; `&'static str` is a lifetime.
            if line.match_indices("static").any(|(i, _)| !line[..i].ends_with('\'') && !line[..i].ends_with(word) && !line[i + 6..].starts_with(word)) {
                why.push("static");
            }
            if line.contains("unsafe") && line != "#![forbid(unsafe_code)]" {
                why.push("unsafe");
            }
            found.extend(why.iter().map(|w| format!("{path}:{}: {w}", n + 1)));
        }
    }

    // The manifest: the listed crates and no others, nothing per OS, no build script.
    let manifest = fs::read_to_string(root().join("core/Cargo.toml")).unwrap();
    let mut section = "";
    for line in manifest.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        if line.starts_with('[') {
            section = line;
            if !["[package]", "[dependencies]", "[dev-dependencies]"].contains(&line) {
                found.push(format!("core/Cargo.toml: {line}"));
            }
            continue;
        }
        let key = line.split('=').next().unwrap().trim();
        let allowed = CORE_DEPENDENCIES.iter().find(|(s, _)| *s == section).map(|(_, names)| *names);
        if allowed.is_some_and(|names| !names.contains(&key)) || (section == "[package]" && key == "build") {
            found.push(format!("core/Cargo.toml: {section} {key}"));
        }
        // The list above reads only a crate's name. Its features matter as much: none may bring the
        // OS's randomness in, and these two do by default.
        if allowed.is_some() && line.contains("getrandom") {
            found.push(format!("core/Cargo.toml: {section} {key} names getrandom"));
        }
        if section == "[dependencies]" && ["aes-gcm", "p256"].contains(&key) && !line.contains("default-features = false") {
            found.push(format!("core/Cargo.toml: {section} {key} keeps its default features"));
        }
    }
    if root().join("core/build.rs").exists() {
        found.push("core/build.rs: core has no build script".into());
    }
    assert!(found.is_empty(), "core does no I/O, has no code for one OS and keeps no state:\n{}", found.join("\n"));
}

/// A `Keystore` is bound to its workspace in one place, which only core can call: a second way to
/// make one, or a public `bind`, would let any caller pick the workspace a handle reads. (The doc
/// test on `Keystore` shows `bind` can't be named from outside; it would pass as well if `bind`
/// were renamed and another constructor made public.)
#[test]
fn only_core_binds_a_keystore() {
    let files = sources(&["core/src"]);
    let lines = || files.iter().flat_map(|(path, text)| text.lines().map(move |l| (path.as_str(), l)));
    let binds: Vec<_> = lines().filter(|(_, l)| l.contains("-> Keystore<")).collect();
    assert_eq!(binds, [("core/src/store.rs", "    pub(crate) fn bind(ws: WsId, backend: &'p dyn KeystoreBackend) -> Keystore<'p> {")]);
    let made: Vec<_> = lines().filter(|(_, l)| l.trim_start().starts_with("Keystore {")).map(|(path, _)| path).collect();
    assert_eq!(made, ["core/src/store.rs"]);
}
