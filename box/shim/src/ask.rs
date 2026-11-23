//! `ask`: the asker. Claude Code's hooks run it (the image's managed settings, which name it for
//! each event below); it reads the hook's JSON on stdin and tells halti, at `POST /ask` on
//! halti.internal, whether the agent now waits for its owner, and what kind of wait it is. halti
//! answers at once, `nobody`: nobody answers from the phone. It then ends 0 with no output, so that
//! Claude Code goes on as if there were no hook. It prints nothing.
//!
//! | Hook | Sent |
//! |---|---|
//! | Notification `permission_prompt` | `permission-prompt` |
//! | Notification `idle_prompt` | `turn-ended` |
//! | Notification `elicitation_dialog`, `agent_needs_input` | `needs-input` |
//! | PreToolUse | `question` for AskUserQuestion, else `working` |
//! | Stop | `turn-ended`, or nothing while a background task runs |
//! | UserPromptSubmit | `typed`, or `working` for a background task's notification |
//! | PostToolUse, PermissionDenied | `working` |
//! | SubagentStop, SessionEnd | `working`: the sub-agent or the session is gone |
//!
//! Anything else, or input that isn't JSON, sends nothing.
//!
//! A permission prompt is told by its Notification alone, which comes 6 seconds after the dialog
//! opens, and not if it was answered by then. PermissionRequest comes as the dialog opens, and
//! after a yes nothing is heard until the tool ends: a long build just allowed would be told as a
//! wait.
//!
//! What is sent is one fixed form, fields each after its length in two bytes big-endian: the label
//! `halti-ask-v1`, the event, a session tag (16 bytes made from the hook's `session_id` and, for a
//! sub-agent, its `agent_id`, so each is a session of its own), and the text the hook showed, clipped
//! to halti's caps. halti keeps neither the tag nor the text in what it tells the phone. The host's
//! side is halti's src/notices.rs.
//!
//! A session that ends, or a sub-agent that returns, waits no more, and no later hook would carry
//! its tag: a `claude -p` ends with Stop, and a sub-agent's prompt answered No raises nothing.
//!
//! A Stop while a background task runs isn't the agent waiting: it ends again when the task does.
//! A background task's end raises UserPromptSubmit with the task's notification as the prompt, which
//! the owner didn't type: one that starts `<task-notification>` is `working`, not `typed`.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// halti itself, in the box: halti.internal.
const DOOR: ([u8; 4], u16) = ([127, 0, 0, 2], 80);
const PATH: &str = "/ask";
const LABEL: &[u8] = b"halti-ask-v1";
/// How long the door has to take the call and answer it.
const WAIT: Duration = Duration::from_secs(5);
/// The most of the hook's input read; longer input sends nothing.
const INPUT_MAX: u64 = 16 * 1024 * 1024;
/// halti's caps: a header, the end of a message, a question, an option's label and description,
/// how many questions and options, and the whole text.
const NAME_MAX: usize = 80;
const BODY_MAX: usize = 2000;
const QUESTION_MAX: usize = 300;
const LABEL_MAX: usize = 80;
const DESCRIPTION_MAX: usize = 200;
const QUESTIONS_MAX: usize = 4;
const OPTIONS_MAX: usize = 4;
const TEXT_MAX: usize = 8 * 1024;
/// How deep the hook's JSON may nest.
const DEPTH_MAX: usize = 128;

/// Reads the hook's input, tells halti, and ends 0.
pub fn main() -> ! {
    let mut input = Vec::new();
    let read = io::stdin().take(INPUT_MAX + 1).read_to_end(&mut input);
    let said = match read {
        Ok(_) if input.len() as u64 <= INPUT_MAX => parse(&input).map(|hook| said(&hook)),
        _ => None,
    };
    if let Some(Said { event: Some(event), tag, text }) = said {
        let _ = send(SocketAddr::from(DOOR), &form(event, &tag, &text));
    }
    std::process::exit(0)
}

/// What one hook comes to.
#[derive(Debug, PartialEq)]
struct Said {
    /// The event sent, if any.
    event: Option<&'static str>,
    tag: [u8; 16],
    text: Vec<u8>,
}

/// What the hook whose input is `hook` sends.
fn said(hook: &Json) -> Said {
    let text = |field: &str| hook.get(field).and_then(Json::text).unwrap_or("");
    let tag = tag(text("session_id"), text("agent_id"));
    let tool = text("tool_name");
    let (event, body) = match text("hook_event_name") {
        "Notification" => match text("notification_type") {
            "permission_prompt" => (Some("permission-prompt"), Vec::new()),
            "idle_prompt" => (Some("turn-ended"), Vec::new()),
            "elicitation_dialog" | "agent_needs_input" => (Some("needs-input"), Vec::new()),
            _ => (None, Vec::new()),
        },
        "PreToolUse" if tool == "AskUserQuestion" => (Some("question"), questions(hook.get("tool_input"))),
        "PreToolUse" | "PostToolUse" | "PermissionDenied" | "SubagentStop" | "SessionEnd" => (Some("working"), Vec::new()),
        "Stop" if background_runs(hook) => (None, Vec::new()),
        "Stop" => (Some("turn-ended"), fields(&[clip_start(text("last_assistant_message"), BODY_MAX)])),
        "UserPromptSubmit" if text("prompt").starts_with("<task-notification>") => (Some("working"), Vec::new()),
        "UserPromptSubmit" => (Some("typed"), Vec::new()),
        _ => (None, Vec::new()),
    };
    let text = if body.len() > TEXT_MAX { Vec::new() } else { body };
    Said { event, tag, text }
}

/// Whether a background task of the session still runs.
fn background_runs(hook: &Json) -> bool {
    let tasks = hook.get("background_tasks").and_then(Json::items).unwrap_or_default();
    tasks.iter().any(|task| task.get("status").and_then(Json::text) == Some("running"))
}

/// A question's text: up to four questions, each its header, its question, whether several
/// options may be taken, then up to four options, each its label and description.
fn questions(input: Option<&Json>) -> Vec<u8> {
    let asked = input.and_then(|input| input.get("questions")).and_then(Json::items).unwrap_or_default();
    let mut text = Vec::new();
    for question in asked.iter().take(QUESTIONS_MAX) {
        let field = |name: &str| question.get(name).and_then(Json::text).unwrap_or("");
        let several = if question.get("multiSelect") == Some(&Json::Bool(true)) { "1" } else { "0" };
        let mut parts = vec![clip_end(field("header"), NAME_MAX), clip_end(field("question"), QUESTION_MAX), several];
        for option in question.get("options").and_then(Json::items).unwrap_or_default().iter().take(OPTIONS_MAX) {
            let field = |name: &str| option.get(name).and_then(Json::text).unwrap_or("");
            parts.push(clip_end(field("label"), LABEL_MAX));
            parts.push(clip_end(field("description"), DESCRIPTION_MAX));
        }
        push(&mut text, &fields(&parts));
    }
    text
}

/// The first `max` bytes of `text` at most, ending on a character's boundary.
fn clip_end(text: &str, max: usize) -> &str {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// The last `max` bytes of `text` at most, starting on a character's boundary.
fn clip_start(text: &str, max: usize) -> &str {
    let mut start = text.len().saturating_sub(max);
    while !text.is_char_boundary(start) {
        start += 1;
    }
    &text[start..]
}

/// The session tag: two FNV-1a hashes of the session's id and the sub-agent's, if any. It only has
/// to tell this box's sessions apart; halti keeps it on the machine.
fn tag(session: &str, agent: &str) -> [u8; 16] {
    let mut tag = [0; 16];
    for (half, basis) in [(0, 0xcbf2_9ce4_8422_2325_u64), (8, 0x8422_2325_cbf2_9ce4)] {
        let mut hash = basis;
        for byte in session.bytes().chain([0]).chain(agent.bytes()) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
        tag[half..half + 8].copy_from_slice(&hash.to_be_bytes());
    }
    tag
}

/// Adds `field` to `bytes`, after its length in two bytes big-endian. Every field here is far below
/// 64 KiB.
fn push(bytes: &mut Vec<u8>, field: &[u8]) {
    bytes.extend_from_slice(&u16::try_from(field.len()).unwrap_or(u16::MAX).to_be_bytes());
    bytes.extend_from_slice(&field[..field.len().min(usize::from(u16::MAX))]);
}

fn fields(parts: &[&str]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for part in parts {
        push(&mut bytes, part.as_bytes());
    }
    bytes
}

/// What is sent for `event`.
fn form(event: &str, tag: &[u8], text: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for field in [LABEL, event.as_bytes(), tag, text] {
        push(&mut bytes, field);
    }
    bytes
}

/// Sends `form` to the door at `to`, and reads its answer.
fn send(to: SocketAddr, form: &[u8]) -> io::Result<Vec<u8>> {
    let mut door = TcpStream::connect_timeout(&to, WAIT)?;
    door.set_read_timeout(Some(WAIT))?;
    door.set_write_timeout(Some(WAIT))?;
    let head = format!("POST {PATH} HTTP/1.1\r\nHost: halti.internal\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", form.len());
    door.write_all(&[head.as_bytes(), form].concat())?;
    let mut answer = Vec::new();
    door.take(4096).read_to_end(&mut answer)?;
    Ok(answer)
}

/// JSON, as far as the asker reads it.
#[derive(Clone, Debug, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    /// A number, as written.
    Number(String),
    Text(String),
    Items(Vec<Json>),
    Fields(Vec<(String, Json)>),
}

impl Json {
    fn get(&self, name: &str) -> Option<&Json> {
        match self {
            Json::Fields(fields) => fields.iter().find(|(key, _)| key == name).map(|(_, value)| value),
            _ => None,
        }
    }

    fn text(&self) -> Option<&str> {
        match self {
            Json::Text(text) => Some(text),
            _ => None,
        }
    }

    fn items(&self) -> Option<&[Json]> {
        match self {
            Json::Items(items) => Some(items),
            _ => None,
        }
    }

    /// Writes it as compact JSON: the tests read back what they wrote.
    #[cfg(test)]
    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(yes) => out.push_str(if *yes { "true" } else { "false" }),
            Json::Number(number) => out.push_str(number),
            Json::Text(text) => quote(text, out),
            Json::Items(items) => {
                out.push('[');
                for (n, item) in items.iter().enumerate() {
                    if n > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Json::Fields(fields) => {
                out.push('{');
                for (n, (key, value)) in fields.iter().enumerate() {
                    if n > 0 {
                        out.push(',');
                    }
                    quote(key, out);
                    out.push(':');
                    value.write(out);
                }
                out.push('}');
            }
        }
    }
}

#[cfg(test)]
fn quote(text: &str, out: &mut String) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The JSON `input` is, whole, or None.
fn parse(input: &[u8]) -> Option<Json> {
    let mut reader = Reader { input, at: 0, depth: 0 };
    reader.space();
    let value = reader.value()?;
    reader.space();
    (reader.at == input.len()).then_some(value)
}

struct Reader<'a> {
    input: &'a [u8],
    at: usize,
    depth: usize,
}

impl Reader<'_> {
    fn peek(&self) -> Option<u8> {
        self.input.get(self.at).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.at += 1;
        Some(byte)
    }

    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn word(&mut self, word: &[u8], value: Json) -> Option<Json> {
        let end = self.at.checked_add(word.len())?;
        (self.input.get(self.at..end)? == word).then(|| {
            self.at = end;
            value
        })
    }

    fn value(&mut self) -> Option<Json> {
        match self.peek()? {
            b'{' | b'[' => {
                self.depth += 1;
                if self.depth > DEPTH_MAX {
                    return None;
                }
                let value = if self.peek()? == b'{' { self.fields() } else { self.items() };
                self.depth -= 1;
                value
            }
            b'"' => self.text().map(Json::Text),
            b't' => self.word(b"true", Json::Bool(true)),
            b'f' => self.word(b"false", Json::Bool(false)),
            b'n' => self.word(b"null", Json::Null),
            b'-' | b'0'..=b'9' => {
                let start = self.at;
                while matches!(self.peek(), Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')) {
                    self.at += 1;
                }
                Some(Json::Number(String::from_utf8(self.input[start..self.at].to_vec()).ok()?))
            }
            _ => None,
        }
    }

    fn fields(&mut self) -> Option<Json> {
        self.next();
        let mut fields = Vec::new();
        self.space();
        if self.peek()? == b'}' {
            self.next();
            return Some(Json::Fields(fields));
        }
        loop {
            self.space();
            let key = self.text()?;
            self.space();
            (self.next()? == b':').then_some(())?;
            self.space();
            fields.push((key, self.value()?));
            self.space();
            match self.next()? {
                b',' => {}
                b'}' => return Some(Json::Fields(fields)),
                _ => return None,
            }
        }
    }

    fn items(&mut self) -> Option<Json> {
        self.next();
        let mut items = Vec::new();
        self.space();
        if self.peek()? == b']' {
            self.next();
            return Some(Json::Items(items));
        }
        loop {
            self.space();
            items.push(self.value()?);
            self.space();
            match self.next()? {
                b',' => {}
                b']' => return Some(Json::Items(items)),
                _ => return None,
            }
        }
    }

    fn hex4(&mut self) -> Option<u32> {
        let end = self.at.checked_add(4)?;
        let digits = std::str::from_utf8(self.input.get(self.at..end)?).ok()?;
        let value = u32::from_str_radix(digits, 16).ok().filter(|_| digits.bytes().all(|b| b.is_ascii_hexdigit()))?;
        self.at = end;
        Some(value)
    }

    fn text(&mut self) -> Option<String> {
        (self.next()? == b'"').then_some(())?;
        let mut bytes = Vec::new();
        loop {
            match self.next()? {
                b'"' => return String::from_utf8(bytes).ok(),
                b'\\' => {
                    let c = match self.next()? {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let first = self.hex4()?;
                            let code = if (0xd800..0xdc00).contains(&first) && self.input.get(self.at..self.at + 2) == Some(b"\\u") {
                                self.at += 2;
                                let second = self.hex4()?;
                                if (0xdc00..0xe000).contains(&second) { 0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00) } else { 0xfffd }
                            } else {
                                first
                            };
                            char::from_u32(code).unwrap_or('\u{fffd}')
                        }
                        _ => return None,
                    };
                    let mut buf = [0; 4];
                    bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
                byte if byte < 0x20 => return None,
                byte => bytes.push(byte),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    /// A hook's input as Claude Code 2.1.330 sent it in a box (fixtures/hooks).
    fn fixture(name: &str) -> Json {
        let path = format!("{}/fixtures/hooks/{name}.json", env!("CARGO_MANIFEST_DIR"));
        parse(&std::fs::read(&path).unwrap()).unwrap_or_else(|| panic!("{path} reads"))
    }

    #[test]
    fn each_hook_says_what_the_design_s_table_says() {
        for (name, event) in [
            ("Notification-permission_prompt", Some("permission-prompt")),
            // A question's dialog is a permission prompt too: its kind comes from the hooks before.
            ("Notification-permission_prompt-for-AskUserQuestion", Some("permission-prompt")),
            ("Notification-idle_prompt", Some("turn-ended")),
            ("PreToolUse-AskUserQuestion", Some("question")),
            ("PreToolUse-Bash", Some("working")),
            ("PreToolUse-Bash-subagent", Some("working")),
            ("PreToolUse-Agent", Some("working")),
            ("PostToolUse-Bash-after-terminal-yes", Some("working")),
            ("PostToolUse-AskUserQuestion-answered-at-terminal", Some("working")),
            ("PostToolUse-AskUserQuestion-answered-by-hook-freetext", Some("working")),
            ("PostToolUse-Agent", Some("working")),
            ("Stop", Some("turn-ended")),
            ("Stop-after-block-stop_hook_active", Some("turn-ended")),
            ("UserPromptSubmit", Some("typed")),
            ("UserPromptSubmit-typed-while-Stop-hook-waits", Some("typed")),
            // A background task's end is not the owner typing.
            ("UserPromptSubmit-subagent-task-notification", Some("working")),
            // A permission prompt is told by its Notification: a yes within its 6 seconds, then a
            // long build, is no wait.
            ("PermissionRequest-Bash", None),
            ("PermissionRequest-Bash-subagent", None),
            ("PermissionRequest-AskUserQuestion", None),
            // A sub-agent that returns waits no more.
            ("SubagentStop", Some("working")),
            // Hooks the settings don't name send nothing.
            ("SessionStart", None),
            ("SubagentStart", None),
        ] {
            assert_eq!(said(&fixture(name)).event, event, "{name}");
        }
    }

    #[test]
    fn other_notifications_a_stop_beside_a_running_task_and_input_that_isn_t_json_send_nothing() {
        let notification = |kind: &str| said(&parse(format!(r#"{{"hook_event_name":"Notification","notification_type":"{kind}"}}"#).as_bytes()).unwrap()).event;
        assert_eq!(notification("elicitation_dialog"), Some("needs-input"));
        assert_eq!(notification("agent_needs_input"), Some("needs-input"));
        assert_eq!(notification("auth_success"), None);
        let stop = |tasks: &str| said(&parse(format!(r#"{{"hook_event_name":"Stop","background_tasks":{tasks}}}"#).as_bytes()).unwrap()).event;
        assert_eq!(stop(r#"[{"id":"a","status":"running"}]"#), None);
        assert_eq!(stop(r#"[{"id":"a","status":"completed"}]"#), Some("turn-ended"));
        assert_eq!(stop("[]"), Some("turn-ended"));
        for bad in [&b""[..], b"{", b"[1,]", b"{\"a\":1}x", b"\"\x01\"", b"{\"a\" 1}", b"nul", b"\"\\q\""] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
        let deep = format!("{}{}", "[".repeat(DEPTH_MAX + 1), "]".repeat(DEPTH_MAX + 1));
        assert_eq!(parse(deep.as_bytes()), None, "nested past the limit");
        assert!(parse(format!("{}{}", "[".repeat(DEPTH_MAX), "]".repeat(DEPTH_MAX)).as_bytes()).is_some());
    }

    #[test]
    fn a_session_and_each_of_its_sub_agents_are_told_apart() {
        let main = said(&fixture("PostToolUse-Bash-after-terminal-yes")).tag;
        let same = said(&fixture("PreToolUse-Bash")).tag;
        assert_eq!(main, same, "one session, one tag");
        let parent = said(&fixture("PreToolUse-Agent")).tag;
        let sub = said(&fixture("PermissionRequest-Bash-subagent")).tag;
        assert_ne!(parent, sub, "a sub-agent is a session of its own");
        assert_eq!(sub, said(&fixture("PreToolUse-Bash-subagent")).tag);
        assert_eq!(sub, said(&fixture("SubagentStop")).tag, "its return closes its own wait");
        // A session's end closes the wait of that session, not of its sub-agents.
        let end = said(&parse(br#"{"session_id":"b9d65cd2-f594-409d-a130-eb80345b1e02","hook_event_name":"SessionEnd","reason":"prompt_input_exit"}"#).unwrap());
        assert_eq!((end.event, end.tag), (Some("working"), parent));
        assert_eq!(tag("a", ""), tag("a", ""));
        assert_ne!(tag("ab", ""), tag("a", "b"));
    }

    #[test]
    fn text_is_clipped_to_halti_s_caps_on_character_boundaries() {
        assert_eq!(clip_end("héllo", 2), "h");
        assert_eq!(clip_start("héllo", 4), "llo");
        assert_eq!(clip_end("abc", 10), "abc");
        // The end of the last message is kept.
        let long = format!(r#"{{"hook_event_name":"Stop","last_assistant_message":"{}END"}}"#, "é".repeat(3000));
        let text = said(&parse(long.as_bytes()).unwrap()).text;
        assert!(text.len() <= BODY_MAX + 2 && text.ends_with(b"END"));
        // A question: each with its header, question, several or not, and options.
        let question = said(&fixture("PreToolUse-AskUserQuestion")).text;
        let mut expected = Vec::new();
        push(&mut expected, &fields(&["Color", "Which color?", "0", "Red", "Select red", "Blue", "Select blue"]));
        assert_eq!(question, expected);
        // Many long questions with many long options stay within the whole text's cap.
        let option = format!(r#"{{"label":"{0}","description":"{0}"}}"#, "o".repeat(500));
        let one = format!(r#"{{"question":"{0}","header":"{0}","options":[{1}],"multiSelect":true}}"#, "q".repeat(500), vec![option; 9].join(","));
        let many = format!(r#"{{"hook_event_name":"PreToolUse","tool_name":"AskUserQuestion","tool_input":{{"questions":[{}]}}}}"#, vec![one; 9].join(","));
        let said = said(&parse(many.as_bytes()).unwrap());
        assert!((1..=TEXT_MAX).contains(&said.text.len()), "{}", said.text.len());
    }

    #[test]
    fn json_text_reads_its_escapes_and_writes_back_compact() {
        let read = parse(br#" { "a" : [1, -2.5e3, true, null, "x\"\\\/\n\u00e9\ud83d\ude00\ud800"] } "#).unwrap();
        let mut written = String::new();
        read.write(&mut written);
        assert_eq!(written, "{\"a\":[1,-2.5e3,true,null,\"x\\\"\\\\/\\né😀\u{fffd}\"]}");
        assert_eq!(parse(written.as_bytes()), Some(read));
    }

    #[test]
    fn the_door_is_sent_one_post_with_the_form_and_its_answer_read() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let to = listener.local_addr().unwrap();
        let door = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut got = Vec::new();
            let mut buf = [0; 1024];
            while !got.ends_with(b"\x00\x04done") {
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0, "ended early");
                got.extend_from_slice(&buf[..n]);
            }
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nnobody").unwrap();
            got
        });
        let form = form("turn-ended", &[0xaa; 16], b"done");
        let answer = send(to, &form).unwrap();
        assert!(answer.ends_with(b"nobody"));
        let got = door.join().unwrap();
        let head = format!("POST /ask HTTP/1.1\r\nHost: halti.internal\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", form.len());
        assert_eq!(got, [head.as_bytes(), &form].concat());
        // The form is halti's: the known answer in its src/notices tests.
        let hex: String = form.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "000c68616c74692d61736b2d7631000a7475726e2d656e6465640010aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0004646f6e65");
        // With no door, it gives up in time and says nothing.
        let closed = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        assert!(send(closed, &form).is_err());
    }
}
