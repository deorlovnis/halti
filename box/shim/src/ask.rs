//! `ask`: the asker. Claude Code's hooks run it (the image's managed settings, which name it for
//! each event below); it reads the hook's JSON on stdin and tells halti, at `POST /ask` on
//! halti.internal, whether the agent now waits for its owner, and what kind of wait it is.
//!
//! | Hook | Sent |
//! |---|---|
//! | Notification `permission_prompt` | `permission-prompt` |
//! | Notification `idle_prompt` | `turn-ended` |
//! | Notification `elicitation_dialog`, `agent_needs_input` | `needs-input` |
//! | PermissionRequest | `permit`, but for AskUserQuestion, whose question came before |
//! | PreToolUse | `question` for AskUserQuestion, else `working` |
//! | Stop | `turn-ended`, or nothing while a background task runs |
//! | UserPromptSubmit | `typed`, or `working` for a background task's notification |
//! | PostToolUse, PermissionDenied | `working` |
//! | SubagentStop, SessionEnd | `working`: the sub-agent or the session is gone |
//!
//! Anything else, or input that isn't JSON, sends nothing.
//!
//! `permit`, `question` and `turn-ended` from PermissionRequest, PreToolUse and Stop are held in a
//! run its owner marked away, until it is answered from a phone or with `halti requests`
//! (halti's src/questions.rs), and the hook's limit in the settings covers that wait. halti says
//! at once that it holds the call (`HTTP/1.1 102 Processing`, then the answer when it comes); a call
//! it neither answers nor holds within 5 seconds is given up, as every other call is, so a hung
//! host never holds a hook in a run not marked away. The answer
//! becomes the hook's output on stdout, in one of three fixed shapes:
//!
//! - PermissionRequest: `decision.behavior` `allow`, or `deny` with the reason as `message`. Never
//!   `updatedInput` or `updatedPermissions`: the phone edits no command and grants no "always".
//! - PreToolUse on AskUserQuestion: `permissionDecision: "allow"`, and `updatedInput` the tool's
//!   input as it came with `answers`, each keyed by its question's own text: the label of the
//!   option taken (several joined by ", "), or the text typed in its place.
//! - Stop: `decision: "block"` with the typed text as `reason`, behind fixed words.
//!
//! Otherwise halti answers at once, `nobody`, and it ends 0 with no output, so that Claude Code
//! goes on as if there were no hook. So does an answer that doesn't fit the hook. It always ends 0.
//!
//! A permission prompt's notice comes from its Notification, 6 seconds after the dialog opens, and
//! not if it was answered by then. After a yes nothing is heard until the tool ends: a long build
//! just allowed would be told as a wait.
//!
//! What is sent is one fixed form, fields each after its length in two bytes big-endian: the label
//! `halti-ask-v2`, the event, a session tag (16 bytes made from the hook's `session_id` and, for a
//! sub-agent, its `agent_id`, so each is a session of its own), and the text the hook showed,
//! clipped to halti's caps, with how many bytes were left out. halti keeps neither the tag nor the
//! text in what it tells the phone of a notice. The host's side is halti's src/notices.rs.
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
const LABEL: &[u8] = b"halti-ask-v2";
/// The first field of an answer, in place of `nobody`.
const REPLY_LABEL: &[u8] = b"halti-reply-v1";
/// How long the door has to take the call and answer it, or say that it holds it.
const WAIT: Duration = Duration::from_secs(5);
/// What the door says first of a call it holds as a question, before the answer: from then on the
/// asker waits for the answer as long as the hook may.
const HELD: &[u8] = b"HTTP/1.1 102 Processing\r\n\r\n";
/// The most of the hook's input read; longer input sends nothing.
const INPUT_MAX: u64 = 16 * 1024 * 1024;
/// The most of the door's answer read.
const ANSWER_MAX: u64 = 16 * 1024;
/// halti's caps: a tool's name or a header, a tool's input or the end of a message, a question, an
/// option's label and description, how many questions and options, and the whole text.
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
/// What the agent reads before the text its owner typed to a stopped agent. Not a credential: any
/// text the agent reads could say the same.
const TYPED_WORDS: &str = "Your owner replied from their phone: ";
/// What a permission prompt refused from the phone tells the agent.
const REFUSED_WORDS: &str = "Your owner refused this from their phone.";

/// Reads the hook's input, tells halti, prints the answer if there is one, and ends 0.
pub fn main() -> ! {
    let mut input = Vec::new();
    let read = io::stdin().take(INPUT_MAX + 1).read_to_end(&mut input);
    let hook = match read {
        Ok(_) if input.len() as u64 <= INPUT_MAX => parse(&input),
        _ => None,
    };
    if let Some(hook) = hook
        && let Said { event: Some(event), tag, text } = said(&hook)
    {
        let held = holds(&hook);
        if let Ok(answer) = send(SocketAddr::from(DOOR), &form(event, &tag, &text), held)
            && let Some(output) = output(&hook, &answer)
        {
            let mut out = io::stdout().lock();
            let _ = out.write_all(output.as_bytes()).and_then(|()| out.flush());
        }
    }
    std::process::exit(0)
}

/// Whether halti may hold the call of the hook whose input is `hook`, as a question: those of
/// PermissionRequest, PreToolUse on AskUserQuestion, and Stop. Their limit in the settings covers
/// a question's life; every other hook's call is answered at once.
fn holds(hook: &Json) -> bool {
    let text = |field: &str| hook.get(field).and_then(Json::text).unwrap_or("");
    matches!((text("hook_event_name"), text("tool_name")), ("PermissionRequest" | "Stop", _) | ("PreToolUse", "AskUserQuestion"))
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
        // An AskUserQuestion dialog is a permission prompt too; its question was asked before it.
        "PermissionRequest" if tool == "AskUserQuestion" => (None, Vec::new()),
        "PermissionRequest" => (Some("permit"), permit(tool, hook.get("tool_input"))),
        "PreToolUse" if tool == "AskUserQuestion" => (Some("question"), questions(hook.get("tool_input"))),
        "PreToolUse" | "PostToolUse" | "PermissionDenied" | "SubagentStop" | "SessionEnd" => (Some("working"), Vec::new()),
        "Stop" if background_runs(hook) => (None, Vec::new()),
        "Stop" => {
            let message = text("last_assistant_message");
            let kept = clip_start(message, BODY_MAX);
            (Some("turn-ended"), with_left_out(message.len() - kept.len(), &[kept.as_bytes()]))
        }
        "UserPromptSubmit" if text("prompt").starts_with("<task-notification>") => (Some("working"), Vec::new()),
        "UserPromptSubmit" => (Some("typed"), Vec::new()),
        _ => (None, Vec::new()),
    };
    let text = if body.len() > TEXT_MAX { Vec::new() } else { body };
    Said { event, tag, text }
}

/// The fields of a question's text: how many bytes were left out, four bytes big-endian, then
/// `parts`.
fn with_left_out(left_out: usize, parts: &[&[u8]]) -> Vec<u8> {
    let mut bytes = Vec::new();
    push(&mut bytes, &u32::try_from(left_out).unwrap_or(u32::MAX).to_be_bytes());
    for part in parts {
        push(&mut bytes, part);
    }
    bytes
}

/// A permission prompt's text: the tool's name, and its input as compact JSON, cut at its end.
fn permit(tool: &str, input: Option<&Json>) -> Vec<u8> {
    let mut written = String::new();
    if let Some(input) = input {
        input.write(&mut written);
    }
    let (name, input) = (clip_end(tool, NAME_MAX), clip_end(&written, BODY_MAX));
    with_left_out(tool.len() - name.len() + written.len() - input.len(), &[name.as_bytes(), input.as_bytes()])
}

/// Whether a background task of the session still runs.
fn background_runs(hook: &Json) -> bool {
    let tasks = hook.get("background_tasks").and_then(Json::items).unwrap_or_default();
    tasks.iter().any(|task| task.get("status").and_then(Json::text) == Some("running"))
}

/// A question's text: how many bytes were left out, then up to four questions, each one field: its
/// header, its question, whether several options may be taken, then up to four options, each its
/// label and description.
fn questions(input: Option<&Json>) -> Vec<u8> {
    let asked = input.and_then(|input| input.get("questions")).and_then(Json::items).unwrap_or_default();
    let left_out = std::cell::Cell::new(0);
    let clip = |text: &str, max: usize| {
        let kept = clip_end(text, max);
        left_out.set(left_out.get() + text.len() - kept.len());
        kept.to_string()
    };
    let mut each = Vec::new();
    for question in asked.iter().take(QUESTIONS_MAX) {
        let field = |name: &str| question.get(name).and_then(Json::text).unwrap_or("");
        let several = if question.get("multiSelect") == Some(&Json::Bool(true)) { "1" } else { "0" };
        let mut parts = vec![clip(field("header"), NAME_MAX), clip(field("question"), QUESTION_MAX), several.to_string()];
        let options = question.get("options").and_then(Json::items).unwrap_or_default();
        for option in options.iter().take(OPTIONS_MAX) {
            let field = |name: &str| option.get(name).and_then(Json::text).unwrap_or("");
            parts.push(clip(field("label"), LABEL_MAX));
            parts.push(clip(field("description"), DESCRIPTION_MAX));
        }
        for option in options.iter().skip(OPTIONS_MAX) {
            let field = |name: &str| option.get(name).and_then(Json::text).unwrap_or("");
            left_out.set(left_out.get() + field("label").len() + field("description").len());
        }
        each.push(fields(&parts.iter().map(String::as_str).collect::<Vec<_>>()));
    }
    for question in asked.iter().skip(QUESTIONS_MAX) {
        left_out.set(left_out.get() + question.get("question").and_then(Json::text).unwrap_or("").len());
    }
    with_left_out(left_out.get(), &each.iter().map(Vec::as_slice).collect::<Vec<_>>())
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

/// The fields `bytes` is a run of, each without its length; None if the last one is cut short.
fn split(bytes: &[u8]) -> Option<Vec<&[u8]>> {
    let mut out = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let (length, after) = rest.split_first_chunk::<2>()?;
        let (field, after) = after.split_at_checked(usize::from(u16::from_be_bytes(*length)))?;
        out.push(field);
        rest = after;
    }
    Some(out)
}

/// What is sent for `event`.
fn form(event: &str, tag: &[u8], text: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for field in [LABEL, event.as_bytes(), tag, text] {
        push(&mut bytes, field);
    }
    bytes
}

/// Sends `form` to the door at `to`, and reads the body of its answer. A call that may be `held`
/// waits for it as long as Claude Code lets the hook run, once the door says it holds it; until
/// then, and for any other call, each read waits `WAIT` at most.
fn send(to: SocketAddr, form: &[u8], held: bool) -> io::Result<Vec<u8>> {
    let mut door = TcpStream::connect_timeout(&to, WAIT)?;
    door.set_read_timeout(Some(WAIT))?;
    door.set_write_timeout(Some(WAIT))?;
    let head = format!("POST {PATH} HTTP/1.1\r\nHost: halti.internal\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", form.len());
    door.write_all(&[head.as_bytes(), form].concat())?;
    let mut answer = Vec::new();
    (&door).take(HELD.len() as u64).read_to_end(&mut answer)?;
    // Only a call the door holds as a question waits longer than WAIT, and only one that may be
    // held: its hook's limit covers that wait.
    if held && answer == HELD {
        answer.clear();
        door.set_read_timeout(None)?;
    }
    door.take(ANSWER_MAX).read_to_end(&mut answer)?;
    let at = answer.windows(4).position(|w| w == b"\r\n\r\n").ok_or(io::ErrorKind::InvalidData)?;
    if !answer.starts_with(b"HTTP/1.1 200 ") {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(answer.split_off(at + 4))
}

/// One question's part of an answer: the options taken, by number from 1, or text typed in place.
#[derive(Debug, PartialEq)]
enum Pick {
    Options(Vec<u8>),
    Text(String),
}

/// The hook's output for `answer`, the body halti answered with, if it is an answer that fits the
/// hook whose input is `hook`: None for `nobody`, and for anything else.
fn output(hook: &Json, answer: &[u8]) -> Option<String> {
    let [label, form, content] = split(answer)?[..] else { return None };
    if label != REPLY_LABEL {
        return None;
    }
    let text = |content: &[u8]| String::from_utf8(content.to_vec()).ok();
    let event = hook.get("hook_event_name").and_then(Json::text)?;
    let tool = hook.get("tool_name").and_then(Json::text).unwrap_or("");
    let value = match (event, form) {
        ("PermissionRequest", b"yes") if content.is_empty() && tool != "AskUserQuestion" => permission(Json::Fields(vec![field("behavior", Json::Text("allow".into()))])),
        ("PermissionRequest", b"no") if tool != "AskUserQuestion" => {
            let reason = text(content)?;
            let message = if reason.is_empty() { REFUSED_WORDS.to_string() } else { format!("{REFUSED_WORDS} {reason}") };
            permission(Json::Fields(vec![field("behavior", Json::Text("deny".into())), field("message", Json::Text(message))]))
        }
        ("PreToolUse", b"options") if tool == "AskUserQuestion" => choice(hook.get("tool_input")?, content)?,
        ("Stop", b"text") if !content.is_empty() => {
            Json::Fields(vec![field("decision", Json::Text("block".into())), field("reason", Json::Text(format!("{TYPED_WORDS}{}", text(content)?)))])
        }
        _ => return None,
    };
    let mut out = String::new();
    value.write(&mut out);
    Some(out)
}

fn field(name: &str, value: Json) -> (String, Json) {
    (name.to_string(), value)
}

/// A PermissionRequest hook's output with this decision, and nothing else.
fn permission(decision: Json) -> Json {
    let specific = Json::Fields(vec![field("hookEventName", Json::Text("PermissionRequest".into())), field("decision", decision)]);
    Json::Fields(vec![field("hookSpecificOutput", specific)])
}

/// The PreToolUse output that answers AskUserQuestion: its input as it came, with `answers` for
/// each question answered, keyed by the question's own text. None if the content doesn't fit it.
fn choice(input: &Json, content: &[u8]) -> Option<Json> {
    let asked = input.get("questions").and_then(Json::items)?;
    let parts = split(content)?;
    if parts.len() != asked.len().min(QUESTIONS_MAX) * 2 {
        return None;
    }
    let mut answers = Vec::new();
    for (question, pair) in asked.iter().zip(parts.chunks(2)) {
        let pick = match (pair[0], pair[1]) {
            (numbers, b"") if !numbers.is_empty() => Pick::Options(numbers.to_vec()),
            (b"", typed) if !typed.is_empty() => Pick::Text(String::from_utf8(typed.to_vec()).ok()?),
            _ => return None,
        };
        let text = question.get("question").and_then(Json::text)?;
        let said = match pick {
            Pick::Text(typed) => typed,
            Pick::Options(numbers) => {
                let options = question.get("options").and_then(Json::items)?;
                let several = question.get("multiSelect") == Some(&Json::Bool(true));
                if numbers.len() > 1 && !several {
                    return None;
                }
                let labels =
                    numbers.iter().map(|n| options.iter().take(OPTIONS_MAX).nth(usize::from(*n).checked_sub(1)?)?.get("label").and_then(Json::text)).collect::<Option<Vec<_>>>()?;
                labels.join(", ")
            }
        };
        answers.push(field(text, Json::Text(said)));
    }
    let Json::Fields(input) = input else { return None };
    let mut updated: Vec<(String, Json)> = input.iter().filter(|(name, _)| name != "answers").cloned().collect();
    updated.push(field("answers", Json::Fields(answers)));
    let specific = Json::Fields(vec![
        field("hookEventName", Json::Text("PreToolUse".into())),
        field("permissionDecision", Json::Text("allow".into())),
        field("updatedInput", Json::Fields(updated)),
    ]);
    Some(Json::Fields(vec![field("hookSpecificOutput", specific)]))
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

    /// Writes it as compact JSON.
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

/// `text` as a JSON string: quotes, backslashes and every control character escaped, and the line
/// and paragraph separators, which some JavaScript reads as line ends.
fn quote(text: &str, out: &mut String) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 || c == '\u{7f}' || c == '\u{2028}' || c == '\u{2029}' => out.push_str(&format!("\\u{:04x}", c as u32)),
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
            // A permission prompt's notice comes from its Notification; its dialog opening is a
            // question, which halti holds only in a run marked away.
            ("PermissionRequest-Bash", Some("permit")),
            ("PermissionRequest-Bash-subagent", Some("permit")),
            // An AskUserQuestion dialog is a permission prompt too: its question came before it.
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
    fn only_the_hooks_whose_limit_covers_a_question_wait_for_one() {
        for (name, held) in [
            ("PermissionRequest-Bash", true),
            ("PermissionRequest-Bash-subagent", true),
            ("PreToolUse-AskUserQuestion", true),
            ("Stop", true),
            ("PreToolUse-Bash", false),
            ("Notification-idle_prompt", false),
            ("Notification-permission_prompt", false),
            ("PostToolUse-Bash-after-terminal-yes", false),
            ("UserPromptSubmit", false),
        ] {
            assert_eq!(holds(&fixture(name)), held, "{name}");
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
        // The end of the last message is kept, and how much was left out said first.
        let long = format!(r#"{{"hook_event_name":"Stop","last_assistant_message":"{}END"}}"#, "é".repeat(3000));
        let text = said(&parse(long.as_bytes()).unwrap()).text;
        let parts = split(&text).unwrap();
        assert!(parts[1].len() <= BODY_MAX && parts[1].ends_with(b"END"));
        assert_eq!(u32::from_be_bytes(parts[0].try_into().unwrap()) as usize, 6003 - parts[1].len());
        // A question: how much was left out, then each with its header, question, several or not,
        // and options.
        let question = said(&fixture("PreToolUse-AskUserQuestion")).text;
        let mut expected = Vec::new();
        push(&mut expected, &[0, 0, 0, 0]);
        push(&mut expected, &fields(&["Color", "Which color?", "0", "Red", "Select red", "Blue", "Select blue"]));
        assert_eq!(question, expected);
        // A permission prompt: its tool, and its input as the hook gave it, in compact JSON.
        let permit = said(&fixture("PermissionRequest-Bash")).text;
        let mut expected = Vec::new();
        push(&mut expected, &[0, 0, 0, 0]);
        push(&mut expected, b"Bash");
        push(&mut expected, br#"{"command":"mkdir made_by_bash","description":"Create directory made_by_bash"}"#);
        assert_eq!(permit, expected);
        let huge = format!(r#"{{"hook_event_name":"PermissionRequest","tool_name":"{}","tool_input":{{"command":"{}"}}}}"#, "T".repeat(100), "x".repeat(5000));
        let parts = split(&said(&parse(huge.as_bytes()).unwrap()).text).unwrap().iter().map(|part| part.to_vec()).collect::<Vec<_>>();
        assert_eq!((parts[1].len(), parts[2].len()), (NAME_MAX, BODY_MAX), "cut to the caps");
        assert_eq!(u32::from_be_bytes(parts[0].clone().try_into().unwrap()), 20 + 5000 + 14 - 2000, "and what was cut said");
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
    fn the_door_is_sent_one_post_with_the_form_and_the_body_of_its_answer_read() {
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
        let answer = send(to, &form, false).unwrap();
        assert_eq!(answer, b"nobody");
        let got = door.join().unwrap();
        let head = format!("POST /ask HTTP/1.1\r\nHost: halti.internal\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", form.len());
        assert_eq!(got, [head.as_bytes(), &form].concat());
        // The form is halti's: the known answer in its src/notices tests.
        let hex: String = form.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "000c68616c74692d61736b2d7632000a7475726e2d656e6465640010aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0004646f6e65");
        // With no door, it gives up in time and says nothing.
        let closed = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        assert!(send(closed, &form, true).is_err());
    }

    #[test]
    fn a_call_waits_past_five_seconds_only_once_the_door_says_it_holds_it() {
        // A door that answers late: after it said it holds the call, or with no word before.
        let door = |says_held: bool| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let to = listener.local_addr().unwrap();
            thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let (mut got, mut buf) = (Vec::new(), [0; 1024]);
                while !got.ends_with(b"\x00\x04done") {
                    let n = stream.read(&mut buf).unwrap();
                    assert!(n > 0, "ended early");
                    got.extend_from_slice(&buf[..n]);
                }
                if says_held {
                    stream.write_all(HELD).unwrap();
                }
                thread::sleep(WAIT + Duration::from_secs(1));
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nnobody");
            });
            to
        };
        let form = form("turn-ended", &[0xaa; 16], b"done");
        let (held, silent, unheld) = (door(true), door(false), door(true));
        let calls = [(held, true), (silent, true), (unheld, false)].map(|(to, may)| {
            let form = form.clone();
            thread::spawn(move || {
                let started = std::time::Instant::now();
                (send(to, &form, may).ok(), started.elapsed())
            })
        });
        let [held, silent, unheld] = calls.map(|call| call.join().unwrap());
        assert_eq!(held.0.as_deref(), Some(&b"nobody"[..]), "held: the answer comes");
        // A door that says nothing in time is given up on, even for a hook that may be held: a
        // hung host never holds Claude Code up.
        assert_eq!(silent.0, None);
        assert!(silent.1 < WAIT + Duration::from_millis(900), "{:?}", silent.1);
        // A hook that may not be held never waits longer, whatever the door says.
        assert_eq!(unheld.0, None);
    }

    /// What halti tells a held asker for `form` and `content`.
    fn reply(form: &str, content: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for field in [REPLY_LABEL, form.as_bytes(), content] {
            push(&mut bytes, field);
        }
        bytes
    }

    fn picks(parts: &[(&[u8], &str)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (numbers, text) in parts {
            push(&mut bytes, numbers);
            push(&mut bytes, text.as_bytes());
        }
        bytes
    }

    #[test]
    fn a_yes_or_a_no_to_a_permission_prompt_is_its_decision_and_nothing_more() {
        let hook = fixture("PermissionRequest-Bash");
        assert_eq!(output(&hook, &reply("yes", b"")).unwrap(), r#"{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}"#);
        assert_eq!(
            output(&hook, &reply("no", b"")).unwrap(),
            r#"{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"Your owner refused this from their phone."}}}"#
        );
        let denied = output(&hook, &reply("no", "not \"now\"\u{2028}\x1b[2J".as_bytes())).unwrap();
        assert_eq!(
            denied,
            r#"{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"Your owner refused this from their phone. not \"now\"\u2028\u001b[2J"}}}"#
        );
        // Whatever the answer, the output never edits the command or grants "always".
        let sub = fixture("PermissionRequest-Bash-subagent");
        for hook in [&hook, &sub] {
            for answer in [reply("yes", b""), reply("no", b"x"), reply("no", br#"{"updatedInput":{}}"#), reply("options", &picks(&[(&[1], "")])), reply("text", b"go")] {
                if let Some(out) = output(hook, &answer) {
                    assert!(!out.contains("updatedInput\"") && !out.contains("updatedPermissions") && !out.contains("permissionDecision"), "{out}");
                    assert!(parse(out.as_bytes()).is_some());
                }
            }
        }
        // A yes with content, or a form a permission prompt doesn't take, is no answer.
        assert_eq!(output(&hook, &reply("yes", b"x")), None);
        assert_eq!(output(&hook, &reply("options", &picks(&[(&[1], "")]))), None);
        assert_eq!(output(&hook, &reply("text", b"go")), None);
        assert_eq!(output(&fixture("PermissionRequest-AskUserQuestion"), &reply("yes", b"")), None, "a question's dialog is answered by its question");
    }

    #[test]
    fn a_choice_is_answered_with_the_input_as_it_came_and_answers_keyed_by_each_question() {
        let hook = fixture("PreToolUse-AskUserQuestion");
        let input = r#""updatedInput":{"questions":[{"question":"Which color?","header":"Color","options":[{"label":"Red","description":"Select red"},{"label":"Blue","description":"Select blue"}],"multiSelect":false}]"#;
        let head = r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","#;
        assert_eq!(output(&hook, &reply("options", &picks(&[(&[2], "")]))).unwrap(), format!(r#"{head}{input},"answers":{{"Which color?":"Blue"}}}}}}}}"#));
        assert_eq!(
            output(&hook, &reply("options", &picks(&[(&[], "Green, but only on Tuesdays")]))).unwrap(),
            format!(r#"{head}{input},"answers":{{"Which color?":"Green, but only on Tuesdays"}}}}}}}}"#)
        );
        // An option it doesn't offer, two where one is taken, none, both, or another count of
        // questions, is no answer: Claude Code shows its own dialog.
        for content in
            [picks(&[(&[3], "")]), picks(&[(&[0], "")]), picks(&[(&[1, 2], "")]), picks(&[(&[], "")]), picks(&[(&[1], "x")]), picks(&[(&[1], ""), (&[1], "")]), Vec::new()]
        {
            assert_eq!(output(&hook, &reply("options", &content)), None, "{content:?}");
        }
        for form in ["yes", "no", "text", "stopped"] {
            assert_eq!(output(&hook, &reply(form, b"")), None, "{form}");
        }
        // Several options where the question takes several, each by its own full label, and the
        // key is the question's whole text, however long.
        let long = "q".repeat(500);
        let several = parse(format!(r#"{{"hook_event_name":"PreToolUse","tool_name":"AskUserQuestion","tool_input":{{"questions":[{{"question":"{long}","header":"H","options":[{{"label":"A"}},{{"label":"B"}},{{"label":"C"}}],"multiSelect":true}}]}}}}"#).as_bytes()).unwrap();
        let out = output(&several, &reply("options", &picks(&[(&[1, 3], "")]))).unwrap();
        assert!(out.ends_with(&format!(r#""answers":{{"{long}":"A, C"}}}}}}}}"#)), "{out}");
    }

    #[test]
    fn text_to_a_stopped_agent_comes_behind_the_fixed_words_and_leave_it_stopped_is_no_answer() {
        let hook = fixture("Stop");
        assert_eq!(output(&hook, &reply("text", b"run the tests")).unwrap(), r#"{"decision":"block","reason":"Your owner replied from their phone: run the tests"}"#);
        assert_eq!(output(&hook, &reply("stopped", b"")), None);
        assert_eq!(output(&hook, &reply("text", b"")), None);
        assert_eq!(output(&hook, &reply("yes", b"")), None);
        assert_eq!(output(&hook, &reply("text", &[0xff])), None, "not UTF-8");
        // Nobody, and anything that isn't an answer, prints nothing.
        for answer in [&b"nobody"[..], b"", b"\x00\x0ehalti-reply-v1", &reply("text", b"x")[..20]] {
            assert_eq!(output(&hook, answer), None, "{answer:?}");
        }
        let mut other = Vec::new();
        for field in [&b"halti-reply-v2"[..], b"text", b"x"] {
            push(&mut other, field);
        }
        assert_eq!(output(&hook, &other), None);
    }
}
