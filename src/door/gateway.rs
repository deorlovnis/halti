//! The gateway kind (`names::DOOR_KIND`): plain HTTP/1.1 to halti itself, with keep-alive because Claude Code reuses
//! its connections. Its routes are `/model/...`, the model gateway, and `POST /ask`, where the
//! asker in the box says that its agent waits, or no longer does (`crate::notices`). The box holds a stand-in
//! key; the gateway checks for it, drops the box's own auth headers, adds the real one from the
//! model resource's approved policy and fields, sends the call over TLS to the policy's first
//! host and streams the answer back as it arrives, server-sent events included.
//!
//! The answers are the agent's own conversation, so they aren't masked, but the real key never
//! appears in anything the gateway writes itself.

use std::collections::BTreeMap;
use std::io::{self, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use serde_json::json;
use ureq::http::{self, Response};

use super::http::{self as wire, Head};
use super::{Entry, STANDIN, Shared};
use crate::mask::Masker;
use crate::notices::{ASK_MAX, ASK_PATH, Ask, NOBODY};
use crate::policy::{self, METHODS, Mode};
use crate::requests::{Asked, By};
use crate::source::{self, Hint};

/// Request bodies (a long conversation with images) are read whole, up to this size.
const MAX_BODY: usize = 128 * 1024 * 1024;
/// A connection that sends no request for this long is closed.
const IDLE: Duration = Duration::from_secs(300);
/// The model host has this long to connect, and each wait for its answer or its next bytes
/// can last this long (a model may think a while before the first byte of a plain reply).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const READ_TIMEOUT: Duration = Duration::from_secs(600);
/// Longest path kept in the log.
const MAX_PATH: usize = 200;

/// Headers that belong to one connection, not to the request.
pub(super) const HOP_BY_HOP: [&str; 9] =
    ["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade"];
/// Other headers that aren't passed on: the box's own address and framing (rebuilt for the
/// upstream call), its credentials, and content encodings (the upstream is asked for none).
const DROPPED: [&str; 6] = ["host", "content-length", "expect", "x-api-key", "authorization", "accept-encoding"];

/// The client to the model host. It keeps connections between calls and never follows redirects.
pub fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .max_redirects(0)
        .max_redirects_will_error(false)
        .http_status_as_error(false)
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_per_read(Some(READ_TIMEOUT))
        .build()
        .into()
}

pub fn serve(sh: &Shared, mut reader: BufReader<UnixStream>, mut writer: UnixStream) {
    let _ = writer.set_read_timeout(Some(IDLE));
    while let Ok(true) = exchange(sh, &mut reader, &mut writer) {}
}

/// Why a request was turned away, as the guest and the log hear it.
struct Denied {
    status: u16,
    decision: &'static str,
    message: String,
}

fn denied(status: u16, decision: &'static str, message: impl Into<String>) -> Denied {
    Denied { status, decision, message: message.into() }
}

/// What to send upstream.
struct Plan {
    url: String,
    headers: Vec<(String, String)>,
    /// The key's parts, which must not appear in anything halti says.
    secrets: Vec<String>,
}

/// One request and its response. `Ok(true)` if the connection can serve another.
fn exchange(sh: &Shared, reader: &mut BufReader<UnixStream>, writer: &mut UnixStream) -> io::Result<bool> {
    let head = match wire::read_head(reader) {
        Ok(Some(head)) => head,
        Ok(None) => return Ok(false),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => return close_with(writer, 400, "bad request"),
        Err(e) => return Err(e),
    };
    let Some((method, target, _)) = head.parts() else { return close_with(writer, 400, "bad request") };
    let keep = head.keep_alive();
    if head.header("expect").is_some_and(|v| v.eq_ignore_ascii_case("100-continue")) {
        writer.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
    }
    let max = if target == ASK_PATH { ASK_MAX } else { MAX_BODY };
    let body = match wire::read_body(reader, &head, max) {
        Ok(body) => body,
        Err(e) if e.kind() == io::ErrorKind::FileTooLarge => return close_with(writer, 413, "request body too large"),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => return close_with(writer, 400, "bad request"),
        Err(e) => return Err(e),
    };

    if target == ASK_PATH {
        return ask(sh, writer, &head, method, &body, keep);
    }
    let path: String = target.split('?').next().unwrap_or("").chars().filter(|c| c.is_ascii_graphic()).take(MAX_PATH).collect();
    let up = body.len() as u64;
    let entry = |decision: &str| Entry { method: Some(method.to_string()), path: Some(path.clone()), up, ..Entry::new("model", decision) };
    let response = match plan(sh, &head, method, target).and_then(|plan| send(sh, &plan, method, body)) {
        Ok(response) => response,
        Err(d) => {
            sh.log.write(&Entry { status: Some(d.status), ..entry(d.decision) });
            fail(writer, d.status, &d.message, keep)?;
            return Ok(keep);
        }
    };
    let status = response.status().as_u16();
    let (down, result) = relay(writer, response, method, keep);
    let decision = if result.is_ok() { "allowed" } else { "failed:stream" };
    sh.log.write(&Entry { status: Some(status), down, ..entry(decision) });
    result.map(|()| keep)
}

/// `POST /ask`: what the asker in the box saw. Its event and session tag go to the open workspace
/// that runs the box, if one does, which makes a notice of them that holds neither
/// (`crate::notices`), and it is answered at once, `nobody`: nobody answers from the phone. Not
/// logged: nothing in it leaves the box.
///
/// From a newer asker (`halti-ask-v2`), its text goes there too, and in a run marked away the call
/// is held as a question until it is answered (`crate::questions`): the answer is written on it,
/// and one line logged of it, with no text. A call the asker closes withdraws its question. Any
/// other is answered at once, as above; an older asker's text is dropped as it is read.
///
/// It needs no key, so it takes only what a web page in the box can't send: a browser there may
/// POST to halti.internal with no preflight, but only with a type such as `text/plain`, and it
/// names the page's origin. A call with `Content-Type: application/octet-stream` and no `Origin`
/// is the asker's.
fn ask(sh: &Shared, writer: &mut UnixStream, head: &Head, method: &str, body: &[u8], keep: bool) -> io::Result<bool> {
    let octets = head.header("content-type").is_some_and(|v| v.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/octet-stream"));
    let status = match Ask::parse(body) {
        _ if !method.eq_ignore_ascii_case("POST") => 405,
        _ if head.header("origin").is_some() => 403,
        _ if !octets => 415,
        None => 400,
        Some(ask) => {
            match (&sh.cfg.requests, &ask.text) {
                (Some(asker), Some(text)) => {
                    let peer = writer.try_clone()?;
                    if let Asked::Answered { reply, line } = asker.ask(ask.event, &ask.tag, text, &|| gone(&peer)) {
                        let mut entry = Entry {
                            request: Some(line.id.hex()),
                            question: Some(line.kind.word()),
                            asked: Some(crate::util::hex(&line.hash)),
                            ..Entry::new("question", &format!("answered:{}", line.form.word()))
                        };
                        entry = match &line.by {
                            By::Device(signed) => Entry::signed(Some(line.by.word()), Some(signed), entry),
                            By::Local => Entry { by: Some(line.by.word()), ..entry },
                        };
                        sh.log.write(&entry);
                        wire::respond(writer, 200, "application/octet-stream", &reply, keep)?;
                        return Ok(keep);
                    }
                }
                (Some(asker), None) => asker.tell(ask.event, &ask.tag),
                (None, _) => {}
            }
            200
        }
    };
    let said = if status == 200 { NOBODY } else { "refused" };
    wire::respond(writer, status, "text/plain", said.as_bytes(), keep)?;
    Ok(keep)
}

/// Whether the asker closed its held call: it ended, or Claude Code ended its hook. Looked at
/// without reading or waiting; anything it sent after its call is no sign.
fn gone(stream: &UnixStream) -> bool {
    use std::os::fd::AsRawFd;
    let mut byte = [0u8; 1];
    let read = unsafe { libc::recv(stream.as_raw_fd(), byte.as_mut_ptr().cast(), 1, libc::MSG_PEEK | libc::MSG_DONTWAIT) };
    match read {
        0 => true,
        n if n > 0 => false,
        _ => !matches!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted),
    }
}

/// Decide what the request becomes upstream, or why it is refused. The model resource's policy
/// is loaded for each call, so a change or a revocation takes effect at once.
fn plan(sh: &Shared, head: &Head, method: &str, target: &str) -> Result<Plan, Denied> {
    let Some(rest) = target.strip_prefix("/model/") else {
        return Err(denied(404, "blocked:route", "halti has only /model/... here"));
    };
    if target.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(denied(400, "blocked:bad-request", "bad request target"));
    }
    let Some(model) = &sh.cfg.model else {
        return Err(denied(404, "blocked:no-model", format!("box {} has no model configured", sh.cfg.name)));
    };
    if !has_standin(head) {
        return Err(denied(401, "blocked:no-standin", format!("send {STANDIN} as the key; halti adds the real one")));
    }
    let approved = policy::load(model).map_err(|e| denied(403, "blocked:policy", format!("{e:#}")))?;
    crate::refresh::refresh_due(std::slice::from_ref(model), false, false);
    let fetch = approved.policy.fetch.as_ref().ok_or_else(|| denied(403, "blocked:policy", format!("the policy for {model} has no [fetch] section")))?;
    let method = method.to_ascii_uppercase();
    if !METHODS.contains(&method.as_str()) {
        return Err(denied(405, "blocked:method", format!("method must be one of {}", METHODS.join(", "))));
    }
    // Model calls are POSTs. A resource that asks each time can't serve a conversation.
    if !matches!(method.as_str(), "GET" | "HEAD") && fetch.writes != Mode::Allow {
        let message = format!("the policy for {model} must set writes = \"allow\" in [fetch]: model calls are POST requests");
        return Err(denied(403, "blocked:writes", message));
    }
    let host = fetch.hosts.first().ok_or_else(|| denied(403, "blocked:policy", format!("the policy for {model} lists no hosts")))?;

    let mut secrets = Vec::new();
    let auth = match &fetch.auth {
        Some(template) => {
            let value = policy::fill(template, |field| {
                let source = source::current();
                let value = source.value(model, field).ok_or_else(|| anyhow::anyhow!("{model}/{field} isn't stored ({})", source.hint(Hint::SetValue(model, field))))?;
                secrets.push(value.clone());
                Ok(value)
            });
            Some(value.map_err(|e| denied(502, "failed:key", format!("{e:#}")))?)
        }
        None => None,
    };
    Ok(Plan { url: format!("{}/{rest}", host.trim_end_matches('/')), headers: rewrite_headers(&head.headers, &fetch.auth_header, &fetch.headers, auth.as_deref()), secrets })
}

/// Whether the box sent the stand-in as its key: `x-api-key: STANDIN`, or
/// `Authorization: Bearer STANDIN` for a subscription token.
fn has_standin(head: &Head) -> bool {
    let bearer = |v: &str| match v.split_once(' ') {
        Some((scheme, token)) if scheme.eq_ignore_ascii_case("bearer") => token.trim().to_string(),
        _ => v.trim().to_string(),
    };
    head.header("x-api-key").is_some_and(|v| v.trim() == STANDIN) || head.header("authorization").is_some_and(|v| bearer(v) == STANDIN)
}

/// The headers for the upstream call: the box's, minus hop-by-hop headers, any header the
/// `Connection` header names, its own address and framing, and every credential; then the
/// policy's fixed headers (replacing any of the same name), the real auth header, and a request
/// for uncompressed answers (the gateway doesn't recompress what it streams).
fn rewrite_headers(incoming: &[(String, String)], auth_header: &str, fixed: &BTreeMap<String, String>, auth: Option<&str>) -> Vec<(String, String)> {
    let named: Vec<String> = incoming.iter().filter(|(n, _)| n.eq_ignore_ascii_case("connection")).flat_map(|(_, v)| v.split(',').map(|t| t.trim().to_ascii_lowercase())).collect();
    let mut out: Vec<(String, String)> = incoming
        .iter()
        .filter(|(name, _)| {
            let name = name.to_ascii_lowercase();
            !HOP_BY_HOP.contains(&name.as_str())
                && !DROPPED.contains(&name.as_str())
                && !named.contains(&name)
                && !name.eq_ignore_ascii_case(auth_header)
                && !fixed.keys().any(|k| k.eq_ignore_ascii_case(&name))
        })
        .cloned()
        .collect();
    out.extend(fixed.iter().map(|(n, v)| (n.clone(), v.clone())));
    if let Some(value) = auth {
        out.push((auth_header.to_string(), value.to_string()));
    }
    out.push(("accept-encoding".into(), "identity".into()));
    out
}

/// Make the upstream call. The answer is still unread when this returns.
fn send(sh: &Shared, plan: &Plan, method: &str, body: Vec<u8>) -> Result<Response<ureq::Body>, Denied> {
    let mut request = http::Request::builder().method(method.to_ascii_uppercase().as_str()).uri(plan.url.as_str());
    for (name, value) in &plan.headers {
        request = request.header(name.as_str(), value.as_str());
    }
    let bad = |_| denied(400, "blocked:bad-request", "the request can't be forwarded");
    let result = if body.is_empty() { sh.agent.run(request.body(()).map_err(bad)?) } else { sh.agent.run(request.body(body).map_err(bad)?) };
    result.map_err(|e| {
        let masker = Masker::new(plan.secrets.clone());
        denied(502, "failed:upstream", masker.mask(&format!("halti couldn't get an answer from the model host: {e}")))
    })
}

/// Write the upstream answer to the guest as it arrives, chunked, flushing each piece so
/// events reach the client at once. A failure partway leaves the chunked body unterminated, so
/// the client sees the break. Returns the body bytes written, and how it went.
fn relay(writer: &mut UnixStream, response: Response<ureq::Body>, method: &str, keep: bool) -> (u64, io::Result<()>) {
    let (parts, body) = response.into_parts();
    let status = parts.status.as_u16();
    let bodiless = method.eq_ignore_ascii_case("HEAD") || matches!(status, 204 | 304);
    let mut head = format!("HTTP/1.1 {status} {}\r\n", wire::reason(status)).into_bytes();
    for (name, value) in &parts.headers {
        let name = name.as_str();
        if !HOP_BY_HOP.contains(&name) && !matches!(name, "content-length" | "content-encoding") {
            head.extend_from_slice(format!("{name}: ").as_bytes());
            head.extend_from_slice(value.as_bytes());
            head.extend_from_slice(b"\r\n");
        }
    }
    if !bodiless {
        head.extend_from_slice(b"transfer-encoding: chunked\r\n");
    }
    head.extend_from_slice(if keep { b"connection: keep-alive\r\n\r\n" } else { b"connection: close\r\n\r\n" });
    if let Err(e) = writer.write_all(&head).and_then(|()| writer.flush()) {
        return (0, Err(e));
    }
    if bodiless {
        return (0, Ok(()));
    }
    let (mut body, mut buf, mut total) = (body.into_reader(), [0u8; 16 * 1024], 0u64);
    loop {
        let n = match body.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return (total, Err(e)),
        };
        let mut chunk = format!("{n:x}\r\n").into_bytes();
        chunk.extend_from_slice(&buf[..n]);
        chunk.extend_from_slice(b"\r\n");
        if let Err(e) = writer.write_all(&chunk).and_then(|()| writer.flush()) {
            return (total, Err(e));
        }
        if n == 0 {
            // The "0\r\n\r\n" above is the last chunk with no trailers.
            return (total, Ok(()));
        }
        total += n as u64;
    }
}

/// Answer a request that can't be read on, and end the connection.
fn close_with(writer: &mut UnixStream, status: u16, message: &str) -> io::Result<bool> {
    fail(writer, status, message, false).map(|()| false)
}

/// Answer with an error in the shape the Anthropic API uses, so clients show the message.
fn fail(writer: &mut UnixStream, status: u16, message: &str, keep: bool) -> io::Result<()> {
    let kind = match status {
        400 | 405 => "invalid_request_error",
        401 => "authentication_error",
        403 => "permission_error",
        404 => "not_found_error",
        413 => "request_too_large",
        _ => "api_error",
    };
    let body = json!({ "type": "error", "error": { "type": kind, "message": message } });
    wire::respond(writer, status, "application/json", body.to_string().as_bytes(), keep)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect()
    }

    fn names(headers: &[(String, String)]) -> Vec<String> {
        headers.iter().map(|(n, _)| n.to_ascii_lowercase()).collect()
    }

    fn head(headers: &[(&str, &str)]) -> Head {
        Head { line: "POST /model/v1/messages HTTP/1.1".into(), headers: pairs(headers) }
    }

    #[test]
    fn the_standin_is_accepted_as_an_api_key_or_a_bearer_token() {
        assert!(has_standin(&head(&[("x-api-key", STANDIN)])));
        assert!(has_standin(&head(&[("X-Api-Key", &format!(" {STANDIN} "))])));
        assert!(has_standin(&head(&[("Authorization", &format!("Bearer {STANDIN}"))])));
        assert!(has_standin(&head(&[("authorization", &format!("bearer {STANDIN}"))])));
        assert!(has_standin(&head(&[("authorization", STANDIN)])));
    }

    #[test]
    fn anything_else_as_a_key_is_refused() {
        assert!(!has_standin(&head(&[])));
        assert!(!has_standin(&head(&[("x-api-key", "sk-ant-real")])));
        assert!(!has_standin(&head(&[("authorization", "Bearer sk-ant-oat-real")])));
        assert!(!has_standin(&head(&[("x-api-key", &format!("not-{STANDIN}"))])));
        assert!(!has_standin(&head(&[("authorization", &format!("Basic {STANDIN}"))])));
        assert!(!has_standin(&head(&[("x-other", STANDIN)])));
    }

    #[test]
    fn rewriting_drops_the_boxs_credentials_and_adds_the_real_one() {
        let incoming = pairs(&[
            ("Host", "halti.internal"),
            ("X-Api-Key", STANDIN),
            ("Authorization", &format!("Bearer {STANDIN}")),
            ("anthropic-version", "2023-06-01"),
            ("Content-Type", "application/json"),
            ("Content-Length", "42"),
            ("Accept-Encoding", "gzip, br"),
            ("User-Agent", "claude-cli"),
        ]);
        let out = rewrite_headers(&incoming, "x-api-key", &BTreeMap::new(), Some("sk-real"));
        assert_eq!(
            out,
            pairs(&[
                ("anthropic-version", "2023-06-01"),
                ("Content-Type", "application/json"),
                ("User-Agent", "claude-cli"),
                ("x-api-key", "sk-real"),
                ("accept-encoding", "identity"),
            ])
        );
        assert!(!out.iter().any(|(_, v)| v.contains(STANDIN)));
    }

    #[test]
    fn rewriting_uses_the_policys_auth_header() {
        let incoming = pairs(&[("authorization", &format!("Bearer {STANDIN}")), ("anthropic-beta", "oauth-2025-04-20")]);
        let out = rewrite_headers(&incoming, "Authorization", &BTreeMap::new(), Some("Bearer real-token"));
        assert_eq!(out[0], ("anthropic-beta".to_string(), "oauth-2025-04-20".to_string()));
        assert_eq!(out[1], ("Authorization".to_string(), "Bearer real-token".to_string()));
        assert_eq!(out.iter().filter(|(n, _)| n.eq_ignore_ascii_case("authorization")).count(), 1);
    }

    #[test]
    fn rewriting_drops_hop_by_hop_headers_and_those_the_connection_header_names() {
        let incoming = pairs(&[
            ("Connection", "keep-alive, X-Secret-Hop"),
            ("Keep-Alive", "timeout=5"),
            ("Transfer-Encoding", "chunked"),
            ("TE", "trailers"),
            ("Upgrade", "websocket"),
            ("Proxy-Authorization", "Basic abc"),
            ("Expect", "100-continue"),
            ("x-secret-hop", "1"),
            ("x-keep", "1"),
        ]);
        let out = rewrite_headers(&incoming, "x-api-key", &BTreeMap::new(), None);
        assert_eq!(names(&out), ["x-keep", "accept-encoding"]);
    }

    /// A door whose box an open workspace runs, with that workspace's desk, notices sent at once.
    fn door_of(dir: &std::path::Path, desk: &std::sync::Arc<crate::requests::Desk>) -> Shared {
        let config = super::super::Config {
            name: "acme/dev".into(),
            socket: dir.join("unused.sock"),
            port: None,
            allow: Vec::new(),
            model: None,
            sites: Vec::new(),
            net: super::super::inspect::Net { writes: Mode::Ask, allow_writes: Vec::new(), ask: None },
            log: dir.join("door.log"),
            log_key: [9; 32],
            browser: None,
            ca: None,
            browser_socket: None,
            browser_tokens: Default::default(),
            requests: Some(desk.asker("dev", crate::requests::RunId([7; 8]))),
        };
        Shared::new(config, super::super::addr::Net::system()).unwrap()
    }

    /// Sends `request` on a connection of the gateway kind, and reads until the door closes it.
    fn exchanged(sh: &Shared, request: &[u8]) -> String {
        let (mut guest, door) = UnixStream::pair().unwrap();
        let mut reading = guest.try_clone().unwrap();
        let replied = std::thread::spawn(move || {
            let mut reply = String::new();
            let _ = reading.read_to_string(&mut reply);
            reply
        });
        // Written beside the door, which may answer before it has read it all.
        let request = request.to_vec();
        std::thread::spawn(move || {
            let _ = guest.write_all(&request).and_then(|()| guest.shutdown(std::net::Shutdown::Write));
        });
        serve(sh, BufReader::new(door.try_clone().unwrap()), door);
        replied.join().unwrap()
    }

    /// A call to `/ask` as the asker makes it, with the headers `more` adds.
    fn post_ask_with(body: &[u8], more: &str) -> Vec<u8> {
        [format!("POST /ask HTTP/1.1\r\nHost: halti.internal\r\n{more}Content-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes(), body].concat()
    }

    fn post_ask(body: &[u8]) -> Vec<u8> {
        post_ask_with(body, "Content-Type: application/octet-stream\r\n")
    }

    #[test]
    fn an_ask_is_answered_nobody_at_once_and_reaches_the_desk_without_its_text() {
        let dir = crate::util::TempDir::new("halti-gateway-ask").unwrap();
        let limits = crate::requests::Limits { notice_delay: Duration::ZERO, ..crate::requests::LIMITS };
        let desk = crate::requests::Desk::new("mac-1".into(), "acme".into(), limits, std::sync::Arc::new(Unshown));
        let sh = door_of(&dir.0, &desk);
        let reply = exchanged(&sh, &post_ask(&Ask::bytes(b"turn-ended", b"session-tag", b"PLANTED text")));
        assert!(reply.starts_with("HTTP/1.1 200 OK\r\n") && reply.ends_with("\r\n\r\nnobody"), "{reply}");
        let records = desk.notices();
        assert_eq!(records.len(), 1);
        let notice = crate::notices::Notice::decode(&records[0].0).unwrap();
        assert_eq!((notice.box_name.as_str(), notice.session, notice.kind), ("dev", 1, crate::notices::Kind::TurnEnded));
        assert!(!records[0].0.windows(7).any(|w| w == b"PLANTED" || w == b"session") && records[0].1.is_empty());
        // Working closes it.
        assert!(exchanged(&sh, &post_ask(&Ask::bytes(b"working", b"session-tag", b""))).ends_with("nobody"));
        assert!(desk.notices().is_empty());
        // What isn't the form, or comes by another method, is refused and reaches nothing.
        let text_too_long = post_ask(&Ask::bytes(b"turn-ended", b"t", &[b'x'; crate::notices::TEXT_MAX + 1]));
        for bad in [post_ask(&Ask::bytes(b"waiting", b"t", b"")), post_ask(b"turn-ended"), text_too_long, b"GET /ask HTTP/1.1\r\nConnection: close\r\n\r\n".to_vec()] {
            let reply = exchanged(&sh, &bad);
            assert!(reply.starts_with("HTTP/1.1 400") || reply.starts_with("HTTP/1.1 405"), "{reply}");
        }
        // One longer than the form can be is refused before it is read: the guest may see the
        // connection reset before the answer.
        let long = post_ask(&Ask::bytes(b"turn-ended", b"t", &[b'x'; crate::notices::ASK_MAX]));
        let reply = exchanged(&sh, &long);
        assert!(reply.is_empty() || reply.starts_with("HTTP/1.1 413"), "{reply}");
        assert!(desk.notices().is_empty());
        // A web page in the box can POST with no preflight, but not as the asker does: with a type
        // a page may send, or with none, or naming its origin, it reaches nothing.
        let wait = Ask::bytes(b"turn-ended", b"t", b"");
        for (more, status) in [
            ("", "415"),
            ("Content-Type: text/plain;charset=UTF-8\r\n", "415"),
            ("Content-Type: application/x-www-form-urlencoded\r\n", "415"),
            ("Content-Type: application/octet-stream\r\nOrigin: http://localhost:3000\r\n", "403"),
            ("Origin: null\r\nContent-Type: application/octet-stream\r\n", "403"),
        ] {
            let reply = exchanged(&sh, &post_ask_with(&wait, more));
            assert!(reply.starts_with(&format!("HTTP/1.1 {status}")), "{more}: {reply}");
        }
        assert!(desk.notices().is_empty());
        // A door with no open workspace behind it answers the same, and keeps nothing.
        let alone = Shared::new(super::super::Config { requests: None, ..door_of(&dir.0, &desk).cfg }, super::super::addr::Net::system()).unwrap();
        assert!(exchanged(&alone, &post_ask(&Ask::bytes(b"question", b"t", b""))).ends_with("nobody"));
        assert!(desk.notices().is_empty());
    }

    /// A desk whose questions go to one phone, trusted for acme in a link's folder under `dir`.
    fn asking_desk(dir: &std::path::Path) -> std::sync::Arc<crate::requests::Desk> {
        struct One(halti_core::sealed::AgreementKey, crate::requests::Trusted);
        impl crate::requests::Phones for One {
            fn trusted(&self) -> Vec<(crate::requests::Trusted, Option<halti_core::sealed::AgreementKey>)> {
                vec![(self.1.clone(), Some(self.0))]
            }
            fn machine_key(&self) -> Option<halti_core::sealed::SecretKey> {
                Some(halti_core::sealed::SecretKey::derive(&[1; 32]))
            }
        }
        use rcgen::PublicKeyData;
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let spki = key.subject_public_key_info();
        let trusted =
            crate::requests::Trusted { name: "pixel".into(), key: halti_core::device::DeviceKey::from_spki(&spki).unwrap(), fingerprint: "f".into(), ws: vec!["acme".into()] };
        let _ = dir;
        let limits = crate::requests::Limits { notice_delay: Duration::ZERO, ..crate::requests::LIMITS };
        crate::requests::Desk::with_phones(
            "mac-1".into(),
            "acme".into(),
            limits,
            std::sync::Arc::new(Unshown),
            Box::new(One(halti_core::sealed::SecretKey::derive(&[2; 32]).public(), trusted)),
        )
    }

    #[test]
    fn a_newer_ask_in_a_run_marked_away_is_held_until_answered_and_logged_without_its_text() {
        use crate::questions::{Form, Record};
        let dir = crate::util::TempDir::new("halti-gateway-held").unwrap();
        let desk = asking_desk(&dir.0);
        let sh = door_of(&dir.0, &desk);
        // Not marked away: nobody, at once, as for an older asker.
        let text = crate::fields::join(&[&[0, 0, 0, 0], b"Bash", br#"{"command":"cat SECRET-PLAN"}"#]);
        let reply = exchanged(&sh, &post_ask(&Ask::bytes_v2(b"permit", b"tag", &text)));
        assert!(reply.ends_with("\r\n\r\nnobody"), "{reply}");
        desk.set_away(crate::requests::RunId([7; 8]), Some(crate::requests::now_secs() + 3600));
        // Marked away: the call is held, and the answer given here is written on it.
        let (mut guest, door) = UnixStream::pair().unwrap();
        guest.write_all(&post_ask(&Ask::bytes_v2(b"permit", b"tag", &text))).unwrap();
        let serving = std::thread::spawn(move || serve(&sh, BufReader::new(door.try_clone().unwrap()), door));
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while desk.questions().is_empty() {
            assert!(std::time::Instant::now() < deadline, "never asked");
            std::thread::sleep(Duration::from_millis(10));
        }
        let id = Record::decode(&desk.questions()[0].0).unwrap().id;
        assert_eq!(desk.answer_question_here(id, Form::Yes, b""), crate::questions::Outcome::MaybeUnused);
        let mut reply = Vec::new();
        guest.read_to_end(&mut reply).unwrap();
        serving.join().unwrap();
        let body = crate::questions::reply(Form::Yes, b"");
        assert!(reply.starts_with(b"HTTP/1.1 200 OK\r\n") && reply.ends_with(&body), "{}", String::from_utf8_lossy(&reply));
        // One line is logged of it: who, which question, its kind and the form, and no text.
        let log = std::fs::read_to_string(dir.0.join("door.log")).unwrap();
        let line = log.lines().find(|line| line.contains("\"kind\":\"question\"")).unwrap();
        for word in ["\"decision\":\"answered:yes\"", "\"by\":\"local\"", "\"question\":\"permit\"", &format!("\"request\":\"{}\"", id.hex()), "\"asked\":\""] {
            assert!(line.contains(word), "{word} in {line}");
        }
        assert!(!log.contains("SECRET") && !log.contains("npm") && !log.contains("Bash"), "{log}");
    }

    #[test]
    fn a_held_ask_the_asker_closes_is_withdrawn() {
        let dir = crate::util::TempDir::new("halti-gateway-gone").unwrap();
        let desk = asking_desk(&dir.0);
        let sh = door_of(&dir.0, &desk);
        desk.set_away(crate::requests::RunId([7; 8]), Some(crate::requests::now_secs() + 3600));
        let text = crate::fields::join(&[&[0, 0, 0, 0], b"done"]);
        let (mut guest, door) = UnixStream::pair().unwrap();
        guest.write_all(&post_ask(&Ask::bytes_v2(b"turn-ended", b"tag", &text))).unwrap();
        let serving = std::thread::spawn(move || serve(&sh, BufReader::new(door.try_clone().unwrap()), door));
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while desk.questions().is_empty() {
            assert!(std::time::Instant::now() < deadline, "never asked");
            std::thread::sleep(Duration::from_millis(10));
        }
        // Claude Code ends the hook: its call closes, and the question goes.
        drop(guest);
        serving.join().unwrap();
        assert!(desk.questions().is_empty());
    }

    struct Unshown;

    impl crate::requests::Prompt for Unshown {
        fn ask(&self, _reason: &str, _withdrawn: &dyn Fn() -> bool) -> crate::requests::Prompted {
            crate::requests::Prompted::Unshown
        }
    }

    #[test]
    fn rewriting_lets_the_policys_fixed_headers_win_and_adds_no_auth_without_one() {
        let incoming = pairs(&[("anthropic-version", "1999-01-01"), ("X-Client", "mine")]);
        let fixed = BTreeMap::from([("Anthropic-Version".to_string(), "2023-06-01".to_string())]);
        let out = rewrite_headers(&incoming, "x-api-key", &fixed, None);
        assert_eq!(out, pairs(&[("X-Client", "mine"), ("Anthropic-Version", "2023-06-01"), ("accept-encoding", "identity")]));
    }
}
