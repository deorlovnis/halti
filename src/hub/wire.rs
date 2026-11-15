//! What crosses the hub's listener: everything a phone app or a machine needs to talk to
//! `halti hub serve`, written so that a client can be built from this text alone. Each signed byte
//! string has a known answer in this file's tests.
//!
//! # Transport
//!
//! - TCP to the address in the pairing string, then TLS 1.3. No other TLS version is offered. ALPN
//!   is `http/1.1` if the client sends one; HTTP/2 is never spoken.
//! - The hub's certificate is self-signed and names `halti-hub`. A client checks nothing in it but
//!   its key: the SHA-256 of the certificate's SubjectPublicKeyInfo, as DER, must equal the pin from
//!   the pairing string, all 32 bytes. Name, dates, issuer and chain are not checked; the pin
//!   replaces all of them, so a client also turns its host name check off. The TLS library must
//!   still check the handshake's signature with that key (TLS 1.3 CertificateVerify): a server that
//!   shows the right certificate without its private key must fail.
//! - HTTP/1.1, one request per connection. A path is matched exactly: a query string makes it
//!   another path. `Host` and a request's `Content-Type` are not looked at; a body is JSON, and a
//!   call that takes "no body" takes none or an empty one. Every reply has `Connection: close`,
//!   `Content-Type: application/json`, `Cache-Control: no-store` and a `Content-Length`, and the hub
//!   closes the connection after it.
//! - The whole request, head and body, must arrive within 10 seconds of the connection. The head
//!   (request line and headers) may be at most 8 KiB, the body at most 4 KiB, sent with
//!   `Content-Length` (chunked is read too, within the same limit). A request that is slower, a
//!   head that is longer or malformed, and a TLS handshake that fails get no reply: the connection
//!   is closed. A head is malformed when its request line isn't exactly `METHOD TARGET
//!   HTTP/VERSION`, one space between each, or a header line has no `:` or a name that isn't an
//!   HTTP token. A body over 4 KiB is answered `413 too-large`.
//! - At most 64 connections at once, and 8 from one address: an IPv4 address, or for IPv6 the first
//!   64 bits of the address. An IPv4 address that reaches the hub as IPv6 (`::ffff:a.b.c.d`) counts
//!   as itself. One more is closed as soon as it is accepted, before TLS.
//! - Every request with a token is checked against the hub's table before anything else is done.
//!
//! # Encodings
//!
//! - **Bytes** in a JSON body are lowercase hex, two characters per byte. Upper case is refused.
//! - **Times** are RFC 3339 in UTC with whole seconds, `2026-12-15T10:00:00Z`, by the hub's clock.
//! - **Names.** A device's or a machine's name is 1 to 32 bytes of `a-z`, `0-9`, `-` and `_`,
//!   starting with a letter or a digit. A workspace's name is 1 to 32 bytes of `a-z`, `0-9` and
//!   `-`, starting with a letter or a digit.
//! - **A public key** is a P-256 key's SubjectPublicKeyInfo in DER, with the named curve and the
//!   point uncompressed: exactly 91 bytes, the 26 bytes
//!   `3059301306072a8648ce3d020106082a8648ce3d030107034200`, then `04`, x (32) and y (32). This is
//!   what Android's `PublicKey.getEncoded()` gives for a P-256 key. Any other encoding is refused.
//! - **A signature** is ECDSA over P-256 with SHA-256 of the signed bytes, as strict DER
//!   `SEQUENCE { r INTEGER, s INTEGER }`, at most 72 bytes: what Android's
//!   `Signature.getInstance("SHA256withECDSA")` gives. Either s of a pair is accepted.
//! - **Signed bytes** are a run of fields, each a 2-byte big-endian length and then that many bytes,
//!   in the order listed, nothing before the first or after the last. The first field is always the
//!   label, in ASCII. A field that is a name, a push address or a label is its ASCII bytes. Example:
//!   the fields `ab` and the empty string are `0002 6162 0000`.
//! - **A fingerprint** is the SHA-256 of a signing key's 91 bytes. People compare its first 10
//!   bytes, shown as 5 groups of 4 lowercase hex characters with a space between:
//!   `5a7a 78cc a4a0 f420 d9bc`.
//! - **A token** is the client's own: 32 bytes from a secure random source, written as lowercase hex
//!   behind a prefix, `halti_dev_` for a phone and `halti_mach_` for a machine, so 74 or 75 ASCII
//!   characters. It travels only in the header `Authorization: Bearer TOKEN`, never in a URL or a
//!   body. The hub keeps only its **token hash**: the SHA-256 of the token's ASCII text, prefix
//!   included. A body names a new token by that hash, never by the token.
//!
//! # The pairing string
//!
//! `halti pair` on the hub shows it as a QR code (byte mode) and as one line of text:
//!
//! ```text
//! halti-pair/1/KIND/ADDRESS/PIN/CODE
//! ```
//!
//! KIND is `device` or `machine`. ADDRESS is `HOST:PORT`, where HOST is a DNS name, an IPv4
//! address, or an IPv6 address in brackets; it never holds `/`. PIN is the 64 hex characters of the
//! pin. CODE is 32 hex characters: 16 bytes the hub drew, good for one pairing, for 2 minutes, and
//! only at the endpoint of its KIND.
//!
//! # Pairing a phone
//!
//! The app makes two P-256 keys: a **signing key**, which signs everything below, and an
//! **agreement key**, for key agreement only. It draws its token. Then:
//!
//! `POST /v1/pair`, no `Authorization`, body:
//!
//! ```json
//! {"code": "<16 bytes>", "signing_key": "<91 bytes>", "agreement_key": "<91 bytes>",
//!  "key_signature": "<DER>", "token_hash": "<32 bytes>", "push": "<text>", "signature": "<DER>"}
//! ```
//!
//! - `key_signature` is the signing key's signature over the fields `halti-device-keys-v1`, the
//!   signing key (91), the agreement key (91). It vouches for the agreement key wherever that key is
//!   shown later, apart from any hub or pairing.
//! - `push` is the phone's push address: 0 to 1,024 bytes of printable ASCII with no space, empty
//!   for none.
//! - `signature` is the signing key's signature over the fields `halti-pair-v1`, the pin (32), the
//!   code (16), the signing key (91), the agreement key (91), `key_signature` (its DER bytes), the
//!   token hash (32), `push`.
//!
//! The reply is `202 {"name": "pixel", "ws": ["acme", "beta"]}`: the name and workspaces given at
//! `halti pair`. The token does **not** work yet. The terminal on the hub shows the fingerprint and
//! asks the person there whether it is the one the app shows; the app shows it now. Until someone
//! answers there, a call with the token gets `401 pending`; after `y` it works, after `N` it gets
//! `401 unknown`. The app polls `GET /v1/me` every few seconds to learn which. A request that is
//! refused (malformed, a bad signature) leaves the code unused.
//!
//! # Pairing a machine
//!
//! `POST /v1/join`, no `Authorization`, body:
//!
//! ```json
//! {"code": "<16 bytes>", "machine_key": "<91 bytes>", "token_hash": "<32 bytes>"}
//! ```
//!
//! `machine_key` is the machine's P-256 key for key agreement, as a public key above. Nothing is
//! signed. The reply is `202 {"name": "server-1"}`; then, as for a phone, the token works once the
//! answer at the hub's terminal is `y`.
//!
//! # Calls with a token
//!
//! `GET /v1/me`, any token: `200`
//!
//! ```json
//! {"kind": "device", "name": "pixel", "ws": ["acme", "beta"], "issued": "<time>",
//!  "expires": "<time>", "renew_from": "<time>", "renewable_until": "<time>", "conflict": null}
//! ```
//!
//! For a machine, `kind` is `machine`, `ws` is empty, and `conflict` is the time the hub marked
//! its token as used from two places, or null.
//!
//! **Renewing a phone's token** takes two calls, each with the phone's token, which may have
//! expired:
//!
//! 1. `POST /v1/renew/nonce`, no body: `200 {"nonce": "<16 bytes>", "expires": "<time>"}`. A nonce
//!    is good for one renewal, for 2 minutes, and only for this device. Asking again gives another
//!    and leaves the first good. The client treats its bytes as opaque; a hub restart ends every
//!    nonce given out.
//! 2. `POST /v1/renew`, body `{"nonce": "<16 bytes>", "token_hash": "<32 bytes>", "signature":
//!    "<DER>"}`: the hash of a new token the app drew, and the signing key's signature over the
//!    fields `halti-renew-v1`, the pin (32), the device's name, the nonce (16), the new token hash
//!    (32). A renewal that is made uses its nonce up; one that is refused leaves it good, so a
//!    client may correct and send again within its time. `200 {"expires": "<time>"}`.
//!
//! **Renewing a machine's token**: `POST /v1/renew`, body `{"token_hash": "<32 bytes>"}`, nothing
//! signed. `200 {"expires": "<time>"}`.
//!
//! # Token life
//!
//! - A token works for 30 days from its issue (pairing, or renewal).
//! - A phone may renew at any time while its row is kept. After day 30 its token is refused with
//!   `401 expired` for every call but the two renewal calls, which work until day 90. On day 90 the
//!   hub deletes the row, which is a revoke: pair again.
//! - A machine may renew from day 10 to day 30 (`403 too-early` before). After day 30 its token is
//!   refused for everything, renewal included; the row is deleted on day 90 after its issue.
//! - The token a renewal replaced keeps working until the new one is first used, and for at most
//!   24 hours, never past its own day 30. It is not taken for a renewal: a phone gets
//!   `401 replaced`. A client that sent a renewal and got no reply tries its new token first.
//! - **Token conflict.** The hub keeps every token a machine had, until 90 days after that token's
//!   issue. One of them used after it stopped working, or used to ask for a renewal at all, marks
//!   the machine's row: the hub cannot tell which side is the real machine. That call gets `401
//!   conflict`; the current token still works, its `/v1/me` shows the mark, and its renewal gets
//!   `409 conflict`. Only `halti revoke` on the hub clears the mark; until then a pairing of the
//!   name is refused at the hub's terminal.
//!
//! # Errors
//!
//! Every refusal is a status and the body `{"error": "<word>"}`; an expired phone token's also has
//! `"renewable_until": "<time>"`.
//!
//! | Status | Word | When |
//! |---|---|---|
//! | 400 | `malformed` | The body isn't the JSON of that call: a field missing or unknown, bad hex, a wrong length, a bad name, a key not on the curve, a new token hash equal to one the row holds |
//! | 401 | `no-token` | No `Authorization: Bearer` with a token of the right form |
//! | 401 | `unknown` | No such token: never paired, refused at the terminal, revoked, deleted, a phone's replaced token after it stopped working, or a machine's 90 days after its issue |
//! | 401 | `pending` | Paired, and nobody has answered at the hub's terminal yet |
//! | 401 | `expired` | Past day 30, for a call it no longer admits |
//! | 401 | `replaced` | A phone's replaced token, sent to a renewal call |
//! | 401 | `conflict` | A machine's replaced token (see Token conflict) |
//! | 403 | `wrong-kind` | A machine's token at `/v1/renew/nonce`, which is a phone's |
//! | 403 | `bad-code` | The pairing code is unknown, used, past its 2 minutes, or of the other kind |
//! | 403 | `bad-signature` | A signature does not verify |
//! | 403 | `bad-nonce` | The nonce is unknown, used or past its 2 minutes |
//! | 403 | `too-early` | A machine's renewal before day 10 |
//! | 404 | `not-found` | No such path |
//! | 405 | `method` | The path takes another method |
//! | 409 | `conflict` | A renewal of a machine whose row is marked |
//! | 413 | `too-large` | A body over 4 KiB |
//! | 503 | `unavailable` | A renewal the hub could not write down: nothing changed, and the token sent still works. Try again later |
//!
//! A client shows these words, never a body as text.

use std::fmt;

use halti_core::device::{self, DeviceKey};
use halti_core::ids::WsName;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::fields;
use crate::util::{self, hex};

/// What the signing key signs to vouch for the agreement key.
pub const KEYS_LABEL: &str = "halti-device-keys-v1";
/// What a phone signs to pair.
pub const PAIR_LABEL: &str = "halti-pair-v1";
/// What a phone signs to renew its token.
pub const RENEW_LABEL: &str = "halti-renew-v1";

/// The first part of a pairing string.
const INVITE: &str = "halti-pair/1";

/// The longest push address.
pub const PUSH_MAX: usize = 1024;

/// A public key's length, as `device` takes it.
pub const KEY_LEN: usize = device::SPKI_LEN;

/// The bytes a client sends for a phone or a machine: who holds a token, a code or a row.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Device,
    Machine,
}

impl Kind {
    pub fn word(self) -> &'static str {
        match self {
            Kind::Device => "device",
            Kind::Machine => "machine",
        }
    }

    fn from_word(word: &str) -> Option<Kind> {
        match word {
            "device" => Some(Kind::Device),
            "machine" => Some(Kind::Machine),
            _ => None,
        }
    }

    /// What its tokens start with.
    pub fn prefix(self) -> &'static str {
        match self {
            Kind::Device => "halti_dev_",
            Kind::Machine => "halti_mach_",
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.word())
    }
}

/// What the signing key signs to vouch for the agreement key.
pub fn keys_bytes(signing_key: &[u8], agreement_key: &[u8]) -> Vec<u8> {
    fields::join(&[KEYS_LABEL.as_bytes(), signing_key, agreement_key])
}

/// What a phone's pairing request says, all of which it signs.
pub struct PairRequest {
    pub code: [u8; 16],
    pub signing_key: Vec<u8>,
    pub agreement_key: Vec<u8>,
    pub key_signature: Vec<u8>,
    pub token_hash: [u8; 32],
    pub push: String,
}

/// What a phone signs to pair with the hub whose pin is `pin`.
pub fn pair_bytes(pin: &[u8; 32], request: &PairRequest) -> Vec<u8> {
    fields::join(&[PAIR_LABEL.as_bytes(), pin, &request.code, &request.signing_key, &request.agreement_key, &request.key_signature, &request.token_hash, request.push.as_bytes()])
}

/// What a phone signs to renew its token.
pub fn renew_bytes(pin: &[u8; 32], name: &str, nonce: &[u8; 16], token_hash: &[u8; 32]) -> Vec<u8> {
    fields::join(&[RENEW_LABEL.as_bytes(), pin, name.as_bytes(), nonce, token_hash])
}

impl PairRequest {
    /// Checks both keys and both signatures, `signature` being the one over the whole request, for
    /// the hub with this pin. The signing key comes back.
    pub fn verify(&self, pin: &[u8; 32], signature: &[u8]) -> Result<DeviceKey, Refused> {
        let key = DeviceKey::from_spki(&self.signing_key).map_err(|_| Refused::Malformed)?;
        device::check_agreement_key(&self.agreement_key).map_err(|_| Refused::Malformed)?;
        if !push_ok(&self.push) {
            return Err(Refused::Malformed);
        }
        key.verify(&keys_bytes(&self.signing_key, &self.agreement_key), &self.key_signature).map_err(|_| Refused::BadSignature)?;
        key.verify(&pair_bytes(pin, self), signature).map_err(|_| Refused::BadSignature)?;
        Ok(key)
    }
}

/// A push address: printable ASCII with no space, at most `PUSH_MAX` bytes; empty for none.
fn push_ok(push: &str) -> bool {
    push.len() <= PUSH_MAX && push.bytes().all(|b| (0x21..0x7f).contains(&b))
}

/// The body of `POST /v1/pair`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairBody {
    code: String,
    signing_key: String,
    agreement_key: String,
    key_signature: String,
    token_hash: String,
    push: String,
    signature: String,
}

/// A phone's pairing request and its signature, from the body. Only the form is checked here.
pub fn pair_body(body: &[u8]) -> Result<(PairRequest, Vec<u8>), Refused> {
    let body: PairBody = json(body)?;
    let request = PairRequest {
        code: bytes(&body.code)?,
        signing_key: key(&body.signing_key)?,
        agreement_key: key(&body.agreement_key)?,
        key_signature: signature(&body.key_signature)?,
        token_hash: bytes(&body.token_hash)?,
        push: body.push,
    };
    Ok((request, signature(&body.signature)?))
}

/// What a machine sends to pair.
pub struct JoinRequest {
    pub code: [u8; 16],
    pub machine_key: Vec<u8>,
    pub token_hash: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinBody {
    code: String,
    machine_key: String,
    token_hash: String,
}

/// A machine's pairing request from the body, its key checked.
pub fn join_body(body: &[u8]) -> Result<JoinRequest, Refused> {
    let body: JoinBody = json(body)?;
    let request = JoinRequest { code: bytes(&body.code)?, machine_key: key(&body.machine_key)?, token_hash: bytes(&body.token_hash)? };
    device::check_agreement_key(&request.machine_key).map_err(|_| Refused::Malformed)?;
    Ok(request)
}

/// What a phone sends to renew.
pub struct DeviceRenewal {
    pub nonce: [u8; 16],
    pub token_hash: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceRenewBody {
    nonce: String,
    token_hash: String,
    signature: String,
}

pub fn device_renew_body(body: &[u8]) -> Result<DeviceRenewal, Refused> {
    let body: DeviceRenewBody = json(body)?;
    Ok(DeviceRenewal { nonce: bytes(&body.nonce)?, token_hash: bytes(&body.token_hash)?, signature: signature(&body.signature)? })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MachineRenewBody {
    token_hash: String,
}

/// The new token hash a machine sends to renew.
pub fn machine_renew_body(body: &[u8]) -> Result<[u8; 32], Refused> {
    let body: MachineRenewBody = json(body)?;
    bytes(&body.token_hash)
}

/// A call that takes no body has none, or an empty one.
pub fn no_body(body: &[u8]) -> Result<(), Refused> {
    if body.is_empty() { Ok(()) } else { Err(Refused::Malformed) }
}

fn json<'a, T: Deserialize<'a>>(body: &'a [u8]) -> Result<T, Refused> {
    serde_json::from_slice(body).map_err(|_| Refused::Malformed)
}

fn bytes<const N: usize>(text: &str) -> Result<[u8; N], Refused> {
    unhex(text).ok_or(Refused::Malformed)
}

fn key(text: &str) -> Result<Vec<u8>, Refused> {
    util::unhex(text).filter(|key| key.len() == KEY_LEN).ok_or(Refused::Malformed)
}

fn signature(text: &str) -> Result<Vec<u8>, Refused> {
    util::unhex(text).filter(|sig| !sig.is_empty() && sig.len() <= device::SIGNATURE_MAX).ok_or(Refused::Malformed)
}

/// The SHA-256 of a token's text.
pub fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// The kind and hash of the token in an `Authorization` header's value, if it is one: `Bearer `,
/// then a prefix and 64 lowercase hex characters.
pub fn bearer(value: &str) -> Option<(Kind, [u8; 32])> {
    let token = value.strip_prefix("Bearer ")?;
    let kind = [Kind::Device, Kind::Machine].into_iter().find(|kind| token.starts_with(kind.prefix()))?;
    let digits = &token[kind.prefix().len()..];
    unhex::<32>(digits)?;
    Some((kind, token_hash(token)))
}

/// Exactly `N` bytes from lowercase hex.
pub fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    util::unhex(text)?.try_into().ok()
}

/// A device's or a machine's name: 1 to 32 of a-z, 0-9, `-` and `_`, starting with a letter or a
/// digit (`fields::is_name`). Never echoed when refused.
pub fn check_name(name: &str) -> Result<(), Refused> {
    if !fields::is_name(name) {
        return Err(Refused::Malformed);
    }
    Ok(())
}

/// The fingerprint people compare: the first 10 bytes of the key's SHA-256, as five groups of four.
pub fn fingerprint(signing_key: &[u8]) -> String {
    let digest = device::fingerprint(signing_key);
    hex(&digest[..10]).as_bytes().chunks(4).map(|group| String::from_utf8_lossy(group).into_owned()).collect::<Vec<_>>().join(" ")
}

/// What `halti pair` shows: where the hub is, its pin, and a code good once.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Invite {
    pub kind: Kind,
    pub address: String,
    pub pin: [u8; 32],
    pub code: [u8; 16],
}

impl fmt::Display for Invite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{INVITE}/{}/{}/{}/{}", self.kind, self.address, hex(&self.pin), hex(&self.code))
    }
}

impl Invite {
    /// The line as the hub writes it, and nothing else.
    pub fn parse(line: &str) -> Option<Invite> {
        let rest = line.strip_prefix(INVITE)?.strip_prefix('/')?;
        let parts: Vec<&str> = rest.split('/').collect();
        let [kind, address, pin, code] = parts[..] else { return None };
        check_address(address).ok()?;
        Some(Invite { kind: Kind::from_word(kind)?, address: address.to_string(), pin: unhex(pin)?, code: unhex(code)? })
    }
}

/// An address clients reach the hub at: `HOST:PORT`, a port of 1 to 65535, and a host of letters,
/// digits, `.`, `-`, or an IPv6 address in brackets.
pub fn check_address(address: &str) -> Result<(), String> {
    let bad = || format!("{address} isn't HOST:PORT (an IPv6 address in brackets)");
    let (host, port) = address.rsplit_once(':').ok_or_else(bad)?;
    if !port.bytes().all(|b| b.is_ascii_digit()) || port.parse::<u16>().ok().filter(|p| *p > 0).is_none() {
        return Err(bad());
    }
    let ok = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(v6) => v6.parse::<std::net::Ipv6Addr>().is_ok(),
        None => !host.is_empty() && host.len() <= 253 && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'),
    };
    if ok { Ok(()) } else { Err(bad()) }
}

/// Why a call was refused: its status and the word in its body.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refused {
    Malformed,
    NoToken,
    Unknown,
    Pending,
    /// Past day 30; a phone's row may still renew until this time.
    Expired(Option<jiff::Timestamp>),
    Replaced,
    /// A machine's replaced token.
    Conflict,
    WrongKind,
    BadCode,
    BadSignature,
    BadNonce,
    TooEarly,
    NotFound,
    Method,
    /// A renewal of a machine whose row is marked.
    Marked,
    TooLarge,
    /// A renewal the hub could not write down, and so undid.
    Unwritten,
}

impl Refused {
    pub fn status(self) -> u16 {
        match self {
            Refused::Malformed => 400,
            Refused::NoToken | Refused::Unknown | Refused::Pending | Refused::Expired(_) | Refused::Replaced | Refused::Conflict => 401,
            Refused::WrongKind | Refused::BadCode | Refused::BadSignature | Refused::BadNonce | Refused::TooEarly => 403,
            Refused::NotFound => 404,
            Refused::Method => 405,
            Refused::Marked => 409,
            Refused::TooLarge => 413,
            Refused::Unwritten => 503,
        }
    }

    pub fn word(self) -> &'static str {
        match self {
            Refused::Malformed => "malformed",
            Refused::NoToken => "no-token",
            Refused::Unknown => "unknown",
            Refused::Pending => "pending",
            Refused::Expired(_) => "expired",
            Refused::Replaced => "replaced",
            Refused::Conflict | Refused::Marked => "conflict",
            Refused::WrongKind => "wrong-kind",
            Refused::BadCode => "bad-code",
            Refused::BadSignature => "bad-signature",
            Refused::BadNonce => "bad-nonce",
            Refused::TooEarly => "too-early",
            Refused::NotFound => "not-found",
            Refused::Method => "method",
            Refused::TooLarge => "too-large",
            Refused::Unwritten => "unavailable",
        }
    }

    /// The reply's body.
    pub fn body(self) -> serde_json::Value {
        match self {
            Refused::Expired(Some(until)) => serde_json::json!({"error": self.word(), "renewable_until": time(until)}),
            _ => serde_json::json!({"error": self.word()}),
        }
    }
}

/// A time as the wire writes it.
pub fn time(t: jiff::Timestamp) -> String {
    t.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// A workspace list as a phone's pairing gives it: one or more names, each once.
pub fn workspaces(names: &[String]) -> Result<Vec<WsName>, Refused> {
    let mut out: Vec<WsName> = Vec::new();
    for name in names {
        let name = WsName::parse(name).map_err(|_| Refused::Malformed)?;
        if !out.contains(&name) {
            out.push(name);
        }
    }
    if out.is_empty() { Err(Refused::Malformed) } else { Ok(out) }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known answers, made apart from this code: the keys by `openssl ecparam -name prime256v1
    // -genkey` and `openssl pkey -pubout -outform DER`, the byte strings by a few lines of Python
    // following the text above, and the signatures by `openssl dgst -sha256 -sign` over them.

    /// The pin: the bytes 01 to 20.
    fn pin() -> [u8; 32] {
        std::array::from_fn(|i| i as u8 + 1)
    }
    /// The code: the bytes a0 to af.
    fn code() -> [u8; 16] {
        std::array::from_fn(|i| 0xa0 + i as u8)
    }
    /// The nonce: the bytes 50 to 5f.
    fn nonce() -> [u8; 16] {
        std::array::from_fn(|i| 0x50 + i as u8)
    }
    const SIGNING_KEY: &str = "3059301306072a8648ce3d020106082a8648ce3d030107034200043b6aa11762eb968f8b4fbee065b47e356990e923b4817a936152c14286c308c95683278c53\
        24078488ce8a20a1ee31992f4e3cc7fbae1da979e93db075904fee";
    const AGREEMENT_KEY: &str = "3059301306072a8648ce3d020106082a8648ce3d030107034200044f4e2d7a4c9a3823da62bef209eb1304ed2bee76502d7e3f129addc052bc3ce983f31f44a4\
        57b19b122f906de9f6023e1d89c3fbb3e4e0fc2843e1e7840385eb";
    const TOKEN: &str = "halti_dev_1111111111111111111111111111111111111111111111111111111111111111";
    const TOKEN_HASH: &str = "9b4dc1c60800746a0b05c5545afb7f961dbf94d8d94bdd53bc1413c92676e0a2";
    const NEW_TOKEN: &str = "halti_dev_2222222222222222222222222222222222222222222222222222222222222222";
    const NEW_TOKEN_HASH: &str = "58b3d7750ce0d8a3178f232824324bade41e2df4a88c1011b971213857b8706a";
    const MACHINE_TOKEN: &str = "halti_mach_3333333333333333333333333333333333333333333333333333333333333333";
    const MACHINE_TOKEN_HASH: &str = "9ec3b08ba07517c20236518e4a6fc0890d87b6b772cf6b33649dcccca036b47b";
    const PUSH: &str = "fcm:example-push-address";
    const FINGERPRINT: &str = "d20d 5b7c 72c8 6e12 5e7a";
    const KEYS_BYTES: &str = "001468616c74692d6465766963652d6b6579732d7631005b3059301306072a8648ce3d020106082a8648ce3d030107034200043b6aa11762eb968f8b4fbee065\
        b47e356990e923b4817a936152c14286c308c95683278c5324078488ce8a20a1ee31992f4e3cc7fbae1da979e93db075904fee005b3059301306072a8648ce3d\
        020106082a8648ce3d030107034200044f4e2d7a4c9a3823da62bef209eb1304ed2bee76502d7e3f129addc052bc3ce983f31f44a457b19b122f906de9f6023e\
        1d89c3fbb3e4e0fc2843e1e7840385eb";
    const KEYS_SIGNATURE: &str = "304502207320665ae0e9e45636f7217f2ba4f3228bd2e60e99cc51f6b1492da79c490065022100c0ecbe2c842e882f89362f5793fd442fd9a0ec923f6f27dc05\
        d64f5c78c22f46";
    const PAIR_BYTES: &str = "000d68616c74692d706169722d763100200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200010a0a1a2a3a4a5a6a7a8a9aaabac\
        adaeaf005b3059301306072a8648ce3d020106082a8648ce3d030107034200043b6aa11762eb968f8b4fbee065b47e356990e923b4817a936152c14286c308c9\
        5683278c5324078488ce8a20a1ee31992f4e3cc7fbae1da979e93db075904fee005b3059301306072a8648ce3d020106082a8648ce3d030107034200044f4e2d\
        7a4c9a3823da62bef209eb1304ed2bee76502d7e3f129addc052bc3ce983f31f44a457b19b122f906de9f6023e1d89c3fbb3e4e0fc2843e1e7840385eb004730\
        4502207320665ae0e9e45636f7217f2ba4f3228bd2e60e99cc51f6b1492da79c490065022100c0ecbe2c842e882f89362f5793fd442fd9a0ec923f6f27dc05d6\
        4f5c78c22f4600209b4dc1c60800746a0b05c5545afb7f961dbf94d8d94bdd53bc1413c92676e0a2001866636d3a6578616d706c652d707573682d6164647265\
        7373";
    const PAIR_SIGNATURE: &str = "3045022100f4d116b510cef9f91755796c7c88cf74e7476462ba2714a2706b90357482736b02204fd1376498543f9a4be627bbc159eff8ae6a26f03f84e28a32\
        584e0eb610618e";
    const RENEW_BYTES: &str = "000e68616c74692d72656e65772d763100200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200005706978656c00105051525354\
        55565758595a5b5c5d5e5f002058b3d7750ce0d8a3178f232824324bade41e2df4a88c1011b971213857b8706a";
    const RENEW_SIGNATURE: &str = "30460221009183ec133831d9bc303cc119e4324a3b2ad8ed43783ae159e9f3f4fea42c4d9c022100ed50f38b17b6000eec135be7c8e51b15a5d1c384b69006f6\
        415a59db25171210";

    fn bytes(text: &str) -> Vec<u8> {
        util::unhex(text).unwrap()
    }

    fn request() -> PairRequest {
        PairRequest {
            code: code(),
            signing_key: bytes(SIGNING_KEY),
            agreement_key: bytes(AGREEMENT_KEY),
            key_signature: bytes(KEYS_SIGNATURE),
            token_hash: unhex(TOKEN_HASH).unwrap(),
            push: PUSH.to_string(),
        }
    }

    #[test]
    fn a_token_hash_is_the_sha256_of_its_text() {
        assert_eq!(hex(&token_hash(TOKEN)), TOKEN_HASH);
        assert_eq!(hex(&token_hash(NEW_TOKEN)), NEW_TOKEN_HASH);
        assert_eq!(hex(&token_hash(MACHINE_TOKEN)), MACHINE_TOKEN_HASH);
        assert_eq!(bearer(&format!("Bearer {TOKEN}")), Some((Kind::Device, unhex(TOKEN_HASH).unwrap())));
        assert_eq!(bearer(&format!("Bearer {MACHINE_TOKEN}")), Some((Kind::Machine, unhex(MACHINE_TOKEN_HASH).unwrap())));
        // Anything else is no token: another scheme, case or length, upper-case hex, another prefix.
        for value in [
            TOKEN.to_string(),
            format!("bearer {TOKEN}"),
            format!("Bearer  {TOKEN}"),
            format!("Bearer {TOKEN}0"),
            format!("Bearer {}", &TOKEN[..TOKEN.len() - 1]),
            format!("Bearer {}", TOKEN.to_uppercase()),
            format!("Bearer halti_dev_{}", "A".repeat(64)),
            format!("Bearer halti_root_{}", "1".repeat(64)),
            format!("Bearer {TOKEN} "),
        ] {
            assert_eq!(bearer(&value), None, "{value}");
        }
    }

    #[test]
    fn the_signed_byte_strings_are_unchanged() {
        assert_eq!(hex(&keys_bytes(&bytes(SIGNING_KEY), &bytes(AGREEMENT_KEY))), KEYS_BYTES);
        assert_eq!(hex(&pair_bytes(&pin(), &request())), PAIR_BYTES);
        assert_eq!(hex(&renew_bytes(&pin(), "pixel", &nonce(), &unhex(NEW_TOKEN_HASH).unwrap())), RENEW_BYTES);
        assert_eq!(fingerprint(&bytes(SIGNING_KEY)), FINGERPRINT);
    }

    #[test]
    fn signatures_made_by_openssl_verify() {
        let key = DeviceKey::from_spki(&bytes(SIGNING_KEY)).unwrap();
        assert_eq!(key.verify(&bytes(KEYS_BYTES), &bytes(KEYS_SIGNATURE)), Ok(()));
        assert_eq!(key.verify(&bytes(RENEW_BYTES), &bytes(RENEW_SIGNATURE)), Ok(()));
        assert_eq!(request().verify(&pin(), &bytes(PAIR_SIGNATURE)).map(|_| ()), Ok(()));
        // One signature is never another's.
        assert!(key.verify(&bytes(PAIR_BYTES), &bytes(RENEW_SIGNATURE)).is_err());
        assert_eq!(request().verify(&pin(), &bytes(KEYS_SIGNATURE)).map(|_| ()), Err(Refused::BadSignature));
    }

    #[test]
    fn a_pairing_request_fails_for_any_change() {
        let signature = bytes(PAIR_SIGNATURE);
        let mut other_pin = pin();
        other_pin[0] ^= 1;
        assert_eq!(request().verify(&other_pin, &signature).map(|_| ()), Err(Refused::BadSignature), "another hub's pin");
        let changes: [fn(&mut PairRequest); 5] = [|r| r.code[15] ^= 1, |r| r.token_hash[0] ^= 1, |r| r.push.push('x'), |r| r.push.clear(), |r| r.key_signature[10] ^= 1];
        for (i, change) in changes.iter().enumerate() {
            let mut changed = request();
            change(&mut changed);
            assert_eq!(changed.verify(&pin(), &signature).map(|_| ()), Err(Refused::BadSignature), "change {i}");
        }
        // Keys that aren't keys, and a push address with a space, are malformed before any signature is checked.
        let mut bad_key = request();
        bad_key.agreement_key[90] ^= 1;
        assert_eq!(bad_key.verify(&pin(), &signature).map(|_| ()), Err(Refused::Malformed));
        let mut spaced = request();
        spaced.push = "fcm: x".into();
        assert_eq!(spaced.verify(&pin(), &signature).map(|_| ()), Err(Refused::Malformed));
        let mut swapped = request();
        std::mem::swap(&mut swapped.signing_key, &mut swapped.agreement_key);
        assert_eq!(swapped.verify(&pin(), &signature).map(|_| ()), Err(Refused::BadSignature));
    }

    #[test]
    fn a_pairing_body_reads_as_the_text_says() {
        let body = serde_json::json!({
            "code": hex(&code()), "signing_key": SIGNING_KEY.replace(' ', ""), "agreement_key": AGREEMENT_KEY, "key_signature": KEYS_SIGNATURE,
            "token_hash": TOKEN_HASH, "push": PUSH, "signature": PAIR_SIGNATURE,
        });
        let (read, signature) = pair_body(body.to_string().as_bytes()).unwrap();
        assert_eq!(read.verify(&pin(), &signature).map(|_| ()), Ok(()));
        // A field more or less, upper-case hex, a short key.
        let mut extra = body.clone();
        extra["name"] = "pixel".into();
        let mut missing = body.clone();
        missing.as_object_mut().unwrap().remove("push");
        let mut upper = body.clone();
        upper["token_hash"] = TOKEN_HASH.to_uppercase().into();
        let mut short = body.clone();
        short["signing_key"] = SIGNING_KEY[..180].into();
        for bad in [extra, missing, upper, short] {
            assert!(matches!(pair_body(bad.to_string().as_bytes()), Err(Refused::Malformed)), "{bad}");
        }
        assert!(matches!(pair_body(b"not json"), Err(Refused::Malformed)));
    }

    #[test]
    fn a_pairing_string_reads_back_and_nothing_else_does() {
        let invite = Invite { kind: Kind::Device, address: "10.0.0.5:8443".into(), pin: pin(), code: code() };
        let line = invite.to_string();
        assert_eq!(line, "halti-pair/1/device/10.0.0.5:8443/0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20/a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        assert_eq!(Invite::parse(&line), Some(invite.clone()));
        let v6 = Invite { kind: Kind::Machine, address: "[fd00::5]:8443".into(), ..invite.clone() };
        assert_eq!(Invite::parse(&v6.to_string()), Some(v6));
        for bad in [
            line.replace("halti-pair/1", "halti-pair/2"),
            line.replace("/device/", "/phone/"),
            line.replace("10.0.0.5:8443", "10.0.0.5"),
            line.replace("10.0.0.5:8443", "10.0.0.5:0"),
            line.replace("10.0.0.5:8443", "10.0.0.5:99999"),
            line.replace("10.0.0.5:8443", "fd00::5:8443"),
            line.replace("10.0.0.5:8443", "hub example:8443"),
            line.replace("/a0a1", "/A0A1"),
            format!("{line}/"),
            line[..line.len() - 2].to_string(),
        ] {
            assert_eq!(Invite::parse(&bad), None, "{bad}");
        }
    }

    #[test]
    fn names_follow_the_one_rule() {
        for good in ["pixel", "server-1", "build_box", "9", &"x".repeat(32)] {
            assert_eq!(check_name(good), Ok(()), "{good}");
        }
        for bad in ["", "-x", "_x", "Pixel", "pi xel", "pixel.", "a/b", "é", &"x".repeat(33)] {
            assert_eq!(check_name(bad), Err(Refused::Malformed), "{bad}");
        }
        assert_eq!(workspaces(&["acme".into(), "beta".into(), "acme".into()]).unwrap().len(), 2);
        for bad in [vec![], vec!["Acme".to_string()], vec!["ac_me".to_string()], vec![String::new()]] {
            assert_eq!(workspaces(&bad), Err(Refused::Malformed), "{bad:?}");
        }
    }

    #[test]
    fn every_refusal_has_its_status_and_word() {
        let until = "2027-02-13T10:00:00Z".parse().unwrap();
        let all = [
            (Refused::Malformed, 400, "malformed"),
            (Refused::NoToken, 401, "no-token"),
            (Refused::Unknown, 401, "unknown"),
            (Refused::Pending, 401, "pending"),
            (Refused::Expired(None), 401, "expired"),
            (Refused::Replaced, 401, "replaced"),
            (Refused::Conflict, 401, "conflict"),
            (Refused::WrongKind, 403, "wrong-kind"),
            (Refused::BadCode, 403, "bad-code"),
            (Refused::BadSignature, 403, "bad-signature"),
            (Refused::BadNonce, 403, "bad-nonce"),
            (Refused::TooEarly, 403, "too-early"),
            (Refused::NotFound, 404, "not-found"),
            (Refused::Method, 405, "method"),
            (Refused::Marked, 409, "conflict"),
            (Refused::TooLarge, 413, "too-large"),
            (Refused::Unwritten, 503, "unavailable"),
        ];
        for (refused, status, word) in all {
            assert_eq!((refused.status(), refused.word()), (status, word));
            assert_eq!(refused.body(), serde_json::json!({"error": word}));
        }
        assert_eq!(Refused::Expired(Some(until)).body(), serde_json::json!({"error": "expired", "renewable_until": "2027-02-13T10:00:00Z"}));
    }
}
