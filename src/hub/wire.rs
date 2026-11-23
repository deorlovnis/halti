//! What crosses the hub's listener: everything a phone app or a machine needs to talk to
//! `halti hub serve`, written so that a client can be built from this text alone. Each signed byte
//! string has a known answer in this file's tests, but a request's record and the answer to it,
//! whose are in `crate::requests`'s.
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
//!   (request line and headers) may be at most 8 KiB, the body at most 4 KiB (16 KiB for
//!   `POST /v1/machine/state` and `POST /v1/machine/questions`, 20 KiB for
//!   `POST /v1/machine/question`, 8 KiB for `POST /v1/reply`), sent with `Content-Length` (chunked is read too, within the same
//!   limit). A request that is slower, a head that is longer or malformed, and a TLS handshake that
//!   fails get no reply: the connection is closed. A head is malformed when its request line isn't
//!   exactly `METHOD TARGET HTTP/VERSION`, one space between each, or a header line has no `:` or a
//!   name that isn't an HTTP token. A body over its limit is answered `413 too-large`.
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
//! - **A request id** is 16 bytes a machine drew; **a run id** is 8 bytes a machine drew as a box
//!   started. In JSON both are hex, as all bytes are.
//! - **A machine code** is what people compare when a machine trusts a phone: the first 10 bytes of
//!   the SHA-256 of the fields `halti-machine-code-v1`, the machine's name, the machine's key (91),
//!   then each workspace the phone is trusted for there, sorted by their bytes, each once; shown as a
//!   fingerprint is. Example: machine `server-1`, the key in this file's tests, workspaces `beta`
//!   and `acme`: `0813 369a 1400 9098 7602`.
//! - **Sealed text** is what the machine and the phone hide from the hub: HPKE (RFC 9180) in
//!   mode_auth with DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM, by the machine key to
//!   the phone's agreement key, or by the agreement key to a key the machine made for one question.
//!   The info, associated data and bytes are in `halti_core::sealed`; the known answers both sides
//!   test against are in `tests/fixtures/sealed-text-vectors.json`. A notice and an agent's question
//!   carry it, and a phone's answer to the question and the machine's receipt (below).
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
//!  "expires": "<time>", "renew_from": "<time>", "renewable_until": "<time>", "conflict": null,
//!  "now": "<time>"}
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
//! `now` in `GET /v1/me` is the hub's clock as it answered. A client that counts a token's days
//! compares the other times with it, never with its own clock.
//!
//! # A request's record
//!
//! A machine asks about a write as a **request**: one fixed byte string, its **record**, a run of
//! fields as above, in this order and nothing else:
//!
//! | Field | Bytes |
//! |---|---|
//! | label | `halti-approval-v1` |
//! | machine | the machine's name at the hub |
//! | ws | the workspace's name |
//! | box | the box's name, a name as a device's is |
//! | run | the run id (8) |
//! | kind | `write`, the only kind yet |
//! | action | the method, a space and the URL, sensitive query values masked: 1 to 1,024 bytes of printable ASCII (0x20 to 0x7e), every other byte percent-encoded by the machine; it ends ` (cut)` where it was cut |
//! | id | the request id (16) |
//! | expiry | seconds since 1970 by the machine's clock, 8 bytes big-endian |
//!
//! A client reads a record whole or not at all: a field missing, of the wrong length or form, or a
//! byte after the last, and it is not shown. It shows machine, workspace and box first, then the
//! action, and never anything the record doesn't hold.
//!
//! # What a phone does
//!
//! Every call below takes a phone's token; a machine's gets `403 wrong-kind`. The hub shows a phone
//! only what concerns its workspaces, the ones named at `halti pair`: a request, a run or a
//! workspace outside them is never listed, and a call that names one gets `410 gone`.
//!
//! The app polls while it is open: `GET /v1/requests` and `GET /v1/state` every 3 seconds while a
//! screen shows them, never more often than once a second; nothing while it is closed.
//!
//! **Requests.** `GET /v1/requests`, no body: `200 {"requests": [{"machine": "server-1",
//! "record": "<bytes>"}]}`, every request that waits in the phone's workspaces, from every machine,
//! in the order of the machines' names, then of the ids. A request leaves the list once its machine
//! answered it, withdrew it or let it expire, and a minute after its expiry by the hub's clock at
//! the latest.
//!
//! **Answering one.** The app shows the record, asks for fingerprint or PIN, and signs with the
//! signing key the record's bytes followed by one more field, `yes` or `no`: for a record `R`, the
//! bytes `R 0003 796573` to approve and `R 0002 6e6f` to deny. SHA-256 of those bytes is what the
//! machine itself names an answer by. It signs only bytes it rebuilt from the record it displayed,
//! never a hash it was handed. Then `POST /v1/answer`, body
//! `{"machine": "server-1", "id": "<16 bytes>", "decision": "yes", "signature": "<DER>"}` (or
//! `"no"`): `202 {"n": 7}`, the number of what it sent, for `GET /v1/state`. The hub checks the
//! signature against the phone's key and refuses one that can't count (`403 bad-signature`), then
//! holds it for the machine. A request the hub doesn't hold, or holds hidden, is `410 gone`. Only
//! the machine decides: it checks the signature again, against the keys it was told to trust for
//! that workspace (`halti devices trust`), and over its own record of that id, which must still
//! wait. The first answer that counts wins, the machine's own or a phone's; any later one is `gone`
//! there. A signed `no` is a refusal like one at the machine.
//!
//! **Hiding one.** `POST /v1/hide`, body `{"machine": "server-1", "id": "<16 bytes>"}`, nothing
//! signed: `200 {}`. It closes the remote copy for every phone and nothing else: the machine still
//! waits, and is answered there or expires. Any phone that may see the request can do it.
//!
//! **Waiting, with the app closed.** `POST /v1/wait` is the one call that takes no token. It takes
//! the phone's **wake credential** in the header `Authorization: Wake <64 hex>`: the SHA-256 of the
//! fields `halti-wake-v1` and the hash of the phone's current token (32). The app computes it
//! whenever it holds the token and keeps it apart, for a service that runs while the phone is
//! locked; the hub computes it from the row. It works on this call alone, and this call takes
//! nothing else: a token here gets `403 wrong-kind`, the credential anywhere else `401 no-token`.
//! It works while the row is kept, its token expired or not; after a renewal only the new token's
//! does; a machine has none. Example: the token `halti_dev_` then `0123456789abcdef` four times has
//! the hash `b1b1a551...fa7272cc` and the wake credential `ab256275...38a624d5`, as this file's
//! tests have them whole.
//!
//! The body is `{"seen": "<32 bytes>", "notices_seen": "<32 bytes>", "questions_seen": "<32
//! bytes>"}`. `seen` is the SHA-256 of the request ids the call was last answered with, each 16
//! bytes, sorted by their bytes and run together; `""` for none. `notices_seen` is the same over
//! the notice ids it was last answered with, and `questions_seen` over the question ids; an app
//! that isn't told of notices, or of questions, leaves that field out. A field the hub doesn't know
//! is passed over. The reply is `200 {"requests": ["<16 bytes>", ...], "notices": ["<16 bytes>",
//! ...], "questions": ["<16 bytes>", ...]}`: the ids of the requests `GET /v1/requests` would list
//! now, of the notices `GET /v1/notices` would, and of the questions `GET /v1/questions` would, that
//! the phone may be told of now (below), each sorted by their bytes; `notices` only when the body
//! had `notices_seen`, and `questions` only when it had `questions_seen`.
//!
//! It comes at once when the requests differ from `seen`. When only the notices or questions differ
//! from what the phone named, it comes within the agents' limits, which notices and questions share:
//! at most once in 10 seconds for a phone, and in an hour 6 times for one box and 20 for one
//! machine, a box counting once for each answer that lists a notice or question of it that is new
//! to the phone. A change that only closes them counts only against the 10 seconds. Otherwise the hub holds the call until one of those, or 240 seconds, and
//! answers then. A notice or question new to the phone is in an answer only as those limits allow,
//! whatever ends the call: an answer that ends for a request, the 240 seconds or a newer call, at a
//! time the limits don't allow, lists only those the phone was told already that are still open,
//! and the new one comes in a later answer. So `notices` may list fewer than `GET /v1/notices` does,
//! and `questions` fewer than `GET /v1/questions`. What the phone was told is the answer its
//! `notices_seen` (or `questions_seen`) names, of the last five the hub gave it: an answer the phone
//! never read, as it gave up on the call or lost it, changes nothing. The app keeps the lists apart:
//! a new request id raises the request notification, a new notice or question id the agent one
//! ("halti: an agent is waiting for you"), and neither raises the other. No text of a question is
//! ever in a notification.
//! A phone has one such call at a time: a newer one ends the one before with the lists as they are.
//! The credential tells the hub's holder how many requests and notices wait and when that changes;
//! it reads, answers, hides or stops nothing.
//!
//! **Notices.** A notice says that an agent in a box waits for its owner: `GET /v1/notices`, no
//! body: `200 {"notices": [{"machine": "server-1", "record": "<bytes>", "sealed": "<bytes>"}]}`,
//! every notice in the phone's workspaces that its machine sealed to this phone, from every
//! machine, in the order of the machines' names, then of the ids. A notice leaves the list once
//! its machine closed it: the agent went on, its run ended, or its workspace closed. It is never
//! closed for its age. Nothing is answered from a notice; the app says where to answer: "The agent
//! in acme/dev is waiting for you: permission prompt. Since 14:02. Answer at its terminal."
//!
//! The record is one fixed byte string, a run of fields as above, in this order and nothing else:
//!
//! | Field | Bytes |
//! |---|---|
//! | label | `halti-notice-v1` |
//! | machine | the machine's name at the hub |
//! | ws | the workspace's name |
//! | box | the box's name, a name as a device's is |
//! | run | the run id (8) |
//! | session | the agent session's number in that run, 1 to 8, 4 bytes big-endian |
//! | kind | `permission-prompt`, `question`, `turn-ended` or `needs-input` |
//! | id | 16 bytes the machine drew for this notice |
//! | since | when the wait began: seconds since 1970 by the machine's clock, 8 bytes big-endian |
//!
//! No byte of it was chosen inside the box: the box can choose only whether there is a notice,
//! when, and which of the four kinds. `sealed` is sealed text (above) by the machine key to this
//! phone's agreement key, with the label `halti-sealed-notice-v1` and the record's bytes as the
//! associated data; the plaintext is empty, so it is 81 bytes. The app reads the record whole or
//! not at all, opens `sealed` under the key it compared for the machine the record names, and
//! lists the notice only if it opens and the record's machine and workspace are ones that machine
//! was compared for (`devices trust`). One the hub made up, or whose record it changed, does not
//! open; the app counts such records as refused and shows nothing of them.
//!
//! A notice that came back from a question that ended while its agent still waited (below) has the
//! reason as its sealed text, in place of nothing: the fields `expired`, `not-away` (the run is no
//! longer marked away), `left` (its owner left it for the terminal), `no-phone` (no phone is trusted
//! for the workspace any more) or `before-away` (the wait began before the run was marked away),
//! then 8 bytes big-endian: the question's expiry for `expired`, else 0. So it is 81 to 108 bytes.
//! The app shows the reason on the notice's line ("expired 03:10"), and nothing for an empty one.
//!
//! **Questions.** In a run its owner marked away at a terminal, an agent's wait is a question the
//! phone may answer: a permission prompt (`permit`: yes or no, a no with an optional reason), a
//! question with options (`choice`: for each question an option, several where it allows, or typed
//! text in place), or a turn that ended (`idle`: typed text, or "Leave it stopped"). Its text is the
//! agent's: halti did not write it and can't check it. `GET /v1/questions`, no body: `200
//! {"questions": [{"machine": "server-1", "record": "<bytes>", "sealed": "<bytes>"}]}`, every
//! question in the phone's workspaces that its machine sealed to this phone, from every machine, in
//! the order of the machines' names, then of the ids. A question leaves the list once its machine
//! closed it (answered, or withdrawn: the agent went on, its run ended or is no longer marked away,
//! the workspace closed), and a minute after its expiry by the hub's clock at the latest.
//!
//! The notice of its agent's session stays in the notices list while the question waits: an app
//! that reads no questions (it sends no `questions_seen`), or a hub that carries none, still tells
//! the owner of the wait, as before there were questions. An app that lists questions shows the
//! question in the notice's place: it hides a notice whose machine, workspace, box, run and session
//! are those of a question it lists. Once the question is answered its notice is closed; when it
//! ends with the agent still waiting, its notice is replaced by a new one with the reason
//! (above).
//!
//! `record` is the question's clear fields, a run of fields as above, in this order and nothing
//! else:
//!
//! | Field | Bytes |
//! |---|---|
//! | label | `halti-question-v1` |
//! | machine | the machine's name at the hub |
//! | ws | the workspace's name |
//! | box | the box's name, a name as a device's is |
//! | run | the run id (8) |
//! | session | the agent session's number in that run, 1 to 8, 4 bytes big-endian |
//! | kind | `permit`, `choice` or `idle` |
//! | id | 16 bytes the machine drew for this question |
//! | expiry | seconds since 1970 by the machine's clock, 8 bytes big-endian: 8 hours at most, and never past the mark's end |
//!
//! `sealed` is sealed text by the machine key to this phone's agreement key, label
//! `halti-sealed-question-v1`, the clear fields the associated data. Its plaintext, the sealed
//! fields, is a run of fields: a salt (16), the **reply key** (91: a P-256 public key the machine
//! made for this question alone), then, by kind:
//!
//! | Kind | Fields after the salt and reply key |
//! |---|---|
//! | `permit` | left out (4), the tool's name (0 to 80), its input as JSON (0 to 2,000, cut at its end) |
//! | `choice` | left out (4), then 1 to 4 questions, each one field that is itself a run of: header (0 to 80), question (0 to 300), `0` or `1` (several options may be taken), then 0 to 4 options, each its label (0 to 80) and description (0 to 200) |
//! | `idle` | left out (4), the end of the agent's last message (0 to 2,000, cut at its start) |
//!
//! Text is UTF-8. `left out` is how many bytes of what the agent wrote were cut to fit, 4 bytes
//! big-endian, the box's own count: the app shows it above the buttons. The **whole record** is the
//! clear fields followed by the plaintext, at most 8 KiB; the app reads it whole or not at all,
//! opens `sealed` only under the key it compared for the machine the record names, shows it only for
//! a machine and workspace it compared, and computes the SHA-256 of the whole record as it showed it.
//!
//! **Answering one.** After fingerprint or PIN each time, the app builds the answer's form and
//! content from what it showed:
//!
//! | Kind | Form | Content |
//! |---|---|---|
//! | `permit` | `yes` | nothing |
//! | `permit` | `no` | the reason typed, 0 to 2,000 bytes |
//! | `choice` | `options` | for each question of the record, in order, two fields: the option numbers taken, one byte each from 1, rising, one unless the question takes several; and the text typed in place of an option; exactly one of the two empty; all text together at most 2,000 bytes |
//! | `idle` | `text` | the text typed, 1 to 2,000 bytes |
//! | `idle` | `stopped` | nothing: "Leave it stopped" |
//!
//! It draws 16 random bytes of salt and signs with the signing key the fields `halti-answer-v1`, the
//! SHA-256 of the whole record (32), the form, and the SHA-256 of the salt followed by the content
//! (32). It never signs a hash it was handed. It seals, by its agreement key to the reply key, label
//! `halti-sealed-answer-v1`, the record's clear fields as the associated data, the fields: form,
//! salt (16), content, signature (DER). Then `POST /v1/reply`, body `{"machine": "server-1", "id":
//! "<16 bytes>", "sealed": "<bytes>"}`, at most 8 KiB, the sealed bytes 81 to 3,072: `202 {"n": 9}`,
//! the number of what it sent, for `GET /v1/state`. A question the hub doesn't hold, or not sealed
//! to this phone, is `410 gone`. The hub can read none of it; only the machine opens and checks it:
//! the device is trusted there for that workspace, the answer opens under the reply key and the
//! device's agreement key, the signature is the device's over the machine's own record, the
//! question still waits and its time isn't over, and the answer fits it (a form of its kind, option
//! numbers it offers, text within the caps). The first answer that counts goes to the agent.
//!
//! **The receipt.** The entry of `sent` (below) for a reply holds the machine's word and, once the
//! machine has said it, `"receipt": "<bytes>"`: sealed text by the machine key to this phone,
//! label `halti-sealed-receipt-v1`, whose associated data are the fields `halti-receipt-v1`, the
//! machine, the workspace and the question's id (16), which the app builds from what it sent; and
//! whose plaintext is the fields: the SHA-256 of the signed bytes as the machine rebuilt them (32;
//! all zeros for an answer that didn't open), then one word: `delivered` (handed to the agent's
//! waiting hook, for a `choice` or an `idle`), `maybe-unused` (handed to it, for a `permit`),
//! `not-pending` (answered already, withdrawn, or the agent no longer waits), `expired`,
//! `does-not-fit`, `bad-signature`, `untrusted` (not trusted there for that workspace) or
//! `unreadable`. The app takes as delivered only a receipt that opens under the key it compared for
//! that machine and names the hash of what it signed; until then the answer is "sent, not
//! confirmed". A phone not trusted there at all gets no receipt: the word alone, `refused`. The hub
//! and a holder of the machine's token can make no receipt that opens.
//!
//! A `permit` is never `delivered`. While its hook waits, Claude Code shows its own permission
//! dialog at the terminal too, and an answer there (Yes, No or Esc) doesn't end the hook: Claude
//! Code then ignores what the hook says later, and no hook tells halti after a No or an Esc. So the
//! machine can't know whether the answer was used, and says `maybe-unused`. The app shows it as
//! neither done nor refused, for example: "Handed to the agent. Its terminal shows the same prompt:
//! if it was answered there first, this answer was not used." A `choice` or an `idle` the terminal
//! can't answer while its hook waits (the question isn't on the screen; what the owner types after
//! a turn's end withdraws the question at once), so theirs is `delivered`.
//!
//! The known answers of the record, the signed bytes, the sealed answer and the receipt are in
//! `tests/fixtures/question-vectors.json`.
//!
//! **Stopping runs.** The app signs, after fingerprint or PIN, these fields, in this order and
//! nothing else:
//!
//! | Field | Bytes |
//! |---|---|
//! | label | `halti-stop-v1` |
//! | machine | the machine's name at the hub |
//! | ws | the workspace's name |
//! | box | the first run's box, a name as a device's is, as `GET /v1/state` listed it with that run |
//! | run | the first run's id (8) |
//!
//! then a box and a run for each further run, in the order sent: 1 to 32 runs, so 5 to 67 fields.
//! The app signs only runs it showed, each with the box it showed it under. Then `POST /v1/stop`,
//! body `{"machine": "server-1", "ws": "acme", "runs": [{"box": "dev", "run": "<8 bytes>"}, ...],
//! "signature": "<DER>"}`, the same runs and boxes in the same order: `202 {"n": 8}`. The machine
//! stops each of those runs it has under the box named with it. It doesn't stop one it has under
//! another box, and says so (`wrong-box` below); one it doesn't have it passes over, so a stop sent
//! again stops nothing new. "Stop all" is one stop for each workspace the machine shows, naming
//! every run it shows there.
//!
//! **Confirming a stop.** A stop is `sent, not confirmed` until its entry in `sent` of
//! `GET /v1/state` (below), found by its `n`, holds the machine's word: that entry is the only
//! confirmation. A run the machine stopped leaves its `runs` as soon as the run ends, in the
//! machine's next report, which may reach the hub before the word or after it; and a run that ends
//! by itself leaves the same way. So the app never takes a run no longer listed as a stop
//! confirmed, nor a run still listed as one refused. The entry stays after the run is gone, for as
//! long as `sent` says.
//!
//! **State.** `GET /v1/state`, no body: `200`
//!
//! ```json
//! {"machines": [{"name": "server-1", "key": "<91 bytes>", "ws": ["acme"], "conflict": null,
//!                "reported": "<time>", "since": "<time>",
//!                "workspaces": [{"name": "acme", "open": true,
//!                                "runs": [{"box": "dev", "run": "<8 bytes>"}]}]}],
//!  "sent": [{"n": 7, "kind": "answer", "machine": "server-1", "ws": "acme", "id": "<16 bytes>",
//!            "state": "approved", "at": "<time>"},
//!           {"n": 8, "kind": "stop", "machine": "server-1", "ws": "acme",
//!            "runs": [{"box": "dev", "run": "<8 bytes>"}], "state": "stopped", "at": "<time>"}]}
//! ```
//!
//! - `machines`: each machine whose last report says it trusts this phone, for workspaces of the
//!   phone's. `key` is the machine's key from its join; `ws` the workspaces it trusts the phone
//!   for. The app computes the machine code from `name`, `key` and `ws` for its Machines screen, and
//!   lists the machine as waiting to be compared until the person there taps "same". A machine that
//!   is no longer listed was revoked or hasn't reported since the hub started: the app keeps what it
//!   compared, and shows it as not reporting. `conflict` is the time the hub marked its token as
//!   used from two places, or null. `reported` is the hub's time of its last report; one older than
//!   a minute is not reporting. `since` changes when the machine's link starts again: a restart.
//!   `workspaces` are those of `ws` it reports, open or closed, each with the runs of its boxes.
//! - `sent`: what this phone sent each machine in the last hour by the hub's clock, the last 64 for
//!   each machine, by `n`. What other phones send never pushes an entry out; a hub restart forgets
//!   them all, and a stop then not confirmed may be sent again. `state` is `queued` (the machine
//!   hasn't taken it), `taken` (it has, and said nothing yet), or the machine's word: for an answer
//!   `approved`, `denied`, `gone` (no such request waits there: it was answered, expired, or
//!   withdrawn) or `refused` (not signed by a device trusted there for that workspace, over that
//!   request); for a stop `stopped` (it stopped at least one of the runs named, and named every one
//!   that runs there with its box), `none` (no run named runs there), `wrong-box` (at least one run
//!   named runs there under another box: none of those was stopped, and each of the others that
//!   runs there under the box named with it was), or `refused` (not signed by a device trusted
//!   there for that workspace, over those fields); for a reply, the receipt's word, or `refused`;
//!   for any `unreached` (that workspace isn't open there), `malformed` or `unknown` (a machine of
//!   an older halti). A reply's entry also has its `id`, and `receipt` once there is one.
//!   The hub can lie about all of it; the machine's own word reaches the phone only through it.
//!
//! # What a machine does
//!
//! A machine's link holds its token; every call below takes it, and a phone's gets
//! `403 wrong-kind`. The hub takes the machine's name from its token row.
//!
//! **Reporting.** `POST /v1/machine/state`, at most 16 KiB, when what it reports changed and at
//! least every 20 seconds:
//!
//! ```json
//! {"link": "<16 bytes>", "workspaces": [{"name": "acme", "open": true,
//!                                        "runs": [{"box": "dev", "run": "<8 bytes>"}]}],
//!  "trusted": [{"device": "pixel", "ws": ["acme"]}], "requests": ["<16 bytes>", ...]}
//! ```
//!
//! `link` is drawn as the link starts. `workspaces` are those a trusted phone may see, at most 64,
//! each with at most 32 runs; `trusted` the phones it trusts, at most 64; `requests` the ids of every
//! request that waits in those workspaces, at most 256. A machine with more reports that many and
//! answers the rest itself. `200 {"devices": [...], "missing": ["<16 bytes>", ...]}`. The hub drops
//! each request of this machine's that isn't listed, and `missing` names those listed that it
//! doesn't hold, as many as it has room for (50 in all): the link posts each of them. `devices`
//! lists every phone not revoked whose workspaces meet those in `trusted`, as
//! `POST /v1/machine/device` gives one. The link drops its trust in every phone that isn't on that
//! list with the same keys; a list it can't read whole changes nothing. A phone whose token expired
//! stays on it.
//!
//! **Posting a request.** `POST /v1/machine/request`, body `{"record": "<bytes>"}`: `200 {}`, also
//! for one held already. A record that names another machine is `403 other-machine`; one past its
//! expiry by more than a minute of the hub's clock is `410 gone`; one more than the hub holds for a
//! machine, 50, is `429 full`.
//!
//! **Taking what phones sent.** `POST /v1/machine/inbox`, body `{"done": [{"n": 7, "said":
//! "approved"}, ...]}`, at most 64, each word 1 to 16 of a-z and `-`: what came of what it took
//! before, and for a reply the receipt it sealed, as `"receipt": "<bytes>"`, 81 to 256 bytes. Those
//! leave the hub's queue. Then the call waits until something is queued for this machine, at most
//! 25 seconds, and answers `200 {"items": [...]}`, every item still queued, those taken before and
//! not said done included, oldest first:
//!
//! ```json
//! {"n": 7, "kind": "answer", "device": "pixel", "ws": "acme", "id": "<16 bytes>",
//!  "decision": "yes", "signature": "<DER>"}
//! {"n": 8, "kind": "stop", "device": "pixel", "ws": "acme",
//!  "runs": [{"box": "dev", "run": "<8 bytes>"}], "signature": "<DER>"}
//! {"n": 9, "kind": "reply", "device": "pixel", "ws": "acme", "id": "<16 bytes>",
//!  "sealed": "<bytes>"}
//! ```
//!
//! The link calls again at once; when the hub can't be reached it waits, longer each time, up to a
//! minute. An item of a kind it doesn't know is said `unknown` and nothing is done with it. At most
//! 64 items wait for one machine; one more is `429 full` to the phone that sent it.
//!
//! **Notices.** `POST /v1/machine/notices`, body `{"notices": ["<16 bytes>", ...]}`, at most 50:
//! the ids of every notice that is open in the workspaces a trusted phone may see. The hub closes
//! each of this machine's notices that isn't listed, and answers `200 {"missing": ["<16 bytes>",
//! ...]}`, those listed that it doesn't hold, as many as it has room for (50 in all). The link
//! posts each: `POST /v1/machine/notice`, body `{"record": "<bytes>", "sealed": [{"device":
//! "pixel", "sealed": "<bytes>"}, ...]}`, a copy for each phone trusted for its workspace, 1 to 64,
//! each 81 to 256 bytes: `200 {}`. For one held already with the same record, these copies take
//! the place of those held: the link posts a notice again when the phones trusted for its workspace
//! change. A record that names another machine is `403 other-machine`; one more than the hub
//! holds, `429 full`. The link calls with each report, and when the notices change.
//!
//! **Questions.** `POST /v1/machine/questions`, body `{"questions": [{"id": "<16 bytes>",
//! "devices": ["pixel", ...]}, ...]}`, at most 20 questions and 16 KiB: every question that waits in
//! the workspaces a trusted phone may see, each with the phones it is sealed to. The hub drops each
//! of this machine's questions not listed, and each copy of a phone not named, and answers `200
//! {"missing": [{"id": "<16 bytes>", "device": "pixel"}, ...]}`, the copies it lacks, of as many
//! questions as it has room for (20 in all). The link posts each: `POST /v1/machine/question`, body
//! `{"record": "<bytes>", "device": "pixel", "sealed": "<bytes>"}`, at most 20 KiB, the record the
//! question's clear fields and the copy 81 to 8,273 bytes: `200 {}`. It takes the place of that
//! phone's copy of a question held already with the same record; another record of the same id is
//! `400 malformed`, one that names another machine `403 other-machine`, one past its expiry by more
//! than a minute `410 gone`, one more than the hub holds `429 full`. The open workspace seals the
//! copies itself, as it alone holds the text; the link only carries them.
//!
//! **A phone's keys.** `POST /v1/machine/device`, body `{"name": "pixel"}`: `200 {"name": "pixel",
//! "signing_key": "<91 bytes>", "agreement_key": "<91 bytes>", "key_signature": "<DER>", "ws":
//! ["acme"]}`, or `410 gone`. `halti devices trust` shows the signing key's fingerprint to compare
//! with the phone, and checks `key_signature`.
//!
//! **Its token.** From day 10 the link draws a new token, writes it down, then renews. If no reply
//! comes, it calls `GET /v1/me` with the new token before anything else, and sends nothing with
//! the old token until that call is answered: `200` means the renewal was made, `401 unknown` that
//! it wasn't, and the old token is used again. A call that gets no reply is tried again, with the
//! new token, since the hub may have seen it: the old token stops once the new one is first used.
//!
//! # Errors
//!
//! Every refusal is a status and the body `{"error": "<word>"}`; an expired phone token's also has
//! `"renewable_until": "<time>"`.
//!
//! | Status | Word | When |
//! |---|---|---|
//! | 400 | `malformed` | The body isn't the JSON of that call: a field missing or unknown, bad hex, a wrong length, a bad name, a key not on the curve, a new token hash equal to one the row holds |
//! | 401 | `no-token` | No `Authorization: Bearer` with a token of the right form; at `/v1/wait`, no `Authorization: Wake` with a credential of the right form |
//! | 401 | `unknown` | No such token or wake credential: never paired, refused at the terminal, revoked, deleted, a phone's replaced token after it stopped working, or a machine's 90 days after its issue |
//! | 401 | `pending` | Paired, and nobody has answered at the hub's terminal yet |
//! | 401 | `expired` | Past day 30, for a call it no longer admits |
//! | 401 | `replaced` | A phone's replaced token, sent to a renewal call |
//! | 401 | `conflict` | A machine's replaced token (see Token conflict) |
//! | 403 | `wrong-kind` | A machine's token at a phone's call (`/v1/renew/nonce` and those of "What a phone does"), or a phone's at a machine's, or any token at `/v1/wait` |
//! | 403 | `other-machine` | A machine's record or notice that names another machine |
//! | 403 | `bad-code` | The pairing code is unknown, used, past its 2 minutes, or of the other kind |
//! | 403 | `bad-signature` | A signature does not verify |
//! | 403 | `bad-nonce` | The nonce is unknown, used or past its 2 minutes |
//! | 403 | `too-early` | A machine's renewal before day 10 |
//! | 404 | `not-found` | No such path |
//! | 405 | `method` | The path takes another method |
//! | 409 | `conflict` | A renewal of a machine whose row is marked |
//! | 410 | `gone` | The request, machine or phone a call names isn't held: answered, withdrawn, expired, hidden, revoked, never there, or outside the phone's workspaces |
//! | 413 | `too-large` | A body over its limit |
//! | 429 | `full` | One request, notice, question, answer or stop more than the hub holds for that machine |
//! | 503 | `unavailable` | A renewal the hub could not write down: nothing changed, and the token sent still works. Try again later |
//!
//! Every word is 1 to 16 of a-z and `-`. A client shows these words, never a body as text, and
//! shows nothing it got in place of a word that isn't one.

use std::fmt;

use halti_core::device::{self, DeviceKey};
use halti_core::ids::WsName;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::fields;
use crate::requests::RunId;
use crate::util::{self, hex};

/// What the signing key signs to vouch for the agreement key.
pub const KEYS_LABEL: &str = "halti-device-keys-v1";
/// What a phone signs to pair.
pub const PAIR_LABEL: &str = "halti-pair-v1";
/// What a phone signs to renew its token.
pub const RENEW_LABEL: &str = "halti-renew-v1";
/// What a phone signs to stop runs.
pub const STOP_LABEL: &str = "halti-stop-v1";
/// What a machine code is a hash of.
pub const MACHINE_CODE_LABEL: &str = "halti-machine-code-v1";
/// What a phone's wake credential is a hash of.
pub const WAKE_LABEL: &str = "halti-wake-v1";

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

/// What a phone signs to stop runs of a workspace on a machine: the label, the machine, the
/// workspace, then for each run the name of the box it was shown under and its 8 bytes, each a field
/// of its own.
pub fn stop_bytes(machine: &str, ws: &str, runs: &[(String, RunId)]) -> Vec<u8> {
    let mut bytes = fields::join(&[STOP_LABEL.as_bytes(), machine.as_bytes(), ws.as_bytes()]);
    for (box_name, run) in runs {
        fields::push(&mut bytes, box_name.as_bytes());
        fields::push(&mut bytes, &run.0);
    }
    bytes
}

/// The machine code people compare at `halti devices trust`: the first 10 bytes of the SHA-256 of
/// the label, the machine's name, its key, then each workspace the device is trusted for there,
/// in byte order, each once.
pub fn machine_code(machine: &str, key: &[u8], ws: &[String]) -> String {
    let mut ws: Vec<&str> = ws.iter().map(String::as_str).collect();
    ws.sort_unstable();
    ws.dedup();
    let mut bytes = fields::join(&[MACHINE_CODE_LABEL.as_bytes(), machine.as_bytes(), key]);
    for name in ws {
        fields::push(&mut bytes, name.as_bytes());
    }
    groups(&Sha256::digest(&bytes)[..10])
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

pub(super) fn json<'a, T: Deserialize<'a>>(body: &'a [u8]) -> Result<T, Refused> {
    serde_json::from_slice(body).map_err(|_| Refused::Malformed)
}

pub(super) fn bytes<const N: usize>(text: &str) -> Result<[u8; N], Refused> {
    unhex(text).ok_or(Refused::Malformed)
}

fn key(text: &str) -> Result<Vec<u8>, Refused> {
    util::unhex(text).filter(|key| key.len() == KEY_LEN).ok_or(Refused::Malformed)
}

pub(super) fn signature(text: &str) -> Result<Vec<u8>, Refused> {
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

/// The wake credential of the token with this hash.
pub fn wake_of(token_hash: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(fields::join(&[WAKE_LABEL.as_bytes(), token_hash])).into()
}

/// The wake credential in an `Authorization` header's value, if it is one: `Wake `, then 64
/// lowercase hex characters.
pub fn wake(value: &str) -> Option<[u8; 32]> {
    unhex(value.strip_prefix("Wake ")?)
}

/// The body of `POST /v1/wait`. Fields it doesn't know are passed over, so an app newer or older
/// than the hub still waits.
#[derive(Deserialize)]
struct WaitBody {
    seen: String,
    notices_seen: Option<String>,
    questions_seen: Option<String>,
}

/// What a waiting phone was last told.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Seen {
    /// The hash of the requests' ids, or None for none.
    pub requests: Option<[u8; 32]>,
    /// From an app that is told of notices: the hash of their ids, or None for none.
    pub notices: Option<Option<[u8; 32]>>,
    /// From an app that is told of questions: the hash of their ids, or None for none.
    pub questions: Option<Option<[u8; 32]>>,
}

pub fn wait_body(body: &[u8]) -> Result<Seen, Refused> {
    let body: WaitBody = json(body)?;
    let hash = |text: &str| if text.is_empty() { Ok(None) } else { bytes(text).map(Some) };
    Ok(Seen { requests: hash(&body.seen)?, notices: body.notices_seen.as_deref().map(hash).transpose()?, questions: body.questions_seen.as_deref().map(hash).transpose()? })
}

/// The hash of these ids, sorted, as a waiting phone names what it was told; None for none.
pub fn seen_of(ids: &[[u8; 16]]) -> Option<[u8; 32]> {
    let mut sorted = ids.to_vec();
    sorted.sort();
    (!sorted.is_empty()).then(|| Sha256::digest(sorted.concat()).into())
}

/// Exactly `N` bytes from lowercase hex.
pub fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    util::unhex(text)?.try_into().ok()
}

/// Whether `text` is a word as the wire's replies and a machine's `said` give them: 1 to 16 of a-z
/// and `-`. A client shows only such words from a hub.
pub fn is_word(text: &str) -> bool {
    (1..=16).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
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
    groups(&device::fingerprint(signing_key)[..10])
}

/// Bytes as lowercase hex in groups of four characters with a space between.
fn groups(bytes: &[u8]) -> String {
    hex(bytes).as_bytes().chunks(4).map(|group| String::from_utf8_lossy(group).into_owned()).collect::<Vec<_>>().join(" ")
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
    /// The request, machine or device a call names isn't held: answered, withdrawn, expired,
    /// hidden, revoked, never there, or outside the caller's workspaces.
    Gone,
    /// A machine's record that names another machine.
    OtherMachine,
    /// As many as the hub holds of that kind for that machine.
    Full,
}

impl Refused {
    pub fn status(self) -> u16 {
        match self {
            Refused::Malformed => 400,
            Refused::NoToken | Refused::Unknown | Refused::Pending | Refused::Expired(_) | Refused::Replaced | Refused::Conflict => 401,
            Refused::WrongKind | Refused::BadCode | Refused::BadSignature | Refused::BadNonce | Refused::TooEarly | Refused::OtherMachine => 403,
            Refused::NotFound => 404,
            Refused::Method => 405,
            Refused::Marked => 409,
            Refused::Gone => 410,
            Refused::TooLarge => 413,
            Refused::Full => 429,
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
            Refused::Gone => "gone",
            Refused::OtherMachine => "other-machine",
            Refused::Full => "full",
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

    // A second key and its known answers, made the same way: a stop, and a machine code.
    const OPENSSL_KEY: &str = "3059301306072a8648ce3d020106082a8648ce3d03010703420004ad474f6ad6407053a2fdb194da78b401e1c5768d31d9db888c3996aeeecc3747d9\
        4a1ea3f9aa90bc2e5cdec1617c9a4738cf570e9c62843d0fe5ce95a75e198d";
    const STOP_BYTES: &str = "000d68616c74692d73746f702d763100056d61632d31000461636d65000364657600080102030405060708000377656200081112131415161718";
    const STOP_SHA256: &str = "63205eeef68b4432afcf5f1a58566a5fe4221b3021cd4b4722a60e01dfabf40e";
    const STOP_SIGNATURE: &str = "3046022100eb21a20a20400be8e43b514218b4d39811d52e7209e79836d380ff9d9d6539910221008413713fb277e89f631e0767e1019bafacea1eebaf01a443\
        8933390dc01f8c1e";
    const MACHINE_CODE: &str = "0813 369a 1400 9098 7602";
    const OPENSSL_FINGERPRINT: &str = "ca72 9ca9 e915 a0f0 5614";

    fn bytes(text: &str) -> Vec<u8> {
        util::unhex(text).unwrap()
    }

    /// Two runs and the boxes they were shown under: dev's 01 to 08, web's 11 to 18.
    fn runs() -> [(String, RunId); 2] {
        [("dev".into(), RunId([1, 2, 3, 4, 5, 6, 7, 8])), ("web".into(), RunId([0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]))]
    }

    #[test]
    fn a_stop_is_signed_over_the_machine_the_workspace_and_each_run_with_its_box() {
        assert_eq!(hex(&stop_bytes("mac-1", "acme", &runs())), STOP_BYTES);
        assert_eq!(hex(&Sha256::digest(bytes(STOP_BYTES))), STOP_SHA256);
        let key = DeviceKey::from_spki(&bytes(OPENSSL_KEY)).unwrap();
        assert_eq!(key.verify(&stop_bytes("mac-1", "acme", &runs()), &bytes(STOP_SIGNATURE)), Ok(()));
        // Another machine, workspace, run, order, or box named with a run is another stop.
        let [first, second] = runs();
        let swapped = [(second.0.clone(), first.1), (first.0.clone(), second.1)];
        for other in [
            stop_bytes("mac-2", "acme", &runs()),
            stop_bytes("mac-1", "beta", &runs()),
            stop_bytes("mac-1", "acme", std::slice::from_ref(&first)),
            stop_bytes("mac-1", "acme", &[second, first]),
            stop_bytes("mac-1", "acme", &swapped),
        ] {
            assert!(key.verify(&other, &bytes(STOP_SIGNATURE)).is_err());
        }
    }

    #[test]
    fn a_machine_code_covers_the_name_the_key_and_the_workspaces_in_order() {
        let key = bytes(OPENSSL_KEY);
        assert_eq!(fingerprint(&key), OPENSSL_FINGERPRINT);
        assert_eq!(machine_code("server-1", &key, &["acme".into(), "beta".into()]), MACHINE_CODE);
        // The order they were named in, and a name twice, change nothing.
        assert_eq!(machine_code("server-1", &key, &["beta".into(), "acme".into(), "beta".into()]), MACHINE_CODE);
        // Another name, key or set of workspaces is another code.
        let other_key = bytes(SIGNING_KEY);
        for other in [
            machine_code("server-2", &key, &["acme".into(), "beta".into()]),
            machine_code("server-1", &other_key, &["acme".into(), "beta".into()]),
            machine_code("server-1", &key, &["acme".into()]),
        ] {
            assert_ne!(other, MACHINE_CODE);
        }
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
            (Refused::Gone, 410, "gone"),
            (Refused::OtherMachine, 403, "other-machine"),
            (Refused::Full, 429, "full"),
        ];
        for (refused, status, word) in all {
            assert_eq!((refused.status(), refused.word()), (status, word));
            assert_eq!(refused.body(), serde_json::json!({"error": word}));
        }
        assert_eq!(Refused::Expired(Some(until)).body(), serde_json::json!({"error": "expired", "renewable_until": "2027-02-13T10:00:00Z"}));
    }
}
