//! The hub's table: one row for each paired phone and machine, by name, with the hash of its token
//! and how long that token lives. The hub keeps nothing else about them, and no key of any
//! workspace: a row holds public keys only.
//!
//! Pairings that are under way and the renewal nonces already used are held beside the rows, in
//! memory only. Every rule here takes the time as an argument, so the tests can be any day of a
//! token's life; the hub passes its own clock. The numbers of a token's life are the constants
//! below, and nowhere else.

use std::collections::{BTreeMap, HashMap};

use halti_core::device::DeviceKey;
use halti_core::ids::WsName;
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};

use super::wire::{self, DeviceRenewal, JoinRequest, Kind, PairRequest, Refused};

/// How long a token works from its issue.
pub const LIFE: SignedDuration = SignedDuration::from_hours(30 * 24);
/// A machine may renew from this far into its token's life, and not before.
pub const MACHINE_RENEW_FROM: SignedDuration = SignedDuration::from_hours(10 * 24);
/// How long after its token's day 30 a phone may still renew it. A machine has no such time.
pub const LATE_RENEWAL: SignedDuration = SignedDuration::from_hours(60 * 24);
/// How long a row is kept from its token's issue, if the token is never renewed: then it is deleted.
/// A phone's last renewal is on the last day of it. A machine's earlier tokens are kept as long.
pub const KEPT: SignedDuration = SignedDuration::from_hours((30 + 60) * 24);
/// How long the token a renewal replaced keeps working, at most: until the new one is first used.
pub const OLD_TOKEN: SignedDuration = SignedDuration::from_hours(24);
/// How long a pairing code is good for, unused.
pub const CODE_LIFE: SignedDuration = SignedDuration::from_secs(120);
/// How long a renewal nonce is good for.
pub const NONCE_LIFE: SignedDuration = SignedDuration::from_secs(120);
/// Seconds in a day, for counting a token's days left.
const DAY_SECS: i64 = 24 * 3600;
/// How often a row's "last seen" time moves, and so is written down, at most.
const SEEN_EVERY: SignedDuration = SignedDuration::from_secs(60);

/// A paired phone or machine.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub name: String,
    /// What a phone may see; a machine has none.
    pub ws: Vec<WsName>,
    pub keys: Keys,
    /// A phone's push address, empty for none.
    pub push: String,
    pub push_changed: Option<Timestamp>,
    pub paired: Timestamp,
    pub token: Token,
    /// The token the last renewal replaced.
    pub old: Option<OldToken>,
    /// A machine's tokens before the one it holds, the one in `old` too, each until `KEPT` after its
    /// issue: any of them used again marks the row, as a copy's would.
    #[serde(default)]
    pub retired: Vec<Token>,
    /// When the hub saw this machine's token used from two places.
    pub conflict_since: Option<Timestamp>,
    pub last_seen: Option<Timestamp>,
}

/// The public keys a row holds.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum Keys {
    Device {
        #[serde(with = "hexed")]
        signing: Vec<u8>,
        #[serde(with = "hexed")]
        agreement: Vec<u8>,
        /// The signing key's signature over the agreement key.
        #[serde(with = "hexed")]
        binding: Vec<u8>,
    },
    Machine {
        #[serde(with = "hexed")]
        key: Vec<u8>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Token {
    #[serde(with = "hexed32")]
    pub hash: [u8; 32],
    pub issued: Timestamp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OldToken {
    #[serde(with = "hexed32")]
    pub hash: [u8; 32],
    /// It works until this time, and not after.
    pub until: Timestamp,
}

impl Row {
    pub fn kind(&self) -> Kind {
        match self.keys {
            Keys::Device { .. } => Kind::Device,
            Keys::Machine { .. } => Kind::Machine,
        }
    }

    pub fn expires(&self) -> Timestamp {
        self.token.issued + LIFE
    }

    /// The last moment a renewal is taken.
    pub fn renewable_until(&self) -> Timestamp {
        match self.kind() {
            Kind::Device => self.expires() + LATE_RENEWAL,
            Kind::Machine => self.expires(),
        }
    }

    /// The first moment a renewal is taken.
    pub fn renew_from(&self) -> Timestamp {
        match self.kind() {
            Kind::Device => self.token.issued,
            Kind::Machine => self.token.issued + MACHINE_RENEW_FROM,
        }
    }

    /// Whether the row reads as the hub wrote it: names, keys and workspaces checked as when it was
    /// made.
    fn check(&self) -> Result<(), String> {
        wire::check_name(&self.name).map_err(|_| "a row's name isn't one".to_string())?;
        match &self.keys {
            Keys::Device { signing, agreement, binding } => {
                let key = DeviceKey::from_spki(signing).map_err(|_| format!("{}'s signing key isn't one", self.name))?;
                halti_core::device::check_agreement_key(agreement).map_err(|_| format!("{}'s second key isn't one", self.name))?;
                key.verify(&wire::keys_bytes(signing, agreement), binding).map_err(|_| format!("{}'s keys aren't signed", self.name))?;
                if self.ws.is_empty() {
                    return Err(format!("{} has no workspaces", self.name));
                }
            }
            Keys::Machine { key } => halti_core::device::check_agreement_key(key).map_err(|_| format!("{}'s machine key isn't one", self.name))?,
        }
        Ok(())
    }
}

/// What a pairing's claim brought: the keys and the token hash it will be paired with.
#[derive(Clone, Debug)]
pub enum Claim {
    Device { signing: Vec<u8>, agreement: Vec<u8>, binding: Vec<u8>, token_hash: [u8; 32], push: String },
    Machine { key: Vec<u8>, token_hash: [u8; 32] },
}

impl Claim {
    fn token_hash(&self) -> &[u8; 32] {
        match self {
            Claim::Device { token_hash, .. } | Claim::Machine { token_hash, .. } => token_hash,
        }
    }
}

/// A pairing under way: `halti pair` waits for it to be claimed and answered.
#[derive(Clone, Debug)]
pub struct Pairing {
    pub id: u64,
    code: [u8; 16],
    pub kind: Kind,
    pub name: String,
    pub ws: Vec<WsName>,
    /// The code is taken until this time.
    pub until: Timestamp,
    pub claim: Option<Claim>,
}

/// Who a token belongs to, once checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    pub name: String,
    pub kind: Kind,
}

/// What `halti devices` shows of a row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listed {
    pub name: String,
    pub kind: Kind,
    pub ws: Vec<String>,
    /// A phone's fingerprint, as people compare it.
    pub fingerprint: Option<String>,
    pub last_seen: Option<Timestamp>,
    pub token: TokenState,
    pub conflict_since: Option<Timestamp>,
    pub push_changed: Option<Timestamp>,
}

/// Where a token is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum TokenState {
    /// Days left, a part of one counted whole: a token just made has 30, one in its last day 1.
    Left { days: i64 },
    /// A phone's, past day 30: renewable until then.
    Renewable { until: Timestamp },
    /// A machine's, past day 30: it joins again.
    Expired,
}

/// The rows, the pairings under way, and the renewal nonces used, each with the time it stops
/// being good anyway. The hub keeps no nonce it gives out (see `Table::nonce`).
#[derive(Clone, Default)]
pub struct Table {
    rows: BTreeMap<String, Row>,
    pairings: Vec<Pairing>,
    used: HashMap<[u8; 16], Timestamp>,
    next_id: u64,
    /// Whether the rows changed since they were last written down.
    dirty: bool,
}

/// Why a pairing can't be started or finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotPaired {
    /// A row has the name.
    Taken,
    /// A row has the name and is marked `token conflict`: only a revoke frees it.
    Marked,
    /// Another pairing under way has the name.
    Busy,
    /// The pairing is gone: refused, its code expired unclaimed, or never there.
    Gone,
}

/// Compared in the same time whatever the bytes, so a reply's timing tells nothing of a code.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl Table {
    /// The rows as the hub wrote them, each checked.
    pub fn from_rows(rows: Vec<Row>) -> Result<Table, String> {
        let mut table = Table::default();
        for row in rows {
            row.check()?;
            if table.rows.insert(row.name.clone(), row).is_some() {
                return Err("two rows have one name".into());
            }
        }
        Ok(table)
    }

    /// The rows, to write down.
    pub fn rows(&self) -> Vec<Row> {
        self.rows.values().cloned().collect()
    }

    /// Whether the rows changed since the last call, which clears it.
    pub fn take_dirty(&mut self) -> bool {
        std::mem::take(&mut self.dirty)
    }

    /// Notes that the rows are not written down as they are, so the next call writes them.
    pub fn set_dirty(&mut self) {
        self.dirty = true;
    }

    /// Deletes every row whose token was issued `KEPT` ago or more, and a machine's earlier tokens
    /// as old. For a phone this is a revoke.
    pub fn purge(&mut self, now: Timestamp) {
        let before = self.rows.len();
        self.rows.retain(|_, row| now < row.token.issued + KEPT);
        self.dirty |= self.rows.len() != before;
        for row in self.rows.values_mut() {
            let before = row.retired.len();
            row.retired.retain(|token| now < token.issued + KEPT);
            self.dirty |= row.retired.len() != before;
        }
        self.used.retain(|_, until| now < *until);
        self.pairings.retain(|p| p.claim.is_some() || now < p.until);
    }

    /// Whether a row lets a new pairing of `kind` take `name`: none has it, or a machine's whose
    /// token has expired, which a machine's pairing replaces. A marked row is never replaced.
    fn row_free(&self, kind: Kind, name: &str, now: Timestamp) -> Result<(), NotPaired> {
        match self.rows.get(name) {
            None => Ok(()),
            Some(row) if row.conflict_since.is_some() => Err(NotPaired::Marked),
            Some(row) if kind == Kind::Machine && row.kind() == Kind::Machine && now >= row.expires() => Ok(()),
            Some(_) => Err(NotPaired::Taken),
        }
    }

    /// Starts a pairing of `name`, with `code`, which the caller drew. Its id comes back.
    pub fn start(&mut self, kind: Kind, name: &str, ws: Vec<WsName>, code: [u8; 16], now: Timestamp) -> Result<u64, NotPaired> {
        self.purge(now);
        self.row_free(kind, name, now)?;
        if self.pairings.iter().any(|p| p.name == name) {
            return Err(NotPaired::Busy);
        }
        self.next_id += 1;
        self.pairings.push(Pairing { id: self.next_id, code, kind, name: name.to_string(), ws, until: now + CODE_LIFE, claim: None });
        Ok(self.next_id)
    }

    /// The pairing with this id, if it is still under way.
    pub fn pairing(&self, id: u64) -> Option<&Pairing> {
        self.pairings.iter().find(|p| p.id == id)
    }

    /// Ends a pairing with nothing paired.
    pub fn drop_pairing(&mut self, id: u64) {
        self.pairings.retain(|p| p.id != id);
    }

    /// Whether a token hash is held anywhere: by a row, as its token or one it replaced, or by a
    /// claim. A new token must be none of these.
    fn hash_held(&self, hash: &[u8; 32]) -> bool {
        self.rows.values().any(|row| same(&row.token.hash, hash) || replaced(row, hash))
            || self.pairings.iter().filter_map(|p| p.claim.as_ref()).any(|claim| same(claim.token_hash(), hash))
    }

    /// The unclaimed pairing this code is for, at the endpoint of `kind`.
    fn code_for(&mut self, code: &[u8; 16], kind: Kind, now: Timestamp) -> Result<&mut Pairing, Refused> {
        self.purge(now);
        let pairing = self.pairings.iter_mut().find(|p| same(&p.code, code)).ok_or(Refused::BadCode)?;
        if pairing.kind != kind || pairing.claim.is_some() || now >= pairing.until {
            return Err(Refused::BadCode);
        }
        Ok(pairing)
    }

    /// A phone's pairing request, its signatures already checked against the hub's pin. Its
    /// pairing's name and workspaces come back.
    pub fn claim_device(&mut self, request: PairRequest, now: Timestamp) -> Result<(String, Vec<WsName>), Refused> {
        if self.hash_held(&request.token_hash) {
            return Err(Refused::Malformed);
        }
        let pairing = self.code_for(&request.code, Kind::Device, now)?;
        pairing.claim = Some(Claim::Device {
            signing: request.signing_key,
            agreement: request.agreement_key,
            binding: request.key_signature,
            token_hash: request.token_hash,
            push: request.push,
        });
        Ok((pairing.name.clone(), pairing.ws.clone()))
    }

    /// A machine's pairing request. Its pairing's name comes back.
    pub fn claim_machine(&mut self, request: JoinRequest, now: Timestamp) -> Result<String, Refused> {
        if self.hash_held(&request.token_hash) {
            return Err(Refused::Malformed);
        }
        let pairing = self.code_for(&request.code, Kind::Machine, now)?;
        pairing.claim = Some(Claim::Machine { key: request.machine_key, token_hash: request.token_hash });
        Ok(pairing.name.clone())
    }

    /// The person said yes: the claimed pairing becomes a row, and its token works from now.
    pub fn confirm(&mut self, id: u64, now: Timestamp) -> Result<(), NotPaired> {
        self.purge(now);
        let Some(at) = self.pairings.iter().position(|p| p.id == id && p.claim.is_some()) else { return Err(NotPaired::Gone) };
        let pairing = self.pairings.remove(at);
        self.row_free(pairing.kind, &pairing.name, now)?;
        let (keys, token_hash, push) = match pairing.claim.expect("a claimed pairing") {
            Claim::Device { signing, agreement, binding, token_hash, push } => (Keys::Device { signing, agreement, binding }, token_hash, push),
            Claim::Machine { key, token_hash } => (Keys::Machine { key }, token_hash, String::new()),
        };
        let push_changed = (!push.is_empty()).then_some(now);
        let row = Row {
            name: pairing.name.clone(),
            ws: pairing.ws,
            keys,
            push,
            push_changed,
            paired: now,
            token: Token { hash: token_hash, issued: now },
            old: None,
            retired: Vec::new(),
            conflict_since: None,
            last_seen: None,
        };
        self.rows.insert(pairing.name, row);
        self.dirty = true;
        Ok(())
    }

    /// Deletes a row; whether there was one.
    pub fn revoke(&mut self, name: &str) -> bool {
        let found = self.rows.remove(name).is_some();
        self.dirty |= found;
        found
    }

    /// Who holds the token with this hash, sent with a prefix of `kind`, for a call that is a
    /// renewal or not. Looked up before anything else a call does.
    pub fn authenticate(&mut self, kind: Kind, hash: &[u8; 32], renewal: bool, now: Timestamp) -> Result<Caller, Refused> {
        self.purge(now);
        if let Some(row) = self.rows.values_mut().find(|row| same(&row.token.hash, hash)) {
            if row.kind() != kind {
                return Err(Refused::Unknown);
            }
            // The new token is used: the one it replaced stops.
            if let Some(old) = row.old.as_mut()
                && old.until > now
            {
                old.until = now;
                self.dirty = true;
            }
            if now >= row.expires() {
                let late_ok = row.kind() == Kind::Device && renewal;
                if !late_ok {
                    return Err(Refused::Expired((row.kind() == Kind::Device).then(|| row.renewable_until())));
                }
            }
            let caller = Caller { name: row.name.clone(), kind };
            self.seen(&caller.name, now);
            return Ok(caller);
        }
        if let Some(row) = self.rows.values_mut().find(|row| replaced(row, hash)) {
            if row.kind() != kind {
                return Err(Refused::Unknown);
            }
            // Only the token the last renewal replaced may still work; a machine's earlier ones never.
            let works = row.old.as_ref().is_some_and(|old| same(&old.hash, hash) && now < old.until);
            return match kind {
                Kind::Machine if !works || renewal => {
                    if row.conflict_since.is_none() {
                        row.conflict_since = Some(now);
                        self.dirty = true;
                    }
                    Err(Refused::Conflict)
                }
                Kind::Device if !works => Err(Refused::Unknown),
                Kind::Device if renewal => Err(Refused::Replaced),
                _ => {
                    let caller = Caller { name: row.name.clone(), kind };
                    self.seen(&caller.name, now);
                    Ok(caller)
                }
            };
        }
        if self.pairings.iter().filter_map(|p| p.claim.as_ref()).any(|claim| same(claim.token_hash(), hash)) {
            return Err(Refused::Pending);
        }
        Err(Refused::Unknown)
    }

    /// Notes that a row's token was used now. "Last seen" moves only when it is a while old, so
    /// what is written down is what the hub shows, to within that while.
    fn seen(&mut self, name: &str, now: Timestamp) {
        if let Some(row) = self.rows.get_mut(name)
            && row.last_seen.is_none_or(|seen| now.duration_since(seen) >= SEEN_EVERY)
        {
            row.last_seen = Some(now);
            self.dirty = true;
        }
    }

    /// The row of this name.
    pub fn row(&self, name: &str) -> Option<&Row> {
        self.rows.get(name)
    }

    /// A nonce for a phone's renewal, and when it stops being good. The hub keeps none: a nonce is
    /// that time in seconds, 4 bytes, then `drawn`, 4 random bytes, then a MAC under `key` over
    /// those and the row, 8 bytes, which only this hub process can make. So asking for one changes
    /// nothing, and a copy of the token that asks can't spoil the nonce the phone holds.
    pub fn nonce(&self, caller: &Caller, key: &[u8; 32], drawn: [u8; 4], now: Timestamp) -> Result<([u8; 16], Timestamp), Refused> {
        let row = self.rows.get(&caller.name).ok_or(Refused::Unknown)?;
        let until = u32::try_from((now + NONCE_LIFE).as_second()).expect("the hub's clock is between 1970 and 2106");
        let mut nonce = [0; 16];
        nonce[..4].copy_from_slice(&until.to_be_bytes());
        nonce[4..8].copy_from_slice(&drawn);
        let mac = nonce_mac(key, row, &nonce[..8]);
        nonce[8..].copy_from_slice(&mac);
        Ok((nonce, Timestamp::from_second(until.into()).expect("a u32 of seconds is a time")))
    }

    /// Gives a row a new token, the one it had working on for a while.
    fn replace_token(&mut self, name: &str, hash: [u8; 32], now: Timestamp) -> Timestamp {
        let row = self.rows.get_mut(name).expect("a caller's row");
        let old_until = (now + OLD_TOKEN).min(row.expires());
        if row.kind() == Kind::Machine {
            row.retired.push(row.token.clone());
        }
        row.old = Some(OldToken { hash: row.token.hash, until: old_until });
        row.token = Token { hash, issued: now };
        self.dirty = true;
        row.expires()
    }

    /// A phone's renewal, signed by its key over the hub's pin, its name, the nonce and the new
    /// token's hash, the nonce one this hub gave this row with `key`. A renewal that is made uses
    /// its nonce up; one refused leaves it as it was. When the new token expires comes back.
    pub fn renew_device(&mut self, caller: &Caller, renewal: &DeviceRenewal, pin: &[u8; 32], key: &[u8; 32], now: Timestamp) -> Result<Timestamp, Refused> {
        let row = self.rows.get(&caller.name).ok_or(Refused::Unknown)?;
        let (head, mac) = renewal.nonce.split_at(8);
        let secs = u32::from_be_bytes(head[..4].try_into().expect("4 bytes"));
        let until = Timestamp::from_second(secs.into()).expect("a u32 of seconds is a time");
        if !same(mac, &nonce_mac(key, row, head)) || now >= until || self.used.contains_key(&renewal.nonce) {
            return Err(Refused::BadNonce);
        }
        let Keys::Device { signing, .. } = &row.keys else { return Err(Refused::WrongKind) };
        let device = DeviceKey::from_spki(signing).map_err(|_| Refused::Unknown)?;
        device.verify(&wire::renew_bytes(pin, &caller.name, &renewal.nonce, &renewal.token_hash), &renewal.signature).map_err(|_| Refused::BadSignature)?;
        if self.hash_held(&renewal.token_hash) {
            return Err(Refused::Malformed);
        }
        self.used.insert(renewal.nonce, until);
        Ok(self.replace_token(&caller.name, renewal.token_hash, now))
    }

    /// A machine's renewal: from day 10 of its token, never while its row is marked.
    pub fn renew_machine(&mut self, caller: &Caller, hash: [u8; 32], now: Timestamp) -> Result<Timestamp, Refused> {
        let row = self.rows.get(&caller.name).ok_or(Refused::Unknown)?;
        if row.conflict_since.is_some() {
            return Err(Refused::Marked);
        }
        if now < row.renew_from() {
            return Err(Refused::TooEarly);
        }
        if self.hash_held(&hash) {
            return Err(Refused::Malformed);
        }
        Ok(self.replace_token(&caller.name, hash, now))
    }

    /// Every row, as `halti devices` shows it.
    pub fn list(&mut self, now: Timestamp) -> Vec<Listed> {
        self.purge(now);
        self.rows
            .values()
            .map(|row| {
                let token = if now < row.expires() {
                    TokenState::Left { days: (row.expires().duration_since(now).as_secs() + DAY_SECS - 1) / DAY_SECS }
                } else if row.kind() == Kind::Device {
                    TokenState::Renewable { until: row.renewable_until() }
                } else {
                    TokenState::Expired
                };
                let fingerprint = match &row.keys {
                    Keys::Device { signing, .. } => Some(wire::fingerprint(signing)),
                    Keys::Machine { .. } => None,
                };
                Listed {
                    name: row.name.clone(),
                    kind: row.kind(),
                    ws: row.ws.iter().map(|ws| ws.to_string()).collect(),
                    fingerprint,
                    last_seen: row.last_seen,
                    token,
                    conflict_since: row.conflict_since,
                    push_changed: row.push_changed,
                }
            })
            .collect()
    }
}

/// Whether `hash` is a token the row had before the one it holds, and still knows.
fn replaced(row: &Row, hash: &[u8; 32]) -> bool {
    row.old.as_ref().is_some_and(|old| same(&old.hash, hash)) || row.retired.iter().any(|token| same(&token.hash, hash))
}

/// What ties a renewal nonce to its row: 8 bytes of an HMAC-SHA256 over the row's name, when it
/// was paired, and the nonce's first 8 bytes, its time and its random part.
fn nonce_mac(key: &[u8; 32], row: &Row, head: &[u8]) -> [u8; 8] {
    let mac = crate::audit::hmac_sha256(key, &[&wire::fields(&[row.name.as_bytes(), &row.paired.as_nanosecond().to_be_bytes(), head])]);
    wire::unhex(&mac[..16]).expect("an HMAC is hex")
}

/// Bytes as lowercase hex in the table's file.
mod hexed {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::wire::hex(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        super::wire::unhex_any(&text).ok_or_else(|| serde::de::Error::custom("not lowercase hex"))
    }
}

/// A 32-byte hash as lowercase hex in the table's file.
mod hexed32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::wire::hex(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        super::wire::unhex(&text).ok_or_else(|| serde::de::Error::custom("not 32 bytes of lowercase hex"))
    }
}
