//! A log of JSON lines chained with an HMAC, for the logs that live outside a box's reach (the
//! door's, in the box's store). Each line gets a `mac` field: HMAC-SHA256, with a key only halti
//! holds, over the previous line's mac and this line's other fields. Editing a line, or taking
//! one out of the middle, breaks the chain from there on, which `verify` reports. Cutting off the
//! end can't be seen from the log alone; the `Head` that halti keeps elsewhere when a box stops
//! covers that up to the last stop. (The same scheme as `audit`.)
//!
//! The log is in a box's store, which halti treats as hostile, so it is opened without following
//! a link: each part of its path from the one before (`nofollow`).

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Map, Value};

use crate::audit::hmac_sha256;
use crate::boxes::nofollow::{self, Found};

/// The last line is looked for in this many bytes at the end of the file.
const TAIL: u64 = 16384;
const MAC: &str = "mac";

pub struct Chain {
    /// The folder the log is in, or below, taken as it is.
    root: PathBuf,
    /// The log's path in `root`, opened a part at a time.
    rel: PathBuf,
    key: [u8; 32],
}

/// The text of the log at `rel` in the folder `root`, "" if it isn't there. A link on the way or
/// at `rel` is refused, never followed.
pub fn read(root: &Path, rel: &Path) -> Result<String> {
    let shown = || format!("reading {}", root.join(rel).display());
    match nofollow::open(root, rel).with_context(shown)? {
        Found::Missing => Ok(String::new()),
        Found::File(mut file) => {
            let mut text = String::new();
            file.read_to_string(&mut text).with_context(shown)?;
            Ok(text)
        }
        Found::Link => Err(anyhow!("{} is a link; links aren't followed", rel.display())).with_context(shown),
        Found::Folder(_) | Found::Other => Err(anyhow!("{} isn't a plain file", rel.display())).with_context(shown),
    }
}

/// What a check found.
#[derive(Debug, PartialEq)]
pub struct Verified {
    /// Lines whose chain holds.
    pub chained: usize,
    /// Lines from before the log was chained: they can't be checked.
    pub unchained: usize,
    /// The mac of each chained line, first to last.
    pub macs: Vec<String>,
}

/// Where a log's chain stood when halti last put it away: how many chained lines, and the mac of
/// the last. Kept outside the log (in the Keychain), it is what shows a log whose chain was
/// stripped, or whose end was cut off before that point.
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Head {
    pub lines: usize,
    pub mac: String,
}

impl Verified {
    pub fn head(&self) -> Option<Head> {
        self.macs.last().map(|mac| Head { lines: self.macs.len(), mac: mac.clone() })
    }

    /// Whether this log still holds `head`: at least as many chained lines, the same mac there.
    pub fn check(&self, head: &Head) -> Result<()> {
        match self.macs.get(head.lines.wrapping_sub(1)) {
            Some(mac) if *mac == head.mac => Ok(()),
            Some(_) => bail!("line {} isn't the one halti recorded when the box last stopped: the log was replaced or rewritten", self.unchained + head.lines),
            None => bail!("the log has {} chained lines, but had {} when the box last stopped: lines were cut off or their chain was stripped", self.macs.len(), head.lines),
        }
    }
}

impl Chain {
    /// The log at `path`. Its folder is taken as it is; the file is opened without following a link.
    pub fn new(path: &Path, key: [u8; 32]) -> Self {
        let root = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        Self::within(root, Path::new(path.file_name().unwrap_or_default()), key)
    }

    /// The log at `rel` in the folder `root`, every part of `rel` opened without following a link.
    pub fn within(root: &Path, rel: &Path, key: [u8; 32]) -> Self {
        Self { root: root.to_path_buf(), rel: rel.to_path_buf(), key }
    }

    fn path(&self) -> PathBuf {
        self.root.join(&self.rel)
    }

    /// The file, to read and to add to, made private to the user with its folders if it isn't there.
    fn open(&self) -> Result<File> {
        nofollow::append(&self.root, &self.rel, 0o600).with_context(|| format!("opening {}", self.path().display()))
    }

    /// Make sure the log can be written: its folders and the file (private to the user).
    pub fn create(&self) -> Result<()> {
        fs::create_dir_all(&self.root).with_context(|| format!("creating {}", self.root.display()))?;
        self.open()?;
        Ok(())
    }

    /// Add a line (a JSON object) to the end, chained to the one before. Whoever else appends
    /// to the same file waits for the lock, so two writers can't chain to the same line.
    pub fn append(&self, line: Value) -> Result<()> {
        let Value::Object(mut fields) = line else { bail!("a log line is a JSON object") };
        fields.remove(MAC);
        let mut file = self.open()?;
        file.lock()?;
        let prev = last_mac(&mut file)?;
        let mac = self.mac(&prev, &fields)?;
        fields.insert(MAC.into(), Value::String(mac));
        file.write_all(format!("{}\n", Value::Object(fields)).as_bytes())?;
        Ok(())
    }

    fn mac(&self, prev: &str, fields: &Map<String, Value>) -> Result<String> {
        // `Map` keeps its keys in one order, so what is written and what is read back agree.
        let body = serde_json::to_string(fields)?;
        Ok(hmac_sha256(&self.key, &[prev.as_bytes(), b"\n", body.as_bytes()]))
    }

    /// Check every line against the chain. A line without a mac is fine only before the first
    /// one that has it (a log from before chaining); anything else that fails names its line.
    pub fn verify(&self) -> Result<Verified> {
        let text = read(&self.root, &self.rel)?;
        let (mut prev, mut found) = (String::new(), Verified { chained: 0, unchained: 0, macs: Vec::new() });
        for (no, line) in text.lines().enumerate().map(|(i, l)| (i + 1, l)).filter(|(_, l)| !l.trim().is_empty()) {
            let broken = || anyhow!("the chain breaks at line {no}: that line, or one before it, was changed or removed");
            let Ok(Value::Object(mut fields)) = serde_json::from_str::<Value>(line) else { return Err(broken()) };
            match fields.remove(MAC) {
                None if found.chained == 0 => found.unchained += 1,
                Some(Value::String(mac)) if self.mac(&prev, &fields)? == mac => {
                    found.macs.push(mac.clone());
                    prev = mac;
                    found.chained += 1;
                }
                _ => return Err(broken()),
            }
        }
        Ok(found)
    }
}

/// The mac of the last line, or "" if there is none (or it has none).
fn last_mac(file: &mut File) -> Result<String> {
    let len = file.metadata()?.len();
    file.seek(SeekFrom::Start(len.saturating_sub(TAIL)))?;
    let mut tail = Vec::new();
    file.read_to_end(&mut tail)?;
    let text = String::from_utf8_lossy(&tail);
    let last = text.lines().rev().find(|l| !l.trim().is_empty());
    Ok(last.and_then(|l| serde_json::from_str::<Value>(l).ok()).and_then(|v| v.get(MAC).and_then(Value::as_str).map(str::to_string)).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::util::TempDir;
    use serde_json::json;

    fn chain(dir: &TempDir) -> Chain {
        Chain::new(&dir.0.join("log").join("door.log"), [7; 32])
    }

    fn write(chain: &Chain, n: usize) {
        chain.create().unwrap();
        for i in 0..n {
            chain.append(json!({ "kind": "request", "n": i, "url": format!("https://a.example.com/{i}") })).unwrap();
        }
    }

    fn lines(chain: &Chain) -> Vec<String> {
        fs::read_to_string(chain.path()).unwrap().lines().map(str::to_string).collect()
    }

    fn put(chain: &Chain, lines: &[String]) {
        fs::write(chain.path(), lines.join("\n") + "\n").unwrap();
    }

    fn counts(chain: &Chain) -> (usize, usize) {
        let found = chain.verify().unwrap();
        (found.chained, found.unchained)
    }

    #[test]
    fn the_head_kept_elsewhere_shows_a_stripped_cut_or_replaced_log() {
        let dir = TempDir::new("halti-chain").unwrap();
        let c = chain(&dir);
        write(&c, 5);
        let head = c.verify().unwrap().head().unwrap();
        assert_eq!(head.lines, 5);
        let original = lines(&c);

        // More lines since: the head still holds.
        write(&c, 2);
        c.verify().unwrap().check(&head).unwrap();

        // Every mac taken out: on its own the log reads as one from before chaining.
        let stripped: Vec<String> = original
            .iter()
            .map(|l| {
                let mut v: Value = serde_json::from_str(l).unwrap();
                v.as_object_mut().unwrap().remove(MAC);
                v.to_string()
            })
            .collect();
        put(&c, &stripped);
        assert_eq!(counts(&c), (0, 5), "the log alone can't tell");
        let e = c.verify().unwrap().check(&head).unwrap_err().to_string();
        assert!(e.contains("stripped"), "{e}");

        // The end cut off.
        put(&c, &original[..3]);
        assert!(c.verify().unwrap().check(&head).is_err());

        // A whole new log with other lines, chained with the same key.
        fs::remove_file(c.path()).unwrap();
        c.create().unwrap();
        for i in 0..6 {
            c.append(json!({ "kind": "request", "n": i, "url": "https://other.example.com/" })).unwrap();
        }
        let e = c.verify().unwrap().check(&head).unwrap_err().to_string();
        assert!(e.contains("replaced"), "{e}");
    }

    #[test]
    fn a_chain_of_lines_verifies() {
        let dir = TempDir::new("halti-chain").unwrap();
        let c = chain(&dir);
        assert_eq!(counts(&c), (0, 0), "a log that doesn't exist is empty");
        write(&c, 5);
        assert_eq!(counts(&c), (5, 0));
        assert!(lines(&c).iter().all(|l| l.contains("\"mac\":\"")));
        // A second writer carries on from the last line.
        Chain::new(&c.path(), [7; 32]).append(json!({ "kind": "box", "decision": "stopped" })).unwrap();
        assert_eq!(c.verify().unwrap().chained, 6);
        assert!(Chain::new(&c.path(), [8; 32]).verify().is_err(), "another key can't verify it");
    }

    #[test]
    fn an_edited_line_is_found() {
        let dir = TempDir::new("halti-chain").unwrap();
        let c = chain(&dir);
        write(&c, 5);
        let mut l = lines(&c);
        l[2] = l[2].replace("/2", "/9");
        put(&c, &l);
        let e = c.verify().unwrap_err().to_string();
        assert!(e.contains("line 3"), "{e}");
    }

    #[test]
    fn a_deleted_line_in_the_middle_is_found() {
        let dir = TempDir::new("halti-chain").unwrap();
        let c = chain(&dir);
        write(&c, 5);
        let mut l = lines(&c);
        l.remove(2);
        put(&c, &l);
        let e = c.verify().unwrap_err().to_string();
        assert!(e.contains("line 3"), "{e}");
        // So is the first line taken out.
        let mut l = lines(&c);
        l.remove(0);
        l.insert(2, "{}".into());
        put(&c, &l);
        assert!(c.verify().is_err());
    }

    #[test]
    fn a_stripped_mac_and_garbage_are_found_but_an_old_unchained_start_is_allowed() {
        let dir = TempDir::new("halti-chain").unwrap();
        let c = chain(&dir);
        write(&c, 3);
        let mut l = lines(&c);
        let stripped = l[1].split(",\"mac\"").next().unwrap().to_string() + "}";
        let original = l[1].clone();
        l[1] = stripped;
        put(&c, &l);
        assert!(c.verify().unwrap_err().to_string().contains("line 2"));
        l[1] = "not json".into();
        put(&c, &l);
        assert!(c.verify().is_err());
        l[1] = original;

        // A log from before chaining: its lines stay unchecked, the new ones chain on.
        let old = [r#"{"kind":"proxy","decision":"allowed"}"#.to_string(), r#"{"kind":"proxy","decision":"closed"}"#.to_string()];
        fs::remove_file(c.path()).unwrap();
        put(&c, &old);
        c.append(json!({ "kind": "request" })).unwrap();
        c.append(json!({ "kind": "request" })).unwrap();
        assert_eq!(counts(&c), (2, 2));
        // But a line without a mac after a chained one is an edit.
        let mut l = lines(&c);
        l.push(old[0].clone());
        put(&c, &l);
        assert!(c.verify().unwrap_err().to_string().contains("line 5"));
    }

    #[test]
    fn only_objects_are_lines_and_a_mac_in_one_is_replaced() {
        let dir = TempDir::new("halti-chain").unwrap();
        let c = chain(&dir);
        c.create().unwrap();
        assert!(c.append(json!("text")).is_err());
        c.append(json!({ "kind": "x", "mac": "forged" })).unwrap();
        assert_eq!(c.verify().unwrap().chained, 1);
    }

    #[test]
    fn a_link_in_the_log_s_place_or_on_its_way_is_never_followed() {
        let dir = TempDir::new("halti-chain").unwrap();
        let (mnt, outside) = (dir.0.join("mnt"), dir.0.join("outside"));
        fs::create_dir_all(mnt.join("log")).unwrap();
        fs::create_dir_all(outside.join("log")).unwrap();
        fs::write(outside.join("file"), "the person's own\n").unwrap();
        fs::write(outside.join("log/door.log"), "the person's own\n").unwrap();
        let own = || (fs::read_to_string(outside.join("file")).unwrap(), fs::read_to_string(outside.join("log/door.log")).unwrap());

        // At the end: the log is a link to a file of the person's.
        std::os::unix::fs::symlink(outside.join("file"), mnt.join("log/door.log")).unwrap();
        // On the way: the store's folder is a link to a folder of the person's, with a log in it.
        let linked = dir.0.join("linked");
        fs::create_dir_all(&linked).unwrap();
        std::os::unix::fs::symlink(outside.join("log"), linked.join("log")).unwrap();
        for (root, error) in [(&mnt, "log/door.log is a link; links aren't followed"), (&linked, "log is a link; links aren't followed")] {
            let c = Chain::within(root, Path::new("log/door.log"), [7; 32]);
            for e in [c.create().unwrap_err(), c.append(json!({ "kind": "x" })).unwrap_err(), c.verify().unwrap_err(), read(root, Path::new("log/door.log")).unwrap_err()] {
                assert_eq!(e.root_cause().to_string(), error);
            }
        }
        assert!(Chain::new(&mnt.join("log/door.log"), [7; 32]).append(json!({ "kind": "x" })).is_err(), "a log given by its path");
        assert_eq!(own(), ("the person's own\n".to_string(), "the person's own\n".to_string()), "nothing written through a link");

        // A log that isn't there yet is made, its folder too.
        let c = Chain::within(&mnt, Path::new("new/door.log"), [7; 32]);
        assert_eq!(read(&mnt, Path::new("new/door.log")).unwrap(), "");
        c.create().unwrap();
        c.append(json!({ "kind": "x" })).unwrap();
        assert_eq!(c.verify().unwrap().chained, 1);
        assert_eq!(fs::metadata(mnt.join("new/door.log")).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
