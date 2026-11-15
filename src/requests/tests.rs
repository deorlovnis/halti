use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use halti_core::device::DeviceKey;

use super::*;

/// A record with every field fixed, and its bytes, SHA-256 and answers worked out apart from this
/// code (Python's struct and hashlib).
fn known() -> Record {
    Record {
        machine: "mac-1".into(),
        ws: "acme".into(),
        box_name: "dev".into(),
        run: RunId([1, 2, 3, 4, 5, 6, 7, 8]),
        kind: Kind::Write,
        action: "POST https://api.example.com/v1/x?key=********".into(),
        id: Id([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
        expiry: 1_763_164_800,
    }
}

const KNOWN: &str = concat!(
    "001168616c74692d617070726f76616c2d7631",
    "00056d61632d31",
    "000461636d65",
    "0003646576",
    "00080102030405060708",
    "00057772697465",
    "002e504f53542068747470733a2f2f6170692e6578616d706c652e636f6d2f76312f783f6b65793d2a2a2a2a2a2a2a2a",
    "0010000102030405060708090a0b0c0d0e0f",
    "0008000000006917c280",
);

#[test]
fn a_record_is_its_fields_each_after_its_length_in_order() {
    let bytes = known().encode().unwrap();
    assert_eq!(hex(&bytes), KNOWN);
    assert_eq!(bytes.len(), 130);
    assert_eq!(hex(&Sha256::digest(&bytes)), "ce5c9c73e04cd021d7dd562a078b981b315ae7b0e7504a9a06038504924e8c8e");
    assert_eq!(Record::decode(&bytes), Some(known()));
    assert_eq!(known().shown(), "acme/dev");
}

#[test]
fn an_answer_is_the_record_shown_and_its_decision() {
    let bytes = known().encode().unwrap();
    assert_eq!(hex(&answer_digest(&bytes, true)), "c84579e9b007722e140216ade537eb63d0a185df71811ab9df039e8344c99b52");
    assert_eq!(hex(&answer_digest(&bytes, false)), "75e55c3e754d66fdc6f0c4447d9e6bd3e1397f546152850d37bf77451a78404c");
    // Another record, by one byte of its id, is another answer.
    let other = Record { id: Id([1; 16]), ..known() }.encode().unwrap();
    assert_ne!(answer_digest(&other, true), answer_digest(&bytes, true));
    // A record followed by its decision is no record: the two never read as one another.
    let mut followed = bytes.clone();
    fields::push(&mut followed, b"yes");
    assert_eq!(Record::decode(&followed), None);
}

#[test]
fn a_record_that_breaks_any_rule_is_refused_whole() {
    let bytes = known().encode().unwrap();
    // Cut anywhere, or with a byte more.
    for end in 0..bytes.len() {
        assert_eq!(Record::decode(&bytes[..end]), None, "cut at {end}");
    }
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(Record::decode(&longer), None);
    // Each field broken, in the bytes as they would arrive.
    let swapped = |from: &[u8], to: &[u8]| {
        let mut field = Vec::new();
        fields::push(&mut field, from);
        let mut other = Vec::new();
        fields::push(&mut other, to);
        let at = bytes.windows(field.len()).position(|w| w == field).unwrap();
        [&bytes[..at], &other[..], &bytes[at + field.len()..]].concat()
    };
    for (from, to) in [
        (&b"halti-approval-v1"[..], &b"halti-question-v1"[..]),
        (b"mac-1", b"Mac-1"),
        (b"mac-1", b"mac.1"),
        (b"mac-1", b""),
        (b"acme", &[b'a'; 33]),
        (b"dev", b"de v"),
        (&[1, 2, 3, 4, 5, 6, 7, 8], &[1, 2, 3, 4, 5, 6, 7]),
        (b"write", b"start"),
        (b"POST https://api.example.com/v1/x?key=********", b"POST https://api.example.com/\x1b[2J"),
        (b"POST https://api.example.com/v1/x?key=********", b"POST https://\xc3\xa9.example.com/"),
        (b"POST https://api.example.com/v1/x?key=********", b""),
        (b"POST https://api.example.com/v1/x?key=********", &[b'a'; ACTION_MAX + 1]),
        (&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], &[0; 15]),
        (&[0, 0, 0, 0, 0x69, 0x17, 0xc2, 0x80], &[0x69, 0x17, 0xc2, 0x80]),
    ] {
        assert_eq!(Record::decode(&swapped(from, to)), None, "{:?}", String::from_utf8_lossy(to));
    }
    // The longest of each still reads.
    let longest = Record { machine: "m".repeat(32), ws: "w".repeat(32), box_name: "b".repeat(32), action: "a".repeat(ACTION_MAX), ..known() };
    assert_eq!(Record::decode(&longest.encode().unwrap()), Some(longest));
}

#[test]
fn a_record_is_made_only_of_fields_it_takes() {
    for broken in [
        Record { machine: "Mac".into(), ..known() },
        Record { ws: "w".repeat(33), ..known() },
        Record { box_name: String::new(), ..known() },
        Record { action: "POST https://x.example.com/\n".into(), ..known() },
        Record { action: "a".repeat(ACTION_MAX + 1), ..known() },
    ] {
        assert!(broken.encode().is_err(), "{broken:?}");
    }
}

#[test]
fn names_are_lowercase_letters_digits_dashes_and_underscores_up_to_32_bytes() {
    for good in ["acme", "dev", "server-1", "a_b", "0", &"x".repeat(32)] {
        check_name(good).unwrap();
    }
    for bad in ["", "Acme", "a.b", "a/b", "a b", "é", "-a", "_a", &"x".repeat(33)] {
        assert!(check_name(bad).is_err(), "{bad}");
    }
    assert_eq!(check_name("A").unwrap_err().to_string(), "\"A\" isn't a name a record takes: 1 to 32 of a-z, 0-9, - and _, starting with a letter or digit");
    // A host name becomes one.
    assert_eq!(machine_from("Deniss-MacBook-Pro.local"), "deniss-macbook-pro");
    assert_eq!(machine_from("server_1"), "server_1");
    assert_eq!(machine_from("büro"), "b-ro");
    assert_eq!(machine_from(&"h".repeat(40)), "h".repeat(32));
    assert_eq!(machine_from(""), "machine");
    assert_eq!(machine_from(".local"), "machine");
    // Nor does it start with what a name can't start with.
    assert_eq!(machine_from("_build"), "build");
    assert_eq!(machine_from("été"), "t-");
    assert_eq!(machine_from("--"), "machine");
    check_name(&machine_name()).unwrap();
}

#[test]
fn an_action_is_printable_ascii_and_says_where_it_was_cut() {
    assert_eq!(action("POST", "https://api.example.com/v1/x"), "POST https://api.example.com/v1/x");
    assert_eq!(action("POST", "https://api.example.com/\u{e9}\t"), "POST https://api.example.com/%C3%A9%09");
    // The log's mark for a URL it cut, and an action too long for a record.
    assert_eq!(action("PUT", "https://api.example.com/long…"), "PUT https://api.example.com/long (cut)");
    let long = action("POST", &format!("https://api.example.com/{}", "a".repeat(2000)));
    assert_eq!(long.len(), ACTION_MAX);
    assert!(long.starts_with("POST https://api.example.com/aaa") && long.ends_with("a (cut)"), "{long}");
    let just = format!("https://api.example.com/{}", "a".repeat(ACTION_MAX - 29));
    assert_eq!(action("POST", &just).len(), ACTION_MAX, "one that fits is whole");
    assert!(!action("POST", &just).ends_with(CUT));
}

#[test]
fn ids_are_hex_and_random() {
    let id = Id([0xab; 16]);
    assert_eq!((id.hex().len(), id.short()), (32, "abababab".to_string()));
    assert_ne!(Id::random(), Id::random());
    assert_ne!(RunId::random(), RunId::random());
}

// --- the desk ---

/// What the fake prompt does when it is asked.
enum Step {
    Say(Prompted),
    /// Waits until it is withdrawn, then says nothing.
    UntilWithdrawn,
    /// Waits until the flag is set, then says this.
    After(Arc<AtomicBool>, Prompted),
}

/// The prompt here, scripted: each question takes the next step, and is noted. It counts the
/// questions that are up at once, as the real one's windows would be.
#[derive(Default)]
struct Script {
    steps: Mutex<VecDeque<Step>>,
    asked: Mutex<Vec<String>>,
    withdrawn: AtomicUsize,
    up: AtomicUsize,
    most_up: AtomicUsize,
}

impl Script {
    fn with(steps: Vec<Step>) -> Arc<Script> {
        Arc::new(Script { steps: Mutex::new(steps.into()), ..Script::default() })
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().clone()
    }

    /// How many questions were withdrawn.
    fn withdrawn(&self) -> usize {
        self.withdrawn.load(Ordering::SeqCst)
    }

    /// The most questions that were up at once.
    fn most_up(&self) -> usize {
        self.most_up.load(Ordering::SeqCst)
    }
}

impl Prompt for Script {
    fn ask(&self, reason: &str, withdrawn: &dyn Fn() -> bool) -> Prompted {
        self.asked.lock().unwrap().push(reason.to_string());
        let up = self.up.fetch_add(1, Ordering::SeqCst) + 1;
        self.most_up.fetch_max(up, Ordering::SeqCst);
        // The step is taken before it waits, so nothing here keeps a second question waiting.
        let step = self.steps.lock().unwrap().pop_front();
        let said = match step {
            Some(Step::Say(said)) => said,
            Some(Step::UntilWithdrawn) => {
                until(withdrawn);
                self.withdrawn.fetch_add(1, Ordering::SeqCst);
                Prompted::Unshown
            }
            Some(Step::After(go, said)) => {
                until(|| go.load(Ordering::SeqCst));
                said
            }
            None => panic!("asked more than the script says: {reason}"),
        };
        self.up.fetch_sub(1, Ordering::SeqCst);
        said
    }
}

/// Waits until `check` holds, or ten seconds pass.
fn until(check: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !check() {
        assert!(Instant::now() < deadline, "it never happened");
        thread::sleep(Duration::from_millis(10));
    }
}

fn limits() -> Limits {
    Limits { wait: Duration::from_secs(20), ..LIMITS }
}

fn desk(limits: Limits, prompt: Arc<dyn Prompt>) -> Arc<Desk> {
    Desk::new("mac-1".into(), "acme".into(), limits, prompt)
}

const POST: &str = "POST https://api.example.com/v1/x";

/// Box `name` raises a request on a thread of its own, with `confirm`; what it came to, once it did.
fn raising(desk: &Arc<Desk>, name: &str, confirm: bool) -> thread::JoinHandle<Raised> {
    let asker = desk.asker(name, RunId([7; 8]));
    thread::spawn(move || asker.raise(POST, confirm, &|| false))
}

/// The one request that waits: its record and bytes, once it waits.
fn the_one(desk: &Desk) -> (Record, Vec<u8>) {
    until(|| desk.records().len() == 1);
    let bytes = desk.records().remove(0);
    (Record::decode(&bytes).unwrap(), bytes)
}

#[test]
fn a_request_raised_is_listed_as_its_record_and_the_first_answer_wins() {
    let desk = desk(limits(), Script::with(vec![]));
    let raised = raising(&desk, "dev", false);
    let (record, bytes) = the_one(&desk);
    assert_eq!((record.machine.as_str(), record.ws.as_str(), record.box_name.as_str(), record.run, record.kind), ("mac-1", "acme", "dev", RunId([7; 8]), Kind::Write));
    assert_eq!(record.action, POST);
    let left = record.expiry - now_secs();
    assert!((20..=21).contains(&left), "it expires by this machine's clock, never sooner than its wait: {left}");
    // A digest of another decision, or of other bytes, names no request.
    assert_eq!(desk.answer_here(true, &answer_digest(&bytes, false)), Here::Gone);
    assert_eq!(desk.answer_here(true, &[0; 32]), Here::Gone);
    assert_eq!(desk.answer_here(true, &answer_digest(&bytes, true)), Here::Approved);
    // The second answer finds it settled.
    assert_eq!(desk.answer_here(false, &answer_digest(&bytes, false)), Here::Gone);
    assert_eq!(raised.join().unwrap(), Raised { id: Some(record.id), came: Came::Yes(By::Local) });
    assert!(desk.records().is_empty(), "it goes once it is answered");
}

#[test]
fn a_denial_from_another_terminal_counts_at_once() {
    let script = Script::with(vec![Step::UntilWithdrawn]);
    let desk = desk(limits(), script.clone());
    let raised = raising(&desk, "dev", true);
    let (_, bytes) = the_one(&desk);
    until(|| script.asked().len() == 1);
    assert_eq!(desk.answer_here(false, &answer_digest(&bytes, false)), Here::Denied);
    assert_eq!(raised.join().unwrap().came, Came::No(By::Local));
    // The prompt here was withdrawn, and nothing more was asked for a no.
    until(|| script.withdrawn() > 0);
    assert_eq!(script.asked(), [format!("let box acme/dev send {POST}")]);
}

#[test]
fn the_prompt_here_answers_and_is_withdrawn_when_another_terminal_does() {
    // Its yes and its no each settle the request.
    for (said, came) in [(Prompted::Yes, Came::Yes(By::Local)), (Prompted::No, Came::No(By::Local))] {
        let desk = desk(limits(), Script::with(vec![Step::Say(said)]));
        assert_eq!(raising(&desk, "dev", true).join().unwrap().came, came);
    }
    // A yes from another terminal takes it down, and asks it again first, naming the terminal:
    // only once the first is down, so two are never up at once.
    let script = Script::with(vec![Step::UntilWithdrawn, Step::Say(Prompted::Yes)]);
    let desk = desk(limits(), script.clone());
    let raised = raising(&desk, "dev", true);
    let (_, bytes) = the_one(&desk);
    until(|| script.asked().len() == 1);
    assert_eq!(desk.answer_here(true, &answer_digest(&bytes, true)), Here::Approved);
    assert_eq!(script.withdrawn(), 1);
    assert_eq!(script.most_up(), 1, "the first prompt went before the second was asked");
    assert_eq!(raised.join().unwrap().came, Came::Yes(By::Local));
    assert_eq!(script.asked(), [format!("let box acme/dev send {POST}"), format!("let box acme/dev send {POST}, as answered in another terminal")]);
}

#[test]
fn a_yes_the_prompt_here_doesnt_confirm_leaves_the_request_waiting_and_its_prompt_back() {
    for refused in [Prompted::No, Prompted::Unshown] {
        let script = Script::with(vec![Step::UntilWithdrawn, Step::Say(refused), Step::UntilWithdrawn]);
        let desk = desk(limits(), script.clone());
        let raised = raising(&desk, "dev", true);
        let (record, bytes) = the_one(&desk);
        until(|| script.asked().len() == 1);
        assert_eq!(desk.answer_here(true, &answer_digest(&bytes, true)), Here::Declined);
        assert_eq!(desk.records(), std::slice::from_ref(&bytes), "it still waits");
        // The prompt where the box runs is asked again, and stays up.
        until(|| script.asked().len() == 3);
        assert!(!desk.withdrawn(record.id));
        assert_eq!(desk.answer_here(false, &answer_digest(&bytes, false)), Here::Denied);
        assert_eq!(raised.join().unwrap().came, Came::No(By::Local));
        until(|| script.withdrawn() == 2);
        let box_runs = format!("let box acme/dev send {POST}");
        assert_eq!(script.asked(), [box_runs.clone(), format!("{box_runs}, as answered in another terminal"), box_runs]);
        assert_eq!(script.most_up(), 1);
    }
}

#[test]
fn one_yes_from_another_terminal_is_asked_about_at_a_time() {
    let go = Arc::new(AtomicBool::new(false));
    let script = Script::with(vec![Step::UntilWithdrawn, Step::After(go.clone(), Prompted::No), Step::UntilWithdrawn]);
    let desk = desk(limits(), script.clone());
    let raised = raising(&desk, "dev", true);
    let (_, bytes) = the_one(&desk);
    until(|| script.asked().len() == 1);
    let first = {
        let (desk, bytes) = (desk.clone(), bytes.clone());
        thread::spawn(move || desk.answer_here(true, &answer_digest(&bytes, true)))
    };
    until(|| script.asked().len() == 2);
    // While the prompt here asks about one yes, another is refused at once and asks nothing.
    for _ in 0..5 {
        assert_eq!(desk.answer_here(true, &answer_digest(&bytes, true)), Here::Busy);
    }
    assert_eq!(script.asked().len(), 2);
    go.store(true, Ordering::SeqCst);
    assert_eq!(first.join().unwrap(), Here::Declined);
    until(|| script.asked().len() == 3);
    // A no still counts at once.
    assert_eq!(desk.answer_here(false, &answer_digest(&bytes, false)), Here::Denied);
    assert_eq!(raised.join().unwrap().came, Came::No(By::Local));
    assert_eq!(script.most_up(), 1);
}

#[test]
fn a_yes_whose_request_closes_while_the_prompt_here_asks_is_gone() {
    let script = Script::with(vec![Step::UntilWithdrawn, Step::UntilWithdrawn]);
    let desk = desk(Limits { wait: Duration::from_millis(800), ..LIMITS }, script.clone());
    let raised = raising(&desk, "dev", true);
    let (_, bytes) = the_one(&desk);
    until(|| script.asked().len() == 1);
    assert_eq!(desk.answer_here(true, &answer_digest(&bytes, true)), Here::Gone);
    assert_eq!(raised.join().unwrap().came, Came::Expired);
    assert_eq!(script.asked().len(), 2, "the prompt where the box runs isn't asked again");
}

#[test]
fn a_request_past_its_records_expiry_is_closed_whatever_the_wait_says() {
    let desk = desk(limits(), Script::with(vec![]));
    let raised = raising(&desk, "dev", false);
    let (_, bytes) = the_one(&desk);
    // As after a sleep: the machine's clock passed the expiry, the clock the wait is timed by didn't.
    desk.table().waiting[0].record.expiry = now_secs() - 1;
    assert!(desk.records().is_empty());
    assert_eq!(desk.answer_here(true, &answer_digest(&bytes, true)), Here::Gone);
    assert_eq!(raised.join().unwrap().came, Came::Expired);
}

#[test]
fn where_nothing_confirms_nothing_is_asked() {
    let script = Script::with(vec![]);
    let desk = desk(limits(), script.clone());
    let raised = raising(&desk, "dev", false);
    let (_, bytes) = the_one(&desk);
    assert_eq!(desk.answer_here(true, &answer_digest(&bytes, true)), Here::Approved);
    assert_eq!(raised.join().unwrap().came, Came::Yes(By::Local));
    assert!(script.asked().is_empty());
}

#[test]
fn a_request_nobody_answers_expires_as_a_no() {
    let script = Script::with(vec![Step::UntilWithdrawn]);
    let desk = desk(Limits { wait: Duration::from_millis(400), ..LIMITS }, script.clone());
    let started = Instant::now();
    let raised = raising(&desk, "dev", true);
    let (_, bytes) = the_one(&desk);
    let raised = raised.join().unwrap();
    assert!(raised.id.is_some() && raised.came == Came::Expired, "{raised:?}");
    assert!(started.elapsed() >= Duration::from_millis(400));
    // The prompt here went with it, and an answer after it finds nothing.
    until(|| script.withdrawn() > 0);
    assert!(desk.records().is_empty());
    assert_eq!(desk.answer_here(true, &answer_digest(&bytes, true)), Here::Gone);
}

#[test]
fn a_box_has_three_requests_waiting_at_most_and_the_desk_fifty() {
    let desk = desk(limits(), Script::with(vec![]));
    let waiting: Vec<_> = (0..3).map(|_| raising(&desk, "dev", false)).collect();
    until(|| desk.records().len() == 3);
    assert_eq!(desk.asker("dev", RunId([7; 8])).raise(POST, false, &|| false), Raised { id: None, came: Came::Full });
    // Another box still may.
    let web = raising(&desk, "web", false);
    until(|| desk.records().len() == 4);
    for bytes in desk.records() {
        assert_eq!(desk.answer_here(false, &answer_digest(&bytes, false)), Here::Denied);
    }
    for raised in waiting {
        assert_eq!(raised.join().unwrap().came, Came::No(By::Local));
    }
    assert_eq!(web.join().unwrap().came, Came::No(By::Local));
    // The desk's own limit counts every box's, and says it is the workspace's.
    let desk = Desk::new("mac-1".into(), "acme".into(), Limits { per_desk: 2, ..limits() }, Script::with(vec![]));
    let waiting = [raising(&desk, "dev", false), raising(&desk, "web", false)];
    until(|| desk.records().len() == 2);
    assert_eq!(desk.asker("api", RunId([7; 8])).raise(POST, false, &|| false).came, Came::WorkspaceFull);
    desk.close();
    for raised in waiting {
        assert_eq!(raised.join().unwrap().came, Came::Withdrawn);
    }
}

#[test]
fn after_three_refusals_in_a_row_a_box_rests() {
    let rest = Duration::from_millis(500);
    let desk = desk(Limits { wait: Duration::from_millis(600), rest, ..LIMITS }, Script::with(vec![]));
    let deny = |name: &str| {
        let raised = raising(&desk, name, false);
        let (_, bytes) = the_one(&desk);
        assert_eq!(desk.answer_here(false, &answer_digest(&bytes, false)), Here::Denied);
        raised.join().unwrap().came
    };
    let approve = |name: &str| {
        let raised = raising(&desk, name, false);
        let (_, bytes) = the_one(&desk);
        assert_eq!(desk.answer_here(true, &answer_digest(&bytes, true)), Here::Approved);
        raised.join().unwrap().came
    };
    let expire = |name: &str| raising(&desk, name, false).join().unwrap().came;
    // Two, then a yes: the count starts again.
    assert_eq!((deny("dev"), expire("dev"), approve("dev")), (Came::No(By::Local), Came::Expired, Came::Yes(By::Local)));
    // Three in a row, denied or not answered: refused at once, for a while, and only that box.
    assert_eq!((deny("dev"), expire("dev"), deny("dev")), (Came::No(By::Local), Came::Expired, Came::No(By::Local)));
    let rested = Instant::now();
    assert_eq!(desk.asker("dev", RunId([7; 8])).raise(POST, false, &|| false), Raised { id: None, came: Came::Resting });
    assert_eq!(expire("web"), Came::Expired);
    while rested.elapsed() < rest {
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(approve("dev"), Came::Yes(By::Local));
}

#[test]
fn a_request_is_withdrawn_when_its_box_stops_or_the_workspace_closes() {
    let script = Script::with(vec![Step::UntilWithdrawn]);
    let desk = desk(limits(), script.clone());
    let stopped = Arc::new(AtomicBool::new(false));
    let (asker, stopping) = (desk.asker("dev", RunId([7; 8])), stopped.clone());
    let raised = thread::spawn(move || asker.raise(POST, true, &|| stopping.load(Ordering::SeqCst)));
    let (_, bytes) = the_one(&desk);
    stopped.store(true, Ordering::SeqCst);
    assert_eq!(raised.join().unwrap().came, Came::Withdrawn);
    until(|| script.withdrawn() > 0);
    assert_eq!(desk.answer_here(true, &answer_digest(&bytes, true)), Here::Gone);
    // Closing withdraws what waits, and from then on nothing is raised.
    let raised = raising(&desk, "dev", false);
    the_one(&desk);
    desk.close();
    assert_eq!(raised.join().unwrap().came, Came::Withdrawn);
    assert_eq!(desk.asker("dev", RunId([7; 8])).raise(POST, false, &|| false), Raised { id: None, came: Came::Withdrawn });
}

// --- answers from a phone ---

// Known answers, made apart from this code: the key by `openssl ecparam -name prime256v1 -genkey`
// and `openssl pkey -pubout -outform DER`, the bytes by a few lines of Python following the text of
// this module, and the signature by `openssl dgst -sha256 -sign` over them.
const OPENSSL_KEY: &str = concat!(
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004ad474f6ad6407053a2fdb194da78b401e1c5768d31d9db888c3996aeeecc3747d9",
    "4a1ea3f9aa90bc2e5cdec1617c9a4738cf570e9c62843d0fe5ce95a75e198d",
);
const ANSWER_YES_SIGNATURE: &str =
    concat!("3046022100bb06b04aa4bf5e4bf2ef8f5c2e6a1956bcdc4cfe6f34ea2d9e57c39d19f805b5022100eb527ee01876a08fc15dd17f11ad77568da1f5107a43bc8b", "01c37309cda22f26",);

fn unhexed(text: &str) -> Vec<u8> {
    crate::util::unhex(text).unwrap()
}

#[test]
fn a_phone_signs_the_bytes_whose_digest_a_local_answer_names() {
    let bytes = known().encode().unwrap();
    assert_eq!(hex(&answer_bytes(&bytes, true)), format!("{KNOWN}0003796573"));
    assert_eq!(hex(&answer_bytes(&bytes, false)), format!("{KNOWN}00026e6f"));
    // SHA-256 over them is the digest `halti requests` sends: what an ECDSA signature signs.
    assert_eq!(<[u8; 32]>::from(Sha256::digest(answer_bytes(&bytes, true))), answer_digest(&bytes, true));
    let key = DeviceKey::from_spki(&unhexed(OPENSSL_KEY)).unwrap();
    assert_eq!(key.verify(&answer_bytes(&bytes, true), &unhexed(ANSWER_YES_SIGNATURE)), Ok(()));
    assert!(key.verify(&answer_bytes(&bytes, false), &unhexed(ANSWER_YES_SIGNATURE)).is_err(), "a yes is no no");
    let other = Record { id: Id([1; 16]), ..known() }.encode().unwrap();
    assert!(key.verify(&answer_bytes(&other, true), &unhexed(ANSWER_YES_SIGNATURE)).is_err(), "nor a yes to another request");
}

/// A phone's signing key, and how a machine that trusts it for `ws` holds it.
fn phone(name: &str, ws: &[&str]) -> (rcgen::KeyPair, Trusted) {
    use rcgen::PublicKeyData;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let spki = key.subject_public_key_info();
    let trusted = Trusted {
        name: name.into(),
        key: DeviceKey::from_spki(&spki).unwrap(),
        fingerprint: crate::hub::wire::fingerprint(&spki),
        ws: ws.iter().map(|ws| ws.to_string()).collect(),
    };
    (key, trusted)
}

fn signed(key: &rcgen::KeyPair, bytes: &[u8], yes: bool) -> Vec<u8> {
    use rcgen::SigningKey;
    key.sign(&answer_bytes(bytes, yes)).unwrap()
}

#[test]
fn a_signed_answer_counts_only_from_a_device_trusted_for_the_workspace() {
    let script = Script::with(vec![Step::UntilWithdrawn]);
    let desk = desk(limits(), script.clone());
    let (pixel, pixel_trusted) = phone("pixel", &["acme"]);
    let (tablet, tablet_trusted) = phone("tablet", &["beta"]);
    let all = [pixel_trusted.clone(), tablet_trusted];
    let trust = |name: &str| all.iter().find(|trusted| trusted.name == name).cloned();
    let raised = raising(&desk, "dev", true);
    let (record, bytes) = the_one(&desk);
    until(|| script.asked().len() == 1);
    // A device nobody trusts, one trusted for another workspace, another key under a trusted name,
    // a signature over the other decision: each refused, and the request still waits.
    for (device, key, yes) in [("nobody", &pixel, true), ("tablet", &tablet, true), ("pixel", &tablet, true), ("pixel", &pixel, false)] {
        assert_eq!(desk.answer_signed(&trust, device, true, record.id, &signed(key, &bytes, yes)), Here::Refused, "{device}");
    }
    assert_eq!(desk.answer_signed(&trust, "pixel", true, Id([9; 16]), &signed(&pixel, &bytes, true)), Here::Gone, "no such request");
    assert_eq!(desk.records().len(), 1);
    // The right one: approved with nothing asked here, and the prompt here withdrawn.
    assert_eq!(desk.answer_signed(&trust, "pixel", true, record.id, &signed(&pixel, &bytes, true)), Here::Approved);
    let came = raised.join().unwrap().came;
    let Came::Yes(By::Device(by)) = &came else { panic!("{came:?}") };
    assert_eq!((by.device.as_str(), &by.fingerprint, &by.record), ("pixel", &pixel_trusted.fingerprint, &bytes));
    assert_eq!(pixel_trusted.key.verify(&answer_bytes(&bytes, true), &by.signature), Ok(()), "kept as it was checked");
    until(|| script.withdrawn() > 0);
    assert_eq!(script.asked().len(), 1, "a signed yes asks nothing more here");
    // The first answer won: the same again, or one from here, finds nothing.
    assert_eq!(desk.answer_signed(&trust, "pixel", true, record.id, &signed(&pixel, &bytes, true)), Here::Gone);
    assert_eq!(desk.answer_here(false, &answer_digest(&bytes, false)), Here::Gone);
}

#[test]
fn a_signed_no_counts_and_an_answer_from_here_first_leaves_it_nothing() {
    let desk = desk(limits(), Script::with(vec![]));
    let (pixel, trusted) = phone("pixel", &["acme"]);
    let trust = |name: &str| (name == "pixel").then(|| trusted.clone());
    let raised = raising(&desk, "dev", false);
    let (record, bytes) = the_one(&desk);
    assert_eq!(desk.answer_signed(&trust, "pixel", false, record.id, &signed(&pixel, &bytes, false)), Here::Denied);
    assert!(matches!(raised.join().unwrap().came, Came::No(By::Device(_))));
    let raised = raising(&desk, "dev", false);
    let (record, bytes) = the_one(&desk);
    assert_eq!(desk.answer_here(true, &answer_digest(&bytes, true)), Here::Approved);
    assert_eq!(desk.answer_signed(&trust, "pixel", false, record.id, &signed(&pixel, &bytes, false)), Here::Gone);
    assert_eq!(raised.join().unwrap().came, Came::Yes(By::Local));
}

#[test]
fn a_signed_answer_after_expiry_is_gone() {
    let desk = desk(Limits { wait: Duration::from_millis(300), ..limits() }, Script::with(vec![]));
    let (pixel, trusted) = phone("pixel", &["acme"]);
    let trust = |name: &str| (name == "pixel").then(|| trusted.clone());
    let raised = raising(&desk, "dev", false);
    let (record, bytes) = the_one(&desk);
    assert_eq!(raised.join().unwrap().came, Came::Expired);
    assert_eq!(desk.answer_signed(&trust, "pixel", true, record.id, &signed(&pixel, &bytes, true)), Here::Gone);
}

/// Boxes that run until a stop names them.
struct Running(Mutex<Vec<(String, RunId)>>);

impl Runs for Running {
    fn runs(&self) -> Vec<(String, RunId)> {
        self.0.lock().unwrap().clone()
    }

    fn stop(&self, runs: &[RunId]) -> u32 {
        let mut boxes = self.0.lock().unwrap();
        let before = boxes.len();
        boxes.retain(|(_, run)| !runs.contains(run));
        (before - boxes.len()) as u32
    }
}

#[test]
fn a_signed_answer_or_stop_handed_over_again_is_told_what_it_came_to() {
    use rcgen::SigningKey;
    let desk = desk(limits(), Script::with(vec![]));
    let (pixel, trusted) = phone("pixel", &["acme"]);
    let trust = |name: &str| (name == "pixel").then(|| trusted.clone());
    let boxes = Running(Mutex::new(vec![("dev".into(), RunId([1; 8]))]));
    let acme = halti_core::ids::WsName::parse("acme").unwrap();
    // A yes that counted, handed over again as it was: approved again, and nothing more is done.
    let raised = raising(&desk, "dev", false);
    let (record, bytes) = the_one(&desk);
    let answer = Records::Signed { ws: acme.clone(), device: "pixel".into(), yes: true, id: record.id, signature: signed(&pixel, &bytes, true) };
    assert_eq!(told(&desk, &trust, &boxes, &answer), [Told::Approved]);
    assert!(matches!(raised.join().unwrap().came, Came::Yes(By::Device(_))));
    assert_eq!(told(&desk, &trust, &boxes, &answer), [Told::Approved]);
    // Signed again, it is another answer: the request is gone.
    let again = Records::Signed { ws: acme.clone(), device: "pixel".into(), yes: true, id: record.id, signature: signed(&pixel, &bytes, true) };
    assert_eq!(told(&desk, &trust, &boxes, &again), [Told::Gone]);
    // A stop likewise: the box it stopped is said stopped again; another signature stops nothing.
    let named = vec![("dev".to_string(), RunId([1; 8]))];
    let stop = |signature: Vec<u8>| Records::Stop { ws: acme.clone(), device: "pixel".into(), runs: named.clone(), signature };
    let signature = pixel.sign(&crate::hub::wire::stop_bytes("mac-1", "acme", &named)).unwrap();
    let stopped = |stopped| [Told::Stopped { stopped, wrong_box: 0 }];
    assert_eq!(told(&desk, &trust, &boxes, &stop(signature.clone())), stopped(1));
    assert_eq!(told(&desk, &trust, &boxes, &stop(signature)), stopped(1));
    let other = pixel.sign(&crate::hub::wire::stop_bytes("mac-1", "acme", &named)).unwrap();
    assert_eq!(told(&desk, &trust, &boxes, &stop(other)), stopped(0));
}

#[test]
fn a_signed_stop_leaves_each_run_named_with_another_box() {
    use rcgen::SigningKey;
    let desk = desk(limits(), Script::with(vec![]));
    let (pixel, trusted) = phone("pixel", &["acme"]);
    let trust = |name: &str| (name == "pixel").then(|| trusted.clone());
    let (dev, prod, web) = (RunId([1; 8]), RunId([2; 8]), RunId([3; 8]));
    let boxes = Running(Mutex::new(vec![("dev".into(), dev), ("prod".into(), prod), ("web".into(), web)]));
    let stop = |runs: &[(&str, RunId)]| {
        let runs: Vec<(String, RunId)> = runs.iter().map(|(name, run)| (name.to_string(), *run)).collect();
        let signature = pixel.sign(&crate::hub::wire::stop_bytes("mac-1", "acme", &runs)).unwrap();
        stop_signed(&desk, &trust, &boxes, "pixel", &runs, &signature)
    };
    // prod's run named as dev's, and web's as a box that isn't there: both run on. dev, named with
    // its own box, stops; a run that isn't there is passed over.
    assert_eq!(stop(&[("dev", dev), ("dev", prod), ("scratch", web), ("dev", RunId([9; 8]))]), Some(Told::Stopped { stopped: 1, wrong_box: 2 }));
    assert_eq!(boxes.runs(), vec![("prod".to_string(), prod), ("web".to_string(), web)]);
    assert_eq!(stop(&[("web", prod)]), Some(Told::Stopped { stopped: 0, wrong_box: 1 }));
    assert_eq!(stop(&[("prod", prod), ("web", web)]), Some(Told::Stopped { stopped: 2, wrong_box: 0 }));
    assert!(boxes.runs().is_empty());
}

#[test]
fn a_stop_says_run_for_one_and_runs_for_more() {
    assert_eq!(runs_named(1), "1 run");
    assert_eq!(runs_named(2), "2 runs");
    assert_eq!(runs_named(32), "32 runs");
}
