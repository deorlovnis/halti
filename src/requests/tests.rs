use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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
