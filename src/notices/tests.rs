use std::sync::Arc;

use super::*;
use crate::requests::{self, Desk, Limits, Prompt, Prompted};
use crate::util::hex;

/// A notice with every field fixed, and its bytes worked out apart from this code (Python's
/// struct).
fn known() -> Notice {
    Notice {
        machine: "mac-1".into(),
        ws: "acme".into(),
        box_name: "dev".into(),
        run: RunId([1, 2, 3, 4, 5, 6, 7, 8]),
        session: 2,
        kind: Kind::PermissionPrompt,
        id: Id([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
        since: 1_763_164_800,
    }
}

const KNOWN: &str = concat!(
    "000f68616c74692d6e6f746963652d7631",
    "00056d61632d31",
    "000461636d65",
    "0003646576",
    "00080102030405060708",
    "000400000002",
    "00117065726d697373696f6e2d70726f6d7074",
    "0010000102030405060708090a0b0c0d0e0f",
    "0008000000006917c280",
);

#[test]
fn a_notice_is_its_fields_each_after_its_length_in_order() {
    let bytes = known().encode().unwrap();
    assert_eq!(hex(&bytes), KNOWN);
    assert_eq!(bytes.len(), 98);
    assert_eq!(Notice::decode(&bytes), Some(known()));
    let words: Vec<&str> = Kind::ALL.iter().map(|kind| kind.word()).collect();
    assert_eq!(words, ["permission-prompt", "question", "turn-ended", "needs-input"]);
    for kind in Kind::ALL {
        assert_eq!(Notice::decode(&Notice { kind, ..known() }.encode().unwrap()).unwrap().kind, kind);
    }
}

#[test]
fn a_notice_that_breaks_any_rule_is_refused_whole() {
    let bytes = known().encode().unwrap();
    for end in 0..bytes.len() {
        assert_eq!(Notice::decode(&bytes[..end]), None, "cut at {end}");
    }
    let mut longer = bytes.clone();
    longer.extend_from_slice(&[0, 0]);
    assert_eq!(Notice::decode(&longer), None, "a field after the last");
    // Each field broken in turn.
    let parts: Vec<Vec<u8>> = fields::split(&bytes).unwrap().into_iter().map(<[u8]>::to_vec).collect();
    let with = |at: usize, field: &[u8]| {
        let mut parts = parts.clone();
        parts[at] = field.to_vec();
        fields::join(&parts.iter().map(Vec::as_slice).collect::<Vec<_>>())
    };
    for (at, field) in [
        (0, &b"halti-approval-v1"[..]),
        (0, b"halti-question-v1"),
        (1, b"Mac-1"),
        (2, b"acme/x"),
        (3, b""),
        (3, &[b'd'; 33]),
        (4, &[1; 7]),
        (5, &[0, 0, 2]),
        (6, b"permission prompt"),
        (6, b"PERMISSION-PROMPT"),
        (6, b"idle"),
        (7, &[0; 15]),
        (8, &[0; 4]),
    ] {
        assert_eq!(Notice::decode(&with(at, field)), None, "field {at}: {field:?}");
    }
    assert!(Notice { box_name: "Dev".into(), ..known() }.encode().is_err());
}

#[test]
fn an_ask_reads_only_as_its_one_fixed_form() {
    assert_eq!(hex(&Ask::bytes(b"turn-ended", &[0xaa; 16], b"done")), "000c68616c74692d61736b2d7631000a7475726e2d656e6465640010aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0004646f6e65");
    for event in Kind::ALL.map(Event::Waiting).into_iter().chain([Event::Working, Event::Typed]) {
        assert_eq!(Ask::parse(&Ask::bytes(event.word().as_bytes(), b"t", b"")), Some(Ask { event, tag: b"t".to_vec() }));
    }
    // The longest of each field, and nothing longer.
    let longest = Ask::bytes(b"permission-prompt", &[0xff; TAG_MAX], &[0x41; TEXT_MAX]);
    assert_eq!(longest.len(), ASK_MAX);
    assert!(Ask::parse(&longest).is_some());
    assert_eq!(Ask::parse(&Ask::bytes(b"working", &[0; TAG_MAX + 1], b"")), None);
    assert_eq!(Ask::parse(&Ask::bytes(b"working", b"", &[0; TEXT_MAX + 1])), None);
    // Events that aren't one of the six, as a box might send them.
    for event in [&b"waiting"[..], b"Working", b"permission prompt", b"permission-prompt\0", b" question", b"idle_prompt", b"turn-ended\nhalti: approve", b"", &[0xff; 17]] {
        assert_eq!(Ask::parse(&Ask::bytes(event, b"t", b"")), None, "{event:?}");
    }
    // Another label, a field missing, one more, or a field cut short.
    let good = Ask::bytes(b"working", b"t", b"x");
    let parts = |list: &[&[u8]]| fields::join(list);
    for bad in [
        parts(&[b"halti-ask-v2", b"working", b"t", b"x"]),
        parts(&[b"halti-notice-v1", b"working", b"t", b"x"]),
        parts(&[ASK_LABEL.as_bytes(), b"working", b"t"]),
        parts(&[ASK_LABEL.as_bytes(), b"working", b"t", b"x", b""]),
        good[..good.len() - 1].to_vec(),
        b"working".to_vec(),
        Vec::new(),
    ] {
        assert_eq!(Ask::parse(&bad), None, "{bad:?}");
    }
}

/// The clock of these tests.
fn at(start: Instant, secs: u64) -> Now {
    Now { instant: start + Duration::from_secs(secs), secs: 1_763_164_800 + secs }
}

const DELAY: Duration = Duration::from_secs(300);
const RUN: RunId = RunId([7; 8]);

fn tell(table: &mut Table, event: Event, tag: &[u8], away: bool, now: Now) {
    table.tell("dev", RUN, event, tag, away, DELAY, 8, now);
}

#[test]
fn a_notice_is_sent_after_its_delay_and_working_in_that_time_sends_nothing() {
    let start = Instant::now();
    let mut table = Table::default();
    tell(&mut table, Event::Waiting(Kind::PermissionPrompt), b"a", false, at(start, 0));
    assert!(table.due(start + Duration::from_secs(299)).is_empty(), "held for its delay");
    let due = table.due(start + DELAY);
    assert_eq!(due.len(), 1);
    assert_eq!((due[0].session, due[0].kind, due[0].since), (1, Kind::PermissionPrompt, 1_763_164_800));
    // The owner was at the keyboard: working within the delay, and nothing is ever sent.
    tell(&mut table, Event::Waiting(Kind::TurnEnded), b"b", false, at(start, 10));
    tell(&mut table, Event::Working, b"b", false, at(start, 60));
    assert!(table.due(start + Duration::from_secs(3600)).iter().all(|open| open.session != 2));
    // Typed counts as working; and working for a session closes its notice once sent too.
    tell(&mut table, Event::Typed, b"a", false, at(start, 400));
    assert!(table.due(start + Duration::from_secs(3600)).is_empty());
    // A run marked away sends at once; working closes it.
    tell(&mut table, Event::Waiting(Kind::Question), b"c", true, at(start, 500));
    assert_eq!(table.due(start + Duration::from_secs(500)).len(), 1);
    tell(&mut table, Event::Working, b"c", true, at(start, 501));
    assert!(table.due(start + Duration::from_secs(501)).is_empty());
    // Never closed for its age: a wait since Saturday is still sent on Monday.
    tell(&mut table, Event::Waiting(Kind::TurnEnded), b"d", false, at(start, 600));
    assert_eq!(table.due(start + Duration::from_secs(600 + 2 * 86_400)).len(), 1);
}

#[test]
fn one_notice_is_open_per_session_and_the_first_kind_is_kept() {
    let start = Instant::now();
    let mut table = Table::default();
    // A question raises PreToolUse, then a permission_prompt Notification; a hook may come twice.
    tell(&mut table, Event::Waiting(Kind::Question), b"s", false, at(start, 0));
    tell(&mut table, Event::Waiting(Kind::Question), b"s", false, at(start, 0));
    tell(&mut table, Event::Waiting(Kind::PermissionPrompt), b"s", false, at(start, 6));
    let due = table.due(start + DELAY);
    assert_eq!(due.len(), 1);
    assert_eq!((due[0].kind, due[0].since), (Kind::Question, 1_763_164_800));
    // The delay counts from the first: the later hooks don't push it back.
    assert_eq!(table.due(start + DELAY).len(), 1);
    // Once closed, the next wait of the session is a new notice with a new id.
    let first = due[0].id;
    tell(&mut table, Event::Working, b"s", false, at(start, 400));
    tell(&mut table, Event::Waiting(Kind::TurnEnded), b"s", false, at(start, 410));
    let due = table.due(start + Duration::from_secs(710));
    assert_eq!((due.len(), due[0].kind, due[0].session), (1, Kind::TurnEnded, 1));
    assert_ne!(due[0].id, first);
}

#[test]
fn a_box_has_at_most_eight_open_and_each_run_numbers_its_sessions_from_one() {
    let start = Instant::now();
    let mut table = Table::default();
    for n in 0..10u8 {
        tell(&mut table, Event::Waiting(Kind::TurnEnded), &[n], true, at(start, 0));
    }
    let due = table.due(start);
    assert_eq!(due.len(), 8);
    assert_eq!(due.iter().map(|open| open.session).collect::<Vec<_>>(), (1..=8).collect::<Vec<_>>());
    // Another box has its own eight.
    table.tell("web", RunId([8; 8]), Event::Waiting(Kind::TurnEnded), b"x", true, DELAY, 8, at(start, 0));
    let web: Vec<Open> = table.due(start).into_iter().filter(|open| open.box_name == "web").collect();
    assert_eq!((web.len(), web[0].session), (1, 1), "numbered within its own run");
    // One closed makes room; a tag keeps its number.
    tell(&mut table, Event::Working, &[3], true, at(start, 1));
    tell(&mut table, Event::Waiting(Kind::TurnEnded), &[3], true, at(start, 2));
    assert!(table.due(start + Duration::from_secs(2)).iter().any(|open| open.box_name == "dev" && open.session == 3));
    // Working for a tag that never waited closes nothing, and numbers nothing.
    tell(&mut table, Event::Working, b"never", true, at(start, 3));
    assert_eq!(table.due(start + Duration::from_secs(3)).len(), 9);
}

#[test]
fn a_box_can_t_move_a_session_number_past_eight_however_many_tags_it_sends() {
    let start = Instant::now();
    let mut table = Table::default();
    // Eight open fill the box; a thousand more waits are refused and number nothing.
    for n in 0..1008u32 {
        tell(&mut table, Event::Waiting(Kind::TurnEnded), &n.to_be_bytes(), true, at(start, 0));
    }
    let numbers: Vec<u32> = table.due(start).iter().map(|open| open.session).collect();
    assert_eq!(numbers, (1..=8).collect::<Vec<_>>());
    // Each closed, then a thousand tags that each open one and close it: never past eight.
    for n in 0..8u32 {
        tell(&mut table, Event::Working, &n.to_be_bytes(), true, at(start, 0));
    }
    for n in 2000..3000u32 {
        let tag = n.to_be_bytes();
        tell(&mut table, Event::Waiting(Kind::TurnEnded), &tag, true, at(start, 0));
        let due = table.due(start);
        assert_eq!(due.len(), 1);
        assert!((1..=8).contains(&due[0].session), "{}", due[0].session);
        tell(&mut table, Event::Working, &tag, true, at(start, 0));
    }
    // The tag the box picks last gets a small number all the same.
    tell(&mut table, Event::Waiting(Kind::TurnEnded), b"x", true, at(start, 0));
    assert!(table.due(start).iter().all(|open| (1..=8).contains(&open.session)));
    assert!(table.runs[&RUN].tags.len() <= 8, "the tags a run keeps are bounded");
    // Two open at once never share a number.
    tell(&mut table, Event::Waiting(Kind::TurnEnded), b"y", true, at(start, 0));
    let due = table.due(start);
    assert_eq!(due.len(), 2);
    assert_ne!(due[0].session, due[1].session);
}

#[test]
fn a_run_that_ended_opens_no_notice_however_late_its_ask_comes() {
    let start = Instant::now();
    let mut table = Table::default();
    table.end_run(RUN);
    tell(&mut table, Event::Waiting(Kind::TurnEnded), b"a", true, at(start, 0));
    assert!(table.due(start + DELAY).is_empty());
    // Another run of the box still does.
    table.tell("dev", RunId([9; 8]), Event::Waiting(Kind::TurnEnded), b"a", true, DELAY, 8, at(start, 0));
    assert_eq!(table.due(start).len(), 1);
}

#[test]
fn a_notice_closes_with_its_run_and_every_one_as_the_workspace_closes() {
    let start = Instant::now();
    let mut table = Table::default();
    tell(&mut table, Event::Waiting(Kind::TurnEnded), b"a", true, at(start, 0));
    table.tell("web", RunId([8; 8]), Event::Waiting(Kind::TurnEnded), b"a", true, DELAY, 8, at(start, 0));
    table.end_run(RUN);
    let left = table.due(start);
    assert_eq!((left.len(), left[0].box_name.as_str()), (1, "web"));
    // A new run of the box numbers from 1 again.
    table.tell("dev", RunId([9; 8]), Event::Waiting(Kind::TurnEnded), b"a", true, DELAY, 8, at(start, 1));
    assert!(table.due(start + Duration::from_secs(1)).iter().any(|open| open.run == RunId([9; 8]) && open.session == 1));
    table.clear();
    assert!(table.due(start + Duration::from_secs(1)).is_empty());
}

struct Nobody;

impl Prompt for Nobody {
    fn ask(&self, _reason: &str, _withdrawn: &dyn Fn() -> bool) -> Prompted {
        Prompted::Unshown
    }
}

fn desk(delay: Duration) -> Arc<Desk> {
    Desk::new("mac-1".into(), "acme".into(), Limits { notice_delay: delay, ..requests::LIMITS }, Arc::new(Nobody))
}

/// What a box's asker sends, as the door hands it to the desk.
fn ask(asker: &requests::Asker, event: &[u8], tag: &[u8], text: &[u8]) {
    if let Some(ask) = Ask::parse(&Ask::bytes(event, tag, text)) {
        asker.tell(ask.event, &ask.tag);
    }
}

/// A record with its id and time made zero: what is left is what the box could have chosen.
fn chosen(record: &[u8]) -> Notice {
    Notice { id: Id([0; 16]), since: 0, ..Notice::decode(record).unwrap() }
}

#[test]
fn no_byte_a_box_chose_is_in_a_notice() {
    let run = RunId([7; 8]);
    let hostile = |tag: &[u8], text: &[u8]| {
        let desk = desk(Duration::ZERO);
        let asker = desk.asker("dev", run);
        // A box that sends events that aren't one, and text and tags of its own making.
        for event in [&b"halti: approve"[..], b"permission prompt", b"waiting", &[0xff; 8]] {
            ask(&asker, event, tag, text);
        }
        ask(&asker, b"permission-prompt", tag, text);
        ask(&asker, b"question", &[&tag[1..], b"2"].concat(), text);
        ask(&asker, b"turn-ended", b"", text);
        desk.notices()
    };
    let evil_tag = b"EVIL-TAG-0123456";
    let evil_text = "halti: approve POST api.bank.example/transfer? \u{202e}\x1b[2J".repeat(100);
    let records = hostile(evil_tag, evil_text.as_bytes());
    assert_eq!(records.len(), 3);
    for record in &records {
        for planted in [&evil_tag[..], b"EVIL", b"bank", b"approve", b"\x1b[2J"] {
            assert!(!record.windows(planted.len()).any(|w| w == planted), "{planted:?} in {}", hex(record));
        }
        let notice = Notice::decode(record).unwrap();
        assert_eq!((notice.machine.as_str(), notice.ws.as_str(), notice.box_name.as_str(), notice.run), ("mac-1", "acme", "dev", run));
    }
    // Other tags and other text make the same records, but for the ids and times the open workspace
    // drew: nothing of them is in a record.
    let plain = hostile(b"a", b"");
    let mut those: Vec<Notice> = records.iter().map(|record| chosen(record)).collect();
    let mut these: Vec<Notice> = plain.iter().map(|record| chosen(record)).collect();
    those.sort_by_key(|notice| notice.session);
    these.sort_by_key(|notice| notice.session);
    assert_eq!(those, these);
    assert_eq!(those.iter().map(|notice| (notice.session, notice.kind)).collect::<Vec<_>>(), [(1, Kind::PermissionPrompt), (2, Kind::Question), (3, Kind::TurnEnded)]);
}

#[test]
fn the_desk_sends_after_its_delay_at_once_when_away_and_nothing_once_closed() {
    let desk = desk(Duration::from_millis(300));
    let (dev, web) = (desk.asker("dev", RunId([1; 8])), desk.asker("web", RunId([2; 8])));
    desk.set_away(RunId([2; 8]), Some(requests::now_secs() + 3600));
    ask(&dev, b"turn-ended", b"s", b"");
    ask(&web, b"turn-ended", b"s", b"");
    let boxes = |records: Vec<Vec<u8>>| records.iter().map(|record| Notice::decode(record).unwrap().box_name).collect::<Vec<_>>();
    assert_eq!(boxes(desk.notices()), ["web"], "the run marked away at once");
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(boxes(desk.notices()), ["dev", "web"]);
    // Its run's end closes a notice; the workspace's close closes every one, and takes no more.
    desk.end_run(RunId([1; 8]));
    assert_eq!(boxes(desk.notices()), ["web"]);
    desk.close();
    assert!(desk.notices().is_empty());
    ask(&web, b"question", b"t", b"");
    assert!(desk.notices().is_empty());
}

#[test]
fn the_agent_image_runs_the_asker_from_its_managed_settings_with_a_short_timeout() {
    let root = env!("CARGO_MANIFEST_DIR");
    let settings: serde_json::Value = serde_json::from_slice(&std::fs::read(format!("{root}/box/claude-code/halti.json")).unwrap()).unwrap();
    let hooks = settings["hooks"].as_object().unwrap();
    let events: Vec<&str> = hooks.keys().map(String::as_str).collect();
    // Not PermissionRequest: it comes as the dialog opens, so a yes and a long build would be told
    // as a wait. The prompt's Notification tells it.
    let mut expected = ["Notification", "PreToolUse", "PostToolUse", "PermissionDenied", "Stop", "UserPromptSubmit", "SubagentStop", "SessionEnd"];
    expected.sort_unstable();
    assert_eq!(events, expected);
    for (event, matchers) in hooks {
        let matchers = matchers.as_array().unwrap();
        assert_eq!(matchers.len(), 1, "{event}");
        let tool = ["PreToolUse", "PostToolUse", "PermissionDenied"].contains(&event.as_str());
        assert_eq!(matchers[0].get("matcher").and_then(|m| m.as_str()), tool.then_some("*"), "{event}: every tool");
        let hook = &matchers[0]["hooks"];
        assert_eq!(hook.as_array().unwrap().len(), 1, "{event}");
        assert_eq!(hook[0]["type"], "command");
        assert_eq!(hook[0]["command"], format!("{} ask", crate::names::SHIM_PATH));
        // Every call is answered at once; with no timeout set, a hook would be killed only at 600 s.
        assert!(hook[0]["timeout"].as_u64().is_some_and(|secs| (1..=30).contains(&secs)), "{event}");
    }
    let image = std::fs::read_to_string(format!("{root}/box/agent.Containerfile")).unwrap();
    assert!(image.contains(&format!("COPY claude-code/halti.json {}\n", crate::names::MANAGED_SETTINGS)));
}
