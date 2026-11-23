//! Confirmation by the person at the Mac: Touch ID, or the login password as a fallback.
//! An agent can't answer this prompt, so it gates everything that loosens a policy or
//! releases a value outside halti.

use anyhow::{Result, bail};

use crate::requests::Prompted;

/// How long the Touch ID window of a request stays up before it is taken down (the `TIMEOUT` of
/// `ask_person_until`, which is frozen): the request then waits on for an answer from elsewhere.
pub const TOUCH_ID_WAIT: std::time::Duration = std::time::Duration::from_secs(120);

/// The answers to one request's prompts, in order (true: approved). A request that is audited
/// keeps its own and passes it to every `confirm` it causes, so each answer comes back to the
/// request that asked and to no other: not another call's, a door's, or another box's in the same
/// process. A prompt no log records is given a fresh one.
#[derive(Default, Debug)]
pub struct Answers(Vec<bool>);

impl Answers {
    pub fn all(&self) -> &[bool] {
        &self.0
    }
}

/// Ask for confirmation for the request `answers` belongs to, and keep the answer there; macOS
/// shows it as "halti is trying to <reason>."
pub fn confirm(answers: &mut Answers, reason: &str) -> Result<()> {
    let result = prompt(reason);
    #[cfg(test)]
    SHOWN.lock().unwrap().push((reason.to_string(), result.is_ok()));
    answers.0.push(result.is_ok());
    result
}

/// Every prompt this test process showed and no test has taken yet, with its answer: tests count
/// the prompts a door raised by their reasons. Nothing outside tests has it.
#[cfg(test)]
static SHOWN: std::sync::Mutex<Vec<(String, bool)>> = std::sync::Mutex::new(Vec::new());

/// Takes the answers to the prompts shown so far whose reason starts with `about`, in order.
#[cfg(test)]
pub fn shown(about: &str) -> Vec<bool> {
    let mut shown = SHOWN.lock().unwrap();
    let (taken, kept) = std::mem::take(&mut *shown).into_iter().partition(|(reason, _)| reason.starts_with(about));
    *shown = kept;
    taken.into_iter().map(|(_, answer): (String, bool)| answer).collect()
}

/// How a test that has prompts open at the same time answers each, by its reason.
#[cfg(test)]
type ByReason = Box<dyn Fn(&str) -> bool + Send + Sync>;
#[cfg(test)]
static BY_REASON: std::sync::OnceLock<ByReason> = std::sync::OnceLock::new();

/// From now on this test process answers each prompt as `answer` says for its reason (true:
/// approved); once per process.
#[cfg(test)]
pub fn answer_by_reason(answer: impl Fn(&str) -> bool + Send + Sync + 'static) {
    assert!(BY_REASON.set(Box::new(answer)).is_ok(), "prompts are answered by reason once per process");
}

fn prompt(reason: &str) -> Result<()> {
    #[cfg(test)]
    if let Some(answer) = BY_REASON.get() {
        return if answer(reason) { Ok(()) } else { bail!("not approved: {reason}") };
    }
    // Automated tests answer for the user. Release builds don't contain this.
    #[cfg(halti_dev)]
    if let Some(answer) = crate::util::dev_var("HALTI_TEST_APPROVE") {
        eprintln!("halti: [test] {reason}: {}", answer.to_string_lossy());
        return if answer == "yes" { Ok(()) } else { bail!("not approved: {reason}") };
    }

    ask_person(reason)
}

#[cfg(target_os = "macos")]
fn ask_person(reason: &str) -> Result<()> {
    use std::sync::mpsc;
    use std::time::Duration;

    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    /// How long the prompt waits for an answer before it is withdrawn.
    const TIMEOUT: Duration = Duration::from_secs(120);

    let context = unsafe { LAContext::new() };
    let (tx, rx) = mpsc::channel();
    let reply = RcBlock::new(move |ok: Bool, error: *mut NSError| {
        let failure = (!ok.as_bool()).then(|| unsafe { error.as_ref() }.map_or("cancelled".to_string(), |e| e.localizedDescription().to_string()));
        let _ = tx.send(failure);
    });
    unsafe {
        context.evaluatePolicy_localizedReason_reply(LAPolicy::DeviceOwnerAuthentication, &NSString::from_str(reason), &reply);
    }
    match rx.recv_timeout(TIMEOUT) {
        Ok(None) => Ok(()),
        Ok(Some(why)) => bail!("not approved ({why}): {reason}"),
        Err(_) => {
            unsafe { context.invalidate() };
            bail!("no answer to the approval prompt: {reason}")
        }
    }
}

/// Nobody can answer here, so everything that needs a person is refused.
#[cfg(not(target_os = "macos"))]
fn ask_person(reason: &str) -> Result<()> {
    bail!("not approved (Touch ID needs macOS): {reason}")
}

/// Asks as `confirm` does, until `withdrawn` says the question is gone: then the window is taken
/// down. A no is the person's own, a Cancel or a failed try. A window that couldn't be shown, or
/// was taken down, says nothing, and neither does a system with no Touch ID.
pub fn ask_until(reason: &str, withdrawn: &dyn Fn() -> bool) -> Prompted {
    // Automated tests answer for the user. Release builds don't contain this.
    #[cfg(halti_dev)]
    if let Some(answer) = crate::util::dev_var("HALTI_TEST_APPROVE") {
        eprintln!("halti: [test] {reason}: {}", answer.to_string_lossy());
        return if answer == "yes" { Prompted::Yes } else { Prompted::No };
    }
    ask_person_until(reason, withdrawn)
}

#[cfg(target_os = "macos")]
fn ask_person_until(reason: &str, withdrawn: &dyn Fn() -> bool) -> Prompted {
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::time::{Duration, Instant};

    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    /// How long the window waits for an answer before it is taken down.
    const TIMEOUT: Duration = Duration::from_secs(120);
    /// How often `withdrawn` is looked at.
    const LOOK_EVERY: Duration = Duration::from_millis(100);
    /// LocalAuthentication's codes for a failed try and for Cancel: the person's no.
    const FAILED: isize = -1;
    const CANCELLED: isize = -2;

    let context = unsafe { LAContext::new() };
    let (tx, rx) = mpsc::channel();
    let reply = RcBlock::new(move |ok: Bool, error: *mut NSError| {
        let failure = (!ok.as_bool()).then(|| unsafe { error.as_ref() }.map_or(CANCELLED, |e| e.code()));
        let _ = tx.send(failure);
    });
    unsafe {
        context.evaluatePolicy_localizedReason_reply(LAPolicy::DeviceOwnerAuthentication, &NSString::from_str(reason), &reply);
    }
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match rx.recv_timeout(LOOK_EVERY) {
            Ok(None) => return Prompted::Yes,
            Ok(Some(FAILED | CANCELLED)) => return Prompted::No,
            Ok(Some(_)) | Err(RecvTimeoutError::Disconnected) => return Prompted::Unshown,
            Err(RecvTimeoutError::Timeout) if withdrawn() || Instant::now() >= deadline => {
                unsafe { context.invalidate() };
                return Prompted::Unshown;
            }
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn ask_person_until(_reason: &str, _withdrawn: &dyn Fn() -> bool) -> Prompted {
    Prompted::Unshown
}
