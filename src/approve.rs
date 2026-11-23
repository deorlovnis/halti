//! Confirmation by the person at the Mac: Touch ID, or the login password as a fallback.
//! An agent can't answer this prompt, so it gates everything that loosens a policy or
//! releases a value outside halti.

use std::cell::RefCell;

use anyhow::{Result, bail};

use crate::requests::Prompted;

/// How long the Touch ID window of a request stays up before it is taken down (the `TIMEOUT` of
/// `ask_person_until`, which is frozen): the request then waits on for an answer from elsewhere.
pub const TOUCH_ID_WAIT: std::time::Duration = std::time::Duration::from_secs(120);

thread_local! {
    /// The answers to the call `answers_to` runs on this thread, while it runs (true: approved).
    /// Nothing is kept on a thread no call listens on, such as a door's.
    static LISTENING: RefCell<Option<Vec<bool>>> = const { RefCell::new(None) };
}

/// Runs `call`, and how each prompt it asked was answered, in order. The audit log reads what a call
/// asked. A call's prompts run on the thread that runs it (halti has no async tasks to move them),
/// so the prompts of other calls and of door threads in the same process are never among them.
/// Within another `answers_to`, the outer call hears these answers too.
pub fn answers_to<T>(call: impl FnOnce() -> T) -> (T, Vec<bool>) {
    /// The outer call's answers, put back when this call ends, also by a panic.
    struct Outer(Option<Vec<bool>>);
    impl Drop for Outer {
        fn drop(&mut self) {
            let inner = LISTENING.take().unwrap_or_default();
            let mut outer = self.0.take();
            if let Some(outer) = &mut outer {
                outer.extend(inner);
            }
            LISTENING.set(outer);
        }
    }
    let outer = Outer(LISTENING.replace(Some(Vec::new())));
    let result = call();
    let answers = LISTENING.with_borrow(|answers| answers.clone().unwrap_or_default());
    drop(outer);
    (result, answers)
}

/// Ask for confirmation; macOS shows it as "halti is trying to <reason>."
pub fn confirm(reason: &str) -> Result<()> {
    let result = prompt(reason);
    note(result.is_ok());
    result
}

fn note(approved: bool) {
    LISTENING.with_borrow_mut(|answers| answers.as_mut().map(|answers| answers.push(approved)));
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

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn a_call_hears_only_the_prompts_it_asked_itself() {
        note(false);
        let ((), answers) = answers_to(|| {
            note(true);
            thread::spawn(|| note(false)).join().unwrap();
        });
        assert_eq!(answers, [true], "neither what was asked before nor on another thread");
        let ((), answers) = answers_to(|| ());
        assert!(answers.is_empty(), "nothing was kept from outside a call");
    }

    #[test]
    fn a_call_within_a_call_is_heard_by_both() {
        let (inner, outer) = answers_to(|| {
            note(true);
            let ((), inner) = answers_to(|| note(false));
            inner
        });
        assert_eq!((inner, outer), (vec![false], vec![true, false]));
    }

    #[test]
    fn a_call_that_panics_leaves_the_outer_call_listening() {
        fn fails() {
            note(false);
            panic!("the call fails");
        }
        let ((), outer) = answers_to(|| {
            assert!(std::panic::catch_unwind(|| answers_to(fails)).is_err());
            note(true);
        });
        assert_eq!(outer, [false, true]);
    }
}
