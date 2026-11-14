//! Confirmation by the person at the Mac: Touch ID, or the login password as a fallback.
//! An agent can't answer this prompt, so it gates everything that loosens a policy or
//! releases a value outside halti.

use std::cell::RefCell;

use anyhow::{Result, bail};

thread_local! {
    /// How each prompt this thread asked was answered since its last `take_answers` (true:
    /// approved). Kept per thread: where several boxes run in one process, a call reads back only
    /// what it asked itself.
    static ANSWERS: RefCell<Vec<bool>> = const { RefCell::new(Vec::new()) };
}

/// The answers to the prompts this thread asked so far, and forget them. The audit log reads what a
/// call asked.
pub fn take_answers() -> Vec<bool> {
    ANSWERS.with_borrow_mut(std::mem::take)
}

/// Ask for confirmation; macOS shows it as "halti is trying to <reason>."
pub fn confirm(reason: &str) -> Result<()> {
    let result = prompt(reason);
    note(result.is_ok());
    result
}

fn note(approved: bool) {
    ANSWERS.with_borrow_mut(|answers| answers.push(approved));
}

fn prompt(reason: &str) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn answers_are_kept_per_thread() {
        take_answers();
        note(true);
        let other = thread::spawn(|| {
            note(false);
            take_answers()
        });
        assert_eq!(other.join().unwrap(), [false], "another thread reads only its own");
        assert_eq!(take_answers(), [true]);
        assert!(take_answers().is_empty());
    }
}
