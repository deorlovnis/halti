//! The passphrase key holder of this machine: core's passphrase record (`halti_core::passphrase`),
//! with the passphrase read here and the seed, salt and nonce drawn here.
//!
//! A passphrase is read only from the terminal device, never from standard input, so nothing can
//! pipe one in, and with no terminal it is refused. Whatever was typed before a question is thrown
//! away first. Each question names the workspace from the prompt core gave, and before a delete the
//! terminal says what it removes. No secret mark is shown beside a question, since any program
//! running as you could read one.
//!
//! `ws new` asks for a passphrase of the person's own, typed twice, then reminds them to write it
//! down. Asked to generate one, it makes 20 random characters of base32, 100 bits, shown once and
//! typed again to confirm.
//!
//! A program running as you can type into a terminal it opened, or capture what you type.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;

use anyhow::{Result, anyhow, bail};
use halti_core::holder::{Change, Commitment, KeyHolder, KeyKind, KeyRef, Prompt, Released};
use halti_core::ids::WsName;
use halti_core::key::{KemCiphertext, PublicKey};
use halti_core::passphrase::{self, KdfParams, Passphrase, PassphraseRecord};
use halti_core::platform::{Adapter, Build, Label};
use halti_core::refusal::Refusal;
use zeroize::Zeroizing;

use super::random;

/// RFC 4648's base32 alphabet, in lowercase: easy to read out and to type.
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// The passphrase key holder. It keeps nothing between calls: the record is the key ref, which the
/// workspace's files hold.
pub struct TtyPassphrase {
    /// `ws new` makes the passphrase and shows it once, instead of asking for one of the person's own.
    generate: bool,
}

impl TtyPassphrase {
    /// Nothing is read until a passphrase is asked for.
    pub fn new(generate: bool) -> TtyPassphrase {
        TtyPassphrase { generate }
    }
}

/// Whether a passphrase can be asked here: the terminal, or in a debug build the test variable.
/// `ws new` checks this first, so with no terminal nothing is made.
pub fn ready() -> Result<()> {
    #[cfg(halti_dev)]
    if crate::util::dev_var("HALTI_TEST_PASSPHRASE").is_some() {
        return Ok(());
    }
    open_tty().map(drop)
}

/// The terminal device, to ask on and show to.
fn open_tty() -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| anyhow!("a passphrase is read only from a terminal, and halti has none here (run it in a terminal; a passphrase can't be piped in)"))
}

/// Where a passphrase is typed.
enum Terminal {
    Tty(File),
    /// A debug build's test variable.
    #[cfg(halti_dev)]
    Test(Zeroizing<String>),
}

impl Terminal {
    /// The terminal, for one prompt core gave; or, in a debug build whose test variable is set, that
    /// variable, which answers every question. A development build first shows the words core gave
    /// the prompt, which say it is not protected.
    fn open(prompt: &Prompt) -> Result<Terminal> {
        // Automated tests answer for the user. Release builds don't contain this.
        #[cfg(halti_dev)]
        if let Some(answer) = crate::util::dev_var("HALTI_TEST_PASSPHRASE") {
            eprintln!("halti: [test] {}", prompt.text());
            return Ok(Terminal::Test(Zeroizing::new(answer.to_string_lossy().into_owned())));
        }
        let mut tty = open_tty()?;
        if prompt.build() == Build::Dev {
            writeln!(tty, "{}", prompt.text())?;
        }
        Ok(Terminal::Tty(tty))
    }

    /// Shows a line on the terminal.
    fn say(&mut self, text: &str) -> Result<()> {
        match self {
            Terminal::Tty(tty) => Ok(writeln!(tty, "{text}")?),
            #[cfg(halti_dev)]
            Terminal::Test(_) => Ok(()),
        }
    }

    /// What is typed after `question`, unseen. Ending the input (Ctrl-D), interrupting it (Ctrl-C)
    /// or typing nothing is a "no", and the terminal is put back as it was.
    fn ask(&mut self, question: &str) -> Result<Zeroizing<String>> {
        let tty = match self {
            Terminal::Tty(tty) => tty,
            #[cfg(halti_dev)]
            Terminal::Test(answer) => {
                eprintln!("halti: [test] asked: {question}");
                return Ok(answer.clone());
            }
        };
        // Typeahead meant for something else must not answer this.
        unsafe { libc::tcflush(tty.as_raw_fd(), libc::TCIFLUSH) };
        let typed = match crate::util::sigint_ignored(|| rpassword::prompt_password(question)) {
            Ok(typed) => Zeroizing::new(typed),
            Err(e) if matches!(e.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::Interrupted) => return Err(Refusal::Declined.into()),
            Err(e) => return Err(anyhow::Error::from(e).context("reading the passphrase")),
        };
        usable(typed)
    }
}

/// What was typed, if it can be a passphrase: nothing typed is a "no". rpassword reads each byte
/// that isn't UTF-8 as U+FFFD, so on a terminal not sending UTF-8 different letters would read the
/// same: such an answer is refused before anything is sealed or tried with it.
fn usable(typed: Zeroizing<String>) -> Result<Zeroizing<String>> {
    if typed.is_empty() {
        return Err(Refusal::Declined.into());
    }
    if typed.contains('\u{FFFD}') {
        bail!("what was typed isn't UTF-8 text, so it can't be a passphrase (set the terminal to UTF-8)");
    }
    Ok(typed)
}

impl Adapter for TtyPassphrase {
    fn label(&self) -> Label {
        passphrase::LABEL
    }
}

impl KeyHolder for TtyPassphrase {
    fn kind(&self) -> KeyKind {
        KeyKind::Passphrase
    }

    /// Asks for a new passphrase (the person's own unless `generate`), then seals a seed drawn here under it.
    fn create(&self, prompt: &Prompt, commitment: &Commitment) -> Result<(KeyRef, PublicKey)> {
        let mut terminal = Terminal::open(prompt)?;
        let passphrase = if self.generate { made(&mut terminal, prompt.name())? } else { own(&mut terminal, prompt.name())? };
        let (seed, salt, nonce) = (random::<96>()?, random::<16>()?, random::<12>()?);
        let record = PassphraseRecord::seal_seed(prompt, &passphrase, seed, commitment, KdfParams::DEFAULT, &salt, &nonce)?;
        Ok((record.to_key_ref(), record.public().clone()))
    }

    fn public(&self, key: &KeyRef) -> Result<PublicKey> {
        Ok(PassphraseRecord::from_key_ref(key)?.public().clone())
    }

    /// Asks once, after saying what a delete removes; core's record does the rest. An answer too
    /// short to be a passphrase is a wrong one, refused as any other is: the length rule is for
    /// choosing a passphrase.
    fn decapsulate(&self, key: &KeyRef, prompt: &Prompt, ct: &KemCiphertext) -> Result<Released> {
        let record = PassphraseRecord::from_key_ref(key)?;
        let name = prompt.name();
        let mut terminal = Terminal::open(prompt)?;
        if prompt.change() == Change::Delete {
            terminal.say(&format!("this deletes workspace {name} and everything in it. it can't be undone."))?;
        }
        let typed = terminal.ask(&format!("passphrase for workspace {name}: "))?;
        let passphrase = Passphrase::new(typed).map_err(|_| Refusal::Unreadable)?;
        Ok(record.decapsulate(prompt, &passphrase, ct)?)
    }

    /// The record is the key ref, which the workspace's files hold: there is nothing else to forget.
    fn destroy(&self, _key: &KeyRef) -> Result<()> {
        Ok(())
    }
}

/// Makes the passphrase and shows it once, then has it typed again, so it is known to be written down right.
fn made(terminal: &mut Terminal, name: &WsName) -> Result<Passphrase> {
    #[cfg(halti_dev)]
    if let Terminal::Test(answer) = terminal {
        return Ok(Passphrase::new(answer.clone())?);
    }
    let passphrase = grouped(random::<20>()?.as_slice());
    // Built at its final length too, so no copy of the passphrase is left behind as it grows.
    let mut shown = Zeroizing::new(String::with_capacity(4 + passphrase.len()));
    shown.push_str("    ");
    shown.push_str(&passphrase);
    terminal.say(&format!("passphrase for workspace {name}. it is shown only once, so write it down:\n"))?;
    terminal.say(&shown)?;
    terminal.say("")?;
    for left in (0..3).rev() {
        if *terminal.ask("type it again to confirm: ")? == *passphrase {
            return Ok(Passphrase::new(passphrase)?);
        }
        if left > 0 {
            terminal.say("that doesn't match, try again")?;
        }
    }
    bail!("workspace {name} was not created: the passphrase didn't match")
}

/// Has a passphrase of the person's own typed twice, then says to write it down: nothing else can
/// open the workspace. One too short or too long is asked for again. After three tries the error
/// says what was wrong with the last.
fn own(terminal: &mut Terminal, name: &WsName) -> Result<Passphrase> {
    let question = format!("new passphrase for workspace {name} (at least {} characters): ", Passphrase::MIN_CHARS);
    let mut why = String::new();
    for left in (0..3).rev() {
        let first = terminal.ask(&question)?;
        let retry = match Passphrase::new(first.clone()) {
            Ok(passphrase) => {
                if *terminal.ask("type it again to confirm: ")? == *first {
                    terminal.say(&format!("write this passphrase down and keep it safe. without it, {name} can't be opened."))?;
                    return Ok(passphrase);
                }
                why = "the two passphrases didn't match".to_string();
                "that doesn't match"
            }
            Err(Refusal::ShortPassphrase) => {
                why = Refusal::ShortPassphrase.to_string();
                "too short"
            }
            Err(_) => {
                why = format!("a passphrase has at most {} bytes and no control characters", Passphrase::MAX_BYTES);
                "too long, or it has control characters"
            }
        };
        if left > 0 {
            terminal.say(&format!("{retry}, try again"))?;
        }
    }
    Err(anyhow!(why).context(format!("workspace {name} was not created")))
}

/// Each byte's low 5 bits as one character of base32, with a dash after every 4: 20 bytes make a
/// passphrase of 100 bits. Built at its final length, so nothing is copied as it grows.
fn grouped(bytes: &[u8]) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::with_capacity(bytes.len() * 5 / 4));
    for (i, byte) in bytes.iter().enumerate() {
        if i > 0 && i.is_multiple_of(4) {
            text.push('-');
        }
        text.push(char::from(BASE32[usize::from(byte & 31)]));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_made_passphrase_is_twenty_characters_of_base32_in_groups_of_four() {
        let seq: Vec<u8> = (0..20).collect();
        assert_eq!(grouped(&seq).as_str(), "abcd-efgh-ijkl-mnop-qrst");
        // Only the low 5 bits count, so each character is one of 32, each as likely.
        assert_eq!(grouped(&[31, 32, 63, 255, 26, 0xe1]).as_str(), "7a77-2b");
        let made = grouped(&[0xff; 20]);
        assert_eq!((made.as_str(), made.len()), ("7777-7777-7777-7777-7777", 24));
        assert!(Passphrase::new(made).is_ok(), "longer than core's minimum");
    }

    #[test]
    fn an_answer_is_refused_when_nothing_was_typed_or_the_terminal_sent_no_utf8() {
        let refusal = usable(Zeroizing::new(String::new())).unwrap_err();
        assert_eq!(refusal.downcast_ref::<Refusal>(), Some(&Refusal::Declined));
        let error = usable(Zeroizing::new("acme passphrase \u{FFFD}ne".to_string())).unwrap_err();
        assert!(error.to_string().contains("isn't UTF-8 text") && error.downcast_ref::<Refusal>().is_none(), "{error:#}");
        assert_eq!(usable(Zeroizing::new("acme passphrase \u{f6}ne".to_string())).unwrap().as_str(), "acme passphrase \u{f6}ne");
    }
}
