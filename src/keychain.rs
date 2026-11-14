//! Keychain items: every value is its own generic password, service "<prefix><resource>/<field>"
//! (the prefix is `names::KEYCHAIN_PREFIX`), account = the macOS user.
//!
//! A workspace's saved passphrase is an item of its own, apart from those (`ws_add` and the rest
//! below): service `halti-ws:<id>`, account the user's name from the passwd entry. It is kept in the
//! login keychain only, opened by its path under the passwd entry's home folder, never the default
//! keychain or the search list, which any program running as the user can change. It is read and
//! written only while macOS may show no window, and written only as a new item.

use std::env;
#[cfg(halti_dev)]
use std::{fs, path::PathBuf};

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

use crate::{names, util};

fn account() -> String {
    env::var("USER").unwrap_or_default()
}

fn service(res: &str, field: &str) -> String {
    format!("{}{res}/{field}", names::KEYCHAIN_PREFIX)
}

/// Debug builds keep items in files under $HALTI_TEST_KEYCHAIN when it is set, so end-to-end
/// tests never touch the real Keychain. Release builds don't contain this.
#[cfg(halti_dev)]
fn fake(res: &str, field: &str) -> Option<PathBuf> {
    Some(PathBuf::from(crate::util::dev_var("HALTI_TEST_KEYCHAIN")?).join(format!("{res}.{field}")))
}

pub fn get(res: &str, field: &str) -> Option<String> {
    #[cfg(halti_dev)]
    if let Some(file) = fake(res, field) {
        return fs::read_to_string(file).ok();
    }
    backend::get(&service(res, field), &account()).ok().map(|v| String::from_utf8_lossy(&v).into_owned())
}

/// Read an item only if macOS lets halti do so without asking. Approval records are read this
/// way: one planted by another program would need a prompt, so it reads as missing.
pub fn get_silently(res: &str, field: &str) -> Option<String> {
    #[cfg(halti_dev)]
    if fake(res, field).is_some() {
        return get(res, field);
    }
    let _no_ui = backend::no_prompts()?;
    get(res, field)
}

/// A password another app keeps, e.g. Chrome's "Chrome Safe Storage". macOS asks the user
/// before halti may read it.
pub fn get_app_password(service: &str, account: &str) -> Result<Vec<u8>> {
    backend::get(service, account)
}

/// Whether the item exists, without reading its value: only reading a value can make
/// macOS ask for Keychain access, so status checks never prompt.
pub fn exists(res: &str, field: &str) -> bool {
    #[cfg(halti_dev)]
    if let Some(file) = fake(res, field) {
        return file.exists();
    }
    backend::exists(&service(res, field), &account())
}

pub fn set(res: &str, field: &str, value: &str) -> Result<()> {
    #[cfg(halti_dev)]
    if let Some(file) = fake(res, field) {
        return fs::write(file, value).with_context(|| format!("storing {res}/{field}"));
    }
    // Updates in place if the item exists, so rotation keeps the same Keychain item.
    backend::set(&service(res, field), &account(), value.as_bytes()).with_context(|| format!("storing {res}/{field} in Keychain"))
}

/// Store the value in a new item, so its access list names only the halti running now.
pub fn replace(res: &str, field: &str, value: &str) -> Result<()> {
    delete(res, field);
    set(res, field, value)
}

pub fn delete(res: &str, field: &str) -> bool {
    #[cfg(halti_dev)]
    if let Some(file) = fake(res, field) {
        return fs::remove_file(file).is_ok();
    }
    backend::delete(&service(res, field), &account())
}

/// The Keychain service of the saved passphrase of the workspace `id` (32 hex characters).
fn ws_service(id: &str) -> String {
    format!("{}{id}", names::WS_KEYCHAIN_PREFIX)
}

/// Debug builds keep a workspace's saved passphrase in a file under $HALTI_TEST_KEYCHAIN when it
/// is set, as they keep every item. Release builds don't contain this.
#[cfg(halti_dev)]
fn ws_fake(id: &str) -> Option<PathBuf> {
    Some(PathBuf::from(crate::util::dev_var("HALTI_TEST_KEYCHAIN")?).join(format!("halti-ws.{id}")))
}

/// Whether the workspace `id` has a saved passphrase, without reading it or letting macOS ask.
pub fn ws_exists(id: &str) -> bool {
    #[cfg(halti_dev)]
    if let Some(file) = ws_fake(id) {
        return file.exists();
    }
    silently(|account| saved_copy::exists(&ws_service(id), account)).unwrap_or(false)
}

/// Saves the passphrase of the workspace `id` as a new item in the login keychain, whose access list
/// names only the halti running now. Never an update of an item that is there: one another program
/// put there keeps its own access list. So any item of that name is removed first, and if macOS
/// still finds one, it is tried again, three times in all; one that can't be removed fails the save.
/// The new item is read back before the save counts, and removed if it doesn't match. With no
/// window allowed, a locked keychain, or one that can't be opened, makes this fail.
pub fn ws_add(id: &str, passphrase: &str) -> Result<()> {
    #[cfg(halti_dev)]
    if let Some(file) = ws_fake(id) {
        let _ = fs::remove_file(&file);
        let mut new = fs::OpenOptions::new().write(true).create_new(true).open(file).context("saving the passphrase")?;
        return std::io::Write::write_all(&mut new, passphrase.as_bytes()).context("saving the passphrase");
    }
    silently(|account| -> Result<()> {
        let service = ws_service(id);
        let stuck = || format!("an item named {service} is in the keychain, and it can't be removed");
        for _ in 0..3 {
            saved_copy::delete(&service, account).with_context(stuck)?;
            if saved_copy::add(&service, account, passphrase.as_bytes())? {
                let back = Zeroizing::new(saved_copy::get(&service, account).unwrap_or_default());
                if back.as_slice() != passphrase.as_bytes() {
                    // Not left behind: the save didn't count, so the next open is typed, not asked.
                    let _ = saved_copy::delete(&service, account);
                    bail!("the passphrase saved in the keychain can't be read back");
                }
                return Ok(());
            }
        }
        bail!(stuck())
    })
    .context("the keychain can't be used here without its windows")?
}

/// The saved passphrase of the workspace `id`: none if it is missing, can't be read without a
/// window (another build wrote it, or the login keychain is locked or can't be opened) or isn't
/// text. Wiped when dropped.
pub fn ws_get(id: &str) -> Option<Zeroizing<String>> {
    #[cfg(halti_dev)]
    if let Some(file) = ws_fake(id) {
        return text(Zeroizing::new(fs::read(file).ok()?));
    }
    let bytes = silently(|account| saved_copy::get(&ws_service(id), account).ok())??;
    text(Zeroizing::new(bytes))
}

/// Removes the saved passphrase of the workspace `id`, with no window allowed: whether one went.
pub fn ws_delete(id: &str) -> bool {
    #[cfg(halti_dev)]
    if let Some(file) = ws_fake(id) {
        return fs::remove_file(file).is_ok();
    }
    silently(|account| saved_copy::delete(&ws_service(id), account).unwrap_or(false)).unwrap_or(false)
}

/// `run` with the user's account while macOS may show no window: none where either can't be had.
fn silently<T>(run: impl FnOnce(&str) -> T) -> Option<T> {
    let account = util::user_name()?;
    let _no_ui = backend::no_prompts()?;
    Some(run(account.as_str()))
}

/// The bytes as text, if they are UTF-8: wiped either way.
fn text(bytes: Zeroizing<Vec<u8>>) -> Option<Zeroizing<String>> {
    std::str::from_utf8(&bytes).ok().map(|text| Zeroizing::new(text.to_string()))
}

/// A workspace's saved copy, in the login keychain only: `SecKeychainOpen` on
/// `<passwd home>/Library/Keychains/login.keychain-db`, the home taken from the passwd entry, never
/// the environment. Not the default keychain or the search list, which a program running as the
/// user can point at a keychain whose password it knows. Items are only added, with
/// `SecKeychainAddGenericPassword`, which never changes one in place. The callers keep macOS's
/// windows off, so a locked login keychain reads as missing and can't be written.
#[cfg(target_os = "macos")]
mod saved_copy {
    use anyhow::{Context, Result};
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
    use security_framework::os::macos::keychain::SecKeychain;

    use crate::util;

    /// What macOS answers when an item of that name is there already (errSecDuplicateItem).
    const DUPLICATE: i32 = -25299;
    /// What macOS answers when there is no item of that name (errSecItemNotFound).
    const NOT_FOUND: i32 = -25300;

    /// The login keychain of the user halti runs as. Opening succeeds on a missing file; the call
    /// that uses it fails then.
    fn login() -> Result<SecKeychain> {
        let home = util::passwd_home().filter(|home| home.is_absolute()).context("no home folder in the passwd entry")?;
        Ok(SecKeychain::open(home.join("Library/Keychains/login.keychain-db"))?)
    }

    /// The search for the item `service`, `account` in that keychain and no other.
    fn item(keychain: &SecKeychain, service: &str, account: &str) -> ItemSearchOptions {
        let mut item = ItemSearchOptions::new();
        item.keychains(std::slice::from_ref(keychain)).class(ItemClass::generic_password()).service(service).account(account);
        item
    }

    /// True if the item was added, false if one of its name is there.
    pub fn add(service: &str, account: &str, value: &[u8]) -> Result<bool> {
        match login()?.add_generic_password(service, account, value) {
            Ok(()) => Ok(true),
            Err(error) if error.code() == DUPLICATE => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub fn get(service: &str, account: &str) -> Result<Vec<u8>> {
        let (value, _item) = login()?.find_generic_password(service, account)?;
        Ok(value.to_vec())
    }

    pub fn exists(service: &str, account: &str) -> bool {
        let Ok(keychain) = login() else { return false };
        let mut search = item(&keychain, service, account);
        search.load_attributes(true).limit(Limit::Max(1));
        search.search().is_ok_and(|found| !found.is_empty())
    }

    /// Whether an item went: false if there was none, an error if one can't be removed.
    pub fn delete(service: &str, account: &str) -> Result<bool> {
        match item(&login()?, service, account).delete() {
            Ok(()) => Ok(true),
            Err(error) if error.code() == NOT_FOUND => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}

/// No Keychain here: nothing is saved or found.
#[cfg(not(target_os = "macos"))]
mod saved_copy {
    use anyhow::{Result, bail};

    pub fn add(_service: &str, _account: &str, _value: &[u8]) -> Result<bool> {
        bail!("the Keychain needs macOS")
    }

    pub fn get(_service: &str, _account: &str) -> Result<Vec<u8>> {
        bail!("the Keychain needs macOS")
    }

    pub fn exists(_service: &str, _account: &str) -> bool {
        false
    }

    pub fn delete(_service: &str, _account: &str) -> Result<bool> {
        bail!("the Keychain needs macOS")
    }
}

#[cfg(target_os = "macos")]
mod backend {
    use anyhow::Result;
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
    use security_framework::os::macos::keychain::{KeychainUserInteractionLock, SecKeychain};
    use security_framework::passwords::{delete_generic_password, get_generic_password, set_generic_password};

    pub fn get(service: &str, account: &str) -> Result<Vec<u8>> {
        Ok(get_generic_password(service, account)?)
    }

    pub fn no_prompts() -> Option<KeychainUserInteractionLock> {
        SecKeychain::disable_user_interaction().ok()
    }

    pub fn exists(service: &str, account: &str) -> bool {
        ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(service)
            .account(account)
            .load_attributes(true)
            .limit(Limit::Max(1))
            .search()
            .is_ok_and(|r| !r.is_empty())
    }

    pub fn set(service: &str, account: &str, value: &[u8]) -> Result<()> {
        Ok(set_generic_password(service, account, value)?)
    }

    pub fn delete(service: &str, account: &str) -> bool {
        delete_generic_password(service, account).is_ok()
    }
}

/// No Keychain here (a box's Linux, for building and testing halti): nothing is stored or found.
/// The debug builds' `fake` still works, so the tests run.
#[cfg(not(target_os = "macos"))]
mod backend {
    use anyhow::{Result, bail};

    pub fn get(_service: &str, _account: &str) -> Result<Vec<u8>> {
        bail!("the Keychain needs macOS")
    }

    /// Stands in for the Mac's lock, which is never had here.
    pub struct NoPrompts;

    pub fn no_prompts() -> Option<NoPrompts> {
        None
    }

    pub fn exists(_service: &str, _account: &str) -> bool {
        false
    }

    pub fn set(_service: &str, _account: &str, _value: &[u8]) -> Result<()> {
        bail!("the Keychain needs macOS")
    }

    pub fn delete(_service: &str, _account: &str) -> bool {
        false
    }
}
