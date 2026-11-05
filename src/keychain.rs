//! Keychain items: every value is its own generic password, service "<prefix><resource>/<field>"
//! (the prefix is `legacy::KEYCHAIN_PREFIX`), account = the macOS user.

use std::env;
#[cfg(halti_dev)]
use std::{fs, path::PathBuf};

use anyhow::{Context, Result};

use crate::legacy;

fn account() -> String {
    env::var("USER").unwrap_or_default()
}

fn service(res: &str, field: &str) -> String {
    format!("{}{res}/{field}", legacy::KEYCHAIN_PREFIX)
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

    pub fn no_prompts() -> Option<std::convert::Infallible> {
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
