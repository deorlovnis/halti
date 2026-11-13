//! A `World` for tests: the approved copy and the Touch ID records kept in memory, sudo and Touch ID
//! answered as the test says, and every question and change kept in order.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use anyhow::{Result, bail};

use super::{Declined, World};
use crate::config::approved::{Found, Place};

pub struct Fake {
    pub anchor: RefCell<Option<String>>,
    pub records: RefCell<BTreeMap<String, String>>,
    /// A write sudo began that failed part way: half the bytes are written, and sudo says no.
    pub cut: Cell<bool>,
    sudo: bool,
    touch_id: bool,
    calls: RefCell<Vec<String>>,
}

impl Fake {
    /// Nothing approved yet, and sudo and Touch ID answering yes or no.
    pub fn answering(sudo: bool, touch_id: bool) -> Fake {
        Fake { anchor: RefCell::new(None), records: RefCell::default(), cut: Cell::new(false), sudo, touch_id, calls: RefCell::default() }
    }

    /// What was asked and changed since the last call.
    pub fn calls(&self) -> Vec<String> {
        self.calls.take()
    }

    fn call(&self, what: String) {
        self.calls.borrow_mut().push(what);
    }
}

impl World for Fake {
    fn read(&self, _place: &Place) -> Found {
        self.anchor.borrow().clone().map_or(Found::Missing, Found::Text)
    }

    fn touch_id(&self, reason: &str) -> Result<()> {
        self.call(format!("touch id: {reason}"));
        if !self.touch_id {
            bail!("not approved: {reason}");
        }
        Ok(())
    }

    fn sudo(&self, reason: &str) -> Result<()> {
        self.call(format!("sudo: {reason}"));
        if !self.sudo {
            return Err(Declined.into());
        }
        Ok(())
    }

    fn sudo_write(&self, _place: &Place, bytes: &[u8]) -> Result<()> {
        self.call("sudo write".to_string());
        if self.cut.get() {
            *self.anchor.borrow_mut() = Some(String::from_utf8_lossy(&bytes[..bytes.len() / 2]).into_owned());
            return Err(Declined.into());
        }
        if !self.sudo {
            return Err(Declined.into());
        }
        *self.anchor.borrow_mut() = Some(String::from_utf8(bytes.to_vec())?);
        Ok(())
    }

    fn pinned(&self, key: &str) -> Option<String> {
        self.records.borrow().get(key).cloned()
    }

    fn pin(&self, key: &str, text: &str) -> Result<()> {
        self.call(format!("pin {key}"));
        self.records.borrow_mut().insert(key.to_string(), text.to_string());
        Ok(())
    }

    fn unpin(&self, key: &str) {
        self.call(format!("unpin {key}"));
        self.records.borrow_mut().remove(key);
    }
}
