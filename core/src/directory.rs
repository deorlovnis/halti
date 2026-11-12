//! The host's directory: what it keeps in clear for each workspace, under the name a person typed.
//! It is enough to find the workspace and to know what opens it, and nothing more: everything else
//! is in the sealed manifest, which opening checks this record against.
//!
//! ```text
//! record = 0x01 (format) ‖ id (16) ‖ key kind (1) ‖ keystore kind (1)
//! ```

use crate::holder::KeyKind;
use crate::ids::WsId;
use crate::refusal::Refusal;
use crate::store::KeystoreKind;

/// The one record format so far.
const FORMAT: u8 = 0x01;

/// One workspace's directory record. Its name is the record's own key (`FileKey::DirRecord`), so
/// it is not repeated here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DirRecord {
    pub id: WsId,
    pub key: KeyKind,
    pub keystore: KeystoreKind,
}

impl DirRecord {
    /// The length of its bytes.
    pub const LEN: usize = 19;

    pub fn to_bytes(self) -> [u8; DirRecord::LEN] {
        let mut bytes = [0; DirRecord::LEN];
        bytes[0] = FORMAT;
        bytes[1..17].copy_from_slice(self.id.as_bytes());
        bytes[17] = self.key.tag();
        bytes[18] = self.keystore.tag();
        bytes
    }

    /// Refuses any other length, format or kind with `Refusal::Unreadable`.
    pub fn from_bytes(bytes: &[u8]) -> Result<DirRecord, Refusal> {
        let [FORMAT, rest @ ..] = bytes else { return Err(Refusal::Unreadable) };
        let Some((id, [key, keystore])) = rest.split_first_chunk::<16>() else { return Err(Refusal::Unreadable) };
        Ok(DirRecord { id: WsId::from_bytes(*id), key: KeyKind::from_tag(*key)?, keystore: KeystoreKind::from_tag(*keystore)? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::vectors::{KAT_DIR_RECORD, hex, ws_bytes};

    /// acme's record as a release build would write it: a passphrase key and a keystore of files.
    fn acme() -> DirRecord {
        DirRecord { id: WsId::from_bytes(ws_bytes()), key: KeyKind::Passphrase, keystore: KeystoreKind::Files }
    }

    #[test]
    fn a_directory_record_is_its_format_its_id_and_two_kinds() {
        let bytes = acme().to_bytes();
        assert_eq!((bytes.len(), DirRecord::LEN), (19, 19));
        // Piece by piece first, so that a difference says where it is.
        assert_eq!(bytes[0], 0x01, "the format");
        assert_eq!(bytes[1..17], ws_bytes(), "the id");
        assert_eq!(bytes[17..], [0x05, 0x02], "a passphrase key, then a keystore of files");
        assert_eq!(bytes.as_slice(), hex(KAT_DIR_RECORD));
        assert_eq!(DirRecord::from_bytes(&bytes), Ok(acme()), "and it reads back");
        // A key held in software and a keystore in memory, as the tests make them.
        let tested = DirRecord { key: KeyKind::Soft, keystore: KeystoreKind::Memory, ..acme() };
        assert_eq!(tested.to_bytes()[17..], [0x04, 0x01]);
        assert_eq!(DirRecord::from_bytes(&tested.to_bytes()), Ok(tested));
    }

    #[test]
    fn a_directory_record_of_another_length_format_or_kind_is_refused() {
        let bytes = acme().to_bytes();
        for len in 0..bytes.len() {
            assert_eq!(DirRecord::from_bytes(&bytes[..len]), Err(Refusal::Unreadable), "cut to {len} bytes");
        }
        let mut longer = bytes.to_vec();
        longer.push(0x02);
        assert_eq!(DirRecord::from_bytes(&longer), Err(Refusal::Unreadable), "one byte more");
        let others = [
            (0, 0x00, "format 0x00"),
            (0, 0x02, "format 0x02"),
            (17, 0x01, "key kind 0x01, kept for hardware"),
            (17, 0x00, "key kind 0x00"),
            (18, 0x03, "keystore kind 0x03, kept for the Keychain"),
            (18, 0x00, "keystore kind 0x00"),
        ];
        for (at, value, what) in others {
            let mut other = bytes;
            other[at] = value;
            assert_eq!(DirRecord::from_bytes(&other), Err(Refusal::Unreadable), "{what}");
        }
    }
}
