//! Which workspace a command means. There is no current workspace to fall back on, and no folder,
//! repo file or variable picks one: files an agent can write must never steer a command at
//! another client.

use anyhow::Result;

use crate::ids::WsName;
use crate::refusal::Refusal;
use crate::store::{FileKey, Files};

/// The workspace a command means: the typed name if a workspace has it, or the only workspace
/// when nothing is typed. A typed name is never swapped for another, and a refusal names no
/// workspace that wasn't typed.
pub fn resolve_name(files: &dyn Files, typed: Option<&str>) -> Result<WsName> {
    if let Some(text) = typed {
        let name = WsName::parse(text)?;
        // Only this workspace's record is looked at, so another's being unreadable changes nothing.
        return match files.read(&FileKey::DirRecord(name.clone()))? {
            Some(_) => Ok(name),
            None => Err(Refusal::Unknown(name).into()),
        };
    }
    // Trusts the list to be whole: a record left out would make another workspace look like the only one.
    let mut names = files.names()?;
    match names.len() {
        0 => Err(Refusal::NoWorkspace.into()),
        1 => Ok(names.remove(0)),
        _ => Err(Refusal::NameOne.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakes::MemFiles;

    fn with(names: &[&str]) -> MemFiles {
        let files = MemFiles::new();
        for name in names {
            files.write_atomic(&FileKey::DirRecord(WsName::parse(name).unwrap()), b"record").unwrap();
        }
        files
    }

    fn refusal(files: &MemFiles, typed: Option<&str>) -> Refusal {
        resolve_name(files, typed).unwrap_err().downcast::<Refusal>().unwrap()
    }

    #[test]
    fn a_typed_name_in_the_directory_is_chosen() {
        let files = with(&["acme", "globex"]);
        assert_eq!(resolve_name(&files, Some("globex")).unwrap().as_str(), "globex");
    }

    #[test]
    fn with_one_workspace_and_nothing_typed_it_is_chosen() {
        assert_eq!(resolve_name(&with(&["acme"]), None).unwrap().as_str(), "acme");
    }

    #[test]
    fn with_two_workspaces_and_nothing_typed_none_is_chosen() {
        assert_eq!(refusal(&with(&["acme", "globex"]), None), Refusal::NameOne);
    }

    #[test]
    fn with_no_workspace_none_is_chosen() {
        assert_eq!(refusal(&with(&[]), None), Refusal::NoWorkspace);
        assert_eq!(refusal(&with(&[]), Some("acme")), Refusal::Unknown(WsName::parse("acme").unwrap()));
    }

    #[test]
    fn a_typed_name_is_never_swapped_for_the_only_workspace() {
        assert_eq!(refusal(&with(&["acme"]), Some("acm")), Refusal::Unknown(WsName::parse("acm").unwrap()));
    }

    #[test]
    fn a_refusal_names_no_workspace_that_was_not_typed() {
        let files = with(&["acme", "globex"]);
        for typed in [None, Some("initech"), Some("Not a name")] {
            let said = resolve_name(&files, typed).unwrap_err().to_string();
            assert!(!said.contains("acme") && !said.contains("globex"), "{said}");
        }
    }

    #[test]
    fn a_badly_formed_name_is_refused_before_any_file_is_read() {
        let files = with(&["acme"]);
        let before = files.calls();
        assert_eq!(refusal(&files, Some("../acme")), Refusal::BadName);
        assert_eq!(refusal(&files, Some("")), Refusal::BadName);
        assert_eq!(files.calls(), before);
    }

    #[test]
    fn a_typed_name_reads_only_its_own_record() {
        let files = with(&["acme", "globex"]);
        let before = files.calls();
        resolve_name(&files, Some("acme")).unwrap();
        assert_eq!(files.calls(), before + 1);
        assert_eq!(files.reads(), [FileKey::DirRecord(WsName::parse("acme").unwrap())]);
    }
}
