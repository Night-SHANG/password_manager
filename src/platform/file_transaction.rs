//! Existing-only publication. Locks coordinate this app, not arbitrary writers.
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

#[cfg(windows)]
#[path = "windows_transaction.rs"]
mod native;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Identity {
    pub volume: u64,
    pub file: u64,
}

pub(crate) fn identity(file: &File, regular: bool) -> io::Result<Identity> {
    let metadata = file.metadata()?;
    if regular && !metadata.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        if regular && metadata.nlink() != 1 {
            return Err(io::Error::other("hardlink aliases are unsupported"));
        }
        Ok(Identity {
            volume: metadata.dev(),
            file: metadata.ino(),
        })
    }
    #[cfg(windows)]
    {
        native::identity(file, regular)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "existing-file transactions require Windows or Linux",
        ))
    }
}

pub(crate) fn open_regular(path: &Path, writable: bool) -> io::Result<File> {
    #[cfg(windows)]
    if path
        .file_name()
        .is_some_and(|name| name.to_string_lossy().contains(':'))
    {
        return Err(io::Error::other("alternate data streams are unsupported"));
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(io::Error::other(
            "symlink or nonregular file is unsupported",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).write(writable);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    #[cfg(windows)]
    {
        native::no_reparse(&mut options);
    }
    let file = options.open(path)?;
    identity(&file, true)?;
    Ok(file)
}

/// The stable sidecar is intentionally never unlinked, including on failure.
pub(crate) struct Lock {
    _file: File,
}
impl Lock {
    pub fn acquire(path: &Path) -> io::Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        }
        #[cfg(windows)]
        {
            native::no_reparse(&mut options);
        }
        let file = options.open(path)?;
        identity(&file, true)?;
        #[cfg(target_os = "linux")]
        {
            rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
        }
        #[cfg(windows)]
        {
            native::lock(&file)?;
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "no existing-file transaction adapter",
            ));
        }
        Ok(Self { _file: file })
    }
}

pub(crate) fn supported_parent(parent: &File, path: &Path) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let _ = path;
        // Explicit local filesystem allowlist. In particular do not treat NFS/CIFS
        // failure semantics as local rename semantics. Overlay is used in CI.
        let kind = rustix::fs::fstatfs(parent)?.f_type as u64;
        if ![0xef53, 0x58465342, 0x9123683e, 0x01021994, 0x794c7630].contains(&kind) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "filesystem is not supported for verified exchange",
            ));
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let _ = parent;
        native::supported_parent(path)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (parent, path);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "existing-file transactions require Windows or Linux",
        ))
    }
}

pub(crate) fn open_directory(path: &Path) -> io::Result<File> {
    if !std::fs::symlink_metadata(path)?.is_dir() {
        return Err(io::Error::other("not a physical directory"));
    }
    #[cfg(windows)]
    {
        native::open_directory(path)
    }
    #[cfg(not(windows))]
    {
        File::open(path)
    }
}

#[derive(Debug)]
pub(crate) struct PublishError {
    pub message: String,
    pub documented_no_progress: bool,
}

pub(crate) fn publish(
    target: &Path,
    parent: &File,
    directory: &Path,
    transaction: &File,
) -> std::result::Result<(), PublishError> {
    #[cfg(target_os = "linux")]
    {
        let _ = directory;
        rustix::fs::renameat_with(
            transaction,
            "publish.pmvault",
            parent,
            target.file_name().unwrap(),
            rustix::fs::RenameFlags::EXCHANGE,
        )
        .map_err(|error| PublishError {
            documented_no_progress: matches!(
                error,
                rustix::io::Errno::NOSYS
                    | rustix::io::Errno::XDEV
                    | rustix::io::Errno::OPNOTSUPP
                    | rustix::io::Errno::INVAL
                    | rustix::io::Errno::NOENT
                    | rustix::io::Errno::ACCESS
                    | rustix::io::Errno::PERM
            ),
            message: format!("rename exchange: {error}"),
        })
    }
    #[cfg(windows)]
    {
        let _ = (parent, transaction);
        native::publish(target, directory)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (target, parent, directory, transaction);
        Err(PublishError {
            message: "unsupported existing-file publication".into(),
            documented_no_progress: true,
        })
    }
}

pub(crate) fn displaced_name() -> &'static str {
    if cfg!(windows) {
        "displaced.pmvault"
    } else {
        "publish.pmvault"
    }
}

pub(crate) fn sync_directory(file: &File) -> io::Result<()> {
    #[cfg(windows)]
    {
        let _ = file;
        Ok(())
    } // Windows has no supported directory-flush guarantee here.
    #[cfg(not(windows))]
    {
        file.sync_all()
    }
}

/// Only bounded nonsecret metadata uses replace-rename. Never used for vaults.
pub(crate) fn replace_descriptor(source: &Path, target: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        native::replace_descriptor(source, target)
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(source, target)
    }
}

#[cfg(any(windows, test))]
pub(crate) fn windows_publish_error(code: i32) -> PublishError {
    PublishError {
        message: format!("ReplaceFileW error {code}"),
        documented_no_progress: matches!(code, 1175 | 1176 | 32 | 33 | 5),
    }
}

#[cfg(all(windows, test))]
pub(crate) fn short_path_for_test(path: &Path) -> io::Result<std::path::PathBuf> {
    native::short_path_for_test(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_existing_publication_retains_actual_displaced_file() {
        let dir = tempfile::tempdir().unwrap();
        let transaction = dir.path().join("transaction");
        std::fs::create_dir(&transaction).unwrap();
        let target = dir.path().join("synthetic.pmvault");
        std::fs::write(&target, b"old synthetic encrypted bytes").unwrap();
        std::fs::write(
            transaction.join("publish.pmvault"),
            b"new synthetic encrypted bytes",
        )
        .unwrap();
        let parent = open_directory(dir.path()).unwrap();
        let opened = open_directory(&transaction).unwrap();
        publish(&target, &parent, &transaction, &opened).unwrap();
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"new synthetic encrypted bytes"
        );
        assert_eq!(
            std::fs::read(transaction.join(displaced_name())).unwrap(),
            b"old synthetic encrypted bytes"
        );
        sync_directory(&parent).unwrap();
        sync_directory(&opened).unwrap();
    }
    #[cfg(windows)]
    #[test]
    fn native_windows_sharing_failure_preserves_both_names_and_unknown_backup() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = tempfile::tempdir().unwrap();
        let transaction = dir.path().join("transaction");
        std::fs::create_dir(&transaction).unwrap();
        let target = dir.path().join("synthetic.pmvault");
        std::fs::write(&target, b"old bytes").unwrap();
        let legacy = dir.path().join("synthetic.pmvault.bak");
        std::fs::write(&legacy, b"unknown backup").unwrap();
        std::fs::write(transaction.join("publish.pmvault"), b"new bytes").unwrap();
        let _sharing_block = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(&target)
            .unwrap();
        let error = publish(
            &target,
            &open_directory(dir.path()).unwrap(),
            &transaction,
            &open_directory(&transaction).unwrap(),
        )
        .unwrap_err();
        assert!(error.documented_no_progress);
        assert_eq!(std::fs::read(target).unwrap(), b"old bytes");
        assert_eq!(
            std::fs::read(transaction.join("publish.pmvault")).unwrap(),
            b"new bytes"
        );
        assert!(!transaction.join("displaced.pmvault").exists());
        assert_eq!(std::fs::read(legacy).unwrap(), b"unknown backup");
    }
}
