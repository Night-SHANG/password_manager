//! Non-destructive file operations only. No temp-path owner or cleanup API.
use super::*;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};

pub(super) trait ExportIo {
    fn parents(&self, target: &Path) -> io::Result<()> {
        let parent = target
            .parent()
            .ok_or_else(|| io::Error::other("missing parent"))?;
        fs::create_dir_all(parent)?;
        let directory = files::open_directory(parent)?;
        files::supported_parent(&directory, parent)
    }
    fn create(&self, target: &Path) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.create_new(true).read(true).write(true);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows::Win32::Storage::FileSystem::{
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            };
            // Allows our readback handle, excludes new competing write/delete handles.
            options
                .share_mode(FILE_SHARE_READ.0)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0);
        }
        options.open(target)
    }
    fn identity(&self, file: &File) -> io::Result<files::Identity> {
        files::identity(file, true)
    }
    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
        file.write(bytes)
    }
    fn flush(&self, file: &mut File) -> io::Result<()> {
        file.flush()
    }
    fn sync(&self, file: &File) -> io::Result<()> {
        file.sync_all()
    }
    fn open(&self, target: &Path) -> io::Result<File> {
        files::open_regular(target, false)
    }
    fn read(&self, file: &mut File, bytes: &mut [u8]) -> io::Result<usize> {
        file.read(bytes)
    }
    fn length(&self, file: &File) -> io::Result<u64> {
        Ok(file.metadata()?.len())
    }
}

pub(super) struct SystemIo;
impl ExportIo for SystemIo {}

pub(super) fn validate_destination(target: &Path) -> io::Result<()> {
    if !target.is_absolute() || target.file_name().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ordinary absolute file path required",
        ));
    }
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        for component in target.components() {
            match component {
                Component::Prefix(prefix)
                    if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) =>
                {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "device and network paths are unsupported",
                    ));
                }
                Component::Normal(name) => {
                    let name = name.to_string_lossy();
                    let base = name
                        .split('.')
                        .next()
                        .unwrap_or_default()
                        .trim_end_matches(' ')
                        .to_uppercase();
                    let numbered_device = ["COM", "LPT"].iter().any(|prefix| {
                        base.strip_prefix(prefix).is_some_and(|suffix| {
                            ["1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³"]
                                .contains(&suffix)
                        })
                    });
                    if name.contains(':')
                        || ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
                            .contains(&base.as_str())
                        || numbered_device
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "device and alternate-stream names are unsupported",
                        ));
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}
