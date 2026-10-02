#![allow(unsafe_code)]
use super::{Identity, PublishError};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle};
use std::path::Path;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::IO::OVERLAPPED;
use windows::core::PCWSTR;
fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}
fn handle(file: &File) -> HANDLE {
    HANDLE(file.as_raw_handle())
}
fn error(error: windows::core::Error) -> io::Error {
    io::Error::from_raw_os_error(error.code().0 & 0xffff)
}
pub(super) fn no_reparse(options: &mut OpenOptions) {
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0);
}
pub(super) fn identity(file: &File, regular: bool) -> io::Result<Identity> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(handle(file), &mut info) }.map_err(error)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || (regular && info.nNumberOfLinks != 1)
    {
        return Err(io::Error::other(
            "reparse points and hardlink aliases are unsupported",
        ));
    }
    Ok(Identity {
        volume: u64::from(info.dwVolumeSerialNumber),
        file: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    })
}
pub(super) fn open_directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
}
pub(super) fn supported_parent(path: &Path) -> io::Result<()> {
    let path = wide(path);
    let mut root = vec![0u16; 32768];
    unsafe { GetVolumePathNameW(PCWSTR(path.as_ptr()), &mut root) }.map_err(error)?;
    // DRIVE_FIXED=3 and DRIVE_RAMDISK=6. No network/mapped-drive guarantee.
    if ![3, 6].contains(&unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) }) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "non-local volume is unsupported",
        ));
    }
    Ok(())
}
pub(super) fn lock(file: &File) -> io::Result<()> {
    let mut overlapped = OVERLAPPED::default();
    unsafe {
        LockFileEx(
            handle(file),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            None,
            1,
            0,
            &mut overlapped,
        )
    }
    .map_err(|e| {
        if e.code().0 & 0xffff == 33 {
            io::Error::new(io::ErrorKind::WouldBlock, "vault writer is busy")
        } else {
            error(e)
        }
    })
    // Closing the file releases the byte-range lock; the pathname remains.
}
pub(super) fn publish(target: &Path, directory: &Path) -> std::result::Result<(), PublishError> {
    let target = wide(target);
    let replacement = wide(&directory.join("publish.pmvault"));
    let backup = wide(&directory.join("displaced.pmvault"));
    unsafe {
        ReplaceFileW(
            PCWSTR(target.as_ptr()),
            PCWSTR(replacement.as_ptr()),
            PCWSTR(backup.as_ptr()),
            REPLACE_FILE_FLAGS(0),
            None,
            None,
        )
    }
    .map_err(|error| {
        let code = error.code().0 & 0xffff; // Capture immediately, before observations.
        super::windows_publish_error(code)
    })
}
pub(super) fn replace_descriptor(source: &Path, target: &Path) -> io::Result<()> {
    let source = wide(source);
    let target = wide(target);
    unsafe {
        MoveFileExW(
            PCWSTR(source.as_ptr()),
            PCWSTR(target.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(error)
}

#[cfg(test)]
pub(super) fn short_path_for_test(path: &Path) -> io::Result<std::path::PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    let source = wide(path);
    let mut out = vec![0u16; 32768];
    let length = unsafe { GetShortPathNameW(PCWSTR(source.as_ptr()), Some(&mut out)) };
    if length == 0 || length as usize >= out.len() {
        return Err(io::Error::last_os_error());
    }
    let short = std::path::PathBuf::from(std::ffi::OsString::from_wide(&out[..length as usize]));
    if short == path {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "no short alias"));
    }
    Ok(short)
}
