#![allow(unsafe_code)]

use std::path::Path;

use windows::Win32::Storage::FileSystem::{
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW, REPLACEFILE_WRITE_THROUGH,
    ReplaceFileW,
};
use windows::Win32::System::DataExchange::GetClipboardSequenceNumber;
use windows::core::PCWSTR;

use crate::{AppError, Result};

fn to_wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn platform_error(context: &str, err: impl std::fmt::Display) -> AppError {
    AppError::Platform(format!("{context}: {err}"))
}

pub fn atomic_replace(target: &Path, replacement: &Path, backup: Option<&Path>) -> Result<()> {
    let target_w = to_wide(target);
    let replacement_w = to_wide(replacement);

    if target.exists() {
        let backup_w = backup.map(to_wide);

        if let Some(path) = backup {
            if path.exists() {
                std::fs::remove_file(path).map_err(|e| AppError::io(path.to_path_buf(), e))?;
            }
        }

        unsafe {
            ReplaceFileW(
                PCWSTR(target_w.as_ptr()),
                PCWSTR(replacement_w.as_ptr()),
                backup_w
                    .as_ref()
                    .map_or(PCWSTR::null(), |wide| PCWSTR(wide.as_ptr())),
                REPLACEFILE_WRITE_THROUGH,
                None,
                None,
            )
            .map_err(|e| platform_error("ReplaceFileW", e))?;
        }
    } else {
        unsafe {
            MoveFileExW(
                PCWSTR(replacement_w.as_ptr()),
                PCWSTR(target_w.as_ptr()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
            .map_err(|e| platform_error("MoveFileExW", e))?;
        }
    }

    Ok(())
}

pub fn clipboard_sequence_number() -> u32 {
    unsafe { GetClipboardSequenceNumber() }
}
