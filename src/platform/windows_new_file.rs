#![allow(unsafe_code)]

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS};
use windows::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};
use windows::core::{HRESULT, PCWSTR};

use crate::{AppError, Result};

pub(super) fn atomic_create_new(target: &Path, replacement: &Path) -> Result<()> {
    let target_w: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
    let replacement_w: Vec<u16> = replacement
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();

    // Same-directory staging keeps this a move on one volume. Omitting
    // MOVEFILE_REPLACE_EXISTING makes the existence check part of the move,
    // while retaining the existing write-through durability behavior.
    unsafe {
        MoveFileExW(
            PCWSTR(replacement_w.as_ptr()),
            PCWSTR(target_w.as_ptr()),
            MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(|error| {
        if error.code() == HRESULT::from_win32(ERROR_ALREADY_EXISTS.0)
            || error.code() == HRESULT::from_win32(ERROR_FILE_EXISTS.0)
        {
            AppError::AlreadyExists
        } else {
            AppError::Platform(format!("MoveFileExW (create new): {error}"))
        }
    })
}
