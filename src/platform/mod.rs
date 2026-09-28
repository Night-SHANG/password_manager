use std::path::Path;

use crate::Result;

#[cfg(windows)]
mod windows_impl;

pub fn atomic_replace(target: &Path, replacement: &Path, backup: Option<&Path>) -> Result<()> {
    #[cfg(windows)]
    {
        windows_impl::atomic_replace(target, replacement, backup)
    }

    #[cfg(not(windows))]
    {
        let _ = backup;
        std::fs::rename(replacement, target)
            .map_err(|e| crate::AppError::io(target.to_path_buf(), e))
    }
}

pub fn clipboard_sequence_number() -> u32 {
    #[cfg(windows)]
    {
        windows_impl::clipboard_sequence_number()
    }

    #[cfg(not(windows))]
    {
        0
    }
}
