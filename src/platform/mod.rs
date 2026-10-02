use std::path::Path;

use iced::{Subscription, Task};

#[cfg(windows)]
use iced::window;

use crate::Result;

#[cfg(not(windows))]
use crate::AppError;

#[cfg(windows)]
use raw_window_handle::RawWindowHandle;

#[cfg(windows)]
mod windows_impl;
#[cfg(windows)]
mod windows_new_file;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityEvent {
    MonitorReady,
    MonitorFailed,
    SessionLocked,
    SessionLoggedOff,
    SystemSuspending,
    ClipboardCleanupFailed,
}

pub fn atomic_replace(target: &Path, replacement: &Path, backup: Option<&Path>) -> Result<()> {
    #[cfg(windows)]
    {
        windows_impl::atomic_replace(target, replacement, backup)
    }

    #[cfg(not(windows))]
    {
        let _ = backup;
        std::fs::rename(replacement, target)
            .map_err(|error| AppError::io(target.to_path_buf(), error))
    }
}

/// Publish a fully written, synced sibling temporary file without replacing any
/// existing destination. The temporary file is cleaned up on publication failure.
pub(crate) fn atomic_create_new(target: &Path, replacement: tempfile::TempPath) -> Result<()> {
    #[cfg(windows)]
    {
        windows_new_file::atomic_create_new(target, &replacement)
    }

    #[cfg(not(windows))]
    {
        // Uses an exclusive rename where supported, otherwise an exclusive hard
        // link. Neither operation can overwrite a destination created concurrently.
        replacement.persist_noclobber(target).map_err(|error| {
            if error.error.kind() == std::io::ErrorKind::AlreadyExists {
                AppError::AlreadyExists
            } else {
                AppError::io(target.to_path_buf(), error.error)
            }
        })
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

pub fn security_events() -> Subscription<SecurityEvent> {
    #[cfg(windows)]
    {
        windows_impl::security_events()
    }

    #[cfg(not(windows))]
    {
        Subscription::none()
    }
}

pub fn set_screen_capture_protection(enabled: bool) -> Task<std::result::Result<bool, String>> {
    #[cfg(windows)]
    {
        window::oldest().and_then(move |id| {
            window::run(id, move |managed_window| {
                let handle = managed_window
                    .window_handle()
                    .map_err(|error| format!("window_handle: {error}"))?;

                match handle.as_raw() {
                    RawWindowHandle::Win32(win32) => {
                        windows_impl::set_screen_capture_protection(win32.hwnd.get(), enabled)
                            .map_err(|error| error.to_string())?;
                        Ok(enabled)
                    }
                    _ => Err("main window is not a Win32 window".to_string()),
                }
            })
        })
    }

    #[cfg(not(windows))]
    {
        let _ = enabled;
        Task::done(Ok(false))
    }
}

pub fn arm_clipboard_clear(expected_sequence: u32, timeout_ms: u32) -> Result<()> {
    #[cfg(windows)]
    {
        windows_impl::arm_clipboard_clear(expected_sequence, timeout_ms)
    }

    #[cfg(not(windows))]
    {
        let _ = (expected_sequence, timeout_ms);
        Ok(())
    }
}

pub fn clear_armed_clipboard_now() -> Result<()> {
    #[cfg(windows)]
    {
        windows_impl::clear_armed_clipboard_now()
    }

    #[cfg(not(windows))]
    {
        Ok(())
    }
}

#[cfg(any(windows, test))]
pub(crate) fn should_clear_clipboard(expected_sequence: u32, current_sequence: u32) -> bool {
    expected_sequence != 0 && expected_sequence == current_sequence
}

#[cfg(test)]
mod tests {
    use super::should_clear_clipboard;

    #[test]
    fn clipboard_cleanup_requires_same_nonzero_sequence() {
        assert!(should_clear_clipboard(42, 42));
        assert!(!should_clear_clipboard(42, 43));
        assert!(!should_clear_clipboard(0, 0));
    }

    #[cfg(unix)]
    #[test]
    fn exclusive_publication_preserves_staged_bytes_and_permissions() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("new.pmvault");
        let mut staged = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        staged.write_all(b"fully written encrypted bytes").unwrap();
        staged
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o640))
            .unwrap();
        staged.as_file().sync_all().unwrap();

        super::atomic_create_new(&target, staged.into_temp_path()).unwrap();

        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"fully written encrypted bytes"
        );
        assert_eq!(
            std::fs::metadata(target).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
