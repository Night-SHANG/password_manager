use std::path::Path;

mod clipboard;
#[cfg(any(windows, test))]
mod security_monitor;
pub use clipboard::{ClipboardCopyOutcome, ClipboardKind, ClipboardSession};

use iced::{Subscription, Task};

#[cfg(windows)]
use iced::window;

use crate::Result;

#[cfg(not(windows))]
use crate::AppError;

#[cfg(windows)]
use raw_window_handle::RawWindowHandle;

#[cfg(any(windows, test))]
mod windows_clipboard;
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
    ClipboardCopyCompleted {
        session: u64,
        request: u64,
        kind: ClipboardKind,
        outcome: ClipboardCopyOutcome,
    },
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

/// A fresh, opaque write permit for one successful vault unlock.
pub fn begin_clipboard_session() -> ClipboardSession {
    #[cfg(windows)]
    {
        windows_impl::begin_clipboard_session()
    }
    #[cfg(not(windows))]
    {
        ClipboardSession::new()
    }
}

pub fn enqueue_password_copy(
    session: &ClipboardSession,
    request: u64,
    text: zeroize::Zeroizing<String>,
    timeout_ms: u32,
) -> Result<()> {
    #[cfg(windows)]
    {
        windows_impl::enqueue_copy(session, request, ClipboardKind::Password, text, timeout_ms)
    }
    #[cfg(not(windows))]
    {
        let _ = (session, request, text, timeout_ms);
        Err(AppError::Platform(
            "native clipboard copying is unavailable on this platform".to_string(),
        ))
    }
}

pub fn enqueue_username_copy(session: &ClipboardSession, request: u64, text: String) -> Result<()> {
    #[cfg(windows)]
    {
        windows_impl::enqueue_copy(
            session,
            request,
            ClipboardKind::Username,
            zeroize::Zeroizing::new(text),
            30_000,
        )
    }
    #[cfg(not(windows))]
    {
        let _ = (session, request, text);
        Err(AppError::Platform(
            "native clipboard copying is unavailable on this platform".to_string(),
        ))
    }
}

/// Revocation is synchronous even when posting the native cleanup fails.
pub fn revoke_and_clear_clipboard(session: &ClipboardSession) -> Result<()> {
    session.revoke();
    #[cfg(windows)]
    {
        windows_impl::queue_revoked_cleanup()
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}

/// Revoke all process-local clipboard permits and flush the retained receipt.
pub fn shutdown_clipboard() -> Result<()> {
    #[cfg(windows)]
    {
        windows_impl::shutdown_clipboard()
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}

/// Attempt receipt-bound cleanup before process exit, with a bounded wait.
pub fn shutdown_clipboard_session(session: &ClipboardSession) -> Result<()> {
    session.revoke_native();
    #[cfg(windows)]
    {
        windows_impl::shutdown_clipboard_session(session)
    }
    #[cfg(not(windows))]
    {
        Ok(())
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

#[cfg(test)]
mod tests {
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
