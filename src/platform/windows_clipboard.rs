#![allow(unsafe_code)]

fn utf16_byte_len(units: usize) -> Option<usize> {
    let bytes = units.checked_mul(std::mem::size_of::<u16>())?;
    (bytes > 0 && bytes <= isize::MAX as usize).then_some(bytes)
}

fn allocation_contains(allocation_bytes: usize, expected_bytes: usize) -> bool {
    expected_bytes > 0
        && expected_bytes <= isize::MAX as usize
        && allocation_bytes >= expected_bytes
}

fn unlock_result_succeeded(result: std::result::Result<(), i32>) -> bool {
    matches!(result, Ok(()) | Err(0))
}

fn owner_lookup(result: std::result::Result<bool, i32>) -> std::result::Result<bool, ()> {
    match result {
        Ok(matches) => Ok(matches),
        Err(0) => Ok(false),
        Err(_) => Err(()),
    }
}

fn payload_matches(allocation: &[u8], expected: &[u8]) -> bool {
    allocation_contains(allocation.len(), expected.len())
        && allocation[..expected.len()] == *expected
}

#[cfg(windows)]
pub(super) use native::{CLIPBOARD_TIMER_ID, WindowsClipboard};

#[cfg(windows)]
mod native {
    use std::ptr::NonNull;
    use std::time::Instant;

    use windows::Win32::Foundation::{HANDLE, HGLOBAL, HWND, NO_ERROR, SetLastError};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardOwner,
        GetClipboardSequenceNumber, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
    };
    use windows::Win32::System::Memory::{
        GMEM_MOVEABLE, GMEM_ZEROINIT, GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock,
    };
    use windows::Win32::System::Ole::CF_UNICODETEXT;
    use windows::Win32::UI::WindowsAndMessaging::{KillTimer, SetTimer};
    use windows::core::{Free, w};
    use zeroize::Zeroize;

    use super::super::clipboard::ClipboardBackend;
    use super::{
        allocation_contains, owner_lookup, payload_matches, unlock_result_succeeded, utf16_byte_len,
    };
    use crate::{AppError, Result};

    pub(crate) const CLIPBOARD_TIMER_ID: usize = 0x504D_434C;

    /// The native clipboard is accessed only on the security-window thread.
    pub(crate) struct WindowsClipboard {
        hwnd: HWND,
        marker_format: u32,
        opened: bool,
        started: Instant,
    }

    pub(crate) struct PreparedClipboard {
        marker: OwnedGlobal,
        text: OwnedGlobal,
    }

    impl WindowsClipboard {
        pub(crate) fn new(hwnd: HWND) -> Result<Self> {
            if hwnd.is_invalid() {
                return Err(AppError::Platform(
                    "Clipboard owner window is invalid".into(),
                ));
            }
            let marker_format =
                unsafe { RegisterClipboardFormatW(w!("PasswordManager.CopyReceipt.v1")) };
            if marker_format == 0 {
                return Err(AppError::Platform("RegisterClipboardFormatW failed".into()));
            }
            Ok(Self {
                hwnd,
                marker_format,
                opened: false,
                started: Instant::now(),
            })
        }

        fn format_matches(&self, format: u32, expected: &[u8]) -> std::result::Result<bool, ()> {
            let handle = unsafe { GetClipboardData(format) }.map_err(|_| ())?;
            let handle = HGLOBAL(handle.0);
            let bytes = unsafe { GlobalSize(handle) };
            // GlobalSize can include allocator padding. Compare only the exact
            // known payload, including the UTF-16 terminator, and never scan it.
            if !allocation_contains(bytes, expected.len()) {
                return Ok(false);
            }
            let lock = GlobalLockGuard::new(handle)?;
            let observed =
                unsafe { std::slice::from_raw_parts(lock.pointer.as_ptr(), expected.len()) };
            let matches = payload_matches(observed, expected);
            lock.unlock()?;
            Ok(matches)
        }
    }

    impl ClipboardBackend for WindowsClipboard {
        type Prepared = PreparedClipboard;

        fn now_ms(&self) -> u64 {
            self.started.elapsed().as_millis().min(u64::MAX as u128) as u64
        }

        fn new_marker(&mut self) -> std::result::Result<[u8; 16], ()> {
            let mut marker = [0; 16];
            getrandom::fill(&mut marker).map_err(|_| ())?;
            Ok(marker)
        }

        fn prepare(
            &mut self,
            text: &[u16],
            marker: [u8; 16],
        ) -> std::result::Result<Self::Prepared, ()> {
            let bytes = utf16_byte_len(text.len()).ok_or(())?;
            if text.last() != Some(&0) || text[..text.len() - 1].contains(&0) {
                return Err(());
            }
            // Windows is little-endian. Borrowing the UTF-16 representation
            // avoids another unprotected plaintext allocation.
            let text = unsafe { std::slice::from_raw_parts(text.as_ptr().cast::<u8>(), bytes) };
            Ok(PreparedClipboard {
                marker: OwnedGlobal::from_bytes(&marker)?,
                text: OwnedGlobal::from_bytes(text)?,
            })
        }

        fn open(&mut self) -> std::result::Result<(), ()> {
            // A failed CloseClipboard keeps the transaction tracked. Settle it
            // before beginning a new open instead of losing the open handle.
            if self.opened {
                self.close()?;
            }
            unsafe { OpenClipboard(Some(self.hwnd)) }.map_err(|_| ())?;
            self.opened = true;
            Ok(())
        }

        fn empty(&mut self) -> std::result::Result<(), ()> {
            if !self.opened {
                return Err(());
            }
            unsafe { EmptyClipboard() }.map_err(|_| ())
        }

        fn set_marker(&mut self, prepared: &mut Self::Prepared) -> std::result::Result<(), ()> {
            if !self.opened {
                return Err(());
            }
            prepared.marker.transfer(self.marker_format)
        }

        fn set_text(&mut self, prepared: &mut Self::Prepared) -> std::result::Result<(), ()> {
            if !self.opened {
                return Err(());
            }
            prepared.text.transfer(u32::from(CF_UNICODETEXT.0))
        }

        fn close(&mut self) -> std::result::Result<(), ()> {
            if self.opened {
                unsafe { CloseClipboard() }.map_err(|_| ())?;
                self.opened = false;
            }
            Ok(())
        }

        fn matches(
            &mut self,
            marker: [u8; 16],
            expected: Option<&[u16]>,
        ) -> std::result::Result<bool, ()> {
            if !self.opened {
                return Err(());
            }
            // NULL with NO_ERROR means no owner. A real lookup error is unknown
            // ownership and must be retried/warned, never treated as replacement.
            unsafe { SetLastError(NO_ERROR) };
            let owner = unsafe { GetClipboardOwner() }
                .map(|owner| owner == self.hwnd)
                .map_err(|error| error.code().0);
            if !owner_lookup(owner)? || !self.format_matches(self.marker_format, &marker)? {
                return Ok(false);
            }
            match expected {
                Some(text) => {
                    let bytes = utf16_byte_len(text.len()).ok_or(())?;
                    let expected =
                        unsafe { std::slice::from_raw_parts(text.as_ptr().cast::<u8>(), bytes) };
                    self.format_matches(u32::from(CF_UNICODETEXT.0), expected)
                }
                None => Ok(true),
            }
        }

        fn sequence(&self) -> u32 {
            unsafe { GetClipboardSequenceNumber() }
        }

        fn arm_timer(&mut self, delay_ms: u32) -> std::result::Result<(), ()> {
            let timer =
                unsafe { SetTimer(Some(self.hwnd), CLIPBOARD_TIMER_ID, delay_ms.max(1), None) };
            if timer == 0 { Err(()) } else { Ok(()) }
        }

        fn stop_timer(&mut self) {
            // KillTimer does not remove already queued WM_TIMER messages. The
            // engine must check its monotonic deadline when dispatching one.
            let _ = unsafe { KillTimer(Some(self.hwnd), CLIPBOARD_TIMER_ID) };
        }
    }

    impl Drop for WindowsClipboard {
        fn drop(&mut self) {
            self.stop_timer();
            let _ = self.close();
        }
    }

    /// Sole owner until SetClipboardData succeeds. Transferred allocations are
    /// deliberately never locked, wiped, or freed by this guard afterward.
    struct OwnedGlobal {
        handle: Option<HGLOBAL>,
        bytes: usize,
    }

    impl OwnedGlobal {
        fn from_bytes(bytes: &[u8]) -> std::result::Result<Self, ()> {
            if !allocation_contains(bytes.len(), bytes.len()) {
                return Err(());
            }
            let handle = unsafe { GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, bytes.len()) }
                .map_err(|_| ())?;
            let allocation = Self {
                handle: Some(handle),
                bytes: bytes.len(),
            };
            let lock = GlobalLockGuard::new(handle)?;
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), lock.pointer.as_ptr(), bytes.len());
            }
            lock.unlock()?;
            Ok(allocation)
        }

        fn transfer(&mut self, format: u32) -> std::result::Result<(), ()> {
            let handle = self.handle.ok_or(())?;
            unsafe { SetClipboardData(format, Some(HANDLE(handle.0))) }.map_err(|_| ())?;
            self.handle = None;
            Ok(())
        }
    }

    impl Drop for OwnedGlobal {
        fn drop(&mut self) {
            let Some(mut handle) = self.handle.take() else {
                return;
            };
            if let Ok(lock) = GlobalLockGuard::new(handle) {
                unsafe { std::slice::from_raw_parts_mut(lock.pointer.as_ptr(), self.bytes) }
                    .zeroize();
                let _ = lock.unlock();
            }
            // windows 0.62.2 GlobalFree's Result wrapper treats the successful
            // NULL result as Err. Free uses the raw ABI and is correct for Drop.
            unsafe { handle.free() };
        }
    }

    struct GlobalLockGuard {
        handle: HGLOBAL,
        pointer: NonNull<u8>,
        locked: bool,
    }

    impl GlobalLockGuard {
        fn new(handle: HGLOBAL) -> std::result::Result<Self, ()> {
            let pointer = NonNull::new(unsafe { GlobalLock(handle) }.cast::<u8>()).ok_or(())?;
            Ok(Self {
                handle,
                pointer,
                locked: true,
            })
        }

        fn unlock(mut self) -> std::result::Result<(), ()> {
            let result = unlock_global(self.handle);
            if result.is_ok() {
                self.locked = false;
            }
            result
        }
    }

    impl Drop for GlobalLockGuard {
        fn drop(&mut self) {
            if self.locked {
                let _ = unlock_global(self.handle);
            }
        }
    }

    fn unlock_global(handle: HGLOBAL) -> std::result::Result<(), ()> {
        // GlobalUnlock returns FALSE with NO_ERROR when the final lock is
        // released. windows 0.62.2 converts that to Err(HRESULT(0)); preserve the
        // actual contract rather than treating a successful release as failure.
        unsafe { SetLastError(NO_ERROR) };
        let result = unsafe { GlobalUnlock(handle) }.map_err(|error| error.code().0);
        if unlock_result_succeeded(result) {
            Ok(())
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{allocation_contains, payload_matches, unlock_result_succeeded, utf16_byte_len};

    #[test]
    fn utf16_size_counts_surrogates_and_terminator() {
        let text: Vec<u16> = "a\u{1f512}".encode_utf16().chain(Some(0)).collect();
        assert_eq!(utf16_byte_len(text.len()), Some(8));
        assert_eq!(utf16_byte_len(0), None);
        assert_eq!(utf16_byte_len(usize::MAX), None);
        assert_eq!(utf16_byte_len(isize::MAX as usize), None);
    }

    #[test]
    fn bounded_reads_allow_allocator_padding_but_not_truncation() {
        assert!(allocation_contains(16, 16));
        assert!(allocation_contains(24, 16));
        assert!(!allocation_contains(15, 16));
        assert!(!allocation_contains(0, 16));
        assert!(!allocation_contains(16, 0));
        assert!(!allocation_contains(usize::MAX, usize::MAX));
    }

    #[test]
    fn final_global_unlock_zero_last_error_is_success() {
        assert!(unlock_result_succeeded(Ok(())));
        assert!(unlock_result_succeeded(Err(0)));
        assert!(!unlock_result_succeeded(Err(0x8007_009e_u32 as i32)));
    }

    #[test]
    fn receipt_payload_matches_exact_text_and_nul_without_reading_padding() {
        let expected = [b'A', 0, 0, 0];
        assert!(payload_matches(&expected, &expected));
        assert!(payload_matches(&[b'A', 0, 0, 0, 0, 0], &expected));
        assert!(!payload_matches(&[b'B', 0, 0, 0], &expected));
        assert!(!payload_matches(&[b'A', 0, b'B', 0], &expected));
        assert!(!payload_matches(&[b'A', 0], &expected));
        assert!(!payload_matches(&[], &[]));
    }
    #[test]
    fn owner_lookup_distinguishes_no_owner_from_lookup_failure() {
        assert_eq!(super::owner_lookup(Ok(true)), Ok(true));
        assert_eq!(super::owner_lookup(Ok(false)), Ok(false));
        assert_eq!(super::owner_lookup(Err(0)), Ok(false));
        assert_eq!(super::owner_lookup(Err(0x8007_0005_u32 as i32)), Err(()));
    }
}
