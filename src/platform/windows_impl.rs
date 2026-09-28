#![allow(unsafe_code)]

use std::cell::RefCell;
use std::ffi::c_void;
use std::path::Path;
use std::sync::atomic::{AtomicIsize, Ordering};

use iced::futures::StreamExt;
use iced::futures::channel::mpsc::{self, UnboundedSender};
use iced::futures::sink::SinkExt;
use iced::{Subscription, stream};
use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Storage::FileSystem::{
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW, REPLACEFILE_WRITE_THROUGH,
    ReplaceFileW,
};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, OpenClipboard,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::RemoteDesktop::{
    NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification, WTSUnRegisterSessionNotification,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, KillTimer, PBT_APMSUSPEND,
    PostMessageW, PostQuitMessage, RegisterClassW, SetTimer, SetWindowDisplayAffinity,
    TranslateMessage, WDA_EXCLUDEFROMCAPTURE, WDA_NONE, WINDOW_EX_STYLE, WM_APP, WM_DESTROY,
    WM_POWERBROADCAST, WM_TIMER, WM_WTSSESSION_CHANGE, WNDCLASSW, WS_OVERLAPPED,
    WTS_SESSION_LOCK, WTS_SESSION_LOGOFF,
};
use windows::core::{PCWSTR, w};

use super::{SecurityEvent, should_clear_clipboard};
use crate::{AppError, Result};

const CLIPBOARD_ARM_MESSAGE: u32 = WM_APP + 0x31;
const CLIPBOARD_CLEAR_NOW_MESSAGE: u32 = WM_APP + 0x32;
const CLIPBOARD_TIMER_ID: usize = 0x504D_434C;
const CLIPBOARD_RETRY_DELAY_MS: u32 = 250;
const CLIPBOARD_MAX_RETRIES: u8 = 4;

static SECURITY_WINDOW: AtomicIsize = AtomicIsize::new(0);

thread_local! {
    static EVENT_SENDER: RefCell<Option<UnboundedSender<SecurityEvent>>> = const { RefCell::new(None) };
    static PENDING_CLIPBOARD: RefCell<Option<PendingClipboard>> = const { RefCell::new(None) };
}

#[derive(Debug, Clone, Copy)]
struct PendingClipboard {
    sequence: u32,
    retries: u8,
}

fn to_wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn platform_error(context: &str, error: impl std::fmt::Display) -> AppError {
    AppError::Platform(format!("{context}: {error}"))
}

pub fn atomic_replace(target: &Path, replacement: &Path, backup: Option<&Path>) -> Result<()> {
    let target_w = to_wide(target);
    let replacement_w = to_wide(replacement);

    if target.exists() {
        let backup_w = backup.map(to_wide);

        if let Some(path) = backup
            && path.exists()
        {
            std::fs::remove_file(path).map_err(|error| AppError::io(path.to_path_buf(), error))?;
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
            .map_err(|error| platform_error("ReplaceFileW", error))?;
        }
    } else {
        unsafe {
            MoveFileExW(
                PCWSTR(replacement_w.as_ptr()),
                PCWSTR(target_w.as_ptr()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
            .map_err(|error| platform_error("MoveFileExW", error))?;
        }
    }

    Ok(())
}

pub fn clipboard_sequence_number() -> u32 {
    unsafe { GetClipboardSequenceNumber() }
}

pub fn set_screen_capture_protection(hwnd_value: isize, enabled: bool) -> Result<()> {
    let hwnd = HWND(hwnd_value as *mut c_void);
    let affinity = if enabled {
        WDA_EXCLUDEFROMCAPTURE
    } else {
        WDA_NONE
    };

    unsafe {
        SetWindowDisplayAffinity(hwnd, affinity)
            .map_err(|error| platform_error("SetWindowDisplayAffinity", error))
    }
}

pub fn security_events() -> Subscription<SecurityEvent> {
    Subscription::run(security_event_stream)
}

fn security_event_stream() -> impl iced::futures::Stream<Item = SecurityEvent> {
    stream::channel(32, async |mut output| {
        let (sender, mut receiver) = mpsc::unbounded();
        let thread_sender = sender.clone();

        let spawn_result = std::thread::Builder::new()
            .name("password-manager-win-events".to_string())
            .spawn(move || {
                if run_security_window(thread_sender.clone()).is_err() {
                    let _ = thread_sender.unbounded_send(SecurityEvent::MonitorFailed);
                }
            });

        if spawn_result.is_err() {
            let _ = output.send(SecurityEvent::MonitorFailed).await;
            return;
        }

        while let Some(event) = receiver.next().await {
            if output.send(event).await.is_err() {
                break;
            }
        }
    })
}

pub fn arm_clipboard_clear(expected_sequence: u32, timeout_ms: u32) -> Result<()> {
    if expected_sequence == 0 {
        return Err(AppError::Platform(
            "clipboard sequence number is unavailable".to_string(),
        ));
    }

    let hwnd = security_window()?;
    unsafe {
        PostMessageW(
            Some(hwnd),
            CLIPBOARD_ARM_MESSAGE,
            WPARAM(expected_sequence as usize),
            LPARAM(timeout_ms.max(1) as isize),
        )
        .map_err(|error| platform_error("PostMessageW(clipboard arm)", error))
    }
}

pub fn clear_armed_clipboard_now() -> Result<()> {
    let hwnd = security_window()?;
    unsafe {
        PostMessageW(
            Some(hwnd),
            CLIPBOARD_CLEAR_NOW_MESSAGE,
            WPARAM(0),
            LPARAM(0),
        )
        .map_err(|error| platform_error("PostMessageW(clipboard clear)", error))
    }
}

fn security_window() -> Result<HWND> {
    let raw = SECURITY_WINDOW.load(Ordering::Acquire);
    if raw == 0 {
        return Err(AppError::Platform(
            "Windows security monitor is not ready".to_string(),
        ));
    }
    Ok(HWND(raw as *mut c_void))
}

fn run_security_window(sender: UnboundedSender<SecurityEvent>) -> Result<()> {
    EVENT_SENDER.with(|slot| {
        *slot.borrow_mut() = Some(sender);
    });

    let module = unsafe {
        GetModuleHandleW(None).map_err(|error| platform_error("GetModuleHandleW", error))?
    };
    let class_name = w!("PasswordManagerSecurityWindow");

    let class = WNDCLASSW {
        hInstance: HINSTANCE(module.0),
        lpszClassName: class_name,
        lpfnWndProc: Some(security_wndproc),
        ..Default::default()
    };

    let atom = unsafe { RegisterClassW(&class) };
    if atom == 0 {
        return Err(platform_error(
            "RegisterClassW",
            std::io::Error::last_os_error(),
        ));
    }

    let hwnd = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class_name,
            w!("Password Manager Security Monitor"),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            None,
            None,
            Some(HINSTANCE(module.0)),
            None,
        )
        .map_err(|error| platform_error("CreateWindowExW", error))?
    };

    unsafe {
        WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION)
            .map_err(|error| platform_error("WTSRegisterSessionNotification", error))?;
    }

    SECURITY_WINDOW.store(hwnd.0 as isize, Ordering::Release);
    send_event(SecurityEvent::MonitorReady);

    let mut message = windows::Win32::UI::WindowsAndMessaging::MSG::default();
    loop {
        let result = unsafe { GetMessageW(&mut message, None, 0, 0) };
        if result.0 == -1 {
            SECURITY_WINDOW.store(0, Ordering::Release);
            return Err(platform_error(
                "GetMessageW",
                std::io::Error::last_os_error(),
            ));
        }
        if result.0 == 0 {
            break;
        }

        unsafe {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

    SECURITY_WINDOW.store(0, Ordering::Release);
    unsafe {
        let _ = WTSUnRegisterSessionNotification(hwnd);
    }
    Ok(())
}

unsafe extern "system" fn security_wndproc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        WM_WTSSESSION_CHANGE => {
            let reason = wparam.0 as u32;
            if reason == WTS_SESSION_LOCK {
                clear_clipboard_if_unchanged(hwnd, true);
                send_event(SecurityEvent::SessionLocked);
            } else if reason == WTS_SESSION_LOGOFF {
                clear_clipboard_if_unchanged(hwnd, true);
                send_event(SecurityEvent::SessionLoggedOff);
            }
            return LRESULT(0);
        }
        WM_POWERBROADCAST if wparam.0 as u32 == PBT_APMSUSPEND => {
            clear_clipboard_if_unchanged(hwnd, true);
            send_event(SecurityEvent::SystemSuspending);
            return LRESULT(1);
        }
        CLIPBOARD_ARM_MESSAGE => {
            let _ = unsafe { KillTimer(Some(hwnd), CLIPBOARD_TIMER_ID) };
            PENDING_CLIPBOARD.with(|pending| {
                *pending.borrow_mut() = Some(PendingClipboard {
                    sequence: wparam.0 as u32,
                    retries: 0,
                });
            });

            let timer = unsafe {
                SetTimer(
                    Some(hwnd),
                    CLIPBOARD_TIMER_ID,
                    (lparam.0 as u32).max(1),
                    None,
                )
            };
            if timer == 0 {
                PENDING_CLIPBOARD.with(|pending| {
                    pending.borrow_mut().take();
                });
                send_event(SecurityEvent::ClipboardCleanupFailed);
            }
            return LRESULT(0);
        }
        CLIPBOARD_CLEAR_NOW_MESSAGE => {
            clear_clipboard_if_unchanged(hwnd, true);
            return LRESULT(0);
        }
        WM_TIMER if wparam.0 == CLIPBOARD_TIMER_ID => {
            clear_clipboard_if_unchanged(hwnd, false);
            return LRESULT(0);
        }
        WM_DESTROY => {
            SECURITY_WINDOW.store(0, Ordering::Release);
            unsafe { PostQuitMessage(0) };
            return LRESULT(0);
        }
        _ => {}
    }

    unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
}

fn clear_clipboard_if_unchanged(hwnd: HWND, force_no_retry: bool) {
    let _ = unsafe { KillTimer(Some(hwnd), CLIPBOARD_TIMER_ID) };

    PENDING_CLIPBOARD.with(|pending_slot| {
        let Some(mut pending) = pending_slot.borrow_mut().take() else {
            return;
        };

        let current = unsafe { GetClipboardSequenceNumber() };
        if !should_clear_clipboard(pending.sequence, current) {
            return;
        }

        match unsafe { OpenClipboard(Some(hwnd)) } {
            Ok(()) => {
                let current_after_open = unsafe { GetClipboardSequenceNumber() };
                if should_clear_clipboard(pending.sequence, current_after_open) {
                    let _ = unsafe { EmptyClipboard() };
                }
                let _ = unsafe { CloseClipboard() };
            }
            Err(_) if !force_no_retry && pending.retries < CLIPBOARD_MAX_RETRIES => {
                pending.retries += 1;
                *pending_slot.borrow_mut() = Some(pending);
                let timer = unsafe {
                    SetTimer(
                        Some(hwnd),
                        CLIPBOARD_TIMER_ID,
                        CLIPBOARD_RETRY_DELAY_MS,
                        None,
                    )
                };
                if timer == 0 {
                    pending_slot.borrow_mut().take();
                    send_event(SecurityEvent::ClipboardCleanupFailed);
                }
            }
            Err(_) => {
                send_event(SecurityEvent::ClipboardCleanupFailed);
            }
        }
    });
}

fn send_event(event: SecurityEvent) {
    EVENT_SENDER.with(|sender| {
        if let Some(sender) = sender.borrow_mut().as_mut() {
            let _ = sender.unbounded_send(event);
        }
    });
}
