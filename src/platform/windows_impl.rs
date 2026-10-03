#![allow(unsafe_code)]

use std::cell::{Cell, RefCell};
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use iced::futures::StreamExt;
use iced::futures::channel::mpsc::{self, UnboundedSender};
use iced::futures::sink::SinkExt;
use iced::{Subscription, stream};
use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::RemoteDesktop::{
    NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification, WTSUnRegisterSessionNotification,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, PBT_APMSUSPEND,
    PostMessageW, PostQuitMessage, RegisterClassW, SetWindowDisplayAffinity, TranslateMessage,
    UnregisterClassW, WDA_EXCLUDEFROMCAPTURE, WDA_NONE, WINDOW_EX_STYLE, WM_APP, WM_DESTROY,
    WM_POWERBROADCAST, WM_TIMER, WM_WTSSESSION_CHANGE, WNDCLASSW, WS_OVERLAPPED, WTS_SESSION_LOCK,
    WTS_SESSION_LOGOFF,
};
use windows::core::{PCWSTR, w};

use super::clipboard::{ClipboardCommand, ClipboardEngine, ClipboardQueue, CopyCommand};
use super::operation_authority::{MonitorAuthorityToken, process_registry};
use super::security_monitor::{
    MAX_STARTUP_ATTEMPTS, MonitorAuthorityGuard, MonitorFailure, claim_monitor, retry_startup,
};
use super::windows_clipboard::{CLIPBOARD_TIMER_ID, WindowsClipboard};
use super::{ClipboardKind, ClipboardSession, SecurityEvent};
use crate::{AppError, Result};

const CLIPBOARD_WAKE_MESSAGE: u32 = WM_APP + 0x31;
const MONITOR_STOP_MESSAGE: u32 = WM_APP + 0x32;
const SHUTDOWN_WAIT_MS: u64 = 300;

static MONITOR_STARTED: AtomicBool = AtomicBool::new(false);
static SECURITY_WINDOW: AtomicIsize = AtomicIsize::new(0);
static CLIPBOARD_QUEUE: OnceLock<Mutex<ClipboardQueue>> = OnceLock::new();

thread_local! {
    static STOPPING_WINDOW: Cell<bool> = const {Cell::new(false)};
    static FAILURE_SENT: Cell<bool> = const {Cell::new(false)};
    static NATIVE_MONITOR_AUTHORITY: RefCell<Option<MonitorAuthorityToken>> = const { RefCell::new(None) };
    static EVENT_SENDER: RefCell<Option<UnboundedSender<SecurityEvent>>> = const { RefCell::new(None) };
    static CLIPBOARD_ENGINE: RefCell<Option<ClipboardEngine<WindowsClipboard>>> = const { RefCell::new(None) };
    static CURRENT_WRITER: RefCell<Option<ClipboardSession>> = const { RefCell::new(None) };
    static DEFERRED_SECURITY_EVENTS: RefCell<Vec<SecurityEvent>> = const { RefCell::new(Vec::new()) };
}

fn clipboard_queue() -> std::sync::MutexGuard<'static, ClipboardQueue> {
    CLIPBOARD_QUEUE
        .get_or_init(|| Mutex::new(ClipboardQueue::default()))
        .lock()
        .unwrap_or_else(|error| {
            let mut queue = error.into_inner();
            queue.revoke_active();
            queue
        })
}

fn platform_error(context: &str, error: impl std::fmt::Display) -> AppError {
    AppError::Platform(format!("{context}: {error}"))
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
        // Capture registration exactly once. A native monitor or its forwarder
        // never resolves whichever App happens to be registered later.
        let Some(token) = process_registry().capture_monitor() else {
            let _ = output.send(SecurityEvent::MonitorFailed).await;
            return;
        };
        let _forwarding_guard = MonitorAuthorityGuard::new(
            token.clone(),
            MonitorFailure::ForwardingClosed,
            request_monitor_stop,
        );
        if !claim_monitor(&MONITOR_STARTED) {
            MonitorFailure::DuplicateOwner.revoke_in(&token, Instant::now());
            let _ = output.send(SecurityEvent::MonitorFailed).await;
            return;
        }
        let (sender, mut receiver) = mpsc::unbounded();
        let thread_sender = sender.clone();
        let thread_token = token.clone();

        let spawn_result = std::thread::Builder::new()
            .name("password-manager-win-events".to_string())
            .spawn(move || {
                NATIVE_MONITOR_AUTHORITY
                    .with(|slot| *slot.borrow_mut() = Some(thread_token.clone()));
                let _native_exit = MonitorAuthorityGuard::new(
                    thread_token.clone(),
                    MonitorFailure::RuntimeExit,
                    || {
                        SECURITY_WINDOW.store(0, Ordering::Release);
                        clipboard_queue().revoke_active_native();
                    },
                );
                for attempt in 1..=MAX_STARTUP_ATTEMPTS {
                    let mut reached_ready = false;
                    let mut cleanup_complete = true;
                    FAILURE_SENT.with(|slot| slot.set(false));
                    let result = run_security_window(
                        thread_sender.clone(),
                        &mut reached_ready,
                        &mut cleanup_complete,
                    );
                    // Classify only at the completed attempt boundary. Before
                    // first Ready there is no auth authority; a torn-down init
                    // failure can retain its single initial Ready grant only
                    // when both structural policy and coordinator agree.
                    let eligible_retry = retry_startup(
                        attempt,
                        reached_ready,
                        cleanup_complete,
                        !thread_sender.is_closed(),
                    );
                    if eligible_retry
                        && MonitorFailure::StartupRetry.revoke_in(&thread_token, Instant::now())
                    {
                        SECURITY_WINDOW.store(0, Ordering::Release);
                        clipboard_queue().revoke_active_native();
                        std::thread::sleep(Duration::from_millis(u64::from(attempt) * 250));
                        continue;
                    }
                    let failure = if result.is_err() && !reached_ready {
                        MonitorFailure::Initialization
                    } else {
                        MonitorFailure::RuntimeExit
                    };
                    failure.revoke_in(&thread_token, Instant::now());
                    SECURITY_WINDOW.store(0, Ordering::Release);
                    clipboard_queue().revoke_active_native();
                    if !FAILURE_SENT.with(Cell::get)
                        && thread_sender
                            .unbounded_send(SecurityEvent::MonitorFailed)
                            .is_err()
                    {
                        MonitorFailure::EventSend.revoke_in(&thread_token, Instant::now());
                    }
                    break;
                }
            });

        if spawn_result.is_err() {
            MonitorFailure::Spawn.revoke_in(&token, Instant::now());
            MONITOR_STARTED.store(false, Ordering::Release);
            let _ = output.send(SecurityEvent::MonitorFailed).await;
            return;
        }

        drop(sender);
        while let Some(event) = receiver.next().await {
            if output.send(event).await.is_err() {
                MonitorFailure::ForwardingClosed.revoke_in(&token, Instant::now());
                break;
            }
        }
        MonitorFailure::ForwardingClosed.revoke_in(&token, Instant::now());
    })
}

fn native_authority_token() -> Option<MonitorAuthorityToken> {
    NATIVE_MONITOR_AUTHORITY.with(|slot| slot.borrow().clone())
}

fn route_native_security_event(event: SecurityEvent) -> bool {
    // Release the TLS borrow before metadata-coordinator entry; a native call
    // never reads the process registry again after the monitor starts.
    native_authority_token().is_some_and(|token| token.route(event, Instant::now()))
}

fn fail_native_monitor(failure: MonitorFailure) {
    if let Some(token) = native_authority_token() {
        failure.revoke_in(&token, Instant::now());
    }
}

fn request_monitor_stop() {
    let raw = SECURITY_WINDOW.load(Ordering::Acquire);
    clipboard_queue().revoke_active_native();
    if raw != 0 {
        // This runs on the forwarding executor, not the native window thread.
        // PostQuitMessage would target the wrong thread; a metadata-only window
        // message asks the owner to exit without waiting for it here.
        let posted = unsafe {
            PostMessageW(
                Some(HWND(raw as *mut c_void)),
                MONITOR_STOP_MESSAGE,
                WPARAM(0),
                LPARAM(0),
            )
        };
        if posted.is_err() {
            SECURITY_WINDOW.store(0, Ordering::Release);
        }
    }
}

pub fn begin_clipboard_session() -> ClipboardSession {
    clipboard_queue().begin()
}

pub fn enqueue_copy(
    session: &ClipboardSession,
    request: u64,
    kind: ClipboardKind,
    text: zeroize::Zeroizing<String>,
    timeout_ms: u32,
) -> Result<()> {
    let hwnd = security_window()?;
    let command = CopyCommand {
        session: session.clone(),
        request,
        kind,
        text,
        timeout_ms,
    };
    clipboard_queue()
        .push_copy(command, || post_clipboard_wake(hwnd))
        .map_err(|()| {
            AppError::Platform(
                "clipboard request was revoked, superseded, or could not be queued".to_string(),
            )
        })
}

pub fn queue_revoked_cleanup() -> Result<()> {
    let hwnd = security_window()?;
    clipboard_queue()
        .push_clear(|| post_clipboard_wake(hwnd))
        .map_err(|()| AppError::Platform("clipboard cleanup could not be queued".to_string()))
}

pub fn shutdown_clipboard() -> Result<()> {
    shutdown_barrier(None)
}

pub fn shutdown_clipboard_session(session: &ClipboardSession) -> Result<()> {
    shutdown_barrier(Some(session.id()))
}

fn shutdown_barrier(session: Option<u64>) -> Result<()> {
    let deadline = Instant::now() + Duration::from_millis(SHUTDOWN_WAIT_MS);
    let mutex = CLIPBOARD_QUEUE.get_or_init(|| Mutex::new(ClipboardQueue::default()));
    let mut queue = loop {
        match mutex.try_lock() {
            Ok(queue) => break queue,
            Err(std::sync::TryLockError::Poisoned(error)) => {
                let mut queue = error.into_inner();
                queue.revoke_active_native();
                break queue;
            }
            Err(std::sync::TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(_) => {
                return Err(AppError::Platform(
                    "clipboard shutdown queue remained busy".to_string(),
                ));
            }
        }
    };
    if session.is_none() {
        queue.revoke_active_native();
    }
    let hwnd = security_window()?;
    let (done, receiver) = std::sync::mpsc::sync_channel(1);
    let queued = match session {
        Some(session) => queue.push_shutdown(session, done, || post_clipboard_wake(hwnd)),
        None => queue.push_stop(done, || post_clipboard_wake(hwnd)),
    };
    drop(queue);
    queued.map_err(|()| {
        AppError::Platform("clipboard shutdown cleanup could not be queued".to_string())
    })?;
    // One total bound covers acquiring the command queue and waiting for the
    // native owner. Shutdown never waits on the native write gate itself.
    match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(true) => Ok(()),
        _ => Err(AppError::Platform(
            "clipboard shutdown cleanup did not complete".to_string(),
        )),
    }
}

fn post_clipboard_wake(hwnd: HWND) -> bool {
    // WM_APP carries no pointer or secret. The typed queue owns and zeroizes
    // payloads and withdraws a failed post while still holding its own mutex.
    unsafe { PostMessageW(Some(hwnd), CLIPBOARD_WAKE_MESSAGE, WPARAM(0), LPARAM(0)).is_ok() }
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

fn run_security_window(
    sender: UnboundedSender<SecurityEvent>,
    reached_ready: &mut bool,
    cleanup_complete: &mut bool,
) -> Result<()> {
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

    *cleanup_complete = false;
    let mut native_cleanup_complete = true;
    let result = run_registered_security_window(
        HINSTANCE(module.0),
        class_name,
        reached_ready,
        &mut native_cleanup_complete,
    );
    let unregistered = unsafe { UnregisterClassW(class_name, Some(HINSTANCE(module.0))) }
        .map_err(|error| platform_error("UnregisterClassW", error));
    *cleanup_complete = native_cleanup_complete && unregistered.is_ok();
    result.and(unregistered)
}

fn run_registered_security_window(
    instance: HINSTANCE,
    class_name: PCWSTR,
    reached_ready: &mut bool,
    native_cleanup_complete: &mut bool,
) -> Result<()> {
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
            Some(instance),
            None,
        )
        .map_err(|error| platform_error("CreateWindowExW", error))?
    };

    *native_cleanup_complete = false;
    if let Err(error) = unsafe { WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) } {
        *native_cleanup_complete = destroy_security_window(hwnd);
        return Err(platform_error("WTSRegisterSessionNotification", error));
    }
    let backend = match WindowsClipboard::new(hwnd) {
        Ok(backend) => backend,
        Err(error) => {
            let unregistered = unsafe { WTSUnRegisterSessionNotification(hwnd) }.is_ok();
            let destroyed = destroy_security_window(hwnd);
            *native_cleanup_complete = unregistered && destroyed;
            return Err(error);
        }
    };
    CLIPBOARD_ENGINE.with(|slot| *slot.borrow_mut() = Some(ClipboardEngine::new(backend)));

    *reached_ready = true;
    SECURITY_WINDOW.store(hwnd.0 as isize, Ordering::Release);
    if !send_event(SecurityEvent::MonitorReady) {
        *native_cleanup_complete = stop_security_window(hwnd);
        return Err(AppError::Platform(
            "Windows monitor readiness could not reach a live authority".to_string(),
        ));
    }

    let mut message = windows::Win32::UI::WindowsAndMessaging::MSG::default();
    loop {
        let result = unsafe { GetMessageW(&mut message, None, 0, 0) };
        if result.0 == -1 {
            let error = platform_error("GetMessageW", std::io::Error::last_os_error());
            *native_cleanup_complete = stop_security_window(hwnd);
            return Err(error);
        }
        if result.0 == 0 {
            break;
        }

        unsafe {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

    *native_cleanup_complete = stop_security_window(hwnd);
    Ok(())
}

fn stop_security_window(hwnd: HWND) -> bool {
    fail_native_monitor(MonitorFailure::RuntimeExit);
    SECURITY_WINDOW.store(0, Ordering::Release);
    clipboard_queue().revoke_active();
    with_engine(|engine| {
        engine.stop();
    });
    let engine = CLIPBOARD_ENGINE.with(|slot| slot.borrow_mut().take());
    drop(engine); // Native Drop calls must run after releasing the RefCell borrow.
    let unregistered = unsafe { WTSUnRegisterSessionNotification(hwnd) }.is_ok();
    let destroyed = destroy_security_window(hwnd);
    unregistered && destroyed
}

fn destroy_security_window(hwnd: HWND) -> bool {
    STOPPING_WINDOW.with(|slot| slot.set(true));
    let destroyed = unsafe { DestroyWindow(hwnd) }.is_ok();
    STOPPING_WINDOW.with(|slot| slot.set(false));
    destroyed
}

fn with_engine(operation: impl FnOnce(&mut ClipboardEngine<WindowsClipboard>)) {
    // Win32 clipboard calls may synchronously reenter this WndProc. Move the
    // engine out instead of keeping a RefCell borrow alive across native calls.
    let Some(mut engine) = CLIPBOARD_ENGINE.with(|slot| slot.borrow_mut().take()) else {
        return;
    };
    operation(&mut engine);
    let mut lifecycle = Vec::new();
    loop {
        let deferred =
            DEFERRED_SECURITY_EVENTS.with(|slot| std::mem::take(&mut *slot.borrow_mut()));
        if deferred.is_empty() {
            break;
        }
        clipboard_queue().revoke_active_native();
        engine.clear_revoked();
        for event in deferred {
            if !lifecycle.contains(&event) {
                lifecycle.push(event);
            }
        }
    }
    let events = engine.events();
    let failed = events.contains(&SecurityEvent::MonitorFailed)
        || lifecycle.contains(&SecurityEvent::MonitorFailed);
    if failed {
        fail_native_monitor(MonitorFailure::RuntimeExit);
    }
    CLIPBOARD_ENGINE.with(|slot| *slot.borrow_mut() = Some(engine));
    for event in events
        .into_iter()
        .chain(lifecycle)
        .filter(|event| *event != SecurityEvent::MonitorFailed)
    {
        send_event(event);
    }
    if failed {
        // Keep restart guidance last, after any copy/cleanup error statuses.
        send_event(SecurityEvent::MonitorFailed);
        SECURITY_WINDOW.store(0, Ordering::Release);
        clipboard_queue().revoke_active_native();
        unsafe { PostQuitMessage(1) };
    }
    let needs_wake = { clipboard_queue().has_work() };
    if !failed
        && needs_wake
        && let Ok(hwnd) = security_window()
    {
        // A reentrant wake may have arrived while the owner was busy. Re-post
        // after restoring it so no typed command loses its only wake-up.
        if !post_clipboard_wake(hwnd) {
            fail_native_monitor(MonitorFailure::EventSend);
            SECURITY_WINDOW.store(0, Ordering::Release);
            clipboard_queue().revoke_active_native();
            send_event(SecurityEvent::MonitorFailed);
            unsafe { PostQuitMessage(1) };
        }
    }
}

fn process_clipboard_queue() {
    if !CLIPBOARD_ENGINE.with(|slot| slot.borrow().is_some()) {
        return;
    }
    loop {
        let command = { clipboard_queue().pop() };
        let Some(command) = command else {
            break;
        };
        with_engine(|engine| match command {
            ClipboardCommand::Copy(command) => {
                CURRENT_WRITER.with(|slot| *slot.borrow_mut() = Some(command.session.clone()));
                engine.write(command);
                CURRENT_WRITER.with(|slot| {
                    slot.borrow_mut().take();
                });
            }
            ClipboardCommand::ClearRevoked => engine.clear_revoked(),
            ClipboardCommand::Shutdown { session, done } => {
                let _ = done.try_send(engine.shutdown(session));
            }
            ClipboardCommand::Stop { done } => {
                let _ = done.try_send(engine.stop());
            }
        });
        if SECURITY_WINDOW.load(Ordering::Acquire) == 0 {
            break;
        }
    }
}

fn native_security_event(event: SecurityEvent) {
    route_native_security_event(event);
    // Coordinator routing is metadata-only and precedes every new clipboard
    // lock/borrow. During inherited SetClipboardData reentrancy the write gate
    // may be held by the caller, but there is no coordinator-to-clipboard edge.
    // A reentrant native event must never wait on the same write gate or on a
    // queue mutex whose caller may be waiting for that gate. Atomically revoke
    // the in-flight writer now; the owner revokes all queued permits and cleans
    // its receipt before delivering the deferred App notification.
    CURRENT_WRITER.with(|slot| {
        if let Some(session) = slot.borrow().as_ref() {
            session.revoke_native();
        }
    });
    DEFERRED_SECURITY_EVENTS.with(|slot| {
        let mut events = slot.borrow_mut();
        if !events.contains(&event) {
            events.push(event);
        }
    });
    with_engine(|_| {});
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
                native_security_event(SecurityEvent::SessionLocked);
            } else if reason == WTS_SESSION_LOGOFF {
                native_security_event(SecurityEvent::SessionLoggedOff);
            }
            return LRESULT(0);
        }
        WM_POWERBROADCAST if wparam.0 as u32 == PBT_APMSUSPEND => {
            native_security_event(SecurityEvent::SystemSuspending);
            return LRESULT(1);
        }
        MONITOR_STOP_MESSAGE => {
            native_security_event(SecurityEvent::MonitorFailed);
            unsafe { PostQuitMessage(0) };
            return LRESULT(0);
        }
        CLIPBOARD_WAKE_MESSAGE => {
            process_clipboard_queue();
            return LRESULT(0);
        }
        WM_TIMER if wparam.0 == CLIPBOARD_TIMER_ID => {
            with_engine(|engine| engine.tick());
            return LRESULT(0);
        }
        WM_DESTROY => {
            if STOPPING_WINDOW.with(Cell::get)
                || SECURITY_WINDOW.load(Ordering::Acquire) != hwnd.0 as isize
            {
                return LRESULT(0);
            }
            SECURITY_WINDOW.store(0, Ordering::Release);
            native_security_event(SecurityEvent::MonitorFailed);
            with_engine(|engine| {
                engine.stop();
            });
            unsafe { PostQuitMessage(0) };
            return LRESULT(0);
        }
        _ => {}
    }
    unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
}

fn send_event(event: SecurityEvent) -> bool {
    // Monitor status can originate outside native_security_event. Revoke (or
    // mark fresh readiness) before any channel/clipboard handling. The bridge
    // refuses Ready if its Weak registration is absent, expired or poisoned.
    if matches!(
        event,
        SecurityEvent::MonitorReady | SecurityEvent::MonitorFailed
    ) {
        let routed = route_native_security_event(event);
        if event == SecurityEvent::MonitorReady && !routed {
            fail_native_monitor(MonitorFailure::MissingAuthority);
            SECURITY_WINDOW.store(0, Ordering::Release);
            clipboard_queue().revoke_active_native();
            unsafe { PostQuitMessage(1) };
            return false;
        }
    }
    if event == SecurityEvent::MonitorFailed {
        FAILURE_SENT.with(|slot| slot.set(true));
    }
    let sent = EVENT_SENDER.with(|sender| {
        sender
            .borrow_mut()
            .as_mut()
            .is_some_and(|sender| sender.unbounded_send(event).is_ok())
    });
    if !sent {
        fail_native_monitor(MonitorFailure::EventSend);
        SECURITY_WINDOW.store(0, Ordering::Release);
        clipboard_queue().revoke_active_native();
        unsafe { PostQuitMessage(1) };
    }
    sent
}
