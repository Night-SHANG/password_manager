use argon2::{Algorithm, Argon2, Params, Version};
use std::time::Instant;

#[cfg(windows)]
fn io_error<E: std::fmt::Display>(context: &str, err: E) -> std::io::Error {
    std::io::Error::other(format!("{context}: {err}"))
}

#[cfg(windows)]
fn to_wide(path: &std::path::Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(windows)]
fn probe_atomic_replace() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::{self, File};
    use std::io::Write;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{ReplaceFileW, REPLACEFILE_WRITE_THROUGH};

    let root = std::env::temp_dir().join(format!(
        "pm-preflight-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root)?;

    let target = root.join("vault.pmvault");
    let replacement = root.join("vault.new");
    let backup = root.join("vault.backup");

    fs::write(&target, b"old")?;
    let mut f = File::create(&replacement)?;
    f.write_all(b"new")?;
    f.sync_all()?;
    drop(f);

    let target_w = to_wide(&target);
    let replacement_w = to_wide(&replacement);
    let backup_w = to_wide(&backup);

    unsafe {
        ReplaceFileW(
            PCWSTR(target_w.as_ptr()),
            PCWSTR(replacement_w.as_ptr()),
            PCWSTR(backup_w.as_ptr()),
            REPLACEFILE_WRITE_THROUGH,
            None,
            None,
        )
        .map_err(|e| io_error("ReplaceFileW", e))?;
    }

    let now = fs::read(&target)?;
    let old = fs::read(&backup)?;
    if now != b"new" || old != b"old" {
        return Err("atomic replacement content verification failed".into());
    }

    let _ = fs::remove_dir_all(&root);
    println!("atomic_replace=ok");
    Ok(())
}

#[cfg(windows)]
unsafe extern "system" fn wndproc(
    hwnd: windows::Win32::Foundation::HWND,
    msg: u32,
    wparam: windows::Win32::Foundation::WPARAM,
    lparam: windows::Win32::Foundation::LPARAM,
) -> windows::Win32::Foundation::LRESULT {
    use windows::Win32::UI::WindowsAndMessaging::DefWindowProcW;
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

#[cfg(windows)]
fn create_probe_window(
) -> Result<windows::Win32::Foundation::HWND, Box<dyn std::error::Error>> {
    use windows::core::w;
    use windows::Win32::Foundation::HINSTANCE;
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, RegisterClassW, WNDCLASSW, WINDOW_EX_STYLE, WS_OVERLAPPED,
    };

    let module = unsafe { GetModuleHandleW(None) }
        .map_err(|e| io_error("GetModuleHandleW", e))?;
    let class_name = w!("PasswordManagerPreflightWindow");

    let wc = WNDCLASSW {
        hInstance: HINSTANCE(module.0),
        lpszClassName: class_name,
        lpfnWndProc: Some(wndproc),
        ..Default::default()
    };

    let atom = unsafe { RegisterClassW(&wc) };
    if atom == 0 {
        return Err(io_error(
            "RegisterClassW",
            std::io::Error::last_os_error(),
        )
        .into());
    }

    let hwnd = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class_name,
            w!("Password Manager Preflight"),
            WS_OVERLAPPED,
            0,
            0,
            320,
            200,
            None,
            None,
            Some(HINSTANCE(module.0)),
            None,
        )
    }
    .map_err(|e| io_error("CreateWindowExW", e))?;

    Ok(hwnd)
}

#[cfg(windows)]
fn probe_session_and_capture() -> Result<(), Box<dyn std::error::Error>> {
    use windows::Win32::System::RemoteDesktop::{
        WTSRegisterSessionNotification, WTSUnRegisterSessionNotification,
        NOTIFY_FOR_THIS_SESSION,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        DestroyWindow, SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE, WDA_NONE,
    };

    let hwnd = create_probe_window()?;

    unsafe {
        WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION)
            .map_err(|e| io_error("WTSRegisterSessionNotification", e))?;

        SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)
            .map_err(|e| io_error("SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)", e))?;

        SetWindowDisplayAffinity(hwnd, WDA_NONE)
            .map_err(|e| io_error("SetWindowDisplayAffinity(WDA_NONE)", e))?;

        WTSUnRegisterSessionNotification(hwnd)
            .map_err(|e| io_error("WTSUnRegisterSessionNotification", e))?;

        DestroyWindow(hwnd).map_err(|e| io_error("DestroyWindow", e))?;
    }

    println!("session_notification=ok");
    println!("screen_capture_affinity=ok");
    Ok(())
}

#[cfg(windows)]
fn probe_clipboard_sequence() {
    use windows::Win32::System::DataExchange::GetClipboardSequenceNumber;
    let seq = unsafe { GetClipboardSequenceNumber() };
    println!("clipboard_sequence_number={seq}");
}

fn probe_argon2id() -> Result<(), Box<dyn std::error::Error>> {
    let params = Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; 32];
    let salt = [0xA5u8; 16];

    let start = Instant::now();
    argon2
        .hash_password_into(b"preflight-only-password", &salt, &mut out)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let elapsed = start.elapsed();

    if out.iter().all(|b| *b == 0) {
        return Err("Argon2id produced an invalid all-zero result".into());
    }

    println!(
        "argon2id_m64MiB_t3_p1_ms={}",
        elapsed.as_millis()
    );
    Ok(())
}

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("windows_capability_probe=start");
    probe_atomic_replace()?;
    probe_session_and_capture()?;
    probe_clipboard_sequence();
    probe_argon2id()?;
    println!("windows_capability_probe=ok");
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("This probe must run on Windows.");
    std::process::exit(2);
}
