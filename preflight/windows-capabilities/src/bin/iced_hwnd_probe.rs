use iced::{Task, window};
use raw_window_handle::RawWindowHandle;

fn get_windows_hwnd(id: window::Id) -> Task<Option<isize>> {
    window::run(id, |managed_window| {
        let handle = managed_window.window_handle().ok()?;

        match handle.as_raw() {
            RawWindowHandle::Win32(win32) => Some(win32.hwnd.get()),
            _ => None,
        }
    })
}

fn main() {
    // Compile-time capability probe:
    // Iced 0.14 window::run exposes the managed window as a type implementing
    // raw-window-handle's HasWindowHandle. The real application can therefore
    // obtain HWND without forking Iced or opening a localhost/WebView bridge.
    let _probe: fn(window::Id) -> Task<Option<isize>> = get_windows_hwnd;
    println!("iced_hwnd_access=compile_ok");
}
