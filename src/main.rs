#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    #[cfg(windows)]
    if std::env::args_os()
        .skip(1)
        .eq([std::ffi::OsString::from("--native-snapshot")])
    {
        use std::io::Write;
        let result = serde_json::to_writer(
            std::io::stdout().lock(),
            &sleep_diagnostics::adapter::native_snapshot(),
        );
        let _ = std::io::stdout().flush();
        if result.is_err() {
            std::process::exit(1);
        }
        return;
    }
    #[cfg(windows)]
    if let Err(error) = sleep_diagnostics::ui::run() {
        use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
        let key = if std::env::args_os().any(|a| a == "--apply-update") {
            "install_error"
        } else {
            "error"
        };
        let language = std::env::var_os("LOCALAPPDATA")
            .and_then(|root| {
                sleep_diagnostics::storage::read_bounded(
                    &std::path::PathBuf::from(root).join("SleepDiagnostics/settings.json"),
                    64 * 1024,
                )
                .ok()
            })
            .and_then(|bytes| {
                serde_json::from_slice::<sleep_diagnostics::storage::Settings>(&bytes).ok()
            })
            .map(|settings| settings.language)
            .unwrap_or_else(|| "en".into());
        let text: Vec<u16> = format!(
            "{}\n\n{}\n{error:#}\0",
            sleep_diagnostics::i18n::tr(&language, key),
            sleep_diagnostics::i18n::tr(&language, "technical")
        )
        .encode_utf16()
        .collect();
        let title: Vec<u16> = "Sleep Diagnostics\0".encode_utf16().collect();
        // SAFETY: Both strings are NUL-terminated and live for the synchronous dialog.
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                text.as_ptr(),
                title.as_ptr(),
                MB_OK | MB_ICONERROR,
            );
        }
    }
    #[cfg(not(windows))]
    eprintln!("Sleep Diagnostics requires Windows 10 or later.");
}
