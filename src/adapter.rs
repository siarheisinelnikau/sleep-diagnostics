use crate::model::*;
use chrono::{DateTime, Utc};

pub trait CollectionAdapter: Send + 'static {
    fn collect(&self, at: DateTime<Utc>) -> Bundle;
}

#[derive(Clone)]
pub struct RecordedAdapter(pub Bundle);
impl CollectionAdapter for RecordedAdapter {
    fn collect(&self, _: DateTime<Utc>) -> Bundle {
        self.0.clone()
    }
}

pub struct WindowsAdapter;

#[cfg(windows)]
pub use windows::native_snapshot;

#[cfg(not(windows))]
impl CollectionAdapter for WindowsAdapter {
    fn collect(&self, at: DateTime<Utc>) -> Bundle {
        let mut bundle = Bundle::empty(at);
        bundle.issues.push(CollectionIssue {
            code: IssueCode::EventLogUnavailable,
            windows_error: None,
        });
        bundle
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::parser::{event_xml, parse_report, validate};
    use std::{
        io::Read,
        os::windows::process::CommandExt,
        process::{Command, Stdio},
        ptr, thread,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::{
        Foundation::{ERROR_ACCESS_DENIED, ERROR_NO_MORE_ITEMS, GetLastError},
        System::{EventLog::*, SystemInformation::GetSystemDirectoryW},
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }
    struct EventHandle(EVT_HANDLE);
    impl Drop for EventHandle {
        fn drop(&mut self) {
            // SAFETY: Each nonzero handle is exclusively owned by this wrapper.
            unsafe {
                EvtClose(self.0);
            }
        }
    }

    impl CollectionAdapter for WindowsAdapter {
        fn collect(&self, at: DateTime<Utc>) -> Bundle {
            let mut bundle = Bundle::empty(at);
            if let Err(code) = read_events(&mut bundle) {
                bundle.issues.push(CollectionIssue {
                    code: if code == ERROR_ACCESS_DENIED {
                        IssueCode::EventLogDenied
                    } else {
                        IssueCode::EventLogUnavailable
                    },
                    windows_error: Some(code),
                });
            }
            // This fixed allowlist contains only bounded read-only queries. Never run /energy,
            // /requestsoverride, /set*, /device* changes, or SetThreadExecutionState.
            for (kind, arguments) in [
                (ReportKind::Requests, vec!["/requests"]),
                (ReportKind::LastWake, vec!["/lastwake"]),
                (ReportKind::WakeTimers, vec!["/waketimers"]),
            ] {
                let started = Utc::now();
                let snapshot = match query(&arguments) {
                    Ok(text) => parse_report(kind, &text, started),
                    Err(availability) => Snapshot {
                        at: started,
                        kind,
                        availability,
                        items: vec![],
                    },
                };
                bundle.snapshots.push(snapshot);
            }
            let native = std::env::current_exe()
                .map_err(|_| Availability::Failed)
                .and_then(|path| {
                    let mut command = Command::new(path);
                    command.arg("--native-snapshot");
                    bounded_command(command)
                })
                .and_then(|json| {
                    crate::parser::import(json.as_bytes(), Utc::now())
                        .map_err(|_| Availability::Failed)
                });
            match native {
                Ok(native) => bundle.snapshots.extend(native.snapshots),
                Err(availability) => {
                    for kind in [ReportKind::WakeArmed, ReportKind::SleepStates] {
                        bundle.snapshots.push(Snapshot {
                            at: Utc::now(),
                            kind,
                            availability,
                            items: vec![],
                        });
                    }
                }
            }
            if validate(&mut bundle).is_err() {
                bundle.issues.push(CollectionIssue {
                    code: IssueCode::InvalidEvent,
                    windows_error: None,
                });
            }
            bundle
        }
    }

    fn read_events(bundle: &mut Bundle) -> Result<(), u32> {
        let channel = wide("System");
        // Separate selects stay below the Windows Event Log XPath complexity limit.
        let xpath = wide(
            r#"<QueryList><Query Id="0" Path="System">
<Select Path="System">*[System[Provider[@Name='Microsoft-Windows-Kernel-Power'] and TimeCreated[timediff(@SystemTime) &lt;= 604800000] and (EventID=41 or EventID=42 or EventID=107 or EventID=109 or EventID=506 or EventID=507)]]</Select>
<Select Path="System">*[System[Provider[@Name='Microsoft-Windows-Power-Troubleshooter'] and TimeCreated[timediff(@SystemTime) &lt;= 604800000] and EventID=1]]</Select>
<Select Path="System">*[System[Provider[@Name='Microsoft-Windows-Kernel-General'] and TimeCreated[timediff(@SystemTime) &lt;= 604800000] and (EventID=1 or EventID=12 or EventID=13)]]</Select>
<Select Path="System">*[System[Provider[@Name='EventLog'] and TimeCreated[timediff(@SystemTime) &lt;= 604800000] and (EventID=6005 or EventID=6006 or EventID=6008)]]</Select>
</Query></QueryList>"#,
        );
        // SAFETY: Local read-only query; both UTF-16 buffers are NUL-terminated.
        let raw = unsafe {
            EvtQuery(
                0,
                channel.as_ptr(),
                xpath.as_ptr(),
                EvtQueryChannelPath | EvtQueryReverseDirection,
            )
        };
        if raw == 0 {
            // SAFETY: Retrieves this thread's immediately preceding Win32 error.
            return Err(unsafe { GetLastError() });
        }
        let query = EventHandle(raw);
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if bundle.events.len() >= MAX_EVENTS || Instant::now() >= deadline {
                bundle.issues.push(CollectionIssue {
                    code: IssueCode::EventLimit,
                    windows_error: None,
                });
                break;
            }
            let mut handle = 0;
            let mut count = 0;
            // SAFETY: A single writable handle slot and valid query on its originating thread.
            let ok = unsafe { EvtNext(query.0, 1, &mut handle, 200, 0, &mut count) };
            if ok == 0 {
                // SAFETY: Immediately follows the failed API call.
                let code = unsafe { GetLastError() };
                if code == ERROR_NO_MORE_ITEMS {
                    break;
                }
                return Err(code);
            }
            let handle = EventHandle(handle);
            match render_event(handle.0)
                .and_then(|xml| event_xml(&xml, bundle.captured_at).map_err(|_| 13u32))
            {
                Ok(parsed) => bundle.events.extend(parsed.events),
                Err(code) => {
                    if bundle.issues.len() < 32 {
                        bundle.issues.push(CollectionIssue {
                            code: IssueCode::InvalidEvent,
                            windows_error: Some(code),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    fn render_event(event: EVT_HANDLE) -> Result<String, u32> {
        let mut used = 0;
        let mut properties = 0;
        // SAFETY: Null buffer requests its required byte count, without rendering message strings.
        unsafe {
            EvtRender(
                0,
                event,
                EvtRenderEventXml,
                0,
                ptr::null_mut(),
                &mut used,
                &mut properties,
            );
        }
        if used == 0 || used > 128 * 1024 {
            // SAFETY: Reads the preceding API error.
            return Err(unsafe { GetLastError() });
        }
        let mut buffer = vec![0u16; (used as usize).div_ceil(2)];
        // SAFETY: Buffer is aligned and allocated for at least the requested byte count.
        if unsafe {
            EvtRender(
                0,
                event,
                EvtRenderEventXml,
                used,
                buffer.as_mut_ptr().cast(),
                &mut used,
                &mut properties,
            )
        } == 0
        {
            // SAFETY: Immediately follows the failed API call.
            return Err(unsafe { GetLastError() });
        }
        let end = buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len());
        String::from_utf16(&buffer[..end]).map_err(|_| 13)
    }

    fn query(arguments: &[&str]) -> Result<String, Availability> {
        let mut directory = vec![0u16; 32768];
        // SAFETY: Writable UTF-16 buffer with its actual capacity.
        let length =
            unsafe { GetSystemDirectoryW(directory.as_mut_ptr(), directory.len() as u32) } as usize;
        if length == 0 || length >= directory.len() {
            return Err(Availability::Failed);
        }
        let program = std::path::PathBuf::from(String::from_utf16_lossy(&directory[..length]))
            .join("powercfg.exe");
        let mut command = Command::new(program);
        command.args(arguments);
        bounded_command(command)
    }

    fn bounded_command(mut command: Command) -> Result<String, Availability> {
        let mut child = command
            .creation_flags(0x08000000)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| Availability::Failed)?;
        let out = child.stdout.take().ok_or(Availability::Failed)?;
        let err = child.stderr.take().ok_or(Availability::Failed)?;
        let read = |stream: Box<dyn Read + Send>| {
            thread::spawn(move || {
                let mut bytes = Vec::new();
                stream
                    .take(128 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .map(|_| bytes)
            })
        };
        let stdout = read(Box::new(out));
        let stderr = read(Box::new(err));
        let deadline = Instant::now() + Duration::from_secs(4);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(Availability::Failed);
                }
                Ok(None) if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(Availability::TimedOut);
                }
                Ok(None) => thread::sleep(Duration::from_millis(25)),
            }
        };
        let output = stdout
            .join()
            .ok()
            .and_then(Result::ok)
            .ok_or(Availability::Failed)?;
        let errors = stderr
            .join()
            .ok()
            .and_then(Result::ok)
            .ok_or(Availability::Failed)?;
        if output.len() > 128 * 1024 || errors.len() > 128 * 1024 {
            return Err(Availability::Truncated);
        }
        let status = status?;
        if !status.success() {
            return Err(if status.code() == Some(5) {
                Availability::PermissionDenied
            } else {
                Availability::Failed
            });
        }
        // powercfg may use UTF-16LE or an OEM codepage. Only accept UTF-8/ASCII or
        // explicit UTF-16 here; guessing an OEM locale would corrupt identities.
        if output.starts_with(&[0xff, 0xfe]) {
            if output.len() % 2 != 0 {
                return Err(Availability::UnparsedLocale);
            }
            let words: Vec<u16> = output[2..]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16(&words).map_err(|_| Availability::UnparsedLocale)
        } else {
            String::from_utf8(output).map_err(|_| Availability::UnparsedLocale)
        }
    }

    /// Runs only in an explicitly requested, bounded helper process. The parent
    /// terminates that exact child on timeout, including an unresponsive device API.
    pub fn native_snapshot() -> Bundle {
        use windows_sys::Win32::System::Power::*;
        let mut bundle = Bundle::empty(Utc::now());
        let mut capabilities = SYSTEM_POWER_CAPABILITIES::default();
        // SAFETY: Read-only supported API with a properly sized output structure.
        let supported = unsafe { GetPwrCapabilities(&mut capabilities) };
        let mut states = Snapshot {
            at: bundle.captured_at,
            kind: ReportKind::SleepStates,
            availability: if supported {
                Availability::Available
            } else {
                Availability::Failed
            },
            items: vec![],
        };
        if supported {
            for (name, present) in [
                ("S0 low-power idle", capabilities.AoAc),
                ("S1", capabilities.SystemS1),
                ("S2", capabilities.SystemS2),
                ("S3", capabilities.SystemS3),
                ("S4", capabilities.SystemS4 && capabilities.HiberFilePresent),
            ] {
                if present {
                    states.items.push(Observation::named(
                        IdentityKind::Unknown,
                        name.into(),
                        RequestType::None,
                    ));
                }
            }
        }
        bundle.snapshots.push(states);
        let mut devices = Snapshot {
            at: bundle.captured_at,
            kind: ReportKind::WakeArmed,
            availability: Availability::Failed,
            items: vec![],
        };
        // SAFETY: Opens a read-only device query session. No state-changing API is used.
        if unsafe { DevicePowerOpen(0) } {
            struct DeviceSession;
            impl Drop for DeviceSession {
                fn drop(&mut self) {
                    // SAFETY: Matches the successful open in this helper process.
                    unsafe {
                        DevicePowerClose();
                    }
                }
            }
            let _session = DeviceSession;
            devices.availability = Availability::Available;
            for index in 0..=MAX_ITEMS {
                let mut name = vec![0u16; 32768];
                let mut size = (name.len() * 2) as u32;
                let flags = DEVICEPOWER_FILTER_DEVICES_PRESENT | DEVICEPOWER_FILTER_WAKEENABLED;
                let criteria = PDCAP_WAKE_FROM_S0_SUPPORTED
                    | PDCAP_WAKE_FROM_S1_SUPPORTED
                    | PDCAP_WAKE_FROM_S2_SUPPORTED
                    | PDCAP_WAKE_FROM_S3_SUPPORTED
                    | PDCAP_WAKE_FROM_D0_SUPPORTED
                    | PDCAP_WAKE_FROM_D1_SUPPORTED
                    | PDCAP_WAKE_FROM_D2_SUPPORTED
                    | PDCAP_WAKE_FROM_D3_SUPPORTED;
                // SAFETY: Aligned UTF-16 output buffer; size is in bytes. Read-only enumeration.
                if !unsafe {
                    DevicePowerEnumDevices(
                        index as u32,
                        flags,
                        criteria,
                        name.as_mut_ptr().cast(),
                        &mut size,
                    )
                } {
                    // SAFETY: Immediately follows the failed device query.
                    let code = unsafe { GetLastError() };
                    if code != ERROR_NO_MORE_ITEMS {
                        devices.availability = if code == ERROR_ACCESS_DENIED {
                            Availability::PermissionDenied
                        } else {
                            Availability::Failed
                        };
                        devices.items.clear();
                    }
                    break;
                }
                if index == MAX_ITEMS {
                    devices.availability = Availability::Truncated;
                    devices.items.clear();
                    break;
                }
                let end = name.iter().position(|c| *c == 0).unwrap_or(name.len());
                let mut item = Observation::named(
                    IdentityKind::Device,
                    crate::parser::clean_text(&String::from_utf16_lossy(&name[..end]), 256),
                    RequestType::None,
                );
                size = (name.len() * 2) as u32;
                // SAFETY: Same scoped index and output buffer, requesting the hardware ID for hashing only.
                if unsafe {
                    DevicePowerEnumDevices(
                        index as u32,
                        flags | DEVICEPOWER_HARDWAREID,
                        criteria,
                        name.as_mut_ptr().cast(),
                        &mut size,
                    )
                } {
                    use sha2::{Digest, Sha256};
                    let end = name.iter().position(|c| *c == 0).unwrap_or(name.len());
                    item.instance_hash = Some(format!(
                        "{:x}",
                        Sha256::digest(String::from_utf16_lossy(&name[..end]).as_bytes())
                    ));
                }
                devices.items.push(item);
            }
        }
        bundle.snapshots.push(devices);
        bundle
    }
}
