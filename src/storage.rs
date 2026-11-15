use crate::{model::*, parser::validate};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub const MAX_HISTORY_BYTES: u64 = 24 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub language: String,
    pub dark: bool,
    pub reduced_motion: bool,
    pub startup_update_check: bool,
    pub retention_days: u32,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            language: "en".into(),
            dark: true,
            reduced_motion: false,
            startup_update_check: true,
            retention_days: 14,
        }
    }
}
impl Settings {
    pub fn normalize(&mut self) {
        if !["en", "ru", "fr", "de", "es", "it"].contains(&self.language.as_str()) {
            self.language = "en".into();
        }
        if ![7, 14, 30].contains(&self.retention_days) {
            self.retention_days = 14;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Windows,
    Imported,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    pub origin: Origin,
    pub saved_at: DateTime<Utc>,
    pub bundle: Bundle,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct History {
    pub schema_version: u32,
    pub captures: Vec<Capture>,
}
impl Default for History {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA,
            captures: vec![],
        }
    }
}
impl History {
    pub fn retain(&mut self, now: DateTime<Utc>, days: u32) {
        let cutoff = now - Duration::days(days.clamp(1, 30) as i64);
        for capture in &mut self.captures {
            if matches!(capture.origin, Origin::Windows) {
                capture.bundle.events.retain(|e| e.at >= cutoff);
                capture.bundle.snapshots.retain(|s| s.at >= cutoff);
            }
        }
        self.captures.retain(|c| {
            c.saved_at >= cutoff
                && (!c.bundle.events.is_empty()
                    || !c.bundle.snapshots.is_empty()
                    || !c.bundle.issues.is_empty())
        });
        self.captures.sort_by_key(|c| c.saved_at);
        while self.captures.len() > 8
            || self
                .captures
                .iter()
                .map(|c| c.bundle.events.len())
                .sum::<usize>()
                > 8192
        {
            self.captures.remove(0);
        }
    }
    pub fn add(&mut self, mut capture: Capture, now: DateTime<Utc>, days: u32) -> Result<()> {
        validate(&mut capture.bundle)?;
        self.captures.push(capture);
        self.retain(now, days);
        Ok(())
    }
}

#[derive(Clone)]
pub struct Store {
    pub root: PathBuf,
    _lock: std::sync::Arc<fs::File>,
}
impl Store {
    pub fn open(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root).context("Cannot open local application storage")?;
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(0);
        }
        let lock = options
            .open(root.join("history.lock"))
            .context("Another instance may already be using local history")?;
        Ok(Self {
            root,
            _lock: std::sync::Arc::new(lock),
        })
    }
    pub fn settings(&self) -> Result<Settings> {
        let path = self.root.join("settings.json");
        if !path.exists() {
            return Ok(Settings::default());
        }
        let mut settings: Settings = serde_json::from_slice(&read_bounded(&path, 64 * 1024)?)?;
        settings.normalize();
        Ok(settings)
    }
    pub fn save_settings(&self, settings: &Settings) -> Result<()> {
        atomic_write(
            &self.root.join("settings.json"),
            &serde_json::to_vec_pretty(settings)?,
        )
    }
    pub fn history(&self, now: DateTime<Utc>, days: u32) -> Result<History> {
        let path = self.root.join("history.json");
        if !path.exists() {
            return Ok(History::default());
        }
        let mut history: History =
            serde_json::from_slice(&read_bounded(&path, MAX_HISTORY_BYTES)?)?;
        ensure!(
            history.schema_version == SCHEMA && history.captures.len() <= 8,
            "Unsupported or oversized local history"
        );
        for capture in &mut history.captures {
            validate(&mut capture.bundle)?;
        }
        history.retain(now, days);
        self.save_history(&history)?;
        Ok(history)
    }
    pub fn save_history(&self, history: &History) -> Result<()> {
        let bytes = serde_json::to_vec(history)?;
        ensure!(
            bytes.len() as u64 <= MAX_HISTORY_BYTES,
            "Local history limit exceeded"
        );
        atomic_write(&self.root.join("history.json"), &bytes)
    }
    pub fn clear(&self) -> Result<()> {
        // A fixed app-owned filename; settings and imported originals are preserved.
        atomic_write(
            &self.root.join("history.json"),
            &serde_json::to_vec(&History::default())?,
        )
    }
}

pub fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(max + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= max, "File size limit exceeded");
    Ok(bytes)
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("Missing output directory")?;
    let temp = parent.join(format!(
        ".sleep-diagnostics-{}-{}.tmp",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::{
                MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
            };
            let source: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
            let target: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            // SAFETY: Same-directory rename of app-owned temporary file, with valid UTF-16 paths.
            let renamed = unsafe {
                MoveFileExW(
                    source.as_ptr(),
                    target.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            };
            ensure!(
                renamed != 0,
                "Cannot atomically replace file: {}",
                std::io::Error::last_os_error()
            );
        }
        #[cfg(not(windows))]
        fs::rename(&temp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Sharing is explicit. Identity labels are salted per report so exports cannot be
/// linked by device serial, task path, process name, PID, or username.
pub fn redacted_export(bundle: &Bundle, salt: &[u8]) -> Result<Vec<u8>> {
    let label = |category: &str, text: &str| {
        let mut hash = Sha256::new();
        hash.update(salt);
        hash.update(text.as_bytes());
        format!("[{category}-{}]", &format!("{:x}", hash.finalize())[..10])
    };
    let mut safe = bundle.clone();
    for event in &mut safe.events {
        for (key, value) in &mut event.data {
            if ["WakeSourceText", "WakeTimerOwner", "WakeTimerContext"].contains(&key.as_str())
                && crate::analysis::meaningful_source(value)
            {
                *value = label("source", value);
            }
        }
    }
    for snapshot in &mut safe.snapshots {
        for item in &mut snapshot.items {
            if snapshot.kind != ReportKind::SleepStates {
                item.name = label("identity", &item.name);
            }
            item.pid = None;
            item.process_started_at = None;
            item.instance_hash = item.instance_hash.as_ref().map(|v| {
                let mut hash = Sha256::new();
                hash.update(salt);
                hash.update(v.as_bytes());
                format!("{:x}", hash.finalize())
            });
        }
    }
    validate(&mut safe)?;
    let bytes = serde_json::to_vec_pretty(&safe)?;
    ensure!(bytes.len() <= MAX_REPORT, "Export exceeds bundle limit");
    Ok(bytes)
}
