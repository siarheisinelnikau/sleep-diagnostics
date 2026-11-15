use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SCHEMA: u32 = 1;
pub const MAX_EVENTS: usize = 4096;
pub const MAX_REPORT: usize = 8 * 1024 * 1024;
pub const MAX_ITEMS: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub schema_version: u32,
    pub captured_at: DateTime<Utc>,
    pub events: Vec<PowerEvent>,
    pub snapshots: Vec<Snapshot>,
    pub issues: Vec<CollectionIssue>,
}

impl Bundle {
    pub fn empty(at: DateTime<Utc>) -> Self {
        Self {
            schema_version: SCHEMA,
            captured_at: at,
            events: vec![],
            snapshots: vec![],
            issues: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PowerEvent {
    pub provider: String,
    pub event_id: u32,
    pub record_id: u64,
    pub at: DateTime<Utc>,
    pub original_offset_minutes: i32,
    pub data: BTreeMap<String, String>,
}

impl PowerEvent {
    pub fn key(&self) -> String {
        use sha2::{Digest, Sha256};
        let bytes = serde_json::to_vec(self).expect("event serialization");
        format!("{:x}", Sha256::digest(bytes))[..24].to_owned()
    }
    pub fn kind(&self) -> EventKind {
        match (self.provider.as_str(), self.event_id) {
            ("Microsoft-Windows-Kernel-Power", 42) => EventKind::Sleep,
            ("Microsoft-Windows-Kernel-Power", 107) => EventKind::Resume,
            ("Microsoft-Windows-Kernel-Power", 506) => EventKind::StandbyEnter,
            ("Microsoft-Windows-Kernel-Power", 507) => EventKind::StandbyExit,
            ("Microsoft-Windows-Power-Troubleshooter", 1) => EventKind::WakeReport,
            ("Microsoft-Windows-Kernel-General", 12) | ("EventLog", 6005) => EventKind::Boot,
            ("Microsoft-Windows-Kernel-General", 13)
            | ("EventLog", 6006)
            | ("Microsoft-Windows-Kernel-Power", 109) => EventKind::Shutdown,
            ("Microsoft-Windows-Kernel-Power", 41) | ("EventLog", 6008) => {
                EventKind::UnexpectedRestart
            }
            ("Microsoft-Windows-Kernel-General", 1) => EventKind::ClockChange,
            _ => EventKind::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Sleep,
    Resume,
    WakeReport,
    Boot,
    Shutdown,
    UnexpectedRestart,
    ClockChange,
    StandbyEnter,
    StandbyExit,
    Other,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReportKind {
    Requests,
    LastWake,
    WakeTimers,
    WakeArmed,
    SleepStates,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Available,
    PermissionDenied,
    Unsupported,
    TimedOut,
    UnparsedLocale,
    Failed,
    Truncated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub at: DateTime<Utc>,
    pub kind: ReportKind,
    pub availability: Availability,
    pub items: Vec<Observation>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKind {
    Process,
    Driver,
    Service,
    Device,
    Timer,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestType {
    Display,
    System,
    AwayMode,
    Execution,
    PerfBoost,
    ActiveLockScreen,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub kind: IdentityKind,
    pub name: String,
    pub request: RequestType,
    // An identity is scoped to its snapshot. A PID alone is never a durable identity.
    pub pid: Option<u32>,
    pub process_started_at: Option<DateTime<Utc>>,
    pub instance_hash: Option<String>,
    pub due_at: Option<DateTime<Utc>>,
}

impl Observation {
    pub fn named(kind: IdentityKind, name: String, request: RequestType) -> Self {
        Self {
            kind,
            name,
            request,
            pid: None,
            process_started_at: None,
            instance_hash: None,
            due_at: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IssueCode {
    EventLogDenied,
    EventLogUnavailable,
    EventLimit,
    InvalidEvent,
    RecordCollision,
    ImportLimited,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionIssue {
    pub code: IssueCode,
    pub windows_error: Option<u32>,
}
