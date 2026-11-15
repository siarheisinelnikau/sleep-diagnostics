use crate::model::*;
use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use quick_xml::{Reader, XmlVersion, events::Event};
use std::collections::BTreeMap;

pub const FIELDS: &[&str] = &[
    "SleepTime",
    "WakeTime",
    "WakeSourceType",
    "WakeSourceText",
    "WakeTimerOwner",
    "WakeTimerContext",
    "OldTime",
    "NewTime",
    "Reason",
    "TargetState",
    "EffectiveState",
];

pub fn allowed(provider: &str, id: u32) -> bool {
    matches!(
        (provider, id),
        (
            "Microsoft-Windows-Kernel-Power",
            41 | 42 | 107 | 109 | 506 | 507
        ) | ("Microsoft-Windows-Power-Troubleshooter", 1)
            | ("Microsoft-Windows-Kernel-General", 1 | 12 | 13)
            | ("EventLog", 6005 | 6006 | 6008)
    )
}

pub fn timestamp(value: &str) -> Result<(DateTime<Utc>, i32)> {
    let parsed = DateTime::parse_from_rfc3339(value.trim())
        .context("Timestamp requires an explicit UTC offset")?;
    Ok((
        parsed.with_timezone(&Utc),
        parsed.offset().local_minus_utc() / 60,
    ))
}

#[derive(Default)]
struct Draft {
    provider: String,
    id: Option<u32>,
    record: Option<u64>,
    at: Option<(DateTime<Utc>, i32)>,
    data: BTreeMap<String, String>,
}

/// Reads event XML without rendering localized messages or retaining computer/user fields.
pub fn event_xml(xml: &str, captured_at: DateTime<Utc>) -> Result<Bundle> {
    ensure!(xml.len() <= MAX_REPORT, "Import exceeds 8 MiB");
    let mut reader = Reader::from_str(xml);
    reader.config_mut().expand_empty_elements = true;
    let mut stack: Vec<(String, String, String)> = Vec::new();
    let mut draft: Option<Draft> = None;
    let mut bundle = Bundle::empty(captured_at);
    loop {
        match reader.read_event().context("Invalid event XML")? {
            Event::Start(tag) => {
                ensure!(stack.len() < 24, "XML nesting limit exceeded");
                let name = String::from_utf8(tag.local_name().as_ref().to_vec())?;
                let mut field = String::new();
                if name == "Event" {
                    ensure!(draft.is_none(), "Nested event");
                    ensure!(bundle.events.len() < MAX_EVENTS, "Too many events");
                    draft = Some(Draft::default());
                }
                for attr in tag.attributes() {
                    let attr = attr?;
                    let value = attr
                        .decoded_and_normalized_value(XmlVersion::Implicit1_0, reader.decoder())?
                        .into_owned();
                    if let Some(d) = draft.as_mut() {
                        match (name.as_str(), attr.key.as_ref()) {
                            ("Provider", b"Name")
                                if stack.last().is_some_and(|n| n.0 == "System") =>
                            {
                                d.provider = value
                            }
                            ("TimeCreated", b"SystemTime")
                                if stack.last().is_some_and(|n| n.0 == "System") =>
                            {
                                d.at = Some(timestamp(&value)?)
                            }
                            ("Data", b"Name") => field = value,
                            _ => {}
                        }
                    }
                }
                stack.push((name, field, String::new()));
            }
            Event::Text(text) => {
                if let Some(node) = stack.last_mut() {
                    ensure!(node.2.len() + text.len() <= 64 * 1024, "XML field too long");
                    node.2.push_str(&text.decode()?);
                }
            }
            Event::CData(text) => {
                if let Some(node) = stack.last_mut() {
                    ensure!(node.2.len() + text.len() <= 64 * 1024, "XML field too long");
                    node.2.push_str(&text.decode()?);
                }
            }
            Event::GeneralRef(reference) => {
                let entity = format!("&{};", reference.decode()?);
                let decoded = quick_xml::escape::unescape(&entity)?;
                if let Some(node) = stack.last_mut() {
                    node.2.push_str(&decoded);
                }
            }
            Event::End(_) => {
                let (name, field, text) = stack.pop().context("Unexpected closing tag")?;
                if let Some(d) = draft.as_mut() {
                    match name.as_str() {
                        "EventID" if stack.last().is_some_and(|n| n.0 == "System") => {
                            d.id = Some(text.trim().parse()?)
                        }
                        "EventRecordID" if stack.last().is_some_and(|n| n.0 == "System") => {
                            d.record = Some(text.trim().parse()?)
                        }
                        "Data"
                            if stack.last().is_some_and(|n| n.0 == "EventData")
                                && FIELDS.contains(&field.as_str()) =>
                        {
                            ensure!(text.len() <= 1024, "Power event value too long");
                            ensure!(!d.data.contains_key(&field), "Duplicate event field");
                            d.data.insert(field, clean_text(&text, 512));
                        }
                        _ => {}
                    }
                }
                if name == "Event" {
                    let d = draft.take().context("Missing event")?;
                    let id = d.id.context("Missing event ID")?;
                    if allowed(&d.provider, id) {
                        let (at, offset) = d.at.context("Missing event timestamp")?;
                        bundle.events.push(PowerEvent {
                            provider: d.provider,
                            event_id: id,
                            record_id: d.record.context("Missing event record ID")?,
                            at,
                            original_offset_minutes: offset,
                            data: d.data,
                        });
                    }
                }
            }
            Event::DocType(_) => bail!("DTD and external entities are not allowed"),
            Event::Eof => break,
            _ => {}
        }
    }
    ensure!(stack.is_empty() && draft.is_none(), "Incomplete event XML");
    validate(&mut bundle)?;
    Ok(bundle)
}

pub fn clean_text(value: &str, max: usize) -> String {
    value
        .chars()
        .filter(|c| {
            !c.is_control() && !matches!(*c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .take(max)
        .collect::<String>()
        .trim()
        .to_owned()
}

pub fn import(bytes: &[u8], at: DateTime<Utc>) -> Result<Bundle> {
    ensure!(bytes.len() <= MAX_REPORT, "Import exceeds 8 MiB");
    let text = std::str::from_utf8(bytes)?
        .trim_start_matches('\u{feff}')
        .trim();
    if text.starts_with('<') {
        return event_xml(text, at);
    }
    let mut bundle: Bundle =
        serde_json::from_str(text).context("Expected a diagnostic bundle or UTF-8 event XML")?;
    validate(&mut bundle)?;
    Ok(bundle)
}

pub fn validate(bundle: &mut Bundle) -> Result<()> {
    ensure!(
        bundle.schema_version == SCHEMA,
        "Unsupported diagnostic schema"
    );
    ensure!(
        bundle.events.len() <= MAX_EVENTS
            && bundle.snapshots.len() <= 64
            && bundle.issues.len() <= 64,
        "Bundle limit exceeded"
    );
    for event in &mut bundle.events {
        ensure!(
            allowed(&event.provider, event.event_id),
            "Unsupported power provider/event"
        );
        ensure!(
            event.record_id > 0 && (-840..=840).contains(&event.original_offset_minutes),
            "Invalid event identity or offset"
        );
        ensure!(event.data.len() <= FIELDS.len(), "Too many event fields");
        for (key, value) in &mut event.data {
            ensure!(
                FIELDS.contains(&key.as_str()) && value.len() <= 1024,
                "Unsupported event field"
            );
            *value = clean_text(value, 512);
            if ["SleepTime", "WakeTime", "OldTime", "NewTime"].contains(&key.as_str()) {
                timestamp(value)?;
            }
            if ["WakeSourceType", "Reason", "TargetState", "EffectiveState"].contains(&key.as_str())
            {
                value
                    .parse::<u32>()
                    .context("Invalid numeric power field")?;
            }
        }
    }
    for snapshot in &mut bundle.snapshots {
        ensure!(snapshot.items.len() <= MAX_ITEMS, "Too many report items");
        for item in &mut snapshot.items {
            ensure!(item.name.len() <= 1024, "Report identity too long");
            item.name = clean_text(&item.name, 256);
            if let Some(hash) = &item.instance_hash {
                ensure!(
                    hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
                    "Invalid instance hash"
                );
            }
            ensure!(
                item.pid.is_none() || item.process_started_at.is_some(),
                "PID identity requires process start time"
            );
        }
        ensure!(
            snapshot.availability == Availability::Available || snapshot.items.is_empty(),
            "Unavailable report contains observations"
        );
    }
    bundle.events.sort_by_key(|e| e.record_id);
    bundle.events.dedup();
    if bundle
        .events
        .windows(2)
        .any(|pair| pair[0].record_id == pair[1].record_id)
        && !bundle
            .issues
            .iter()
            .any(|i| i.code == IssueCode::RecordCollision)
    {
        bundle.issues.push(CollectionIssue {
            code: IssueCode::RecordCollision,
            windows_error: None,
        });
    }
    Ok(())
}

pub fn parse_report(kind: ReportKind, text: &str, at: DateTime<Utc>) -> Snapshot {
    let mut result = parse_report_inner(kind, text, at);
    if result.availability != Availability::Available {
        result.items.clear();
    }
    result
}

fn parse_report_inner(kind: ReportKind, text: &str, at: DateTime<Utc>) -> Snapshot {
    let mut result = Snapshot {
        at,
        kind,
        availability: Availability::UnparsedLocale,
        items: vec![],
    };
    if text.len() > 128 * 1024 {
        result.availability = Availability::Truncated;
        return result;
    }
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    match kind {
        ReportKind::Requests => {
            let mut request = RequestType::None;
            let mut headings = 0;
            let mut pending_entry = false;
            for line in &lines {
                let heading = match *line {
                    "DISPLAY:" => Some(RequestType::Display),
                    "SYSTEM:" => Some(RequestType::System),
                    "AWAYMODE:" => Some(RequestType::AwayMode),
                    "EXECUTION:" => Some(RequestType::Execution),
                    "PERFBOOST:" => Some(RequestType::PerfBoost),
                    "ACTIVELOCKSCREEN:" => Some(RequestType::ActiveLockScreen),
                    _ => None,
                };
                if let Some(value) = heading {
                    request = value;
                    headings += 1;
                    pending_entry = false;
                    continue;
                }
                if request == RequestType::None {
                    return result;
                }
                if *line == "None." {
                    pending_entry = false;
                    continue;
                }
                if line.starts_with('[') {
                    let Some((category, name)) = line.split_once(']') else {
                        return result;
                    };
                    let kind = match category {
                        "[PROCESS" => IdentityKind::Process,
                        "[DRIVER" => IdentityKind::Driver,
                        "[SERVICE" => IdentityKind::Service,
                        _ => return result,
                    };
                    let name = if kind == IdentityKind::Process {
                        name.trim().rsplit(['\\', '/']).next().unwrap_or("")
                    } else {
                        name.trim()
                    };
                    if name.is_empty() {
                        return result;
                    }
                    result
                        .items
                        .push(Observation::named(kind, clean_text(name, 256), request));
                    pending_entry = true;
                } else if !pending_entry {
                    return result;
                }
                // Free-form reasons can contain paths and document titles. Do not retain them.
            }
            if headings >= 3 {
                result.availability = Availability::Available;
            }
        }
        ReportKind::LastWake => {
            let has_count = lines.iter().any(|l| l.starts_with("Wake History Count - "));
            if has_count {
                result.availability = Availability::Available;
                let device = lines.contains(&"Type: Device");
                let name = lines
                    .iter()
                    .find_map(|l| l.strip_prefix("Friendly Name: ").filter(|s| !s.is_empty()))
                    .or_else(|| {
                        lines
                            .iter()
                            .find_map(|l| l.strip_prefix("Description: ").filter(|s| !s.is_empty()))
                    });
                if let Some(name) = name {
                    let mut item = Observation::named(
                        if device {
                            IdentityKind::Device
                        } else {
                            IdentityKind::Unknown
                        },
                        clean_text(name, 256),
                        RequestType::None,
                    );
                    if let Some(instance) =
                        lines.iter().find_map(|l| l.strip_prefix("Instance Path: "))
                    {
                        use sha2::{Digest, Sha256};
                        item.instance_hash =
                            Some(format!("{:x}", Sha256::digest(instance.as_bytes())));
                    }
                    result.items.push(item);
                }
            }
        }
        ReportKind::WakeTimers => {
            if lines == ["There are no active wake timers in the system."] {
                result.availability = Availability::Available;
            } else if lines.iter().any(|l| l.starts_with("Timer set by ")) {
                // Local powercfg dates do not carry a reliable offset. Never guess the timer's due UTC.
                result.availability = Availability::Available;
                for line in &lines {
                    if let Some(owner) = line.strip_prefix("Timer set by ") {
                        let owner = owner.split(" expires at ").next().unwrap_or(owner);
                        let name = owner
                            .rsplit(['\\', '/'])
                            .next()
                            .unwrap_or(owner)
                            .trim_end_matches(')');
                        result.items.push(Observation::named(
                            IdentityKind::Timer,
                            clean_text(name, 256),
                            RequestType::None,
                        ));
                    }
                }
            }
        }
        ReportKind::WakeArmed => {
            // Device names and localized 'none' are indistinguishable without a structured API.
            // Keep them as unconfirmed identities; they are never causal evidence.
            if lines == ["NONE"] || lines == ["None."] {
                result.availability = Availability::Available;
            }
            // Non-empty text is not enough to distinguish a device name from a localized
            // 'none' or an error. Structured bundles can still supply device observations.
        }
        ReportKind::SleepStates => {
            // Localized prose is deliberately not interpreted as a capability list.
        }
    }
    if result.items.len() > MAX_ITEMS {
        result.availability = Availability::Truncated;
    }
    if result.availability != Availability::Available {
        result.items.clear();
    }
    result
}
