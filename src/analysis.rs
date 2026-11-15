use crate::{model::*, parser::timestamp};
use chrono::{DateTime, Duration, Utc};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    Reported,
    Plausible,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentKind {
    SleepCycle,
    SleepOpen,
    ResumeOnly,
    Restart,
    CurrentRequests,
    ClockAdjusted,
    Standby,
    Coverage,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Explanation {
    DirectSource,
    ConflictingSources,
    UnknownSource,
    TimerNearby,
    CurrentBlockers,
    NoCurrentBlockers,
    SleepUnconfirmed,
    RestartBoundary,
    ClockChanged,
    StandbyTransition,
    CoverageOnly,
}

#[derive(Debug, Clone)]
pub struct Incident {
    pub id: String,
    pub at: DateTime<Utc>,
    pub sleep_at: Option<DateTime<Utc>>,
    pub kind: IncidentKind,
    pub confidence: Confidence,
    pub explanation: Explanation,
    pub sources: Vec<String>,
    pub events: Vec<PowerEvent>,
    pub observations: Vec<Snapshot>,
    pub duration_seconds: Option<i64>,
    pub incomplete: bool,
}

impl Incident {
    fn from_event(event: &PowerEvent, kind: IncidentKind, explanation: Explanation) -> Self {
        Self {
            id: event.key(),
            at: event.at,
            sleep_at: None,
            kind,
            confidence: Confidence::Unknown,
            explanation,
            sources: vec![],
            events: vec![event.clone()],
            observations: vec![],
            duration_seconds: None,
            incomplete: false,
        }
    }
}

/// Correlates one bounded capture only. Record order preserves clock-change boundaries.
/// Independent captures are never joined by PID, device name, or a reused record number.
pub fn analyze(bundle: &Bundle) -> Vec<Incident> {
    let mut events: Vec<&PowerEvent> = bundle.events.iter().collect();
    events.sort_by_key(|e| e.record_id);
    let collision = bundle
        .issues
        .iter()
        .any(|i| i.code == IssueCode::RecordCollision);
    let mut output: Vec<Incident> = Vec::new();
    let mut pending_sleep: Option<&PowerEvent> = None;
    let mut resume_index: Option<usize> = None;
    let mut segment_start_record = 0;
    let mut seen = HashSet::new();
    for event in events {
        if !seen.insert(event.key()) {
            continue;
        }
        match event.kind() {
            EventKind::Sleep => {
                if let Some(previous) = pending_sleep.take() {
                    output.push(open_sleep(previous));
                }
                pending_sleep = Some(event);
                resume_index = None;
            }
            EventKind::Resume | EventKind::WakeReport => {
                // A Power-Troubleshooter report can follow Kernel-Power 107. Share evidence
                // only within this clock/boot segment and a narrow time window.
                let nearby = resume_index.filter(|&index| {
                    let prior = &output[index];
                    (event.at - prior.at).num_seconds().abs() <= 120
                        && prior
                            .events
                            .iter()
                            .all(|e| e.record_id > segment_start_record)
                        && prior.events.iter().any(|e| e.kind() == EventKind::Resume)
                        && event.kind() == EventKind::WakeReport
                });
                let index = if let Some(index) = nearby {
                    output[index].events.push(event.clone());
                    index
                } else {
                    let mut incident = Incident::from_event(
                        event,
                        IncidentKind::ResumeOnly,
                        Explanation::UnknownSource,
                    );
                    if let Some(sleep) = pending_sleep.take() {
                        let elapsed = event.at - sleep.at;
                        if !collision
                            && elapsed >= Duration::zero()
                            && elapsed <= Duration::days(30)
                        {
                            incident.kind = IncidentKind::SleepCycle;
                            incident.sleep_at = Some(sleep.at);
                            incident.duration_seconds = Some(elapsed.num_seconds());
                            incident.events.insert(0, sleep.clone());
                        } else {
                            output.push(open_sleep(sleep));
                            incident.incomplete = true;
                        }
                    }
                    output.push(incident);
                    output.len() - 1
                };
                let incident = &mut output[index];
                if event.kind() == EventKind::WakeReport {
                    if let Some(wake_at) = event
                        .data
                        .get("WakeTime")
                        .and_then(|v| timestamp(v).ok())
                        .map(|v| v.0)
                    {
                        let sleep_at = event
                            .data
                            .get("SleepTime")
                            .and_then(|v| timestamp(v).ok())
                            .map(|v| v.0);
                        // Do not rewrite event order with a stale or inconsistent payload time.
                        if (event.at - wake_at).num_seconds().abs() <= 300
                            && sleep_at.is_none_or(|s| s <= wake_at)
                        {
                            if let Some(sleep_at) = sleep_at {
                                let matches_pair = incident
                                    .sleep_at
                                    .is_none_or(|s| (s - sleep_at).num_seconds().abs() <= 120);
                                let no_boundary_crossing =
                                    incident.sleep_at.is_some() || segment_start_record == 0;
                                let bounded_interval = wake_at - sleep_at <= Duration::days(30);
                                if matches_pair
                                    && !collision
                                    && no_boundary_crossing
                                    && bounded_interval
                                {
                                    incident.sleep_at = Some(sleep_at);
                                    incident.at = wake_at;
                                    incident.duration_seconds =
                                        Some((wake_at - sleep_at).num_seconds());
                                    incident.kind = IncidentKind::SleepCycle;
                                } else {
                                    incident.incomplete = true;
                                }
                            }
                        } else {
                            incident.incomplete = true;
                        }
                    }
                    if let Some(source) = event
                        .data
                        .get("WakeSourceText")
                        .filter(|v| meaningful_source(v))
                        && !incident
                            .sources
                            .iter()
                            .any(|s| s.eq_ignore_ascii_case(source))
                    {
                        incident.sources.push(source.clone());
                    }
                    for field in ["WakeTimerOwner", "WakeTimerContext"] {
                        if let Some(owner) = event.data.get(field).filter(|v| meaningful_source(v))
                            && !incident.sources.contains(owner)
                        {
                            incident.sources.push(owner.clone());
                        }
                    }
                }
                resume_index = Some(index);
            }
            EventKind::Boot
            | EventKind::Shutdown
            | EventKind::UnexpectedRestart
            | EventKind::ClockChange => {
                if let Some(sleep) = pending_sleep.take() {
                    output.push(open_sleep(sleep));
                }
                resume_index = None;
                segment_start_record = event.record_id;
                let (kind, explanation) = if event.kind() == EventKind::ClockChange {
                    (IncidentKind::ClockAdjusted, Explanation::ClockChanged)
                } else {
                    (IncidentKind::Restart, Explanation::RestartBoundary)
                };
                output.push(Incident::from_event(event, kind, explanation));
            }
            EventKind::StandbyEnter | EventKind::StandbyExit => {
                if let Some(sleep) = pending_sleep.take() {
                    output.push(open_sleep(sleep));
                }
                resume_index = None;
                segment_start_record = event.record_id;
                output.push(Incident::from_event(
                    event,
                    IncidentKind::Standby,
                    Explanation::StandbyTransition,
                ));
            }
            EventKind::Other => {}
        }
    }
    if let Some(sleep) = pending_sleep {
        output.push(open_sleep(sleep));
    }
    for incident in &mut output {
        if matches!(
            incident.kind,
            IncidentKind::SleepCycle | IncidentKind::ResumeOnly
        ) {
            if !incident.sources.is_empty() {
                // More than one distinct directly reported device is contradictory. Timer
                // owner/context are facets of a timer; they are not competing wake sources.
                let reported: HashSet<String> = incident
                    .events
                    .iter()
                    .filter_map(|e| e.data.get("WakeSourceText"))
                    .filter(|s| meaningful_source(s))
                    .map(|s| s.to_lowercase())
                    .collect();
                if reported.len() > 1 || collision || incident.incomplete {
                    incident.explanation = Explanation::ConflictingSources;
                    incident.confidence = Confidence::Unknown;
                } else {
                    incident.explanation = Explanation::DirectSource;
                    incident.confidence = Confidence::Reported;
                }
            } else if let Some(sleep_at) = incident.sleep_at {
                for snapshot in &bundle.snapshots {
                    if snapshot.kind != ReportKind::WakeTimers
                        || snapshot.availability != Availability::Available
                        || snapshot.at > incident.at
                        || snapshot.at < sleep_at - Duration::minutes(30)
                    {
                        continue;
                    }
                    if bundle.events.iter().any(|e| {
                        matches!(
                            e.kind(),
                            EventKind::Boot
                                | EventKind::Shutdown
                                | EventKind::UnexpectedRestart
                                | EventKind::ClockChange
                        ) && e.at >= snapshot.at
                            && e.at <= sleep_at
                    }) {
                        continue;
                    }
                    let candidates: Vec<_> = snapshot
                        .items
                        .iter()
                        .filter(|i| {
                            i.due_at
                                .is_some_and(|due| (due - incident.at).num_seconds().abs() <= 120)
                        })
                        .cloned()
                        .collect();
                    if !candidates.is_empty() {
                        incident
                            .sources
                            .extend(candidates.iter().map(|i| i.name.clone()));
                        incident.observations.push(Snapshot {
                            items: candidates,
                            ..snapshot.clone()
                        });
                        incident.explanation = Explanation::TimerNearby;
                        incident.confidence = Confidence::Plausible;
                    }
                }
            }
        }
        incident.incomplete |= collision || !bundle.issues.is_empty();
    }
    // Current requests explain their own capture, never a past failed sleep attempt.
    for snapshot in bundle
        .snapshots
        .iter()
        .filter(|s| s.kind == ReportKind::Requests && s.availability == Availability::Available)
    {
        let relevant = snapshot.items.iter().any(|i| {
            matches!(
                i.request,
                RequestType::System | RequestType::AwayMode | RequestType::Execution
            )
        });
        use sha2::{Digest, Sha256};
        output.push(Incident {
            id: format!(
                "requests:{:x}",
                Sha256::digest(serde_json::to_vec(snapshot).expect("snapshot serialization"))
            ),
            at: snapshot.at,
            sleep_at: None,
            kind: IncidentKind::CurrentRequests,
            confidence: if relevant {
                Confidence::Plausible
            } else {
                Confidence::Unknown
            },
            explanation: if relevant {
                Explanation::CurrentBlockers
            } else {
                Explanation::NoCurrentBlockers
            },
            sources: snapshot.items.iter().map(|i| i.name.clone()).collect(),
            events: vec![],
            observations: vec![snapshot.clone()],
            duration_seconds: None,
            incomplete: false,
        });
    }
    output.sort_by_key(|i| std::cmp::Reverse(i.at));
    output
}

pub(crate) fn meaningful_source(source: &str) -> bool {
    ![
        "",
        "0",
        "unknown",
        "unknown source",
        "none",
        "n/a",
        "неизвестно",
        "inconnu",
        "unbekannt",
        "desconocido",
        "sconosciuto",
    ]
    .contains(&source.trim().to_lowercase().as_str())
}

fn open_sleep(event: &PowerEvent) -> Incident {
    let mut incident = Incident::from_event(
        event,
        IncidentKind::SleepOpen,
        Explanation::SleepUnconfirmed,
    );
    incident.sleep_at = Some(event.at);
    incident.incomplete = true;
    incident
}
