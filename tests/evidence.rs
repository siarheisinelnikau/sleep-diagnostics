use chrono::{DateTime, Utc};
use sleep_diagnostics::{
    adapter::{CollectionAdapter, RecordedAdapter},
    analysis::{Confidence, Explanation, IncidentKind, analyze},
    i18n::catalogs,
    model::*,
    parser::{event_xml, import, parse_report, timestamp, validate},
    storage::{Capture, History, Origin, Store, redacted_export},
};

fn at(value: &str) -> DateTime<Utc> {
    timestamp(value).unwrap().0
}
fn event(provider: &str, id: u32, record: u64, time: &str, data: &[(&str, &str)]) -> PowerEvent {
    PowerEvent {
        provider: provider.into(),
        event_id: id,
        record_id: record,
        at: at(time),
        original_offset_minutes: 0,
        data: data
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    }
}
fn sleep(record: u64, time: &str) -> PowerEvent {
    event("Microsoft-Windows-Kernel-Power", 42, record, time, &[])
}
fn resume(record: u64, time: &str) -> PowerEvent {
    event("Microsoft-Windows-Kernel-Power", 107, record, time, &[])
}
fn wake(record: u64, time: &str, source: &str) -> PowerEvent {
    event(
        "Microsoft-Windows-Power-Troubleshooter",
        1,
        record,
        time,
        &[("WakeSourceText", source)],
    )
}
fn bundle(events: Vec<PowerEvent>) -> Bundle {
    let mut b = Bundle::empty(at("2026-11-15T09:00:00Z"));
    b.events = events;
    b
}
fn xml_event(id: u32, record: u64, time: &str, data: &str) -> String {
    format!(
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Kernel-Power"/><EventID>{id}</EventID><EventRecordID>{record}</EventRecordID><TimeCreated SystemTime="{time}"/><Computer>PRIVATE-PC</Computer><Security UserID="private-user"/></System><EventData>{data}<Data Name="UnrelatedFile">C:\Users\Private\diary.txt</Data></EventData></Event>"#
    )
}

#[test]
fn event_xml_keeps_only_power_fields_and_normalizes_offset() {
    let b = event_xml(
        &xml_event(
            42,
            8,
            "2026-10-25T02:10:00+02:00",
            "<Data Name=\"Reason\">4</Data>",
        ),
        Utc::now(),
    )
    .unwrap();
    assert_eq!(b.events[0].at, at("2026-10-25T00:10:00Z"));
    assert_eq!(b.events[0].original_offset_minutes, 120);
    let output = serde_json::to_string(&b).unwrap();
    for forbidden in ["PRIVATE-PC", "private-user", "diary.txt", "UnrelatedFile"] {
        assert!(!output.contains(forbidden));
    }
}

#[test]
fn xml_entities_are_decoded_without_enabling_dtd() {
    let xml = xml_event(
        42,
        1,
        "2026-11-15T02:00:00Z",
        "<Data Name=\"WakeSourceText\">USB &amp; HID &#x41;</Data>",
    );
    assert_eq!(
        event_xml(&xml, Utc::now()).unwrap().events[0].data["WakeSourceText"],
        "USB & HID A"
    );
    assert!(
        event_xml(
            &format!("<!DOCTYPE a [<!ENTITY e SYSTEM 'file:///private'>]>{xml}"),
            Utc::now()
        )
        .is_err()
    );
}

#[test]
fn malformed_or_ambiguous_timestamps_and_event_fields_are_rejected() {
    assert!(timestamp("2026-11-15T02:00:00").is_err());
    assert!(event_xml(&xml_event(42, 1, "not-a-time", ""), Utc::now()).is_err());
    assert!(
        event_xml(
            &xml_event(
                42,
                1,
                "2026-11-15T02:00:00Z",
                "<Data Name=\"Reason\">C:\\Users\\Private</Data>"
            ),
            Utc::now()
        )
        .is_err()
    );
    let mut b = bundle(vec![sleep(1, "2026-11-15T02:00:00Z")]);
    b.events[0].original_offset_minutes = i32::MIN;
    assert!(validate(&mut b).is_err());
}

#[test]
fn nested_duplicate_and_incomplete_xml_are_rejected() {
    let duplicate = xml_event(
        42,
        1,
        "2026-11-15T02:00:00Z",
        "<Data Name=\"Reason\">1</Data><Data Name=\"Reason\">2</Data>",
    );
    assert!(event_xml(&duplicate, Utc::now()).is_err());
    assert!(event_xml("<Events><Event>", Utc::now()).is_err());
    let nested = format!(
        "{}{}{}",
        "<a>".repeat(25),
        xml_event(42, 1, "2026-11-15T02:00:00Z", ""),
        "</a>".repeat(25)
    );
    assert!(event_xml(&nested, Utc::now()).is_err());
}

#[test]
fn unrelated_providers_never_become_sleep_events() {
    let xml = xml_event(42, 1, "2026-11-15T02:00:00Z", "")
        .replace("Microsoft-Windows-Kernel-Power", "Other-Provider");
    assert!(event_xml(&xml, Utc::now()).unwrap().events.is_empty());
}

#[test]
fn dst_fall_back_pairs_by_utc_instead_of_wall_time() {
    let mut first = sleep(10, "2026-10-25T02:55:00+02:00");
    first.original_offset_minutes = 120;
    let mut last = wake(11, "2026-10-25T02:05:00+01:00", "USB controller");
    last.original_offset_minutes = 60;
    let items = analyze(&bundle(vec![last, first]));
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].duration_seconds, Some(600));
    assert_eq!(items[0].confidence, Confidence::Reported);
}

#[test]
fn dst_spring_forward_does_not_inflate_sleep_duration() {
    let items = analyze(&bundle(vec![
        sleep(1, "2026-03-29T01:55:00+01:00"),
        wake(2, "2026-03-29T03:05:00+02:00", "Keyboard"),
    ]));
    assert_eq!(items[0].duration_seconds, Some(600));
}

#[test]
fn resume_and_report_share_evidence_without_duplicate_incidents() {
    let b = bundle(vec![
        sleep(1, "2026-11-15T01:00:00Z"),
        resume(2, "2026-11-15T03:00:00Z"),
        wake(3, "2026-11-15T03:00:02Z", "Network adapter"),
    ]);
    let items = analyze(&b);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].events.len(), 3);
    assert_eq!(items[0].confidence, Confidence::Reported);
}

#[test]
fn contradictory_direct_reports_do_not_select_a_winner() {
    let items = analyze(&bundle(vec![
        sleep(1, "2026-11-15T01:00:00Z"),
        resume(2, "2026-11-15T03:00:00Z"),
        wake(3, "2026-11-15T03:00:02Z", "Keyboard"),
        wake(4, "2026-11-15T03:00:03Z", "Network adapter"),
    ]));
    assert_eq!(items[0].explanation, Explanation::ConflictingSources);
    assert_eq!(items[0].confidence, Confidence::Unknown);
    assert_eq!(items[0].sources.len(), 2);
}

#[test]
fn unknown_and_missing_sources_stay_unknown() {
    for source in ["", "0", "Unknown", "Неизвестно", "Inconnu"] {
        let items = analyze(&bundle(vec![
            sleep(1, "2026-11-15T01:00:00Z"),
            wake(2, "2026-11-15T03:00:00Z", source),
        ]));
        assert_eq!(items[0].confidence, Confidence::Unknown, "{source}");
    }
}

#[test]
fn missing_resume_is_not_reported_as_a_failed_sleep() {
    let items = analyze(&bundle(vec![sleep(1, "2026-11-15T01:00:00Z")]));
    assert_eq!(items[0].explanation, Explanation::SleepUnconfirmed);
    assert_eq!(items[0].duration_seconds, None);
}

#[test]
fn reboot_and_clock_boundaries_block_pairing_even_with_payload_times() {
    for (provider, id) in [
        ("Microsoft-Windows-Kernel-General", 12),
        ("Microsoft-Windows-Kernel-General", 1),
        ("Microsoft-Windows-Kernel-Power", 41),
    ] {
        let mut report = wake(3, "2026-11-15T03:00:00Z", "Keyboard");
        report
            .data
            .insert("SleepTime".into(), "2026-11-15T01:00:00Z".into());
        report
            .data
            .insert("WakeTime".into(), "2026-11-15T03:00:00Z".into());
        let items = analyze(&bundle(vec![
            sleep(1, "2026-11-15T01:00:00Z"),
            event(provider, id, 2, "2026-11-15T02:00:00Z", &[]),
            report,
        ]));
        assert!(
            !items.iter().any(|i| i.kind == IncidentKind::SleepCycle),
            "{provider}/{id}"
        );
        assert!(items.iter().all(|i| i.duration_seconds.is_none()));
    }
}

#[test]
fn backward_clock_without_a_clock_event_cannot_make_a_negative_interval() {
    let items = analyze(&bundle(vec![
        sleep(1, "2026-11-15T04:00:00Z"),
        wake(2, "2026-11-15T03:00:00Z", "Keyboard"),
    ]));
    assert!(items.iter().all(|i| i.duration_seconds.is_none()));
    assert!(items.iter().any(|i| i.kind == IncidentKind::SleepOpen));
}

#[test]
fn modern_standby_is_separate_from_classic_sleep() {
    let items = analyze(&bundle(vec![
        event(
            "Microsoft-Windows-Kernel-Power",
            506,
            1,
            "2026-11-15T01:00:00Z",
            &[],
        ),
        event(
            "Microsoft-Windows-Kernel-Power",
            507,
            2,
            "2026-11-15T03:00:00Z",
            &[],
        ),
    ]));
    assert_eq!(items.len(), 2);
    assert!(
        items
            .iter()
            .all(|i| i.kind == IncidentKind::Standby && i.confidence == Confidence::Unknown)
    );
}

#[test]
fn reused_record_id_is_a_boundary_of_trust() {
    let mut b = bundle(vec![
        sleep(1, "2026-11-15T01:00:00Z"),
        wake(1, "2026-11-15T03:00:00Z", "Keyboard"),
    ]);
    validate(&mut b).unwrap();
    assert!(
        b.issues
            .iter()
            .any(|i| i.code == IssueCode::RecordCollision)
    );
    assert!(
        analyze(&b)
            .iter()
            .all(|i| i.confidence != Confidence::Reported && i.duration_seconds.is_none())
    );
}

fn snapshot(kind: ReportKind, time: &str, name: &str) -> Snapshot {
    Snapshot {
        at: at(time),
        kind,
        availability: Availability::Available,
        items: vec![Observation::named(
            IdentityKind::Device,
            name.into(),
            RequestType::None,
        )],
    }
}

#[test]
fn untimestamped_lastwake_and_armed_devices_are_context_not_cause() {
    let mut b = bundle(vec![
        sleep(1, "2026-11-15T01:00:00Z"),
        resume(2, "2026-11-15T03:00:00Z"),
    ]);
    b.snapshots = vec![
        snapshot(ReportKind::LastWake, "2026-11-15T03:00:01Z", "Keyboard"),
        snapshot(ReportKind::WakeArmed, "2026-11-15T03:00:01Z", "Keyboard"),
    ];
    let items = analyze(&b);
    assert_eq!(items[0].confidence, Confidence::Unknown);
    assert!(items[0].sources.is_empty());
}

#[test]
fn timer_due_near_wake_is_plausible_only_when_observed_before_wake() {
    for (time, expected) in [
        ("2026-11-15T02:00:00Z", Confidence::Plausible),
        ("2026-11-15T04:00:00Z", Confidence::Unknown),
    ] {
        let mut b = bundle(vec![
            sleep(1, "2026-11-15T01:00:00Z"),
            resume(2, "2026-11-15T03:00:00Z"),
        ]);
        let mut timer = snapshot(ReportKind::WakeTimers, time, "Maintenance timer");
        timer.items[0].due_at = Some(at("2026-11-15T03:00:05Z"));
        b.snapshots.push(timer);
        assert_eq!(analyze(&b)[0].confidence, expected);
    }
}

#[test]
fn current_requests_are_never_applied_to_a_past_wake_or_failed_sleep() {
    let mut b = bundle(vec![
        sleep(1, "2026-11-15T01:00:00Z"),
        resume(2, "2026-11-15T03:00:00Z"),
    ]);
    let mut requests = snapshot(ReportKind::Requests, "2026-11-15T09:00:00Z", "player.exe");
    requests.items[0].request = RequestType::System;
    b.snapshots.push(requests);
    let items = analyze(&b);
    assert_eq!(items[0].kind, IncidentKind::CurrentRequests);
    assert_eq!(items[0].explanation, Explanation::CurrentBlockers);
    assert_eq!(items[1].explanation, Explanation::UnknownSource);
    assert!(items[1].sources.is_empty());
}

#[test]
fn display_only_request_does_not_claim_system_sleep_blockage() {
    let mut b = Bundle::empty(Utc::now());
    let mut requests = snapshot(ReportKind::Requests, "2026-11-15T09:00:00Z", "reader.exe");
    requests.items[0].request = RequestType::Display;
    b.snapshots.push(requests);
    assert_eq!(analyze(&b)[0].explanation, Explanation::NoCurrentBlockers);
}

#[test]
fn process_identity_requires_start_time_and_never_merges_by_pid() {
    let mut b = Bundle::empty(Utc::now());
    let mut s = snapshot(ReportKind::Requests, "2026-11-15T09:00:00Z", "worker.exe");
    s.items[0].pid = Some(44);
    b.snapshots.push(s);
    assert!(validate(&mut b).is_err());
    b.snapshots[0].items[0].process_started_at = Some(at("2026-11-15T08:00:00Z"));
    let mut reused = b.snapshots[0].clone();
    reused.at = at("2026-11-15T10:00:00Z");
    reused.items[0].process_started_at = Some(at("2026-11-15T09:30:00Z"));
    b.snapshots.push(reused);
    validate(&mut b).unwrap();
    assert_eq!(analyze(&b).len(), 2);
}

#[test]
fn english_requests_keep_identity_and_type_but_drop_paths_and_reasons() {
    let text = "DISPLAY:\nNone.\nSYSTEM:\n[PROCESS] \\Device\\HarddiskVolume3\\Users\\Private\\player.exe\nPlaying Private diary.txt\nAWAYMODE:\nNone.\nEXECUTION:\nNone.\nPERFBOOST:\nNone.\nACTIVELOCKSCREEN:\nNone.";
    let s = parse_report(ReportKind::Requests, text, Utc::now());
    assert_eq!(s.availability, Availability::Available);
    assert_eq!(s.items[0].name, "player.exe");
    assert_eq!(s.items[0].request, RequestType::System);
    assert!(!serde_json::to_string(&s).unwrap().contains("Private"));
}

#[test]
fn localized_or_partial_reports_cannot_masquerade_as_no_blockers() {
    for text in [
        "ЭКРАН:\nНет.\nСИСТЕМА:\nНет.",
        "DISPLAY:\nNone.\nSYSTEM:\n[PROCESS] player.exe\nAWAYMODE:\nAucun.",
        "",
    ] {
        let s = parse_report(ReportKind::Requests, text, Utc::now());
        assert_eq!(s.availability, Availability::UnparsedLocale);
        assert!(s.items.is_empty());
    }
}

#[test]
fn local_timer_dates_are_not_guessed_as_utc() {
    let s = parse_report(
        ReportKind::WakeTimers,
        "Timer set by [PROCESS] \\Device\\HarddiskVolume3\\Windows\\worker.exe expires at 02:30:00 on 25/10/2026.\nReason: Private task",
        Utc::now(),
    );
    assert_eq!(s.items.len(), 1);
    assert!(s.items[0].due_at.is_none());
    assert!(!serde_json::to_string(&s).unwrap().contains("Private"));
}

#[test]
fn localized_none_is_not_invented_as_a_device_name() {
    let s = parse_report(ReportKind::WakeArmed, "НЕТ", Utc::now());
    assert_eq!(s.availability, Availability::UnparsedLocale);
    assert!(s.items.is_empty());
}

#[test]
fn permission_failures_stay_visible_in_fake_adapter_results() {
    let mut b = Bundle::empty(Utc::now());
    b.issues.push(CollectionIssue {
        code: IssueCode::EventLogDenied,
        windows_error: Some(5),
    });
    b.snapshots.push(Snapshot {
        at: b.captured_at,
        kind: ReportKind::Requests,
        availability: Availability::PermissionDenied,
        items: vec![],
    });
    let captured = RecordedAdapter(b).collect(Utc::now());
    assert_eq!(captured.issues[0].windows_error, Some(5));
    assert!(analyze(&captured).is_empty());
}

#[test]
fn export_redacts_identities_preserves_links_and_does_not_change_unknown_into_known() {
    let mut b = bundle(vec![
        wake(1, "2026-11-15T03:00:00Z", "USB Private serial 123"),
        wake(2, "2026-11-15T04:00:00Z", "Unknown"),
    ]);
    let mut s = snapshot(ReportKind::Requests, "2026-11-15T09:00:00Z", "Private.exe");
    s.items[0].pid = Some(47);
    s.items[0].process_started_at = Some(at("2026-11-15T08:00:00Z"));
    s.items[0].instance_hash = Some("a".repeat(64));
    b.snapshots.push(s);
    let first = redacted_export(&b, b"first salt").unwrap();
    let second = redacted_export(&b, b"second salt").unwrap();
    assert!(!String::from_utf8_lossy(&first).contains("Private"));
    assert_ne!(first, second);
    let imported = import(&first, Utc::now()).unwrap();
    assert_eq!(imported.events[1].data["WakeSourceText"], "Unknown");
    assert!(imported.snapshots[0].items[0].pid.is_none());
    let unknown = analyze(&imported)
        .into_iter()
        .find(|i| i.at == at("2026-11-15T04:00:00Z"))
        .unwrap();
    assert_eq!(unknown.confidence, Confidence::Unknown);
}

#[test]
fn version_and_size_limits_reject_untrusted_bundles() {
    let mut b = Bundle::empty(Utc::now());
    b.schema_version += 1;
    assert!(import(&serde_json::to_vec(&b).unwrap(), Utc::now()).is_err());
    assert!(import(&vec![b' '; MAX_REPORT + 1], Utc::now()).is_err());
    let mut value = serde_json::to_value(Bundle::empty(Utc::now())).unwrap();
    value["computer_name"] = "Private-PC".into();
    assert!(import(&serde_json::to_vec(&value).unwrap(), Utc::now()).is_err());
}

#[test]
fn bounded_history_prunes_old_evidence_and_caps_capture_count() {
    let now = at("2026-11-15T09:00:00Z");
    let mut history = History::default();
    for day in 1..=15 {
        let mut b = bundle(vec![sleep(day, &format!("2026-11-{day:02}T01:00:00Z"))]);
        b.captured_at = at(&format!("2026-11-{day:02}T09:00:00Z"));
        history
            .add(
                Capture {
                    origin: Origin::Windows,
                    saved_at: b.captured_at,
                    bundle: b,
                },
                now,
                7,
            )
            .unwrap();
    }
    assert!(history.captures.len() <= 8);
    assert!(
        history
            .captures
            .iter()
            .flat_map(|c| &c.bundle.events)
            .all(|e| e.at >= at("2026-11-08T09:00:00Z"))
    );
}

#[test]
fn store_clear_preserves_settings_and_unrelated_original_files() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("app")).unwrap();
    let original = dir.path().join("original.json");
    std::fs::write(&original, "original").unwrap();
    let settings = sleep_diagnostics::storage::Settings {
        language: "ru".into(),
        startup_update_check: false,
        ..Default::default()
    };
    store.save_settings(&settings).unwrap();
    let mut h = History::default();
    h.add(
        Capture {
            origin: Origin::Imported,
            saved_at: at("2026-11-15T09:00:00Z"),
            bundle: bundle(vec![sleep(1, "2026-11-15T01:00:00Z")]),
        },
        at("2026-11-15T09:00:00Z"),
        14,
    )
    .unwrap();
    store.save_history(&h).unwrap();
    store.clear().unwrap();
    assert!(
        store
            .history(at("2026-11-15T09:00:00Z"), 14)
            .unwrap()
            .captures
            .is_empty()
    );
    assert_eq!(store.settings().unwrap().language, "ru");
    assert!(!store.settings().unwrap().startup_update_check);
    assert_eq!(std::fs::read_to_string(original).unwrap(), "original");
}

#[test]
fn six_catalogs_have_complete_identical_key_sets() {
    let all = catalogs();
    assert_eq!(all.len(), 6);
    let expected: Vec<_> = all[0].keys().collect();
    for catalog in all {
        assert_eq!(catalog.keys().collect::<Vec<_>>(), expected);
        assert!(catalog.values().all(|s| !s.trim().is_empty()));
    }
}

#[test]
fn old_offline_incidents_are_reviewable_and_expire_from_the_import_date() {
    let now = at("2026-11-15T09:00:00Z");
    let mut old = bundle(vec![
        sleep(1, "2020-01-02T01:00:00Z"),
        wake(2, "2020-01-02T02:00:00Z", "Keyboard"),
    ]);
    old.captured_at = at("2020-01-02T03:00:00Z");
    let mut h = History::default();
    h.add(
        Capture {
            origin: Origin::Imported,
            saved_at: now,
            bundle: old,
        },
        now,
        14,
    )
    .unwrap();
    assert_eq!(
        analyze(&h.captures[0].bundle)[0].duration_seconds,
        Some(3600)
    );
    h.retain(now + chrono::Duration::days(13), 14);
    assert_eq!(h.captures.len(), 1);
    h.retain(now + chrono::Duration::days(15), 14);
    assert!(h.captures.is_empty());
}

#[test]
fn timer_observed_just_before_sleep_can_be_plausible_but_a_stale_timer_cannot() {
    for (when, expected) in [
        ("2026-11-15T00:55:00Z", Confidence::Plausible),
        ("2026-11-14T22:00:00Z", Confidence::Unknown),
    ] {
        let mut b = bundle(vec![
            sleep(1, "2026-11-15T01:00:00Z"),
            resume(2, "2026-11-15T03:00:00Z"),
        ]);
        let mut timer = snapshot(ReportKind::WakeTimers, when, "Maintenance");
        timer.items[0].due_at = Some(at("2026-11-15T03:00:00Z"));
        b.snapshots.push(timer);
        assert_eq!(analyze(&b)[0].confidence, expected);
    }
}

#[test]
fn uninitialized_windows_payload_times_do_not_create_a_centuries_long_sleep() {
    let mut report = wake(1, "2026-11-15T03:00:00Z", "Unknown");
    report
        .data
        .insert("SleepTime".into(), "1601-01-01T00:00:00Z".into());
    report
        .data
        .insert("WakeTime".into(), "2026-11-15T03:00:00Z".into());
    let items = analyze(&bundle(vec![report]));
    assert!(items[0].duration_seconds.is_none());
    assert!(items[0].incomplete);
}
