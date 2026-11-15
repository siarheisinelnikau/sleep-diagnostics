use crate::{
    adapter::{CollectionAdapter, WindowsAdapter},
    analysis::{self, Confidence, Explanation, Incident, IncidentKind},
    i18n::{LANGUAGES, tr},
    model::*,
    parser,
    storage::{self, Capture, History, Origin, Settings, Store},
    update::{self, AvailableUpdate},
};
use anyhow::{Context, Result, ensure};
use chrono::Utc;
use std::{
    cell::{Cell, RefCell},
    collections::{HashMap, HashSet},
    path::PathBuf,
    ptr,
    sync::{Arc, mpsc},
    thread,
};
use windows_sys::Win32::{
    Foundation::*,
    Graphics::Gdi::*,
    System::LibraryLoader::GetModuleHandleW,
    UI::{
        Controls::Dialogs::*, Controls::*, HiDpi::*, Input::KeyboardAndMouse::EnableWindow,
        WindowsAndMessaging::*,
    },
};

const NOTIFY: u32 = WM_APP + 1;
const ANIMATION: usize = 7;
const REVIEW: u16 = 100;
const SETTINGS: u16 = 101;
const COLLECT: u16 = 102;
const IMPORT: u16 = 103;
const EXPORT: u16 = 104;
const FILTER: u16 = 105;
const LIST: u16 = 106;
const DETAIL: u16 = 107;
const THEME: u16 = 110;
const LANGUAGE: u16 = 111;
const REDUCED: u16 = 112;
const STARTUP: u16 = 113;
const RETENTION: u16 = 114;
const CHECK: u16 = 115;
const INSTALL: u16 = 116;
const CLEAR: u16 = 117;
const THEME_LABEL: u16 = 121;
const LANGUAGE_LABEL: u16 = 122;
const RETENTION_LABEL: u16 = 123;

thread_local! { static DEFERRED_NOTICE: Cell<bool> = const { Cell::new(false) }; }

#[derive(Clone)]
struct ReviewItem {
    incident: Incident,
    bundle: Arc<Bundle>,
    origin: Origin,
}
enum Job {
    Initialize,
    Collect,
    Import(PathBuf),
    Export(Arc<Bundle>, PathBuf),
    SaveSettings(Settings),
    Clear,
    Stop,
}
enum Notice {
    Initialized(Settings, Vec<ReviewItem>),
    Data(Vec<ReviewItem>),
    Done(&'static str),
    Error(String),
    Update(Result<Option<AvailableUpdate>, String>),
    Progress(u32),
    InstallReady,
    InstallError(String),
}
#[derive(Clone)]
struct Notifier {
    sender: mpsc::Sender<Notice>,
    window: usize,
}
impl Notifier {
    fn send(&self, notice: Notice) {
        if self.sender.send(notice).is_ok() {
            // SAFETY: This only posts a payload-free wakeup. A destroyed HWND yields failure.
            unsafe {
                PostMessageW(self.window as HWND, NOTIFY, 0, 0);
            }
        }
    }
}

fn review_items(history: &History) -> Vec<ReviewItem> {
    let mut seen = HashSet::new();
    let mut items = vec![];
    for capture in history.captures.iter().rev() {
        let bundle = Arc::new(capture.bundle.clone());
        for incident in analysis::analyze(&bundle) {
            if seen.insert(incident.id.clone()) {
                items.push(ReviewItem {
                    incident,
                    bundle: bundle.clone(),
                    origin: capture.origin.clone(),
                });
            }
        }
        if bundle.events.is_empty() && !bundle.issues.is_empty() {
            // Coverage-only captures remain inspectable even with denied event-log access.
            items.push(ReviewItem {
                incident: Incident {
                    id: format!("coverage:{}", bundle.captured_at),
                    at: bundle.captured_at,
                    sleep_at: None,
                    kind: IncidentKind::Coverage,
                    confidence: Confidence::Unknown,
                    explanation: Explanation::CoverageOnly,
                    sources: vec![],
                    events: vec![],
                    observations: vec![],
                    duration_seconds: None,
                    incomplete: true,
                },
                bundle,
                origin: capture.origin.clone(),
            });
        }
    }
    items.sort_by_key(|i| std::cmp::Reverse(i.incident.at));
    items
}

fn spawn_check(notify: Notifier) {
    thread::spawn(move || {
        notify.send(Notice::Update(
            update::check().map_err(|e| format!("{e:#}")),
        ))
    });
}

fn worker(root: PathBuf, jobs: mpsc::Receiver<Job>, notify: Notifier) {
    let store = match Store::open(root) {
        Ok(store) => store,
        Err(e) => {
            notify.send(Notice::Error(format!("{e:#}")));
            return;
        }
    };
    let mut settings = Settings::default();
    let mut history = History::default();
    for job in jobs {
        let result = (|| -> Result<()> {
            match job {
                Job::Initialize => {
                    settings = store.settings()?;
                    history = store.history(Utc::now(), settings.retention_days)?;
                    notify.send(Notice::Initialized(
                        settings.clone(),
                        review_items(&history),
                    ));
                    if settings.startup_update_check {
                        spawn_check(notify.clone());
                    }
                }
                Job::Collect => {
                    let bundle = WindowsAdapter.collect(Utc::now());
                    let mut next = history.clone();
                    next.add(
                        Capture {
                            origin: Origin::Windows,
                            saved_at: Utc::now(),
                            bundle,
                        },
                        Utc::now(),
                        settings.retention_days,
                    )?;
                    store.save_history(&next)?;
                    history = next;
                    notify.send(Notice::Data(review_items(&history)));
                }
                Job::Import(path) => {
                    let bytes = storage::read_bounded(&path, MAX_REPORT as u64)?;
                    let bundle = parser::import(&bytes, Utc::now())?;
                    let mut next = history.clone();
                    next.add(
                        Capture {
                            origin: Origin::Imported,
                            saved_at: Utc::now(),
                            bundle,
                        },
                        Utc::now(),
                        settings.retention_days,
                    )?;
                    store.save_history(&next)?;
                    history = next;
                    notify.send(Notice::Data(review_items(&history)));
                }
                Job::Export(bundle, path) => {
                    let mut salt = [0u8; 32];
                    getrandom::getrandom(&mut salt).map_err(|_| {
                        anyhow::anyhow!("Secure export identity generation is unavailable")
                    })?;
                    storage::atomic_write(&path, &storage::redacted_export(&bundle, &salt)?)?;
                    notify.send(Notice::Done("exported"));
                }
                Job::SaveSettings(next) => {
                    store.save_settings(&next)?;
                    settings = next;
                    history.retain(Utc::now(), settings.retention_days);
                    store.save_history(&history)?;
                    notify.send(Notice::Data(review_items(&history)));
                }
                Job::Clear => {
                    store.clear()?;
                    history = History::default();
                    notify.send(Notice::Data(vec![]));
                    notify.send(Notice::Done("cleared"));
                }
                Job::Stop => return Ok(()),
            }
            Ok(())
        })();
        if let Err(e) = result {
            notify.send(Notice::Error(format!("{e:#}")));
        }
    }
}

#[derive(Clone, Copy)]
struct Palette {
    background: u32,
    surface: u32,
    text: u32,
    muted: u32,
    accent: u32,
    selected: u32,
    border: u32,
    warning: u32,
}
fn rgb(r: u8, g: u8, b: u8) -> u32 {
    u32::from(r) | (u32::from(g) << 8) | (u32::from(b) << 16)
}
impl Palette {
    fn new(dark: bool) -> Self {
        if dark {
            Self {
                background: rgb(19, 26, 34),
                surface: rgb(28, 38, 48),
                text: rgb(233, 240, 245),
                muted: rgb(174, 190, 205),
                accent: rgb(143, 201, 235),
                selected: rgb(38, 67, 86),
                border: rgb(61, 78, 93),
                warning: rgb(244, 196, 125),
            }
        } else {
            Self {
                background: rgb(242, 246, 250),
                surface: rgb(255, 255, 255),
                text: rgb(25, 44, 61),
                muted: rgb(75, 98, 117),
                accent: rgb(28, 99, 143),
                selected: rgb(219, 237, 248),
                border: rgb(185, 204, 219),
                warning: rgb(134, 79, 13),
            }
        }
    }
}

struct App {
    window: HWND,
    controls: HashMap<u16, HWND>,
    settings: Settings,
    settings_page: bool,
    items: Vec<ReviewItem>,
    filtered: Vec<usize>,
    selected: usize,
    filter: usize,
    dpi: f32,
    width: i32,
    height: i32,
    fonts: [HFONT; 3],
    background: HBRUSH,
    surface: HBRUSH,
    status: &'static str,
    error_detail: Option<String>,
    busy: bool,
    update_busy: bool,
    update_status: &'static str,
    available: Option<AvailableUpdate>,
    download_percent: Option<u32>,
    notices: mpsc::Receiver<Notice>,
    jobs: mpsc::Sender<Job>,
    notify: Notifier,
    animation_left: u8,
    paint_count: u64,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

impl App {
    fn t(&self, key: &str) -> String {
        tr(&self.settings.language, key).to_owned()
    }
    fn s(&self, value: i32) -> i32 {
        (value as f32 * self.dpi).round() as i32
    }
    fn control(&self, id: u16) -> HWND {
        self.controls.get(&id).copied().unwrap_or(ptr::null_mut())
    }
    fn invalidate(&self) {
        // SAFETY: Queues one OS paint; no recurring work is requested here.
        unsafe {
            if IsIconic(self.window) == 0 && IsWindowVisible(self.window) != 0 {
                InvalidateRect(self.window, ptr::null(), 0);
            }
        }
    }
    fn caption(&self, id: u16, text: &str) {
        // SAFETY: Native control and a temporary NUL-terminated string used synchronously.
        unsafe {
            SetWindowTextW(self.control(id), wide(text).as_ptr());
        }
    }
    fn set_combo(&self, id: u16, values: &[String], selection: usize) {
        // SAFETY: Combo-box messages use valid synchronous buffers and integral indices.
        unsafe {
            let handle = self.control(id);
            SendMessageW(handle, CB_RESETCONTENT, 0, 0);
            for value in values {
                SendMessageW(handle, CB_ADDSTRING, 0, wide(value).as_ptr() as isize);
            }
            SendMessageW(handle, CB_SETCURSEL, selection, 0);
        }
    }
    fn make_control(&mut self, id: u16, class: &str, style: u32) {
        // SAFETY: Child HWND is parent-owned. IDs are unique and strings NUL-terminated.
        unsafe {
            let handle = CreateWindowExW(
                0,
                wide(class).as_ptr(),
                wide("").as_ptr(),
                WS_CHILD | WS_VISIBLE | style,
                0,
                0,
                1,
                1,
                self.window,
                id as usize as HMENU,
                GetModuleHandleW(ptr::null()),
                ptr::null(),
            );
            self.controls.insert(id, handle);
        }
    }
    fn create_controls(&mut self) {
        for id in [
            REVIEW, SETTINGS, COLLECT, IMPORT, EXPORT, REDUCED, STARTUP, CHECK, INSTALL, CLEAR,
        ] {
            self.make_control(id, "BUTTON", WS_TABSTOP | BS_OWNERDRAW as u32);
        }
        for id in [FILTER, THEME, LANGUAGE, RETENTION] {
            if id != FILTER {
                self.make_control(
                    match id {
                        THEME => THEME_LABEL,
                        LANGUAGE => LANGUAGE_LABEL,
                        _ => RETENTION_LABEL,
                    },
                    "STATIC",
                    0, // Native STATIC defaults to left alignment.
                );
            }
            self.make_control(
                id,
                "COMBOBOX",
                WS_TABSTOP | CBS_DROPDOWNLIST as u32 | WS_VSCROLL,
            );
        }
        self.make_control(
            LIST,
            "LISTBOX",
            WS_TABSTOP
                | WS_VSCROLL
                | LBS_NOTIFY as u32
                | LBS_OWNERDRAWFIXED as u32
                | LBS_HASSTRINGS as u32
                | LBS_NOINTEGRALHEIGHT as u32,
        );
        self.make_control(
            DETAIL,
            "EDIT",
            WS_TABSTOP
                | WS_VSCROLL
                | ES_MULTILINE as u32
                | ES_READONLY as u32
                | ES_AUTOVSCROLL as u32
                | ES_NOHIDESEL as u32,
        );
        // SAFETY: Static limit in characters on a valid Edit HWND.
        unsafe {
            SendMessageW(self.control(DETAIL), EM_SETLIMITTEXT, 256 * 1024, 0);
        }
        self.refresh_style();
        self.translate();
    }
    fn refresh_style(&mut self) {
        // SAFETY: GDI objects are owned by App. Controls adopt new fonts before old ones are deleted.
        unsafe {
            let old = self.fonts;
            for (index, size) in [15, 21, 28].into_iter().enumerate() {
                self.fonts[index] = CreateFontW(
                    -self.s(size),
                    0,
                    0,
                    0,
                    if index == 0 { 400 } else { 600 },
                    0,
                    0,
                    0,
                    DEFAULT_CHARSET as u32,
                    0,
                    0,
                    CLEARTYPE_QUALITY as u32,
                    0,
                    wide("Segoe UI").as_ptr(),
                );
            }
            for handle in self.controls.values() {
                SendMessageW(*handle, WM_SETFONT, self.fonts[0] as usize, 1);
            }
            for font in old {
                if !font.is_null() {
                    DeleteObject(font);
                }
            }
            if !self.background.is_null() {
                DeleteObject(self.background);
            }
            if !self.surface.is_null() {
                DeleteObject(self.surface);
            }
            let palette = Palette::new(self.settings.dark);
            self.background = CreateSolidBrush(palette.background);
            self.surface = CreateSolidBrush(palette.surface);
            SendMessageW(self.control(LIST), LB_SETITEMHEIGHT, 0, self.s(74) as isize);
            SendMessageW(
                self.control(DETAIL),
                EM_SETMARGINS,
                3,
                ((self.s(16) as u32) << 16 | self.s(16) as u32) as isize,
            );
        }
        self.invalidate();
    }
    fn translate(&mut self) {
        for (id, key) in [
            (REVIEW, "review"),
            (SETTINGS, "settings"),
            (COLLECT, "collect"),
            (IMPORT, "import"),
            (EXPORT, "export"),
            (CHECK, "check"),
            (INSTALL, "install"),
            (CLEAR, "clear"),
        ] {
            self.caption(id, &self.t(key));
        }
        self.caption(
            REDUCED,
            &format!(
                "{} · {}",
                self.t("reduced"),
                self.t(if self.settings.reduced_motion {
                    "enabled"
                } else {
                    "disabled"
                })
            ),
        );
        self.caption(
            STARTUP,
            &format!(
                "{} · {}",
                self.t("startup"),
                self.t(if self.settings.startup_update_check {
                    "enabled"
                } else {
                    "disabled"
                })
            ),
        );
        for (id, key) in [
            (THEME_LABEL, "theme"),
            (LANGUAGE_LABEL, "language"),
            (RETENTION_LABEL, "retention"),
        ] {
            self.caption(id, &self.t(key));
        }
        self.set_combo(
            FILTER,
            &[self.t("all"), self.t("wakes"), self.t("requests_filter")],
            self.filter,
        );
        self.set_combo(
            THEME,
            &[self.t("dark"), self.t("light")],
            usize::from(!self.settings.dark),
        );
        self.set_combo(
            LANGUAGE,
            &LANGUAGES.iter().map(|l| l.1.to_owned()).collect::<Vec<_>>(),
            LANGUAGES
                .iter()
                .position(|l| l.0 == self.settings.language)
                .unwrap_or(0),
        );
        self.set_combo(
            RETENTION,
            &[self.t("days7"), self.t("days14"), self.t("days30")],
            match self.settings.retention_days {
                7 => 0,
                30 => 2,
                _ => 1,
            },
        );
        self.rebuild_list();
    }
    fn layout(&self) {
        let w = self.width;
        let h = self.height;
        let left = (w * 34 / 100).clamp(280, 380);
        let positions = [
            (REVIEW, w - 286, 24, 118, 38),
            (SETTINGS, w - 156, 24, 132, 38),
            (COLLECT, 24, 108, 178, 40),
            (IMPORT, 214, 108, 156, 40),
            (EXPORT, 382, 108, 182, 40),
            (FILTER, w - 292, 108, 268, 260),
            (LIST, 24, 190, left - 24, h - 254),
            (DETAIL, left + 24, 402, w - left - 48, h - 466),
            (THEME, 230, 152, 206, 240),
            (LANGUAGE, 610, 152, (w - 634).max(206), 260),
            (RETENTION, 230, 208, 206, 220),
            (REDUCED, 468, 208, w - 492, 38),
            (STARTUP, 24, 366, w - 48, 38),
            (CHECK, 24, 420, 270, 40),
            (INSTALL, 306, 420, 272, 40),
            (CLEAR, 24, h - 108, 284, 40),
            (THEME_LABEL, 24, 158, 190, 28),
            (LANGUAGE_LABEL, 468, 158, 132, 28),
            (RETENTION_LABEL, 24, 214, 194, 28),
        ];
        // SAFETY: All controls are live child windows. Coordinates are scaled from logical pixels.
        unsafe {
            for (id, x, y, width, height) in positions {
                MoveWindow(
                    self.control(id),
                    self.s(x),
                    self.s(y),
                    self.s(width),
                    self.s(height),
                    1,
                );
                let show = if [REVIEW, SETTINGS].contains(&id) {
                    true
                } else if id >= THEME {
                    self.settings_page
                } else {
                    !self.settings_page
                };
                ShowWindow(self.control(id), if show { SW_SHOW } else { SW_HIDE });
            }
        }
        self.update_enabled();
        self.invalidate();
    }
    fn current(&self) -> Option<&ReviewItem> {
        self.filtered
            .get(self.selected)
            .and_then(|i| self.items.get(*i))
    }
    fn update_enabled(&self) {
        // SAFETY: Enables/disables existing controls only.
        unsafe {
            for id in [
                COLLECT, IMPORT, CLEAR, RETENTION, THEME, LANGUAGE, REDUCED, STARTUP,
            ] {
                EnableWindow(
                    self.control(id),
                    i32::from(!self.busy && self.download_percent.is_none()),
                );
            }
            EnableWindow(
                self.control(EXPORT),
                i32::from(!self.busy && self.current().is_some()),
            );
            EnableWindow(self.control(CHECK), i32::from(!self.update_busy));
            EnableWindow(
                self.control(INSTALL),
                i32::from(!self.busy && !self.update_busy && self.available.is_some()),
            );
        }
    }
    fn begin_job(&mut self, job: Job) {
        self.busy = true;
        self.error_detail = None;
        self.status = "working";
        if self.jobs.send(job).is_err() {
            self.busy = false;
            self.status = "error";
        }
        self.update_enabled();
        self.invalidate();
    }
    fn rebuild_list(&mut self) {
        let old_id = self.current().map(|item| item.incident.id.clone());
        self.filtered = self
            .items
            .iter()
            .enumerate()
            .filter(|(_, item)| match self.filter {
                1 => matches!(
                    item.incident.kind,
                    IncidentKind::SleepCycle
                        | IncidentKind::SleepOpen
                        | IncidentKind::ResumeOnly
                        | IncidentKind::Standby
                ),
                2 => item.incident.kind == IncidentKind::CurrentRequests,
                _ => true,
            })
            .map(|(index, _)| index)
            .collect();
        self.selected = old_id
            .and_then(|id| {
                self.filtered
                    .iter()
                    .position(|i| self.items[*i].incident.id == id)
            })
            .unwrap_or(0);
        // SAFETY: Listbox messages use only synchronous strings and indices.
        unsafe {
            let list = self.control(LIST);
            let visible = IsWindowVisible(list) != 0;
            if visible {
                SendMessageW(list, WM_SETREDRAW, 0, 0);
            }
            SendMessageW(list, LB_RESETCONTENT, 0, 0);
            for index in &self.filtered {
                let incident = &self.items[*index].incident;
                let text = format!(
                    "{} | {} | {}",
                    self.t(kind_key(incident.kind)),
                    incident.at.format("%Y-%m-%d %H:%M:%S UTC"),
                    self.t(confidence_key(incident.confidence))
                );
                SendMessageW(list, LB_ADDSTRING, 0, wide(&text).as_ptr() as isize);
            }
            SendMessageW(list, LB_SETCURSEL, self.selected, 0);
            if visible {
                SendMessageW(list, WM_SETREDRAW, 1, 0);
                InvalidateRect(list, ptr::null(), 0);
            }
        }
        self.refresh_detail();
        self.update_enabled();
        self.invalidate();
    }
    fn refresh_detail(&self) {
        let text = if let Some(item) = self.current() {
            self.detail_text(item)
        } else if let Some(error) = &self.error_detail {
            format!("{}\n\n{}\n{error}", self.t("error"), self.t("technical"))
        } else {
            self.t(if self.items.is_empty() {
                "empty_body"
            } else {
                "history_empty"
            })
        };
        self.caption(DETAIL, &text.replace('\n', "\r\n"));
    }
    fn detail_text(&self, item: &ReviewItem) -> String {
        let i = &item.incident;
        let mut text = format!(
            "{}\n{}\n\n",
            self.t("next"),
            self.t(remedy_key(i.explanation))
        );
        if i.incomplete {
            text += &format!("{}\n\n", self.t("incomplete"));
        }
        if let Some(sleep) = i.sleep_at {
            text += &format!(
                "{}: {} UTC\n",
                self.t("from"),
                sleep.format("%Y-%m-%d %H:%M:%S")
            );
        }
        if let Some(seconds) = i.duration_seconds {
            text += &format!("{}: {seconds} {}\n", self.t("duration"), self.t("seconds"));
        }
        text += &format!("\n{}\n", self.t("evidence"));
        if i.events.is_empty() {
            text += &format!("{}\n", self.t("no_events"));
        }
        for event in &i.events {
            text += &format!(
                "\n{} UTC · {} #{} · {}\n",
                event.at.format("%Y-%m-%d %H:%M:%S%.3f"),
                event.provider,
                event.event_id,
                event.record_id
            );
            let offset = event.original_offset_minutes;
            text += &format!("UTC{:+03}:{:02}\n", offset / 60, offset.abs() % 60);
            for (key, value) in &event.data {
                text += &format!("{key}: {value}\n");
            }
        }
        for snapshot in &i.observations {
            text += &format!(
                "\n{} · {} UTC\n",
                self.t(report_key(snapshot.kind)),
                snapshot.at.format("%Y-%m-%d %H:%M:%S")
            );
            for observation in &snapshot.items {
                text += &format!(
                    "• {}\n{}\n",
                    observation.name,
                    self.t(request_key(observation.request))
                );
            }
        }
        text += &format!(
            "\n{}\n{} · {} UTC\n",
            self.t("coverage"),
            self.t(match item.origin {
                Origin::Windows => "windows",
                Origin::Imported => "imported",
            }),
            item.bundle.captured_at.format("%Y-%m-%d %H:%M:%S")
        );
        if !item.bundle.issues.is_empty() {
            text += &format!("{}\n", self.t("event_limited"));
        }
        for snapshot in &item.bundle.snapshots {
            text += &format!(
                "{}: {}\n",
                self.t(report_key(snapshot.kind)),
                self.t(availability_key(snapshot.availability))
            );
            if snapshot.kind != ReportKind::Requests {
                for item in &snapshot.items {
                    text += &format!("  • {}\n", item.name);
                }
            }
        }
        text += &format!("\n{}\n", self.t("snapshot_context"));
        if let Some(error) = &self.error_detail {
            text += &format!("\n{}\n{error}\n", self.t("technical"));
        }
        text
    }
    fn command(&mut self, id: u16, notification: u16) {
        match id {
            REVIEW | SETTINGS => {
                self.settings_page = id == SETTINGS;
                self.layout();
            }
            COLLECT if !self.busy => self.begin_job(Job::Collect),
            IMPORT if !self.busy => {
                if let Some(path) = self.file_dialog(false) {
                    self.begin_job(Job::Import(path));
                }
            }
            EXPORT if !self.busy => {
                if let Some(path) = self.file_dialog(true)
                    && let Some(item) = self.current()
                {
                    self.begin_job(Job::Export(item.bundle.clone(), path));
                }
            }
            FILTER if notification == CBN_SELCHANGE as u16 => {
                // SAFETY: Queries the current combo index without passing pointers.
                self.filter = unsafe { SendMessageW(self.control(FILTER), CB_GETCURSEL, 0, 0) }
                    .max(0) as usize;
                self.rebuild_list();
            }
            LIST if notification == LBN_SELCHANGE as u16 => {
                // SAFETY: Queries current list index, then schedules a strictly finite transition.
                unsafe {
                    self.selected =
                        SendMessageW(self.control(LIST), LB_GETCURSEL, 0, 0).max(0) as usize;
                    KillTimer(self.window, ANIMATION);
                    self.animation_left = if self.settings.reduced_motion { 0 } else { 6 };
                    if self.animation_left > 0 {
                        SetTimer(self.window, ANIMATION, 16, None);
                    }
                }
                self.refresh_detail();
                self.invalidate();
            }
            THEME | LANGUAGE | RETENTION if notification == CBN_SELCHANGE as u16 && !self.busy => {
                // SAFETY: Queries one of the existing combo boxes.
                let index =
                    unsafe { SendMessageW(self.control(id), CB_GETCURSEL, 0, 0) }.max(0) as usize;
                match id {
                    THEME => self.settings.dark = index == 0,
                    LANGUAGE => {
                        self.settings.language =
                            LANGUAGES.get(index).unwrap_or(&LANGUAGES[0]).0.to_owned()
                    }
                    RETENTION => {
                        self.settings.retention_days = *[7, 14, 30].get(index).unwrap_or(&14)
                    }
                    _ => {}
                }
                self.refresh_style();
                self.translate();
                self.begin_job(Job::SaveSettings(self.settings.clone()));
            }
            REDUCED | STARTUP if !self.busy => {
                if id == REDUCED {
                    self.settings.reduced_motion = !self.settings.reduced_motion;
                } else {
                    self.settings.startup_update_check = !self.settings.startup_update_check;
                }
                self.translate();
                self.begin_job(Job::SaveSettings(self.settings.clone()));
            }
            CLEAR if !self.busy => {
                // SAFETY: Synchronous native confirmation with valid strings.
                let answer = unsafe {
                    MessageBoxW(
                        self.window,
                        wide(&self.t("clear_body")).as_ptr(),
                        wide(&self.t("clear_title")).as_ptr(),
                        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2,
                    )
                };
                if answer == IDYES {
                    self.begin_job(Job::Clear);
                }
            }
            CHECK if !self.update_busy => {
                self.update_busy = true;
                self.update_status = "checking";
                self.update_enabled();
                self.invalidate();
                spawn_check(self.notify.clone());
            }
            INSTALL if !self.update_busy && !self.busy => {
                if let Some(update) = self.available.clone() {
                    self.update_busy = true;
                    self.update_status = "downloading";
                    self.download_percent = Some(0);
                    self.update_enabled();
                    self.invalidate();
                    let notify = self.notify.clone();
                    thread::spawn(move || {
                        match update::prepare_install(&update, |percent| {
                            notify.send(Notice::Progress(percent))
                        }) {
                            Ok(_) => notify.send(Notice::InstallReady),
                            Err(e) => notify.send(Notice::InstallError(format!("{e:#}"))),
                        }
                    });
                }
            }
            _ => {}
        }
    }
    fn receive(&mut self) {
        while let Ok(notice) = self.notices.try_recv() {
            match notice {
                Notice::Initialized(settings, items) => {
                    self.update_busy = settings.startup_update_check;
                    self.update_status = if settings.startup_update_check {
                        "checking"
                    } else {
                        "update_idle"
                    };
                    self.settings = settings;
                    self.items = items;
                    self.busy = false;
                    self.status = "idle";
                    self.refresh_style();
                    self.translate();
                    self.layout();
                }
                Notice::Data(items) => {
                    self.items = items;
                    self.busy = false;
                    self.status = "idle";
                    self.rebuild_list();
                }
                Notice::Done(key) => {
                    self.busy = false;
                    self.status = key;
                }
                Notice::Error(detail) => {
                    self.busy = false;
                    self.status = "error";
                    self.error_detail = Some(detail);
                    self.refresh_detail();
                }
                Notice::Update(result) => {
                    self.update_busy = false;
                    match result {
                        Ok(Some(update)) => {
                            self.available = Some(update);
                            self.update_status = "available";
                        }
                        Ok(None) => {
                            self.available = None;
                            self.update_status = "up_to_date";
                        }
                        Err(_) => self.update_status = "update_error",
                    }
                }
                Notice::Progress(percent) => self.download_percent = Some(percent),
                Notice::InstallError(detail) => {
                    self.update_busy = false;
                    self.download_percent = None;
                    self.update_status = "install_error";
                    self.error_detail = Some(detail);
                    self.refresh_detail();
                }
                Notice::InstallReady => {
                    self.update_status = "installing";
                    // SAFETY: All file work has completed before the updater waits on this process.
                    unsafe {
                        DestroyWindow(self.window);
                    }
                    return;
                }
            }
        }
        self.update_enabled();
        self.invalidate();
    }
    fn file_dialog(&self, save: bool) -> Option<PathBuf> {
        // SAFETY: A modal dialog does not need the finite selection animation to keep ticking.
        unsafe {
            KillTimer(self.window, ANIMATION);
        }
        let mut file = vec![0u16; 32768];
        if save {
            let name = wide(&format!(
                "SleepDiagnostics-{}.json",
                Utc::now().format("%Y%m%d-%H%M%S")
            ));
            file[..name.len()].copy_from_slice(&name);
        }
        let filter = wide(&format!(
            "{}\0{}\0{}\0*.*\0",
            self.t(if save { "json_files" } else { "import_files" }),
            if save { "*.json" } else { "*.json;*.xml" },
            self.t("all_files")
        ));
        let title = wide(&self.t(if save { "export_hint" } else { "import_hint" }));
        let extension = wide("json");
        let mut config: OPENFILENAMEW = OPENFILENAMEW {
            lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
            hwndOwner: self.window,
            lpstrFilter: filter.as_ptr(),
            lpstrFile: file.as_mut_ptr(),
            nMaxFile: file.len() as u32,
            lpstrTitle: title.as_ptr(),
            lpstrDefExt: extension.as_ptr(),
            Flags: OFN_EXPLORER
                | OFN_NOCHANGEDIR
                | OFN_PATHMUSTEXIST
                | if save {
                    OFN_OVERWRITEPROMPT
                } else {
                    OFN_FILEMUSTEXIST
                },
            ..Default::default()
        };
        // SAFETY: All dialog pointers reference buffers alive for the synchronous native call.
        let accepted = unsafe {
            if save {
                GetSaveFileNameW(&mut config)
            } else {
                GetOpenFileNameW(&mut config)
            }
        };
        if accepted == 0 {
            return None;
        }
        use std::os::windows::ffi::OsStringExt;
        let end = file.iter().position(|c| *c == 0).unwrap_or(file.len());
        Some(PathBuf::from(std::ffi::OsString::from_wide(&file[..end])))
    }
    fn text(
        &self,
        dc: HDC,
        text: &str,
        bounds: (i32, i32, i32, i32),
        font: usize,
        color: u32,
        flags: u32,
    ) {
        let (x, y, w, h) = bounds;
        let mut rect = RECT {
            left: self.s(x),
            top: self.s(y),
            right: self.s(x + w),
            bottom: self.s(y + h),
        };
        let text = wide(text);
        // SAFETY: Borrowed paint DC and a valid owned font; DrawText reads a synchronous UTF-16 buffer.
        unsafe {
            let saved = SaveDC(dc);
            SelectObject(dc, self.fonts[font]);
            SetTextColor(dc, color);
            SetBkMode(dc, TRANSPARENT as i32);
            DrawTextW(
                dc,
                text.as_ptr(),
                (text.len() - 1) as i32,
                &mut rect,
                flags | DT_NOPREFIX,
            );
            RestoreDC(dc, saved);
        }
    }
    fn paint(&mut self) {
        // SAFETY: WM_PAINT bracketed by BeginPaint/EndPaint; all DC objects are valid during drawing.
        unsafe {
            let mut ps = PAINTSTRUCT::default();
            let dc = BeginPaint(self.window, &mut ps);
            FillRect(dc, &ps.rcPaint, self.background);
            let p = Palette::new(self.settings.dark);
            self.text(
                dc,
                "Sleep Diagnostics",
                (24, 22, self.width - 340, 40),
                2,
                p.text,
                DT_SINGLELINE | DT_END_ELLIPSIS,
            );
            self.text(
                dc,
                &self.t("tagline"),
                (24, 67, self.width - 48, 24),
                0,
                p.muted,
                DT_SINGLELINE | DT_END_ELLIPSIS,
            );
            if self.settings_page {
                self.text(
                    dc,
                    &self.t("appearance"),
                    (24, 108, self.width - 48, 32),
                    1,
                    p.text,
                    DT_SINGLELINE,
                );
                self.text(
                    dc,
                    &self.t("theme"),
                    (24, 158, 190, 28),
                    0,
                    p.muted,
                    DT_SINGLELINE,
                );
                self.text(
                    dc,
                    &self.t("language"),
                    (468, 158, 132, 28),
                    0,
                    p.muted,
                    DT_SINGLELINE,
                );
                self.text(
                    dc,
                    &self.t("retention"),
                    (24, 214, 194, 28),
                    0,
                    p.muted,
                    DT_SINGLELINE | DT_END_ELLIPSIS,
                );
                self.text(
                    dc,
                    &self.t("motion_help"),
                    (24, 260, self.width - 48, 38),
                    0,
                    p.muted,
                    DT_WORDBREAK,
                );
                self.text(
                    dc,
                    &self.t("updates"),
                    (24, 310, 300, 32),
                    1,
                    p.text,
                    DT_SINGLELINE,
                );
                self.text(
                    dc,
                    &format!("{}  {}", self.t("version"), env!("CARGO_PKG_VERSION")),
                    (350, 314, self.width - 374, 28),
                    0,
                    p.muted,
                    DT_SINGLELINE,
                );
                let mut update_text = self.t(self.update_status);
                if let Some(update) = &self.available
                    && self.update_status == "available"
                {
                    update_text += &format!(" · {}", update.version);
                }
                if let Some(percent) = self.download_percent {
                    update_text += &format!(" · {percent}%");
                }
                self.text(
                    dc,
                    &update_text,
                    (24, 474, self.width - 48, 54),
                    0,
                    if self.update_status.ends_with("error") {
                        p.warning
                    } else {
                        p.muted
                    },
                    DT_WORDBREAK,
                );
                self.text(
                    dc,
                    &self.t("storage"),
                    (24, 536, self.width - 48, (self.height - 652).max(46)),
                    0,
                    p.muted,
                    DT_WORDBREAK,
                );
            } else {
                let left = (self.width * 34 / 100).clamp(280, 380);
                self.text(
                    dc,
                    &self.t("timeline"),
                    (24, 162, left - 24, 26),
                    0,
                    p.muted,
                    DT_SINGLELINE,
                );
                if let Some(item) = self.current() {
                    let i = &item.incident;
                    self.text(
                        dc,
                        &self.t(confidence_key(i.confidence)),
                        (left + 24, 166, self.width - left - 48, 24),
                        0,
                        if i.confidence == Confidence::Unknown {
                            p.warning
                        } else {
                            p.accent
                        },
                        DT_SINGLELINE,
                    );
                    self.text(
                        dc,
                        &self.t(kind_key(i.kind)),
                        (left + 24, 198, self.width - left - 48, 34),
                        1,
                        p.text,
                        DT_SINGLELINE | DT_END_ELLIPSIS,
                    );
                    let source = if i.sources.is_empty() {
                        i.at.format("%Y-%m-%d %H:%M:%S UTC").to_string()
                    } else {
                        i.sources.join(" · ")
                    };
                    // A bounded 96 ms selection fade. No timer exists after it settles.
                    let fade = f32::from(6 - self.animation_left.min(6)) / 6.0;
                    let channel = |shift: u32| {
                        let a = ((p.background >> shift) & 255u32) as f32;
                        let b = ((p.accent >> shift) & 255u32) as f32;
                        (a + (b - a) * fade) as u8
                    };
                    self.text(
                        dc,
                        &source,
                        (left + 24, 240, self.width - left - 48, 26),
                        0,
                        rgb(channel(0), channel(8), channel(16)),
                        DT_SINGLELINE | DT_END_ELLIPSIS,
                    );
                    self.text(
                        dc,
                        &self.t(explanation_key(i.explanation)),
                        (left + 24, 272, self.width - left - 48, 120),
                        0,
                        p.muted,
                        DT_WORDBREAK | DT_END_ELLIPSIS,
                    );
                } else {
                    self.text(
                        dc,
                        &self.t("empty_title"),
                        (left + 24, 194, self.width - left - 48, 86),
                        1,
                        p.text,
                        DT_WORDBREAK,
                    );
                }
            }
            let mut footer = self.t(self.status);
            if self.available.is_some() && !self.settings_page && self.status != "error" {
                footer = format!("{} · {}", self.t("available"), self.t("settings"));
            }
            self.text(
                dc,
                &footer,
                (24, self.height - 48, self.width - 48, 24),
                0,
                if self.status == "error" {
                    p.warning
                } else {
                    p.accent
                },
                DT_SINGLELINE | DT_END_ELLIPSIS,
            );
            EndPaint(self.window, &ps);
            self.paint_count += 1;
        }
    }
    fn draw_item(&self, draw: &DRAWITEMSTRUCT) {
        // SAFETY: System-supplied owner-draw structure is valid for this message. Temporary brush is released.
        unsafe {
            let saved = SaveDC(draw.hDC);
            let p = Palette::new(self.settings.dark);
            let id = draw.CtlID as u16;
            let selected = draw.itemState & ODS_SELECTED != 0;
            let mut rect = draw.rcItem;
            let background = if id == COLLECT
                || id == REVIEW && !self.settings_page
                || id == SETTINGS && self.settings_page
                || selected
            {
                p.selected
            } else {
                p.surface
            };
            let brush = CreateSolidBrush(background);
            FillRect(draw.hDC, &rect, brush);
            DeleteObject(brush);
            let outline = CreateSolidBrush(p.border);
            FrameRect(draw.hDC, &rect, outline);
            DeleteObject(outline);
            if id == LIST {
                if let Some(item) = self
                    .filtered
                    .get(draw.itemID as usize)
                    .and_then(|i| self.items.get(*i))
                {
                    let x = (rect.left as f32 / self.dpi) as i32;
                    let y = (rect.top as f32 / self.dpi) as i32;
                    let w = ((rect.right - rect.left) as f32 / self.dpi) as i32;
                    self.text(
                        draw.hDC,
                        &self.t(kind_key(item.incident.kind)),
                        (x + 14, y + 10, w - 28, 24),
                        0,
                        if selected { p.accent } else { p.text },
                        DT_SINGLELINE | DT_END_ELLIPSIS,
                    );
                    self.text(
                        draw.hDC,
                        &item.incident.at.format("%Y-%m-%d  %H:%M UTC").to_string(),
                        (x + 14, y + 41, w - 28, 24),
                        0,
                        p.muted,
                        DT_SINGLELINE | DT_END_ELLIPSIS,
                    );
                }
            } else {
                let mut buffer =
                    vec![0u16; GetWindowTextLengthW(draw.hwndItem).max(0) as usize + 1];
                let len = GetWindowTextW(draw.hwndItem, buffer.as_mut_ptr(), buffer.len() as i32);
                SelectObject(draw.hDC, self.fonts[0]);
                SetBkMode(draw.hDC, TRANSPARENT as i32);
                SetTextColor(
                    draw.hDC,
                    if draw.itemState & ODS_DISABLED != 0 {
                        p.muted
                    } else if id == CLEAR {
                        p.warning
                    } else {
                        p.text
                    },
                );
                rect.left += self.s(8);
                rect.right -= self.s(8);
                DrawTextW(
                    draw.hDC,
                    buffer.as_ptr(),
                    len,
                    &mut rect,
                    DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX,
                );
            }
            if draw.itemState & ODS_FOCUS != 0 {
                let mut focus = draw.rcItem;
                InflateRect(&mut focus, -self.s(3), -self.s(3));
                DrawFocusRect(draw.hDC, &focus);
            }
            RestoreDC(draw.hDC, saved);
        }
    }
}

impl Drop for App {
    fn drop(&mut self) {
        let _ = self.jobs.send(Job::Stop);
        // SAFETY: The message loop and all child windows have ended before owned GDI objects are freed.
        unsafe {
            for font in self.fonts {
                if !font.is_null() {
                    DeleteObject(font);
                }
            }
            if !self.background.is_null() {
                DeleteObject(self.background);
            }
            if !self.surface.is_null() {
                DeleteObject(self.surface);
            }
        }
    }
}

unsafe extern "system" fn window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // SAFETY: Win32 owns the message arguments. Userdata is a stable RefCell owned by run().
    unsafe {
        if message == WM_NCCREATE {
            let create = &*(lparam as *const CREATESTRUCTW);
            SetWindowLongPtrW(window, GWLP_USERDATA, create.lpCreateParams as isize);
        }
        if message == WM_GETMINMAXINFO {
            let dpi = GetDpiForWindow(window).max(96) as f32 / 96.0;
            let info = &mut *(lparam as *mut MINMAXINFO);
            info.ptMinTrackSize.x = (900.0 * dpi) as i32;
            info.ptMinTrackSize.y = (720.0 * dpi) as i32;
            return 0;
        }
        // Destruction can be synchronous inside a command or worker notification.
        // It must never depend on borrowing state already held by the outer callback.
        if message == WM_DESTROY {
            KillTimer(window, ANIMATION);
            PostQuitMessage(0);
            return 0;
        }
        let pointer = GetWindowLongPtrW(window, GWLP_USERDATA) as *const RefCell<App>;
        if pointer.is_null() {
            return DefWindowProcW(window, message, wparam, lparam);
        }
        // Reentrant control notifications during layout never create aliased mutable state.
        let Ok(mut app) = (*pointer).try_borrow_mut() else {
            if message == NOTIFY {
                DEFERRED_NOTICE.with(|pending| pending.set(true));
            }
            return DefWindowProcW(window, message, wparam, lparam);
        };
        let result = match message {
            WM_CREATE => {
                app.window = window;
                app.create_controls();
                0
            }
            WM_SIZE => {
                if wparam == SIZE_MINIMIZED as usize {
                    KillTimer(window, ANIMATION);
                    app.animation_left = 0;
                    return 0;
                }
                app.width = (lparam as u32 & 0xffff) as f32 as i32;
                app.height = ((lparam as u32 >> 16) & 0xffff) as f32 as i32;
                app.width = (app.width as f32 / app.dpi) as i32;
                app.height = (app.height as f32 / app.dpi) as i32;
                app.layout();
                0
            }
            WM_DPICHANGED => {
                app.dpi = (wparam & 0xffff) as f32 / 96.0;
                app.refresh_style();
                let rect = &*(lparam as *const RECT);
                SetWindowPos(
                    window,
                    ptr::null_mut(),
                    rect.left,
                    rect.top,
                    rect.right - rect.left,
                    rect.bottom - rect.top,
                    SWP_NOZORDER | SWP_NOACTIVATE,
                );
                let mut client = RECT::default();
                GetClientRect(window, &mut client);
                app.width = ((client.right - client.left) as f32 / app.dpi) as i32;
                app.height = ((client.bottom - client.top) as f32 / app.dpi) as i32;
                app.layout();
                0
            }
            WM_COMMAND => {
                app.command((wparam & 0xffff) as u16, ((wparam >> 16) & 0xffff) as u16);
                0
            }
            WM_PAINT => {
                app.paint();
                0
            }
            WM_ERASEBKGND => 1,
            WM_DRAWITEM => {
                app.draw_item(&*(lparam as *const DRAWITEMSTRUCT));
                1
            }
            WM_CTLCOLORLISTBOX | WM_CTLCOLOREDIT | WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => {
                let p = Palette::new(app.settings.dark);
                let label = [THEME_LABEL, LANGUAGE_LABEL, RETENTION_LABEL]
                    .iter()
                    .any(|id| app.control(*id) == lparam as HWND);
                SetTextColor(wparam as HDC, if label { p.muted } else { p.text });
                SetBkColor(wparam as HDC, if label { p.background } else { p.surface });
                if label {
                    app.background as LRESULT
                } else {
                    app.surface as LRESULT
                }
            }
            WM_TIMER if wparam == ANIMATION => {
                if app.animation_left > 0 {
                    app.animation_left -= 1;
                }
                if app.animation_left == 0 || IsIconic(window) != 0 {
                    KillTimer(window, ANIMATION);
                }
                app.invalidate();
                0
            }
            NOTIFY => {
                app.receive();
                0
            }
            WM_CLOSE => {
                if app.busy || app.download_percent.is_some() {
                    app.status = "close_busy";
                    app.invalidate();
                } else {
                    DestroyWindow(window);
                }
                0
            }
            _ => DefWindowProcW(window, message, wparam, lparam),
        };
        drop(app);
        if DEFERRED_NOTICE.with(|pending| pending.replace(false)) {
            PostMessageW(window, NOTIFY, 0, 0);
        }
        result
    }
}

pub fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.first().is_some_and(|a| a == "--apply-update") {
        ensure!(args.len() == 2, "Invalid update arguments");
        return update::apply_install(&PathBuf::from(&args[1]));
    }
    ensure!(
        args.is_empty() || args.len() == 2 && args[0] == "--updated",
        "Unsupported arguments"
    );
    let root = PathBuf::from(
        std::env::var_os("LOCALAPPDATA")
            .context("Windows local application-data directory is unavailable")?,
    )
    .join("SleepDiagnostics");
    let (job_tx, job_rx) = mpsc::channel();
    let (notice_tx, notice_rx) = mpsc::channel();
    let mut state = Box::new(RefCell::new(App {
        window: ptr::null_mut(),
        controls: HashMap::new(),
        settings: Settings::default(),
        settings_page: false,
        items: vec![],
        filtered: vec![],
        selected: 0,
        filter: 0,
        dpi: 1.0,
        width: 1120,
        height: 760,
        fonts: [ptr::null_mut(); 3],
        background: ptr::null_mut(),
        surface: ptr::null_mut(),
        status: "working",
        error_detail: None,
        busy: true,
        update_busy: false,
        update_status: "update_idle",
        available: None,
        download_percent: None,
        notices: notice_rx,
        jobs: job_tx,
        notify: Notifier {
            sender: notice_tx.clone(),
            window: 0,
        },
        animation_left: 0,
        paint_count: 0,
    }));
    // SAFETY: Registers one native window class, embeds the packaged icon, and blocks on GetMessage.
    // There is no render loop, live collection at startup, power request, or background poll timer.
    unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        let module = GetModuleHandleW(ptr::null());
        let icon = LoadIconW(module, std::ptr::without_provenance::<u16>(1));
        let class = wide("SleepDiagnostics.Window.v1");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: module,
            hIcon: icon,
            hCursor: LoadCursorW(ptr::null_mut(), IDC_ARROW),
            lpszClassName: class.as_ptr(),
            ..Default::default()
        };
        ensure!(RegisterClassW(&wc) != 0, "Cannot register native window");
        state.get_mut().dpi = GetDpiForSystem().max(96) as f32 / 96.0;
        let window = CreateWindowExW(
            WS_EX_CONTROLPARENT,
            class.as_ptr(),
            wide("Sleep Diagnostics").as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            state.get_mut().s(1120),
            state.get_mut().s(820),
            ptr::null_mut(),
            ptr::null_mut(),
            module,
            (&*state as *const RefCell<App>).cast(),
        );
        ensure!(!window.is_null(), "Cannot create native window");
        state.borrow_mut().notify.window = window as usize;
        let notify = Notifier {
            sender: notice_tx,
            window: window as usize,
        };
        let completed_update = if args.len() == 2 && args[0] == "--updated" {
            Some(PathBuf::from(&args[1]))
        } else {
            None
        };
        thread::Builder::new()
            .name("diagnostic-worker".into())
            .spawn(move || {
                if let Some(manifest) = completed_update
                    && let Ok(current) = std::env::current_exe()
                {
                    let _ = update::cleanup_completed_install(&manifest, &current);
                }
                worker(root, job_rx, notify)
            })?;
        state.borrow().jobs.send(Job::Initialize)?;
        ShowWindow(window, SW_SHOW);
        let mut message = MSG::default();
        loop {
            let result = GetMessageW(&mut message, ptr::null_mut(), 0, 0);
            if result <= 0 {
                ensure!(result == 0, "Native message loop failed");
                break;
            }
            if IsDialogMessageW(window, &message) == 0 {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }
    Ok(())
}

fn kind_key(kind: IncidentKind) -> &'static str {
    match kind {
        IncidentKind::SleepCycle => "sleep_cycle",
        IncidentKind::SleepOpen => "sleep_open",
        IncidentKind::ResumeOnly => "resume_only",
        IncidentKind::Restart => "restart",
        IncidentKind::CurrentRequests => "current_requests",
        IncidentKind::ClockAdjusted => "clock",
        IncidentKind::Standby => "standby",
        IncidentKind::Coverage => "coverage",
    }
}
fn confidence_key(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Reported => "reported",
        Confidence::Plausible => "plausible",
        Confidence::Unknown => "unknown",
    }
}
fn explanation_key(explanation: Explanation) -> &'static str {
    match explanation {
        Explanation::DirectSource => "direct",
        Explanation::ConflictingSources => "conflict",
        Explanation::UnknownSource => "unknown_source",
        Explanation::TimerNearby => "timer_nearby",
        Explanation::CurrentBlockers => "blockers",
        Explanation::NoCurrentBlockers => "no_blockers",
        Explanation::SleepUnconfirmed => "unconfirmed",
        Explanation::RestartBoundary => "restart_boundary",
        Explanation::ClockChanged => "clock_changed",
        Explanation::StandbyTransition => "standby_transition",
        Explanation::CoverageOnly => "no_events",
    }
}
fn remedy_key(explanation: Explanation) -> &'static str {
    match explanation {
        Explanation::DirectSource => "remedy_direct",
        Explanation::TimerNearby => "remedy_timer",
        Explanation::CurrentBlockers | Explanation::NoCurrentBlockers => "remedy_requests",
        Explanation::RestartBoundary | Explanation::ClockChanged => "remedy_boundary",
        _ => "remedy_unknown",
    }
}
fn report_key(kind: ReportKind) -> &'static str {
    match kind {
        ReportKind::Requests => "requests",
        ReportKind::LastWake => "last_wake",
        ReportKind::WakeTimers => "timers",
        ReportKind::WakeArmed => "armed",
        ReportKind::SleepStates => "states",
    }
}
fn availability_key(value: Availability) -> &'static str {
    match value {
        Availability::Available => "available_status",
        Availability::PermissionDenied => "denied",
        Availability::Unsupported => "unsupported",
        Availability::TimedOut => "timeout",
        Availability::UnparsedLocale => "locale",
        Availability::Failed => "failed",
        Availability::Truncated => "truncated",
    }
}
fn request_key(request: RequestType) -> &'static str {
    match request {
        RequestType::Display => "display_help",
        RequestType::System => "system_help",
        RequestType::AwayMode => "away_help",
        RequestType::Execution => "execution_help",
        RequestType::PerfBoost => "perf_help",
        RequestType::ActiveLockScreen => "lock_help",
        RequestType::None => "none_help",
    }
}
