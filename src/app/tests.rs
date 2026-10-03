use super::*;
use crate::domain::EntryDraft;
use iced_test::{Simulator, selector};

/// Runtime effects are retained so deferred close and clipboard actions are
/// asserted on their actual variants, rather than Task's admission unit count.
pub(super) struct TestEffects {
    pub(super) actions: Vec<iced_test::runtime::Action<Message>>,
}
impl TestEffects {
    pub(super) fn units(&self) -> usize {
        self.actions.len()
    }
    pub(super) fn closes(&self, window: iced::window::Id) -> bool {
        self.actions.iter().any(|action| matches!(action,
            iced_test::runtime::Action::Window(iced_test::runtime::window::Action::Close(id)) if *id == window
        ))
    }
}

/// Keep the real completion observer alive, dispatch metadata back through the
/// real update path, and wait for the worker's Drained acknowledgement. Follow-up
/// disposal and clipboard-shutdown tasks join the same deterministic event loop.
pub(super) fn drain_task(app: &mut App, task: Task<Message>) -> TestEffects {
    use iced::futures::{StreamExt, stream::SelectAll};
    use iced_test::runtime::{Action, task::into_stream};
    let mut effects = TestEffects {
        actions: Vec::new(),
    };
    let mut streams = SelectAll::new();
    if let Some(stream) = into_stream(task) {
        streams.push(stream);
    }
    iced::futures::executor::block_on(async {
        while let Some(action) = streams.next().await {
            match action {
                Action::Output(message) => {
                    if let Some(stream) = into_stream(app.update(message)) {
                        streams.push(stream);
                    }
                }
                action => effects.actions.push(action),
            }
        }
    });
    effects
}

impl App {
    pub(super) fn test_update(&mut self, message: Message) -> TestEffects {
        use iced::futures::{FutureExt, StreamExt};
        use iced_test::runtime::{Action, task::into_stream};
        let native_picker = matches!(test_message(&message), Message::PickPath(_));
        let task = self.update(message);
        let worker_or_shutdown = self.operations.active.is_some()
            || self
                .operations
                .authority
                .snapshot(std::time::Instant::now())
                .occupied
                .is_some()
            || matches!(self.operations.session, operations::SessionUi::Locking)
            || self.operations.shutdown_started;
        if worker_or_shutdown && !native_picker {
            return drain_task(self, task);
        }
        // Native window/clipboard requests need a GUI responder. Preserve their
        // immediate effects, but leave native picker completions under each
        // test's explicit PathPicked injection instead of launching an OS dialog.
        let mut effects = TestEffects {
            actions: Vec::new(),
        };
        if let Some(mut stream) = into_stream(task) {
            while let Some(Some(action)) = stream.next().now_or_never() {
                match action {
                    Action::Output(message) => {
                        effects.actions.extend(self.test_update(message).actions);
                    }
                    action => effects.actions.push(action),
                }
            }
        }
        effects
    }

    pub(super) fn test_drain_pending(&mut self) -> TestEffects {
        let task = self.operations.task.take().unwrap_or_else(Task::none);
        drain_task(self, task)
    }

    /// Only fixture setup that intentionally saves outside App may synchronize
    /// its revised binding. Never call this from the event-loop helper: stale
    /// binding rejection must remain observable in real update regressions.
    pub(super) fn test_sync_fixture_binding(&self) {
        let snapshot = self
            .operations
            .authority
            .snapshot(std::time::Instant::now());
        assert!(!snapshot.masked && !snapshot.closing);
        assert!(snapshot.occupied.is_none() && self.operations.active.is_none());
        let deadline = snapshot
            .live
            .expect("fixture has a real live session")
            .deadline;
        let binding = self
            .session
            .as_ref()
            .expect("fixture session is present")
            .operation_binding();
        self.operations
            .authority
            .activate_session(binding, deadline);
        assert_eq!(
            self.operations
                .authority
                .snapshot(std::time::Instant::now())
                .live
                .unwrap()
                .deadline,
            deadline,
            "fixture synchronization must not extend the idle deadline"
        );
    }

    /// Explicit clock setup models a real already-unlocked session deadline;
    /// changing last_activity alone no longer changes the worker's authority.
    pub(super) fn test_set_fixture_clock(&mut self, last_activity: std::time::Instant) {
        let snapshot = self
            .operations
            .authority
            .snapshot(std::time::Instant::now());
        assert!(!snapshot.masked && !snapshot.closing);
        assert!(snapshot.occupied.is_none() && self.operations.active.is_none());
        let live = snapshot.live.expect("fixture has a real live session");
        assert_eq!(Some(live.binding), snapshot.stamp.session);
        assert_eq!(
            live.binding,
            self.session.as_ref().unwrap().operation_binding(),
            "clock setup must not synchronize a changed session binding"
        );
        self.last_activity = last_activity;
        self.operations.authority.activate_session(
            live.binding,
            last_activity + std::time::Duration::from_secs(u64::from(self.idle_minutes) * 60),
        );
    }

    pub(super) fn test_lock_with_status(&mut self, status: &str) {
        self.lock_with_status(status);
        self.test_drain_pending();
    }

    pub(super) fn test_open_recovery(&mut self) {
        self.open_recovery();
        self.test_drain_pending();
    }
}

/// Pattern-match UI events without discarding the stamp used by App::update.
fn test_message(mut message: &Message) -> &Message {
    while let Message::Ui(_, inner) = message {
        message = inner;
    }
    message
}

#[test]
fn test_runtime_drain_preserves_deferred_close_action() {
    let (_dir, mut app) = fixture(0);
    let window = iced::window::Id::unique();
    let task = app.update(Message::CloseRequested(window));
    assert!(
        app.session.is_none(),
        "close masks before cleanup completes"
    );
    let effects = drain_task(&mut app, task);
    assert!(
        effects.closes(window),
        "close must finish real worker and clipboard cleanup"
    );
    assert_eq!(effects.units(), 1, "close is issued exactly once");
    assert!(app.closing);
}

const SIZES: [(f32, f32); 3] = [(960.0, 640.0), (1280.0, 800.0), (1600.0, 900.0)];

pub(super) fn fixture(count: usize) -> (tempfile::TempDir, App) {
    let dir = tempfile::tempdir().unwrap();
    let mut app = App::initial();
    let path = dir.path().join("synthetic-gui.pmvault");
    let mut vault = VaultSession::create(&path, "gui-synthetic-master-only").unwrap();
    for index in 0..count {
        vault
            .add_entry(EntryDraft::login(
                format!("示例条目 {index:03}"),
                format!("https://account-{index}.example.test"),
                format!("synthetic-user-{index}"),
                "synthetic-not-a-real-password",
            ))
            .unwrap();
    }
    vault.save().unwrap();
    app.vault_path = path.display().to_string();
    app.session = Some(vault);
    app.reset_unlocked_state();
    (dir, app)
}

fn simulator(app: &App, size: (f32, f32)) -> Simulator<'_, Message> {
    Simulator::with_size(
        iced_test::core::Settings {
            default_font: UI_FONT,
            default_text_size: iced::Pixels(14.0),
            ..iced_test::core::Settings::default()
        },
        size,
        app.view(),
    )
}

fn apply_messages(app: &mut App, messages: Vec<Message>) {
    assert!(!messages.is_empty(), "click did not emit a message");
    for message in messages {
        let _ = app.test_update(message);
    }
}

// Text labels also occur on cards behind the opaque overlay. Traverse into
// the actual context panel before selecting its button, not the hidden card.
fn context_button(label: &str) -> impl selector::Selector<Output = selector::Target> + Send + '_ {
    let panel_id = widget::Id::from("context-panel");
    let mut in_context = false;
    move |candidate: selector::Candidate<'_>| {
        if candidate.id() == Some(&panel_id) {
            in_context = true;
        }
        if in_context
            && matches!(&candidate, selector::Candidate::Text { content, .. } if *content == label)
        {
            Some(selector::Target::from(candidate))
        } else {
            None
        }
    }
}

fn click(app: &mut App, label: &str) {
    let mut ui = simulator(app, (1280.0, 800.0));
    ui.click(label).unwrap();
    let messages = ui.into_messages().collect();
    apply_messages(app, messages);
}

fn click_id(app: &mut App, id: String, size: (f32, f32)) -> Vec<Message> {
    let mut ui = simulator(app, size);
    ui.click(selector::id(id)).unwrap();
    ui.into_messages().collect()
}

fn capture(app: &App, name: &str, size: (f32, f32)) {
    use std::io::Write;

    let directory = std::path::PathBuf::from("target/gui-artifacts");
    std::fs::create_dir_all(&directory).unwrap();
    let mut stages = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(directory.join("capture-stages.txt"))
        .unwrap();
    // Only fixed scenario names and logical sizes; never credential values.
    writeln!(stages, "BEGIN {name} {}x{}", size.0, size.1).unwrap();
    stages.flush().unwrap();
    let path = directory.join(format!("{name}-{}x{}.png", size.0 as u32, size.1 as u32));
    simulator(app, size)
        .snapshot(&app.theme())
        .unwrap()
        .matches_image(path)
        .unwrap();
    writeln!(stages, "END {name} {}x{}", size.0, size.1).unwrap();
}

fn assert_finite_rect(bounds: iced::Rectangle) {
    for value in [bounds.x, bounds.y, bounds.width, bounds.height] {
        assert!(value.is_finite(), "non-finite widget geometry: {bounds:?}");
    }
    assert!(bounds.width > 0.0 && bounds.height > 0.0);
}

#[test]
fn message_debug_never_contains_secret_payloads() {
    let value = "synthetic-secret-debug-sentinel";
    for message in [
        Message::MasterPasswordChanged(value.to_string()),
        Message::EditorPasswordChanged(value.to_string()),
        Message::ImportLegacyPasswordChanged(value.to_string()),
        Message::RestorePasswordChanged(value.to_string()),
    ] {
        assert!(!format!("{message:?}").contains(value));
    }
}

#[test]
fn category_delete_moves_entries_without_deleting_credentials() {
    let (_dir, mut app) = fixture(1);
    let _ = app.test_update(Message::CategoryNameChanged("工作".to_string()));
    let _ = app.test_update(Message::AddCategory);
    app.session.as_mut().unwrap().body_mut().entries[0].category = "工作".to_string();
    app.session.as_mut().unwrap().save().unwrap();
    app.test_sync_fixture_binding();
    let _ = app.test_update(Message::RequestDeleteCategory("工作".to_string()));
    let _ = app.test_update(Message::ConfirmDeleteCategory("工作".to_string()));
    let vault = app.session.as_ref().unwrap();
    assert_eq!(vault.entries().len(), 1);
    assert_eq!(vault.entries()[0].category, "其他");
    assert!(!vault.categories().iter().any(|name| name == "工作"));
    vault.verify_current_file().unwrap();
}

#[test]
fn lock_drops_editor_import_preview_and_revealed_state() {
    let (_dir, mut app) = fixture(1);
    let _ = app.test_update(Message::NewEntry);
    let _ = app.test_update(Message::EditorPasswordChanged(
        "synthetic-buffer".to_string(),
    ));
    let _ = app.test_update(Message::Lock);
    assert!(app.session.is_none());
    assert!(matches!(app.panel, Panel::Vault));
    assert!(app.revealed.is_none());
    assert!(app.master_password.is_empty());
    assert!(app.confirm_password.is_empty());
}

#[test]
fn card_action_targets_its_id_and_rejects_stale_targets() {
    let (_dir, mut app) = fixture(2);
    let ids: Vec<_> = app
        .session
        .as_ref()
        .unwrap()
        .entries()
        .iter()
        .map(|e| e.id)
        .collect();
    let _ = app.test_update(Message::SelectEntry(ids[0]));
    let _ = app.test_update(Message::CardAction(ids[1], CardAction::Favorite));
    assert_eq!(app.selected, Some(ids[1]));
    assert!(
        !app.session
            .as_ref()
            .unwrap()
            .entry(ids[0])
            .unwrap()
            .favorite
    );
    assert!(
        app.session
            .as_ref()
            .unwrap()
            .entry(ids[1])
            .unwrap()
            .favorite
    );
    let _ = app.test_update(Message::SearchChanged("does-not-match".to_string()));
    let _ = app.test_update(Message::CardAction(ids[1], CardAction::Favorite));
    assert!(
        app.session
            .as_ref()
            .unwrap()
            .entry(ids[1])
            .unwrap()
            .favorite
    );
    let _ = app.test_update(Message::Lock);
    let _ = app.test_update(Message::CardAction(ids[1], CardAction::CopyPassword));
    assert!(app.selected.is_none());
}

#[test]
#[ignore = "Headless UI suite; run explicitly with the tiny-skia backend in CI"]
fn gui_authentication_modes_and_captures() {
    let mut app = App::initial();
    assert!(!app.dark_mode);
    for size in SIZES {
        let target = simulator(&app, size)
            .find(selector::id("auth-card"))
            .unwrap();
        let bounds = target.bounds();
        assert_finite_rect(bounds);
        assert!(((bounds.x + bounds.width / 2.0) - size.0 / 2.0).abs() < 1.0);
        assert!(((bounds.y + bounds.height / 2.0) - size.1 / 2.0).abs() < 1.0);
        assert!(bounds.x >= 0.0 && bounds.y >= 0.0);
        capture(&app, "open-vault", size);
    }
    assert!(simulator(&app, SIZES[0]).find("确认主密码").is_err());
    click(&mut app, "创建新保险库");
    assert!(app.creating);
    assert!(simulator(&app, SIZES[0]).find("确认主密码").is_ok());
    capture(&app, "create-vault", SIZES[0]);
    click(&mut app, "打开保险库");
    assert!(!app.creating);
}

#[test]
#[ignore = "Headless UI suite; run explicitly with the tiny-skia backend in CI"]
fn gui_cards_search_and_editor_buttons() {
    let (_dir, mut app) = fixture(3);
    let ids: Vec<_> = app
        .session
        .as_ref()
        .unwrap()
        .entries()
        .iter()
        .map(|e| e.id)
        .collect();
    {
        let mut ui = simulator(&app, SIZES[1]);
        assert!(ui.find("示例条目 001").is_ok());
        assert!(ui.find("synthetic-not-a-real-password").is_err());
    }
    for (suffix, action) in [
        ("copy-user", CardAction::CopyUsername),
        ("copy-password", CardAction::CopyPassword),
    ] {
        let messages = click_id(&mut app, format!("{suffix}-{}", ids[1]), SIZES[0]);
        assert!(messages.iter().any(|m| {
            matches!(test_message(m), Message::CardAction(id, value) if *id == ids[1] && *value == action)
        }));
        // Simulator does not execute clipboard tasks; this proves routing only.
    }
    let messages = click_id(&mut app, format!("edit-{}", ids[1]), SIZES[0]);
    apply_messages(&mut app, messages);
    assert!(matches!(&app.panel, Panel::Editor(state) if state.id == Some(ids[1])));
    capture(&app, "edit-entry", SIZES[0]);
    let messages = {
        let mut ui = simulator(&app, SIZES[0]);
        ui.click("取消编辑").unwrap();
        ui.into_messages().collect()
    };
    apply_messages(&mut app, messages);
    let messages = {
        let mut ui = simulator(&app, SIZES[1]);
        ui.click(selector::id(app.search_id.clone())).unwrap();
        ui.typewrite("002");
        ui.into_messages().collect()
    };
    apply_messages(&mut app, messages);
    assert_eq!(app.search, "002");
    assert!(simulator(&app, SIZES[1]).find("示例条目 002").is_ok());
    assert!(simulator(&app, SIZES[1]).find("示例条目 000").is_err());
    click(&mut app, "清空");
    click(&mut app, "+ 添加密码");
    let _ = app.test_update(Message::EditorNameChanged("GUI 新条目".to_string()));
    let _ = app.test_update(Message::EditorPasswordChanged(
        "synthetic-gui-only".to_string(),
    ));
    click(&mut app, "保存条目");
    assert!(matches!(&app.panel, Panel::Vault));
    assert_eq!(app.session.as_ref().unwrap().active_entries().count(), 4);
    assert_eq!(app.view_index.as_ref().unwrap().active_count(), 4);
    assert!(simulator(&app, SIZES[1]).find("GUI 新条目").is_ok());
    let created_id = app
        .session
        .as_ref()
        .unwrap()
        .entries()
        .iter()
        .find(|entry| entry.name == "GUI 新条目")
        .unwrap()
        .id;
    // Real edit/save must replace worker-prepared search metadata too. Merely
    // mutating the session while retaining its old index fails this lookup.
    app.test_update(Message::EditEntry(created_id));
    app.test_update(Message::EditorNameChanged("GUI 修改后".into()));
    click(&mut app, "保存条目");
    app.test_update(Message::SearchChanged("GUI 修改后".into()));
    assert!(simulator(&app, SIZES[1]).find("GUI 修改后").is_ok());
    assert!(simulator(&app, SIZES[1]).find("GUI 新条目").is_err());
    let session = app.session.as_ref().unwrap();
    let positions = app.card_positions(session);
    assert_eq!(positions.len(), 1);
    assert_eq!(session.entries()[positions[0]].id, created_id);
}

#[test]
#[ignore = "Headless UI suite; run explicitly with the tiny-skia backend in CI"]
fn gui_pages_render_at_supported_logical_sizes() {
    let (_dir, app) = fixture(12);
    let id = app.session.as_ref().unwrap().entries()[0].id;
    for size in SIZES {
        let bounds = simulator(&app, size)
            .find(selector::id(format!("card-{id}")))
            .unwrap()
            .bounds();
        assert_finite_rect(bounds);
        assert!(bounds.x >= 250.0 && bounds.x + bounds.width <= size.0);
        capture(&app, "cards", size);
    }
}

#[test]
#[ignore = "Headless UI suite; run explicitly with the tiny-skia backend in CI"]
fn gui_import_page_capture() {
    let (_dir, mut app) = fixture(1);
    click(&mut app, "导入数据");
    assert!(matches!(&app.panel, Panel::Import(_)));
    capture(&app, "import", SIZES[0]);
    click(&mut app, "返回列表");
    assert!(matches!(&app.panel, Panel::Vault));
}

#[test]
#[ignore = "Headless UI suite; run explicitly with the tiny-skia backend in CI"]
fn gui_settings_page_capture() {
    let (_dir, mut app) = fixture(1);
    click(&mut app, "设置");
    assert!(matches!(&app.panel, Panel::Settings(_)));
    capture(&app, "settings", SIZES[1]);
    click(&mut app, "返回列表");
    assert!(matches!(&app.panel, Panel::Vault));
}

#[test]
#[ignore = "Headless UI suite; run explicitly with the tiny-skia backend in CI"]
fn gui_context_and_dark_captures() {
    let (_dir, mut app) = fixture(1);
    let id = app.session.as_ref().unwrap().entries()[0].id;
    let _ = app.test_update(Message::ContextEntry(id));
    capture(&app, "context-actions", SIZES[0]);
    click(&mut app, "显示密码");
    assert!(app.revealed.is_some());
    click(&mut app, "关闭菜单");
    assert!(!app.context_open);
    assert!(app.revealed.is_none());
    let _ = app.test_update(Message::DarkModeChanged(true));
    capture(&app, "cards-dark", SIZES[1]);
}

#[test]
#[ignore = "Headless UI suite; run explicitly with the tiny-skia backend in CI"]
fn gui_empty_and_long_text_captures() {
    let (_dir, mut app) = fixture(0);
    capture(&app, "cards-empty", SIZES[0]);
    let id = app
        .session
        .as_mut()
        .unwrap()
        .add_entry(EntryDraft::login(
            "很长的中文名称😀".repeat(20),
            format!("https://example.test/{}", "long-path/".repeat(40)),
            "很长的账号".repeat(40),
            "synthetic-not-a-real-password",
        ))
        .unwrap();
    // This display fixture intentionally bypasses App's owned mutation lane.
    // Rebuild its metadata explicitly, as production job completion does.
    app.view_index = Some(view_index::ViewIndex::build(app.session.as_ref().unwrap()));
    let bounds = simulator(&app, SIZES[0])
        .find(selector::id(format!("card-{id}")))
        .unwrap()
        .bounds();
    assert_finite_rect(bounds);
    capture(&app, "cards-long-text", SIZES[0]);
}

#[test]
fn several_hundred_rows_filter_without_revealing_secrets() {
    let (_dir, app) = fixture(500);
    let vault = app.session.as_ref().unwrap();
    assert_eq!(
        vault
            .entries()
            .iter()
            .filter(|e| app.entry_visible(e, ""))
            .count(),
        500
    );
    assert_eq!(
        vault
            .entries()
            .iter()
            .filter(|e| app.entry_visible(e, "499"))
            .count(),
        1
    );
}

#[test]
fn entry_interactions_reject_targets_outside_visible_workspace() {
    for action in [
        Message::SelectEntry,
        Message::EditEntry,
        Message::ContextEntry,
    ] {
        for scenario in 0..5 {
            let (_dir, mut app) = fixture(1);
            let mut id = app.session.as_ref().unwrap().entries()[0].id;
            match scenario {
                0 => id = Uuid::new_v4(),
                1 => {
                    let _ = app.test_update(Message::SearchChanged("absent-entry".into()));
                }
                2 => {
                    let _ = app.test_update(Message::SetNav(NavFilter::Favorites));
                }
                3 => {
                    let _ = app.test_update(Message::OpenSettings);
                }
                4 => {
                    let _ = app.test_update(Message::Lock);
                }
                _ => unreachable!(),
            }
            let panel = std::mem::discriminant(&app.panel);
            let _ = app.test_update(action(id));
            assert!(
                app.selected.is_none(),
                "invalid target changed selection: {scenario}"
            );
            assert!(
                !app.context_open,
                "invalid target opened details: {scenario}"
            );
            assert!(app.revealed.is_none());
            assert_eq!(std::mem::discriminant(&app.panel), panel);
        }
    }
}

#[test]
fn leaving_details_drops_the_revealed_buffer() {
    for action in [
        Message::CloseContext,
        Message::CopyUsername,
        Message::CopyPassword,
        Message::ToggleSelectedFavorite,
        Message::NewEntry,
        Message::EditSelected,
        Message::OpenSettings,
        Message::OpenImport,
        Message::CancelPanel,
        Message::SearchChanged("absent-entry".into()),
        Message::SetNav(NavFilter::Favorites),
        Message::RequestPermanentDelete,
        Message::RequestDeleteCategory("其他".into()),
        Message::Lock,
    ] {
        let (_dir, mut app) = fixture(1);
        let id = app.session.as_ref().unwrap().entries()[0].id;
        let _ = app.test_update(Message::ContextEntry(id));
        let _ = app.test_update(Message::ToggleReveal);
        assert!(app.revealed.is_some());
        let action_name = format!("{action:?}");
        let _ = app.test_update(action);
        assert!(!app.context_open, "details remained open: {action_name}");
        assert!(app.revealed.is_none(), "plaintext retained: {action_name}");
    }
}

#[test]
fn reveal_requires_a_visible_entry_in_open_details() {
    let (_dir, mut app) = fixture(1);
    let id = app.session.as_ref().unwrap().entries()[0].id;
    let _ = app.test_update(Message::SelectEntry(id));
    let _ = app.test_update(Message::ToggleReveal);
    assert!(app.revealed.is_none(), "revealed without open details");
    let _ = app.test_update(Message::ContextEntry(id));
    let _ = app.test_update(Message::ToggleReveal);
    assert!(app.revealed.is_some());
    let _ = app.test_update(Message::CloseContext);
    let _ = app.test_update(Message::ToggleReveal);
    assert!(app.revealed.is_none(), "delayed reveal after close");
    let _ = app.test_update(Message::SearchChanged("absent-entry".into()));
    let _ = app.test_update(Message::ToggleReveal);
    assert!(app.revealed.is_none());
    let _ = app.test_update(Message::Lock);
    let _ = app.test_update(Message::ToggleReveal);
    assert!(app.revealed.is_none());
}

#[test]
fn stale_selected_actions_do_not_operate_on_hidden_entries() {
    for action in [
        Message::CopyPassword,
        Message::CopyUsername,
        Message::EditSelected,
        Message::ToggleSelectedFavorite,
        Message::MoveSelectedToRecycleBin,
        Message::RequestPermanentDelete,
    ] {
        let (_dir, mut app) = fixture(1);
        let id = app.session.as_ref().unwrap().entries()[0].id;
        let _ = app.test_update(Message::ContextEntry(id));
        let _ = app.test_update(Message::SearchChanged("absent-entry".into()));
        let task = app.test_update(action);
        assert_eq!(task.units(), 0, "hidden selection emitted a clipboard task");
        assert!(matches!(app.panel, Panel::Vault));
        assert!(app.revealed.is_none());
        let entry = app.session.as_ref().unwrap().entry(id).unwrap();
        assert!(!entry.favorite && !entry.is_deleted());
    }
}

#[test]
#[ignore = "Headless UI suite; run explicitly with the tiny-skia backend in CI"]
fn gui_context_actions_keep_their_original_target() {
    let (_dir, mut app) = fixture(2);
    let ids: Vec<_> = app
        .session
        .as_ref()
        .unwrap()
        .entries()
        .iter()
        .map(|e| e.id)
        .collect();
    for label in [
        "收藏条目",
        "复制账号",
        "复制密码",
        "显示密码",
        "编辑条目",
        "移到回收站",
        "关闭菜单",
    ] {
        for destination in 0..3 {
            let _ = app.test_update(Message::ContextEntry(ids[0]));
            let messages = {
                let mut ui = simulator(&app, SIZES[0]);
                ui.click(context_button(label)).unwrap();
                ui.into_messages().collect::<Vec<_>>()
            };
            assert!(
                !messages.is_empty(),
                "context button emitted no message: {label}"
            );
            if destination == 0 {
                let _ = app.test_update(Message::ContextEntry(ids[1]));
            } else {
                let _ = app.test_update(Message::CloseContext);
                if destination == 2 {
                    let _ = app.test_update(Message::ContextEntry(ids[0]));
                }
            }
            for message in messages {
                assert_eq!(
                    app.test_update(message).units(),
                    0,
                    "stale action emitted a task: {label}"
                );
            }
            assert!(matches!(app.panel, Panel::Vault));
            assert!(app.revealed.is_none(), "stale reveal: {label}");
            assert_eq!(
                app.context_open,
                destination != 1,
                "stale dismissal: {label}"
            );
            for entry in app.session.as_ref().unwrap().entries() {
                assert!(
                    !entry.favorite && !entry.is_deleted(),
                    "stale mutation: {label}"
                );
            }
        }
    }
}

#[test]
#[ignore = "headless GUI regression"]
fn gui_native_picker_entry_points_are_available() {
    let (_dir, mut app) = fixture(0);
    let session = app.session.take();
    for size in SIZES {
        for creating in [false, true] {
            let _ = app.test_update(Message::AuthMode(creating));
            app.auth_options_open = true;
            let label = if creating {
                "选择新建位置"
            } else {
                "选择保险库文件"
            };
            let mut ui = simulator(&app, size);
            ui.click(label).expect("auth picker button missing");
            let purpose = if creating {
                picker::Purpose::CreateVault
            } else {
                picker::Purpose::OpenVault
            };
            let messages: Vec<_> = ui.into_messages().collect();
            assert!(
                matches!(messages.first().map(test_message), Some(Message::PickPath(actual)) if *actual == purpose)
            );
            apply_messages(&mut app, messages);
            assert!(app.picker_pending.is_some());
            let mut ui = simulator(&app, size);
            ui.click(label).unwrap();
            assert_eq!(ui.into_messages().count(), 0);
            let _ = app.test_update(Message::PathPicked(app.picker_sequence, Ok(None)));
            assert!(app.picker_pending.is_none());
            app.status.clear();
            capture(
                &app,
                if creating {
                    "picker-create"
                } else {
                    "picker-open"
                },
                size,
            );
        }
    }
    app.session = session;
    for size in SIZES {
        for (purpose, label) in [
            (picker::Purpose::Import, "选择导入文件"),
            (picker::Purpose::Backup, "选择备份位置"),
            (picker::Purpose::Restore, "选择恢复文件"),
            (picker::Purpose::Csv, "选择 CSV 导出位置"),
        ] {
            let _ = app.test_update(if purpose == picker::Purpose::Import {
                Message::OpenImport
            } else {
                Message::OpenSettings
            });
            let messages = {
                let mut ui = simulator(&app, size);
                scroll_picker_into_view(&mut ui, label, size);
                let target = ui.find(label).unwrap();
                let visible = target.visible_bounds().expect("picker label hidden");
                assert!((visible.height - target.bounds().height).abs() < 0.1);
                assert!(
                    ui.snapshot(&app.theme())
                        .unwrap()
                        .matches_image(format!(
                            "target/gui-artifacts/picker-{purpose:?}-{}.png",
                            size.0 as u32
                        ))
                        .unwrap()
                );
                ui.click(label).unwrap();
                ui.into_messages().collect::<Vec<_>>()
            };
            assert!(
                matches!(messages.first().map(test_message), Some(Message::PickPath(actual)) if *actual == purpose)
            );
            apply_messages(&mut app, messages);
            assert!(app.picker_pending.is_some());
            let mut ui = simulator(&app, size);
            scroll_picker_into_view(&mut ui, label, size);
            ui.click(label).unwrap();
            assert_eq!(
                ui.into_messages().count(),
                0,
                "pending picker button still enabled"
            );
            // Cancel through the same result message delivered by the native task.
            let _ = app.test_update(Message::PathPicked(app.picker_sequence, Ok(None)));
            assert!(app.picker_pending.is_none());
        }
    }
}

fn scroll_picker_into_view(ui: &mut Simulator<'_, Message>, label: &str, size: (f32, f32)) {
    let bounds = ui.find(label).unwrap().bounds();
    let amount = (bounds.center_y() - size.1 / 2.0).max(0.0);
    ui.point_at(iced::Point::new(size.0 - 100.0, size.1 / 2.0));
    ui.simulate([iced::Event::Mouse(iced::mouse::Event::WheelScrolled {
        delta: iced::mouse::ScrollDelta::Pixels { x: 0.0, y: -amount },
    })]);
}

#[test]
#[ignore = "headless GUI regression"]
fn gui_picker_path_fields_stay_clear_of_auth_scrollbar() {
    for creating in [false, true] {
        let mut app = App::initial();
        app.creating = creating;
        app.auth_options_open = true;
        app.status = "合成测试状态 ".repeat(100);
        for size in SIZES {
            let mut ui = simulator(&app, size);
            let viewport = ui.find(selector::id("auth-scroll")).unwrap().bounds();
            let purpose = if creating {
                picker::Purpose::CreateVault
            } else {
                picker::Purpose::OpenVault
            };
            let field = ui
                .find(selector::id(format!("picker-field-{purpose:?}")))
                .unwrap()
                .bounds();
            assert!(
                field.x + field.width <= viewport.x + viewport.width - 18.0 + 0.1,
                "path field overlaps scrollbar: field={field:?} viewport={viewport:?}"
            );
        }
    }
}

#[test]
#[ignore = "headless GUI regression"]
fn gui_safety_settings_are_visible_at_supported_sizes() {
    let (dir, mut app) = fixture(0);
    app.preferences_path = Some(dir.path().join("settings.json"));
    let _ = app.test_update(Message::OpenSettings);
    for size in SIZES {
        let mut ui = simulator(&app, size);
        for label in ["闲置自动锁定", "密码剪贴板清理"] {
            let target = ui.find(label).expect("security setting missing");
            assert!(target.visible_bounds().is_some());
        }
        drop(ui);
        capture(&app, "safety-settings", size);
        let mut ui = simulator(&app, size);
        let bounds = ui
            .click(selector::id("idle-timeout-setting"))
            .unwrap()
            .bounds();
        ui.snapshot(&app.theme())
            .unwrap()
            .matches_image(format!(
                "target/gui-artifacts/safety-timeout-menu-{}.png",
                size.0 as u32
            ))
            .unwrap();
        // Iced menu rows are painted as one widget, so text selectors cannot
        // address individual options. Click the first visible row below the control.
        let point = iced::Point::new(bounds.center_x(), bounds.y + bounds.height + 10.0);
        ui.point_at(point);
        ui.simulate([iced::Event::Mouse(iced::mouse::Event::CursorMoved {
            position: point,
        })]);
        ui.simulate(iced_test::simulator::click());
        let messages: Vec<_> = ui.into_messages().collect();
        assert!(matches!(
            messages.first().map(test_message),
            Some(Message::IdleTimeoutChanged(1))
        ));
        apply_messages(&mut app, messages);
        assert_eq!(app.idle_minutes, 1);
        let _ = app.test_update(Message::IdleTimeoutChanged(5));
        let mut ui = simulator(&app, size);
        let bounds = ui
            .click(selector::id("clipboard-timeout-setting"))
            .unwrap()
            .bounds();
        let point = iced::Point::new(bounds.center_x(), bounds.y + bounds.height + 10.0);
        ui.point_at(point);
        ui.simulate([iced::Event::Mouse(iced::mouse::Event::CursorMoved {
            position: point,
        })]);
        ui.simulate(iced_test::simulator::click());
        let messages: Vec<_> = ui.into_messages().collect();
        assert!(matches!(
            messages.first().map(test_message),
            Some(Message::ClipboardTimeoutChanged(15))
        ));
        apply_messages(&mut app, messages);
        assert_eq!(app.clipboard_seconds, 15);
        let _ = app.test_update(Message::ClipboardTimeoutChanged(30));
    }
}

#[test]
#[ignore = "headless GUI regression"]
fn gui_editor_password_keyboard_copy_uses_managed_pipeline() {
    let (_dir, mut app) = fixture(0);
    let _ = app.test_update(Message::NewEntry);
    let _ = app.test_update(Message::EditorPasswordChanged("synthetic-键盘🦀".into()));
    let _ = app.test_update(Message::ToggleEditorPasswordVisible(app.context_generation));
    for key in ["c", "x"] {
        let mut ui = simulator(&app, SIZES[0]);
        ui.click(selector::id("editor-password-input")).unwrap();
        ui.simulate([iced::Event::Keyboard(keyboard::Event::ModifiersChanged(
            keyboard::Modifiers::CTRL,
        ))]);
        ui.simulate(iced_test::simulator::tap_key(
            keyboard::Key::Character("a".into()),
            None,
        ));
        ui.simulate(iced_test::simulator::tap_key(
            keyboard::Key::Character(key.into()),
            None,
        ));
        let messages: Vec<_> = ui.into_messages().collect();
        if key == "x" {
            assert!(
                !messages.iter().any(|message| matches!(
                    test_message(message),
                    Message::EditorPasswordChanged(_)
                )),
                "cut removed the draft before native copy success"
            );
        }
        assert!(messages.iter().any(|message| {
            match test_message(message) {
                Message::CopyEditorPasswordSelection(_, _, cut) if key == "x" => {
                    cut.as_ref().is_some_and(|cut| {
                        cut.original.as_str() == "synthetic-键盘🦀" && cut.replacement.is_empty()
                    })
                }
                Message::CopyEditorPasswordSelection(_, _, cut) => cut.is_none(),
                _ => false,
            }
        }));

        assert!(
            messages
                .iter()
                .any(|message| matches!(test_message(message),
                    Message::CopyEditorPasswordSelection(generation, value, _)
                    if *generation == app.context_generation && value.as_str() == "synthetic-键盘🦀"
                )),
            "password keyboard copy bypassed managed clipboard"
        );
    }
}

#[test]
#[ignore = "headless GUI regression"]
fn gui_cleanup_warning_remains_visible_after_lock() {
    let (_dir, mut app) = fixture(0);
    let _ = app.test_update(Message::PlatformSecurity(
        SecurityEvent::ClipboardCleanupFailed,
    ));
    let _ = app.test_update(Message::PlatformSecurity(SecurityEvent::SystemSuspending));
    capture(&app, "safety-cleanup-warning", SIZES[0]);
    let mut ui = simulator(&app, SIZES[0]);
    let acknowledgement = ui.find("我已手动处理剪贴板").unwrap();
    assert!(acknowledgement.visible_bounds().is_some());
    ui.click("我已手动处理剪贴板").unwrap();
    let messages: Vec<_> = ui.into_messages().collect();
    apply_messages(&mut app, messages);
    assert!(!app.clipboard_cleanup_failed);
}

fn command_key(ui: &mut Simulator<'_, Message>, key: &str) {
    ui.simulate([iced::Event::Keyboard(keyboard::Event::ModifiersChanged(
        keyboard::Modifiers::CTRL,
    ))]);
    ui.simulate(iced_test::simulator::tap_key(
        keyboard::Key::Character(key.into()),
        None,
    ));
    ui.simulate([iced::Event::Keyboard(keyboard::Event::ModifiersChanged(
        keyboard::Modifiers::empty(),
    ))]);
}

#[test]
#[ignore = "headless GUI regression"]
fn gui_password_cut_batches_preserve_uncopied_draft() {
    let (_dir, mut app) = fixture(0);
    let _ = app.test_update(Message::NewEntry);
    let _ = app.test_update(Message::EditorPasswordChanged("synthetic-original".into()));
    let _ = app.test_update(Message::ToggleEditorPasswordVisible(app.context_generation));
    for before_cut in [false, true] {
        let mut ui = simulator(&app, SIZES[0]);
        ui.click(selector::id("editor-password-input")).unwrap();
        if before_cut {
            ui.tap_key(keyboard::key::Named::End);
            ui.typewrite("Z");
        }
        command_key(&mut ui, "a");
        command_key(&mut ui, "x");
        if !before_cut {
            ui.typewrite("Z");
        }
        let messages: Vec<_> = ui.into_messages().collect();
        if before_cut {
            assert!(messages.iter().any(|message| matches!(test_message(message),
                Message::CopyEditorPasswordSelection(_, _, Some(cut)) if cut.original.as_str() == "synthetic-originalZ"
            )), "cut captured stale view-build text");
        } else {
            assert!(
                messages
                    .iter()
                    .any(|message| matches!(test_message(message),
                        Message::EditorPasswordChanged(value) if value == "synthetic-originalZ"
                    )),
                "batched typing after cut lost the unconfirmed original"
            );
        }
    }
    let mut ui = simulator(&app, SIZES[0]);
    ui.click(selector::id("editor-password-input")).unwrap();
    ui.tap_key(keyboard::key::Named::Home);
    ui.tap_key(keyboard::key::Named::ArrowRight);
    command_key(&mut ui, "x");
    assert!(
        !ui.into_messages().any(|message| matches!(
            test_message(&message),
            Message::EditorPasswordChanged(_) | Message::CopyEditorPasswordSelection(..)
        )),
        "cut without selection changed a password"
    );
    let _ = app.test_update(Message::EditorPasswordChanged("ab👩‍💻e\u{301}cd".into()));
    let mut ui = simulator(&app, SIZES[0]);
    ui.click(selector::id("editor-password-input")).unwrap();
    ui.tap_key(keyboard::key::Named::Home);
    ui.tap_key(keyboard::key::Named::ArrowRight);
    ui.simulate([iced::Event::Keyboard(keyboard::Event::ModifiersChanged(
        keyboard::Modifiers::SHIFT,
    ))]);
    ui.tap_key(keyboard::key::Named::ArrowRight);
    ui.tap_key(keyboard::key::Named::ArrowRight);
    command_key(&mut ui, "x");
    assert!(
        ui.into_messages()
            .any(|message| matches!(test_message(&message),
                Message::CopyEditorPasswordSelection(_, value, Some(cut))
                if value.as_str() == "b👩‍💻" && cut.replacement.as_str() == "ae\u{301}cd"
            )),
        "cut did not respect emoji/combining grapheme boundaries"
    );
    let _ = app.test_update(Message::ToggleEditorPasswordVisible(app.context_generation));
    let mut ui = simulator(&app, SIZES[0]);
    ui.click(selector::id("editor-password-input")).unwrap();
    command_key(&mut ui, "a");
    command_key(&mut ui, "c");
    command_key(&mut ui, "x");
    assert!(
        !ui.into_messages().any(|message| matches!(
            test_message(&message),
            Message::CopyEditorPasswordSelection(..) | Message::EditorPasswordChanged(_)
        )),
        "masked input permitted copy or cut"
    );
}

fn staged_import_fixture() -> (tempfile::TempDir, App) {
    let (dir, mut app) = fixture(0);
    let source = dir.path().join("synthetic-import.csv");
    std::fs::write(
        &source,
        "name,url,username,password,note\nSynthetic,https://synthetic.example.test,user,one,note\n",
    )
    .unwrap();
    let _ = app.test_update(Message::OpenImport);
    let _ = app.test_update(Message::ImportPathChanged(source.display().to_string()));
    let _ = app.test_update(Message::AnalyzeImport);
    (dir, app)
}

#[test]
fn stale_import_events_do_not_target_reanalyzed_preview() {
    let (_dir, mut app) = staged_import_fixture();
    let Panel::Import(state) = &app.panel else {
        panic!("missing import panel")
    };
    let old_id = state.preview.as_ref().unwrap().id();
    let old_apply = Message::ApplyImport(old_id);
    let old_toggle = Message::ImportApplyUpdatesChanged(old_id, false);
    let old_decision = Message::SetImportResolution(old_id, 0, ConflictResolution::KeepBoth);
    let _ = app.test_update(Message::AnalyzeImport);
    let _ = app.test_update(old_toggle);
    let _ = app.test_update(old_decision);
    let Panel::Import(state) = &app.panel else {
        panic!("missing import panel")
    };
    assert!(state.apply_updates);
    assert!(state.resolutions.is_empty());
    let _ = app.test_update(old_apply);
    assert!(app.session.as_ref().unwrap().entries().is_empty());
}

#[test]
fn import_path_navigation_and_lock_discard_staged_preview_and_decisions() {
    for transition in 0..3 {
        let (_dir, mut app) = staged_import_fixture();
        let Panel::Import(state) = &app.panel else {
            panic!("missing import panel")
        };
        let old_id = state.preview.as_ref().unwrap().id();
        match transition {
            0 => {
                let _ = app.test_update(Message::ImportPathChanged("other.csv".into()));
            }
            1 => {
                let _ = app.test_update(Message::CancelPanel);
                let _ = app.test_update(Message::OpenImport);
            }
            _ => {
                let _ = app.test_update(Message::Lock);
            }
        }
        let _ = app.test_update(Message::SetImportResolution(
            old_id,
            0,
            ConflictResolution::KeepBoth,
        ));
        let _ = app.test_update(Message::ImportApplyUpdatesChanged(old_id, false));
        let _ = app.test_update(Message::ApplyImport(old_id));
        if let Panel::Import(state) = &app.panel {
            assert!(state.preview.is_none());
            assert!(state.resolutions.is_empty());
            assert!(state.apply_updates);
        } else {
            assert!(app.session.is_none());
        }
        if let Some(vault) = &app.session {
            assert!(vault.entries().is_empty());
        }
    }
}

#[test]
fn current_import_events_apply_once_and_invalid_choices_are_ignored() {
    let (_dir, mut app) = staged_import_fixture();
    let Panel::Import(state) = &app.panel else {
        panic!("missing import panel")
    };
    let id = state.preview.as_ref().unwrap().id();
    let _ = app.test_update(Message::SetImportResolution(
        id,
        0,
        ConflictResolution::KeepBoth,
    ));
    let _ = app.test_update(Message::SetImportResolution(
        id,
        99,
        ConflictResolution::KeepLocal,
    ));
    let Panel::Import(state) = &app.panel else {
        panic!("missing import panel")
    };
    assert!(state.resolutions.is_empty());
    let _ = app.test_update(Message::ApplyImport(id));
    let Panel::Import(state) = &app.panel else {
        panic!("missing import panel")
    };
    assert!(state.preview.is_none());
    assert!(state.resolutions.is_empty());
    let vault = app.session.as_ref().unwrap();
    assert_eq!(vault.entries().len(), 1);
    let revision = vault.revision();
    let _ = app.test_update(Message::ApplyImport(id));
    assert_eq!(app.session.as_ref().unwrap().revision(), revision);
    assert!(app.revealed.is_none());
}

#[test]
fn reanalysis_and_path_edits_reset_previous_preview_options() {
    for path_edit in [false, true] {
        let (_dir, mut app) = staged_import_fixture();
        let Panel::Import(state) = &app.panel else {
            panic!("missing import panel")
        };
        let id = state.preview.as_ref().unwrap().id();
        let _ = app.test_update(Message::ImportApplyUpdatesChanged(id, false));
        let Panel::Import(state) = &app.panel else {
            panic!("missing import panel")
        };
        assert!(!state.apply_updates);
        let _ = app.test_update(if path_edit {
            Message::ImportPathChanged("other.csv".into())
        } else {
            Message::AnalyzeImport
        });
        let Panel::Import(state) = &app.panel else {
            panic!("missing import panel")
        };
        assert!(state.apply_updates);
        assert!(state.resolutions.is_empty());
    }
}

fn import_choice(
    index: usize,
    label: &str,
) -> impl selector::Selector<Output = selector::Target> + Send + '_ {
    let mut seen = 0;
    move |candidate: selector::Candidate<'_>| {
        if matches!(&candidate, selector::Candidate::Text { content, .. } if *content == label) {
            let matches = seen == index;
            seen += 1;
            if matches {
                return Some(selector::Target::from(candidate));
            }
        }
        None
    }
}

#[test]
#[ignore = "Headless UI suite; run explicitly with the tiny-skia backend in CI"]
fn gui_import_source_duplicates_and_independent_conflict_choices() {
    for size in SIZES {
        let (dir, mut app) = fixture(0);
        let source = dir.path().join("synthetic-decisions.csv");
        std::fs::write(
            &source,
            concat!(
                "name,url,username,password,note\n",
                "Synthetic,https://decisions.example.test,user,synthetic-first,note\n",
                "Synthetic,https://decisions.example.test,user,synthetic-second,note\n",
                "Synthetic,https://decisions.example.test,user,synthetic-second,note\n"
            ),
        )
        .unwrap();
        let _ = app.test_update(Message::OpenImport);
        let _ = app.test_update(Message::ImportPathChanged(source.display().to_string()));
        let _ = app.test_update(Message::AnalyzeImport);
        let Panel::Import(state) = &app.panel else {
            panic!("missing import panel")
        };
        let preview = state.preview.as_ref().unwrap();
        let preview_id = preview.id();
        assert_eq!(preview.summary().source_duplicates, 1);
        assert_eq!(preview.summary().conflicts, 2);
        assert!(preview.rows()[..2].iter().all(|row| matches!(row.class(), ImportClass::Conflict { existing_ids } if existing_ids.is_empty())));
        {
            let mut ui = simulator(&app, size);
            let stats =
                "新增 0 · 已有重复 0 · 源内重复 1 · 更新 0 · 冲突 2 · 本地已删除 0 · 无效 0";
            scroll_picker_into_view(&mut ui, stats, size);
            let target = ui.find(stats).unwrap();
            let visible = target
                .visible_bounds()
                .expect("source duplicate statistics are hidden");
            assert!((visible.height - target.bounds().height).abs() < 0.1);
            assert!(visible.x >= 0.0 && visible.x + visible.width <= size.0);
        }
        capture(&app, "import-source-conflicts", size);
        for (index, label, resolution) in [
            (0, "跳过此行", ConflictResolution::KeepLocal),
            (1, "导入为独立条目", ConflictResolution::KeepBoth),
        ] {
            let messages = {
                let mut ui = simulator(&app, size);
                assert!(ui.find("synthetic-first").is_err());
                assert!(ui.find("synthetic-second").is_err());
                let bounds = ui.find(import_choice(index, label)).unwrap().bounds();
                let amount = (bounds.center_y() - size.1 / 2.0).max(0.0);
                ui.point_at(iced::Point::new(size.0 - 100.0, size.1 / 2.0));
                ui.simulate([iced::Event::Mouse(iced::mouse::Event::WheelScrolled {
                    delta: iced::mouse::ScrollDelta::Pixels { x: 0.0, y: -amount },
                })]);
                let target = ui.find(import_choice(index, label)).unwrap();
                let visible = target.visible_bounds().expect("import choice is hidden");
                assert!((visible.height - target.bounds().height).abs() < 0.1);
                assert!(visible.x >= 0.0 && visible.x + visible.width <= size.0);
                assert!(visible.y >= 0.0 && visible.y + visible.height <= size.1);
                ui.snapshot(&app.theme())
                    .unwrap()
                    .matches_image(format!(
                        "target/gui-artifacts/import-choice-{index}-{}x{}.png",
                        size.0 as u32, size.1 as u32
                    ))
                    .unwrap();
                ui.click(import_choice(index, label)).unwrap();
                ui.into_messages().collect::<Vec<_>>()
            };
            assert!(messages.iter().any(|message| matches!(test_message(message), Message::SetImportResolution(id, row, actual) if *id == preview_id && *row == index && actual == &resolution)));
            apply_messages(&mut app, messages);
            let Panel::Import(state) = &app.panel else {
                panic!("missing import panel")
            };
            assert_eq!(state.resolutions.get(&index), Some(&resolution));
            assert_eq!(
                state.preview.as_ref().unwrap().summary().source_duplicates,
                1
            );
        }
        capture(&app, "import-source-conflicts-resolved", size);
        let messages = {
            let mut ui = simulator(&app, size);
            scroll_picker_into_view(&mut ui, "执行导入", size);
            assert!(ui.find("执行导入").unwrap().visible_bounds().is_some());
            ui.click("执行导入").unwrap();
            ui.into_messages().collect::<Vec<_>>()
        };
        assert!(messages.iter().any(
            |message| matches!(test_message(message), Message::ApplyImport(id) if *id == preview_id)
        ));
        apply_messages(&mut app, messages);
        let vault = app.session.as_ref().unwrap();
        assert_eq!(vault.entries().len(), 1);
        assert_eq!(
            vault.reveal_secret(vault.entries()[0].id).unwrap().password,
            "synthetic-second"
        );
        let Panel::Import(state) = &app.panel else {
            panic!("missing import panel")
        };
        assert!(state.preview.is_none());
        assert!(state.resolutions.is_empty());
        assert!(app.revealed.is_none());
    }
}

#[test]
fn external_mutation_conflict_locks_and_revokes_ui_context() {
    let (_dir, mut app) = fixture(1);
    let id = app.session.as_ref().unwrap().entries()[0].id;
    let path = app.session.as_ref().unwrap().path().to_path_buf();
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.push(b' ');
    std::fs::write(&path, &bytes).unwrap();
    let _ = app.test_update(Message::CardAction(id, CardAction::Favorite));
    assert!(
        app.session.is_none(),
        "external conflict must revoke the stale session"
    );
    assert!(app.revealed.is_none());
    assert!(app.clipboard_session.is_none());
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[test]
fn recovery_inspection_errors_are_visible_and_block_open() {
    let (dir, mut app) = fixture(0);
    app.test_lock_with_status("synthetic");
    // A directory full of unrelated entries exceeds the bounded inspection
    // budget. An incomplete scan must never quietly allow modification.
    for index in 0..4100 {
        std::fs::write(dir.path().join(format!("unrelated-{index}")), b"").unwrap();
    }
    assert!(
        app.check_startup_recovery(),
        "incomplete recovery inspection was silently ignored"
    );
    app.test_drain_pending();
    assert!(app.recovery.is_some());
    assert!(app.status.contains("检查") || app.status.contains("恢复"));
}

#[test]
fn recovery_secrets_and_late_events_are_invalidated_by_lock_and_navigation() {
    let (_dir, mut app) = fixture(0);
    app.test_lock_with_status("synthetic");
    for transition in [
        Message::Lock,
        Message::AuthMode(true),
        Message::ToggleAuthOptions,
        Message::PlatformSecurity(SecurityEvent::MonitorFailed),
    ] {
        app.test_open_recovery();
        let generation = app.recovery.as_ref().unwrap().generation;
        let _ = app.test_update(Message::RecoveryPasswordChanged(
            generation,
            "synthetic-secret".into(),
        ));
        let _ = app.test_update(transition);
        assert!(
            app.recovery.is_none(),
            "navigation left recovery secrets live"
        );
        let _ = app.test_update(Message::RecoveryPasswordChanged(
            generation,
            "stale-secret".into(),
        ));
        let _ = app.test_update(Message::RestoreRecoveryCopy(generation));
        assert!(app.recovery.is_none());
        assert!(app.session.is_none());
    }
}

#[test]
fn recovery_selected_copy_wrong_password_corruption_collision_and_success() {
    let (dir, mut app) = fixture(1);
    let source = app.session.as_ref().unwrap().path().to_path_buf();
    let original = std::fs::read(&source).unwrap();
    let destination = dir.path().join("restored-new.pmvault");
    app.test_lock_with_status("synthetic");
    app.security_monitor_ready = true;
    app.test_open_recovery();
    let generation = app.recovery.as_ref().unwrap().generation;
    let _ = app.test_update(Message::RecoverySourceChanged(
        generation,
        source.display().to_string(),
    ));
    let _ = app.test_update(Message::RecoveryDestinationChanged(
        generation,
        destination.display().to_string(),
    ));
    let _ = app.test_update(Message::RecoveryPasswordChanged(
        generation,
        "wrong-password".into(),
    ));
    let _ = app.test_update(Message::RestoreRecoveryCopy(generation));
    assert!(!destination.exists());
    assert!(app.recovery.as_ref().unwrap().password.is_empty());
    let corrupt = dir.path().join("corrupt.pmvault");
    std::fs::write(&corrupt, b"corrupt synthetic").unwrap();
    let _ = app.test_update(Message::RecoverySourceChanged(
        generation,
        corrupt.display().to_string(),
    ));
    let _ = app.test_update(Message::RecoveryPasswordChanged(
        generation,
        "synthetic-only".into(),
    ));
    let _ = app.test_update(Message::RestoreRecoveryCopy(generation));
    assert!(!destination.exists());
    let _ = app.test_update(Message::RecoverySourceChanged(
        generation,
        source.display().to_string(),
    ));
    std::fs::write(&destination, b"another file").unwrap();
    let _ = app.test_update(Message::RecoveryPasswordChanged(
        generation,
        "gui-synthetic-master-only".into(),
    ));
    let _ = app.test_update(Message::RestoreRecoveryCopy(generation));
    assert_eq!(std::fs::read(&destination).unwrap(), b"another file");
    let new_destination = dir.path().join("actually-new.pmvault");
    let _ = app.test_update(Message::RecoveryDestinationChanged(
        generation,
        new_destination.display().to_string(),
    ));
    let _ = app.test_update(Message::RecoveryPasswordChanged(
        generation,
        "gui-synthetic-master-only".into(),
    ));
    let _ = app.test_update(Message::RestoreRecoveryCopy(generation));
    assert!(app.recovery.is_none());
    assert!(app.session.is_none());
    assert_eq!(std::fs::read(&new_destination).unwrap(), original);
    assert_eq!(std::fs::read(&source).unwrap(), original);
    let _ = app.test_update(Message::RestoreRecoveryCopy(generation));
    assert_eq!(std::fs::read(new_destination).unwrap(), original);
}
#[test]
fn mutation_and_import_uncertainty_lock_but_rejected_mutation_keeps_session() {
    use crate::storage::transaction::{Point, set_worker_hook};
    let (_dir, mut app) = fixture(1);
    let id = app.session.as_ref().unwrap().entries()[0].id;
    set_worker_hook(Point::BeforePublish, || {
        Err(AppError::Platform("synthetic staging rejection".into()))
    });
    let _ = app.test_update(Message::CardAction(id, CardAction::Favorite));
    assert!(app.session.is_some());
    assert!(!app.session.as_ref().unwrap().entry(id).unwrap().favorite);
    set_worker_hook(Point::AfterPublish, || {
        Err(AppError::Platform("synthetic uncertain sync".into()))
    });
    let _ = app.test_update(Message::CardAction(id, CardAction::Favorite));
    assert!(app.session.is_none());
    assert!(app.recovery_notice.is_some());
    let (dir, mut app) = fixture(0);
    let csv = dir.path().join("import.csv");
    std::fs::write(
        &csv,
        "name,url,username,password,note\nSynthetic,https://example.test,u,p,\n",
    )
    .unwrap();
    let _ = app.test_update(Message::OpenImport);
    let _ = app.test_update(Message::ImportPathChanged(csv.display().to_string()));
    let _ = app.test_update(Message::AnalyzeImport);
    let id = match &app.panel {
        Panel::Import(s) => s.preview.as_ref().unwrap().id(),
        _ => panic!(),
    };
    set_worker_hook(Point::AfterPublish, || {
        Err(AppError::Platform("synthetic uncertain import".into()))
    });
    let _ = app.test_update(Message::ApplyImport(id));
    assert!(app.session.is_none());
    assert!(matches!(app.panel, Panel::Vault));
    assert!(app.recovery.is_some());
    let _ = app.test_update(Message::ApplyImport(id));
    assert!(app.session.is_none());
}
#[test]
fn recovery_picker_late_results_and_pending_restore_are_rejected() {
    let (_dir, mut app) = fixture(0);
    app.test_lock_with_status("synthetic");
    app.test_open_recovery();
    let generation = app.recovery.as_ref().unwrap().generation;
    let _ = app.begin_picker(picker::Purpose::RecoverySource);
    let _ = app.test_update(Message::RestoreRecoveryCopy(generation));
    assert!(app.recovery.as_ref().unwrap().source.is_empty());
    app.dismiss_recovery();
    app.test_open_recovery();
    // Native picker-specific late-result assertions also live in picker tests.
    assert_ne!(app.recovery.as_ref().unwrap().generation, generation);
    let _ = app.test_update(Message::RecoverySourceChanged(
        generation,
        "stale.pmvault".into(),
    ));
    assert!(app.recovery.as_ref().unwrap().source.is_empty());
}
#[cfg(windows)]
#[test]
fn recovery_does_not_derive_or_create_before_windows_monitor_ready() {
    let (dir, mut app) = fixture(0);
    let source = app.session.as_ref().unwrap().path().to_path_buf();
    app.test_lock_with_status("synthetic");
    app.test_open_recovery();
    app.security_monitor_ready = false;
    let state = app.recovery.as_mut().unwrap();
    state.source = source.display().to_string();
    state.destination = dir
        .path()
        .join("must-not-exist.pmvault")
        .display()
        .to_string();
    *state.password = "gui-synthetic-master-only".into();
    let generation = state.generation;
    let _ = app.test_update(Message::RestoreRecoveryCopy(generation));
    assert!(!dir.path().join("must-not-exist.pmvault").exists());
    assert!(app.recovery.as_ref().unwrap().password.is_empty());
    assert!(app.status.contains("监控"));
}

#[test]
#[ignore = "headless GUI regression"]
fn gui_locked_recovery_interactions_at_three_sizes() {
    for size in SIZES {
        let (dir, mut app) = fixture(1);
        let source = app.session.as_ref().unwrap().path().to_path_buf();
        app.test_lock_with_status("synthetic recovery review");
        app.security_monitor_ready = true;
        let mut ui = simulator(&app, size);
        ui.click("检查恢复副本").unwrap();
        let messages = ui.into_messages().collect();
        apply_messages(&mut app, messages);
        assert!(app.recovery.is_some());
        let mut ui = simulator(&app, size);
        ui.click("选择此副本").unwrap();
        let messages = ui.into_messages().collect();
        apply_messages(&mut app, messages);
        assert!(!app.recovery.as_ref().unwrap().source.is_empty());
        let mut ui = simulator(&app, size);
        ui.click("选择新文件位置").unwrap();
        let messages = ui.into_messages().collect();
        apply_messages(&mut app, messages);
        assert!(app.picker_pending.is_some());
        // The native OS dialog is not created by iced_test. Cancel its slot and
        // continue using real text-input/button events in the locked surface.
        app.picker_pending = None;
        let destination = dir.path().join("gui-recovered.pmvault");
        let mut ui = simulator(&app, size);
        ui.click(selector::id("recovery-destination")).unwrap();
        ui.typewrite(destination.to_str().unwrap());
        let messages = ui.into_messages().collect();
        apply_messages(&mut app, messages);
        let mut ui = simulator(&app, size);
        ui.click(selector::id("recovery-password")).unwrap();
        ui.typewrite("wrong-password");
        let messages = ui.into_messages().collect();
        apply_messages(&mut app, messages);
        capture(&app, "locked-recovery-selected", size);
        let mut ui = simulator(&app, size);
        ui.click("验证并恢复到新文件").unwrap();
        let messages = ui.into_messages().collect();
        apply_messages(&mut app, messages);
        assert!(!destination.exists());
        assert!(app.recovery.as_ref().unwrap().password.is_empty());
        capture(&app, "locked-recovery-wrong-password", size);
        let mut ui = simulator(&app, size);
        ui.click(selector::id("recovery-password")).unwrap();
        ui.typewrite("gui-synthetic-master-only");
        let messages = ui.into_messages().collect();
        apply_messages(&mut app, messages);
        let mut ui = simulator(&app, size);
        ui.click("验证并恢复到新文件").unwrap();
        let messages = ui.into_messages().collect();
        apply_messages(&mut app, messages);
        assert!(destination.exists());
        assert!(app.recovery.is_none());
        assert!(app.session.is_none());
        assert!(source.exists());
    }
}

#[test]
fn confirmed_restore_adopts_verified_session_or_locks_on_uncertainty() {
    use crate::storage::transaction::{Point, set_worker_hook};
    for point in [Some(Point::BeforePublish), Some(Point::AfterPublish), None] {
        let (dir, mut app) = fixture(1);
        let old_id = app.session.as_ref().unwrap().vault_id();
        let source = dir.path().join("confirmed-source.pmvault");
        let source_session = VaultSession::create(&source, "restore-synthetic-only").unwrap();
        let expected_id = source_session.vault_id();
        let source_bytes = std::fs::read(&source).unwrap();
        let _ = app.test_update(Message::OpenSettings);
        let _ = app.test_update(Message::RestorePathChanged(source.display().to_string()));
        let _ = app.test_update(Message::RestorePasswordChanged(
            "restore-synthetic-only".into(),
        ));
        let _ = app.test_update(Message::ConfirmRestoreChanged(true));
        if let Some(point) = point {
            set_worker_hook(point, || {
                Err(AppError::Platform("synthetic restore boundary".into()))
            });
        }
        let _ = app.test_update(Message::RestoreBackup);
        match point {
            Some(Point::BeforePublish) => {
                assert_eq!(app.session.as_ref().unwrap().vault_id(), old_id);
                assert!(matches!(&app.panel,Panel::Settings(s) if s.restore_password.is_empty()));
            }
            Some(_) => {
                assert!(app.session.is_none());
                assert!(app.recovery.is_some());
                assert!(matches!(app.panel, Panel::Vault));
            }
            None => {
                assert_eq!(app.session.as_ref().unwrap().vault_id(), expected_id);
                assert!(matches!(app.panel, Panel::Vault));
                app.session.as_ref().unwrap().verify_current_file().unwrap();
            }
        }
        assert_eq!(std::fs::read(&source).unwrap(), source_bytes);
        let _ = app.test_update(Message::RestoreBackup);
        assert!(point != Some(Point::AfterPublish) || app.session.is_none());
    }
}

#[test]
fn review_c1_manual_path_edit_does_not_navigate_or_clear_passwords() {
    for creating in [false, true] {
        let mut app = App::initial();
        app.creating = creating;
        app.auth_options_open = true;
        app.master_password = "synthetic-input".into();
        app.confirm_password = "synthetic-confirm".into();
        for path in [
            "",
            "/",
            ".",
            "/synthetic-not-yet-existing/",
            "complete.pmvault",
        ] {
            let _ = app.test_update(Message::VaultPathChanged(path.into()));
            assert!(
                app.recovery.is_none(),
                "manual input was interpreted as open"
            );
            assert_eq!(app.vault_path, path);
            assert_eq!(app.master_password, "synthetic-input");
            assert_eq!(app.confirm_password, "synthetic-confirm");
        }
    }
}
#[test]
fn review_c2_recovery_keeps_clipboard_warning_after_uncertainty() {
    let (_dir, mut app) = fixture(1);
    let id = app.session.as_ref().unwrap().entries()[0].id;
    let _ = app.test_update(Message::PlatformSecurity(
        SecurityEvent::ClipboardCleanupFailed,
    ));
    crate::storage::transaction::set_worker_hook(
        crate::storage::transaction::Point::AfterPublish,
        || Err(AppError::Platform("synthetic uncertainty".into())),
    );
    let _ = app.test_update(Message::CardAction(id, CardAction::Favorite));
    assert!(app.session.is_none());
    assert!(app.recovery.is_some());
    app.status = "a later error must not hide the warning".into();
    let mut ui = simulator(&app, (1280.0, 800.0));
    ui.click("我已手动处理剪贴板")
        .expect("persistent clipboard action disappeared in recovery");
}
#[test]
fn review_c3_save_verification_missing_or_unsupported_source_locks() {
    for mode in ["missing", "directory", "changed"] {
        let (_dir, mut app) = fixture(1);
        let id = app.session.as_ref().unwrap().entries()[0].id;
        app.selected = Some(id);
        app.context_open = true;
        app.toggle_reveal();
        assert!(app.revealed.is_some());
        let path = app.session.as_ref().unwrap().path().to_path_buf();
        if mode == "changed" {
            let mut bytes = std::fs::read(&path).unwrap();
            bytes.push(b' ');
            std::fs::write(&path, bytes).unwrap();
        } else {
            std::fs::remove_file(&path).unwrap();
            if mode == "directory" {
                std::fs::create_dir(&path).unwrap();
            }
        }
        let error = app
            .session
            .as_ref()
            .unwrap()
            .verify_current_file()
            .unwrap_err();
        assert!(
            error.invalidates_session(),
            "missing/type source failure was not invalidating"
        );
        let _ = app.test_update(Message::Save);
        assert!(app.session.is_none());
        assert!(app.revealed.is_none());
        assert!(app.clipboard_session.is_none());
        assert!(matches!(app.panel, Panel::Vault));
        assert!(app.recovery.is_some());
        let expected = match mode {
            "missing" => crate::storage::recovery::CurrentObservation::Missing,
            "directory" => crate::storage::recovery::CurrentObservation::Unreadable,
            _ => crate::storage::recovery::CurrentObservation::Other,
        };
        assert_eq!(app.recovery_notice.as_ref().unwrap().current, expected);
    }
}

fn scroll_to_bottom(ui: &mut Simulator<'_, Message>, id: &str) {
    let bounds = ui.find(selector::id(id.to_owned())).unwrap().bounds();
    ui.point_at(bounds.center());
    ui.simulate([iced::Event::Mouse(iced::mouse::Event::WheelScrolled {
        delta: iced::mouse::ScrollDelta::Lines { x: 0.0, y: -100.0 },
    })]);
}
#[test]
#[ignore = "headless GUI regression"]
fn gui_review_manual_paths_remain_editable_after_picker_fallback() {
    for size in SIZES {
        for creating in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(if creating {
                "created-by-manual-path.pmvault"
            } else {
                "opened-by-manual-path.pmvault"
            });
            if !creating {
                VaultSession::create(&path, "manual-synthetic-only").unwrap();
            }
            let mut app = App::initial();
            app.creating = creating;
            app.security_monitor_ready = true;
            if !creating {
                let mut ui = simulator(&app, size);
                ui.click("更换保险库文件").unwrap();
                let messages = ui.into_messages().collect();
                apply_messages(&mut app, messages);
            }
            app.master_password = "manual-synthetic-only".into();
            if creating {
                app.confirm_password = app.master_password.clone();
            }
            let purpose = if creating {
                picker::Purpose::CreateVault
            } else {
                picker::Purpose::OpenVault
            };
            let mut ui = simulator(&app, size);
            ui.click(if creating {
                "选择新建位置"
            } else {
                "选择保险库文件"
            })
            .unwrap();
            let messages = ui.into_messages().collect();
            apply_messages(&mut app, messages);
            let pending = app.picker_pending.unwrap();
            app.finish_picker(
                pending.id,
                if creating {
                    Err("synthetic native provider unavailable".into())
                } else {
                    Ok(None)
                },
            );
            let mut ui = simulator(&app, size);
            ui.click(selector::id(format!("path-{purpose:?}"))).unwrap();
            command_key(&mut ui, "a");
            ui.tap_key(keyboard::key::Named::Backspace);
            let messages = ui.into_messages().collect();
            apply_messages(&mut app, messages);
            assert!(app.recovery.is_none());
            assert!(app.vault_path.is_empty());
            assert_eq!(app.master_password, "manual-synthetic-only");
            if creating {
                assert_eq!(app.confirm_password, "manual-synthetic-only");
            }
            let mut ui = simulator(&app, size);
            ui.click(selector::id(format!("path-{purpose:?}"))).unwrap();
            ui.typewrite(path.to_str().unwrap());
            let messages = ui.into_messages().collect();
            apply_messages(&mut app, messages);
            assert_eq!(app.vault_path, path.display().to_string());
            assert!(app.recovery.is_none());
            capture(
                &app,
                if creating {
                    "review-manual-create-path"
                } else {
                    "review-manual-open-path"
                },
                size,
            );
            let mut ui = simulator(&app, size);
            scroll_to_bottom(&mut ui, "auth-scroll");
            ui.click(if creating {
                "创建并进入"
            } else {
                "解 锁"
            })
            .unwrap();
            let messages = ui.into_messages().collect();
            apply_messages(&mut app, messages);
            assert!(app.session.is_some(), "{}", app.status);
        }
    }
}
#[test]
#[ignore = "headless GUI regression"]
fn gui_review_recovery_clipboard_warning_survives_password_error() {
    for size in SIZES {
        let (dir, mut app) = fixture(1);
        app.security_monitor_ready = true;
        let id = app.session.as_ref().unwrap().entries()[0].id;
        let _ = app.test_update(Message::PlatformSecurity(
            SecurityEvent::ClipboardCleanupFailed,
        ));
        crate::storage::transaction::set_worker_hook(
            crate::storage::transaction::Point::AfterPublish,
            || {
                Err(AppError::Platform(
                    "synthetic storage uncertainty; diagnostic deliberately persists".into(),
                ))
            },
        );
        let _ = app.test_update(Message::CardAction(id, CardAction::Favorite));
        assert!(app.recovery.is_some());
        let mut ui = simulator(&app, size);
        ui.click("我已手动处理剪贴板").unwrap();
        let stale: Vec<_> = ui.into_messages().collect();
        let _ = app.test_update(Message::PlatformSecurity(
            SecurityEvent::ClipboardCleanupFailed,
        ));
        apply_messages(&mut app, stale);
        assert!(app.clipboard_cleanup_failed);
        let mut ui = simulator(&app, size);
        ui.click("选择此副本").unwrap();
        let messages = ui.into_messages().collect();
        apply_messages(&mut app, messages);
        let destination = dir.path().join("clipboard-warning-new.pmvault");
        let mut ui = simulator(&app, size);
        scroll_to_bottom(&mut ui, "recovery-scroll");
        ui.click(selector::id("recovery-destination")).unwrap();
        ui.typewrite(destination.to_str().unwrap());
        let messages = ui.into_messages().collect();
        apply_messages(&mut app, messages);
        let mut ui = simulator(&app, size);
        scroll_to_bottom(&mut ui, "recovery-scroll");
        ui.click(selector::id("recovery-password")).unwrap();
        ui.typewrite("wrong-password");
        let messages = ui.into_messages().collect();
        apply_messages(&mut app, messages);
        let mut ui = simulator(&app, size);
        scroll_to_bottom(&mut ui, "recovery-scroll");
        ui.click("验证并恢复到新文件").unwrap();
        let messages = ui.into_messages().collect();
        apply_messages(&mut app, messages);
        assert!(!destination.exists());
        assert!(app.clipboard_cleanup_failed);
        assert!(app.recovery.as_ref().unwrap().password.is_empty());
        capture(&app, "review-recovery-clipboard-warning", size);
        let mut ui = simulator(&app, size);
        ui.click("我已手动处理剪贴板").unwrap();
        let messages = ui.into_messages().collect();
        apply_messages(&mut app, messages);
        assert!(!app.clipboard_cleanup_failed);
    }
}

#[test]
fn review_c3_matching_source_verification_keeps_live_session() {
    let (_dir, mut app) = fixture(1);
    let _ = app.test_update(Message::Save);
    assert!(app.session.is_some());
    assert!(app.clipboard_session.is_some());
    assert!(app.recovery.is_none());
    assert!(app.status.contains("校验通过"));
}

#[test]
fn export_close_requests_reach_the_app() {
    assert!(
        safety::runtime_event(
            iced::Event::Window(iced::window::Event::CloseRequested),
            iced::event::Status::Ignored,
            iced::window::Id::unique(),
        )
        .is_some(),
        "normal close must be routed through the plaintext warning guard"
    );
}

#[test]
#[ignore = "headless GUI regression"]
fn gui_export_failure_warning_survives_lock() {
    let (dir, mut app) = fixture(1);
    app.session.as_mut().unwrap().body_mut().entries[0]
        .secret
        .ciphertext
        .clear();
    let _ = app.test_update(Message::OpenSettings);
    let _ = app.test_update(Message::CsvPathChanged(
        dir.path().join("partial.csv").display().to_string(),
    ));
    let _ = app.test_update(Message::ConfirmPlaintextChanged(true));
    let _ = app.test_update(Message::ExportPlaintextCsv);
    let _ = app.test_update(Message::Lock);
    let mut ui = simulator(&app, SIZES[0]);
    assert!(
        ui.find("明文导出未完成，文件可能仍然存在").is_ok(),
        "a retained plaintext warning must survive lock and status replacement"
    );
}

fn install_long_export_notice(app: &mut App) -> String {
    let path = format!(
        "/synthetic/{}/明文文件-尾部.csv",
        "非常长的用户选择目录/".repeat(35)
    );
    app.finish_plaintext_export(Err(AppError::Export(Box::new(
        crate::export::ExportFailure {
            target: path.clone().into(),
            stage: crate::export::Stage::VerifyPath,
            cause: crate::export::Cause::IdentityChanged,
            output: crate::export::OutputDisposition::MayRemain {
                observation: crate::export::Observation {
                    target: crate::export::ObservedTarget::TargetDifferent,
                    error: None,
                },
            },
        },
    ))));
    path
}

#[test]
#[ignore = "headless GUI regression"]
fn gui_export_warning_navigation_recovery_and_close_at_all_sizes() {
    for size in SIZES {
        let (_dir, mut app) = fixture(1);
        let full_path = install_long_export_notice(&mut app);
        let generation = app.export_notice.as_ref().unwrap().generation;
        for phase in ["unlocked", "locked", "recovery"] {
            if phase == "locked" {
                let _ = app.test_update(Message::Lock);
            }
            if phase == "recovery" {
                let _ = app.test_update(Message::OpenRecovery);
            }
            let mut ui = simulator(&app, size);
            assert!(
                ui.find("明文导出未完成，文件可能仍然存在")
                    .unwrap()
                    .visible_bounds()
                    .is_some()
            );
            let button = ui.find("我已了解并会处理可能残留的明文").unwrap();
            assert!(button.visible_bounds().is_some());
            assert!(button.bounds().y + button.bounds().height <= size.1);
            let path = ui.find(full_path.as_str()).unwrap();
            assert_finite_rect(path.bounds());
            assert!(
                path.bounds().width < size.0 - 35.0,
                "full path must wrap within the visible rail"
            );
            let viewport = ui
                .find(selector::id("export-notice-scroll"))
                .unwrap()
                .bounds();
            ui.point_at(viewport.center());
            ui.simulate([iced::Event::Mouse(iced::mouse::Event::WheelScrolled {
                delta: iced::mouse::ScrollDelta::Pixels {
                    x: 0.0,
                    y: -10000.0,
                },
            })]);
            assert!(
                ui.find("失败阶段：VerifyPath · output identity does not match")
                    .unwrap()
                    .visible_bounds()
                    .is_some(),
                "tail of full path/details must be scroll accessible"
            );
            capture(&app, &format!("export-warning-{phase}"), size);
            assert_eq!(app.export_notice.as_ref().unwrap().generation, generation);
        }
        let _ = app.test_update(Message::CloseRequested(iced::window::Id::unique()));
        assert!(app.session.is_none());
        capture(&app, "export-warning-close", size);
        let mut ui = simulator(&app, size);
        for label in ["保持打开", "我理解明文可能残留，仍然退出"] {
            let target = ui.find(label).unwrap();
            assert!(target.visible_bounds().is_some());
            assert!(target.bounds().y + target.bounds().height <= size.1);
        }
        ui.click("保持打开").unwrap();
        let messages = ui.into_messages().collect();
        apply_messages(&mut app, messages);
        assert!(app.export_close_prompt.is_none());
        assert!(app.session.is_none());
        assert!(app.export_notice.is_some());
        let mut ui = simulator(&app, size);
        ui.click("我已了解并会处理可能残留的明文").unwrap();
        let messages = ui.into_messages().collect();
        apply_messages(&mut app, messages);
        assert!(app.export_notice.is_none());
        install_long_export_notice(&mut app);
        let _ = app.test_update(Message::AcknowledgeExportNotice(generation));
        assert!(app.export_notice.is_some());
        let _ = app.test_update(Message::CloseRequested(iced::window::Id::unique()));
        let mut ui = simulator(&app, size);
        ui.click("我理解明文可能残留，仍然退出").unwrap();
        let messages: Vec<_> = ui.into_messages().collect();
        assert_eq!(messages.len(), 1);
        for message in messages {
            assert!(app.test_update(message).units() > 0);
        }
        assert!(app.export_close_prompt.is_none());
        assert!(app.export_notice.is_some());
    }
}

#[test]
#[ignore = "headless GUI regression"]
fn gui_export_repeat_button_is_disabled_until_current_notice_acknowledged() {
    let (_dir, mut app) = fixture(1);
    let _ = app.test_update(Message::OpenSettings);
    let _ = app.test_update(Message::ConfirmPlaintextChanged(true));
    install_long_export_notice(&mut app);
    let mut ui = simulator(&app, SIZES[0]);
    scroll_picker_into_view(&mut ui, "导出明文 CSV", SIZES[0]);
    ui.click("导出明文 CSV").unwrap();
    assert!(
        !ui.into_messages()
            .any(|message| matches!(test_message(&message), Message::ExportPlaintextCsv))
    );
    let generation = app.export_notice.as_ref().unwrap().generation;
    let _ = app.test_update(Message::AcknowledgeExportNotice(generation));
    let mut ui = simulator(&app, SIZES[0]);
    scroll_picker_into_view(&mut ui, "导出明文 CSV", SIZES[0]);
    ui.click("导出明文 CSV").unwrap();
    assert!(
        ui.into_messages()
            .any(|message| matches!(test_message(&message), Message::ExportPlaintextCsv))
    );
}

#[test]
#[ignore = "headless GUI regression"]
fn gui_export_close_warning_keeps_clipboard_acknowledgment_usable() {
    for size in SIZES {
        let (_dir, mut app) = fixture(0);
        install_long_export_notice(&mut app);
        app.note_clipboard_cleanup_failure();
        let _ = app.test_update(Message::CloseRequested(iced::window::Id::unique()));
        capture(&app, "export-warning-close-clipboard", size);
        let mut ui = simulator(&app, size);
        let button = ui.find("我已手动处理剪贴板").unwrap();
        assert!(button.visible_bounds().is_some());
        assert!(button.bounds().y + button.bounds().height <= size.1);
        ui.click("我已手动处理剪贴板").unwrap();
        let messages = ui.into_messages().collect();
        apply_messages(&mut app, messages);
        assert!(!app.clipboard_cleanup_failed);
        assert!(app.export_notice.is_some());
        assert!(app.export_close_prompt.is_some());
        assert!(app.session.is_none());
    }
}
