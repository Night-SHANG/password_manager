use super::*;
use crate::domain::EntryDraft;
use iced_test::{Simulator, selector};

const SIZES: [(f32, f32); 3] = [(960.0, 640.0), (1280.0, 800.0), (1600.0, 900.0)];

fn fixture(count: usize) -> (tempfile::TempDir, App) {
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
        let _ = app.update(message);
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
    let _ = app.update(Message::CategoryNameChanged("工作".to_string()));
    let _ = app.update(Message::AddCategory);
    app.session.as_mut().unwrap().body_mut().entries[0].category = "工作".to_string();
    app.session.as_mut().unwrap().save().unwrap();
    let _ = app.update(Message::RequestDeleteCategory("工作".to_string()));
    let _ = app.update(Message::ConfirmDeleteCategory("工作".to_string()));
    let vault = app.session.as_ref().unwrap();
    assert_eq!(vault.entries().len(), 1);
    assert_eq!(vault.entries()[0].category, "其他");
    assert!(!vault.categories().iter().any(|name| name == "工作"));
    vault.verify_current_file().unwrap();
}

#[test]
fn lock_drops_editor_import_preview_and_revealed_state() {
    let (_dir, mut app) = fixture(1);
    let _ = app.update(Message::NewEntry);
    let _ = app.update(Message::EditorPasswordChanged(
        "synthetic-buffer".to_string(),
    ));
    let _ = app.update(Message::Lock);
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
    let _ = app.update(Message::SelectEntry(ids[0]));
    let _ = app.update(Message::CardAction(ids[1], CardAction::Favorite));
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
    let _ = app.update(Message::SearchChanged("does-not-match".to_string()));
    let _ = app.update(Message::CardAction(ids[1], CardAction::Favorite));
    assert!(
        app.session
            .as_ref()
            .unwrap()
            .entry(ids[1])
            .unwrap()
            .favorite
    );
    let _ = app.update(Message::Lock);
    let _ = app.update(Message::CardAction(ids[1], CardAction::CopyPassword));
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
            matches!(m, Message::CardAction(id, value) if *id == ids[1] && *value == action)
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
    let _ = app.update(Message::EditorNameChanged("GUI 新条目".to_string()));
    let _ = app.update(Message::EditorPasswordChanged(
        "synthetic-gui-only".to_string(),
    ));
    click(&mut app, "保存条目");
    assert!(matches!(&app.panel, Panel::Vault));
    assert_eq!(app.session.as_ref().unwrap().active_entries().count(), 4);
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
    let _ = app.update(Message::ContextEntry(id));
    capture(&app, "context-actions", SIZES[0]);
    click(&mut app, "显示密码");
    assert!(app.revealed.is_some());
    click(&mut app, "关闭菜单");
    assert!(!app.context_open);
    assert!(app.revealed.is_none());
    let _ = app.update(Message::DarkModeChanged(true));
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
                    let _ = app.update(Message::SearchChanged("absent-entry".into()));
                }
                2 => {
                    let _ = app.update(Message::SetNav(NavFilter::Favorites));
                }
                3 => {
                    let _ = app.update(Message::OpenSettings);
                }
                4 => {
                    let _ = app.update(Message::Lock);
                }
                _ => unreachable!(),
            }
            let panel = std::mem::discriminant(&app.panel);
            let _ = app.update(action(id));
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
        let _ = app.update(Message::ContextEntry(id));
        let _ = app.update(Message::ToggleReveal);
        assert!(app.revealed.is_some());
        let action_name = format!("{action:?}");
        let _ = app.update(action);
        assert!(!app.context_open, "details remained open: {action_name}");
        assert!(app.revealed.is_none(), "plaintext retained: {action_name}");
    }
}

#[test]
fn reveal_requires_a_visible_entry_in_open_details() {
    let (_dir, mut app) = fixture(1);
    let id = app.session.as_ref().unwrap().entries()[0].id;
    let _ = app.update(Message::SelectEntry(id));
    let _ = app.update(Message::ToggleReveal);
    assert!(app.revealed.is_none(), "revealed without open details");
    let _ = app.update(Message::ContextEntry(id));
    let _ = app.update(Message::ToggleReveal);
    assert!(app.revealed.is_some());
    let _ = app.update(Message::CloseContext);
    let _ = app.update(Message::ToggleReveal);
    assert!(app.revealed.is_none(), "delayed reveal after close");
    let _ = app.update(Message::SearchChanged("absent-entry".into()));
    let _ = app.update(Message::ToggleReveal);
    assert!(app.revealed.is_none());
    let _ = app.update(Message::Lock);
    let _ = app.update(Message::ToggleReveal);
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
        let _ = app.update(Message::ContextEntry(id));
        let _ = app.update(Message::SearchChanged("absent-entry".into()));
        let task = app.update(action);
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
            let _ = app.update(Message::ContextEntry(ids[0]));
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
                let _ = app.update(Message::ContextEntry(ids[1]));
            } else {
                let _ = app.update(Message::CloseContext);
                if destination == 2 {
                    let _ = app.update(Message::ContextEntry(ids[0]));
                }
            }
            for message in messages {
                assert_eq!(
                    app.update(message).units(),
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
