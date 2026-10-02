use super::*;
use crate::domain::EntryDraft;
use iced_test::{Simulator, selector};

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

#[test]
#[ignore = "headless GUI regression"]
fn gui_native_picker_entry_points_are_available() {
    let (_dir, mut app) = fixture(0);
    let session = app.session.take();
    for size in SIZES {
        for creating in [false, true] {
            let _ = app.update(Message::AuthMode(creating));
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
                matches!(messages.first(), Some(Message::PickPath(actual)) if *actual == purpose)
            );
            apply_messages(&mut app, messages);
            assert!(app.picker_pending.is_some());
            let mut ui = simulator(&app, size);
            ui.click(label).unwrap();
            assert_eq!(ui.into_messages().count(), 0);
            let _ = app.update(Message::PathPicked(app.picker_sequence, Ok(None)));
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
            let _ = app.update(if purpose == picker::Purpose::Import {
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
                matches!(messages.first(), Some(Message::PickPath(actual)) if *actual == purpose)
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
            let _ = app.update(Message::PathPicked(app.picker_sequence, Ok(None)));
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
    let _ = app.update(Message::OpenSettings);
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
            messages.first(),
            Some(Message::IdleTimeoutChanged(1))
        ));
        apply_messages(&mut app, messages);
        assert_eq!(app.idle_minutes, 1);
        let _ = app.update(Message::IdleTimeoutChanged(5));
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
            messages.first(),
            Some(Message::ClipboardTimeoutChanged(15))
        ));
        apply_messages(&mut app, messages);
        assert_eq!(app.clipboard_seconds, 15);
        let _ = app.update(Message::ClipboardTimeoutChanged(30));
    }
}

#[test]
#[ignore = "headless GUI regression"]
fn gui_editor_password_keyboard_copy_uses_managed_pipeline() {
    let (_dir, mut app) = fixture(0);
    let _ = app.update(Message::NewEntry);
    let _ = app.update(Message::EditorPasswordChanged("synthetic-键盘🦀".into()));
    let _ = app.update(Message::ToggleEditorPasswordVisible(app.context_generation));
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
                !messages
                    .iter()
                    .any(|message| matches!(message, Message::EditorPasswordChanged(_))),
                "cut removed the draft before native copy success"
            );
        }
        assert!(messages.iter().any(|message| {
            match message {
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
            messages.iter().any(|message| matches!(message,
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
    let _ = app.update(Message::PlatformSecurity(
        SecurityEvent::ClipboardCleanupFailed,
    ));
    let _ = app.update(Message::PlatformSecurity(SecurityEvent::SystemSuspending));
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
    let _ = app.update(Message::NewEntry);
    let _ = app.update(Message::EditorPasswordChanged("synthetic-original".into()));
    let _ = app.update(Message::ToggleEditorPasswordVisible(app.context_generation));
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
            assert!(messages.iter().any(|message| matches!(message,
                Message::CopyEditorPasswordSelection(_, _, Some(cut)) if cut.original.as_str() == "synthetic-originalZ"
            )), "cut captured stale view-build text");
        } else {
            assert!(
                messages.iter().any(|message| matches!(message,
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
            message,
            Message::EditorPasswordChanged(_) | Message::CopyEditorPasswordSelection(..)
        )),
        "cut without selection changed a password"
    );
    let _ = app.update(Message::EditorPasswordChanged("ab👩‍💻e\u{301}cd".into()));
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
        ui.into_messages().any(|message| matches!(message,
            Message::CopyEditorPasswordSelection(_, value, Some(cut))
            if value.as_str() == "b👩‍💻" && cut.replacement.as_str() == "ae\u{301}cd"
        )),
        "cut did not respect emoji/combining grapheme boundaries"
    );
    let _ = app.update(Message::ToggleEditorPasswordVisible(app.context_generation));
    let mut ui = simulator(&app, SIZES[0]);
    ui.click(selector::id("editor-password-input")).unwrap();
    command_key(&mut ui, "a");
    command_key(&mut ui, "c");
    command_key(&mut ui, "x");
    assert!(
        !ui.into_messages().any(|message| matches!(
            message,
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
    let _ = app.update(Message::OpenImport);
    let _ = app.update(Message::ImportPathChanged(source.display().to_string()));
    let _ = app.update(Message::AnalyzeImport);
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
    let _ = app.update(Message::AnalyzeImport);
    let _ = app.update(old_toggle);
    let _ = app.update(old_decision);
    let Panel::Import(state) = &app.panel else {
        panic!("missing import panel")
    };
    assert!(state.apply_updates);
    assert!(state.resolutions.is_empty());
    let _ = app.update(old_apply);
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
                let _ = app.update(Message::ImportPathChanged("other.csv".into()));
            }
            1 => {
                let _ = app.update(Message::CancelPanel);
                let _ = app.update(Message::OpenImport);
            }
            _ => {
                let _ = app.update(Message::Lock);
            }
        }
        let _ = app.update(Message::SetImportResolution(
            old_id,
            0,
            ConflictResolution::KeepBoth,
        ));
        let _ = app.update(Message::ImportApplyUpdatesChanged(old_id, false));
        let _ = app.update(Message::ApplyImport(old_id));
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
    let _ = app.update(Message::SetImportResolution(
        id,
        0,
        ConflictResolution::KeepBoth,
    ));
    let _ = app.update(Message::SetImportResolution(
        id,
        99,
        ConflictResolution::KeepLocal,
    ));
    let Panel::Import(state) = &app.panel else {
        panic!("missing import panel")
    };
    assert!(state.resolutions.is_empty());
    let _ = app.update(Message::ApplyImport(id));
    let Panel::Import(state) = &app.panel else {
        panic!("missing import panel")
    };
    assert!(state.preview.is_none());
    assert!(state.resolutions.is_empty());
    let vault = app.session.as_ref().unwrap();
    assert_eq!(vault.entries().len(), 1);
    let revision = vault.revision();
    let _ = app.update(Message::ApplyImport(id));
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
        let _ = app.update(Message::ImportApplyUpdatesChanged(id, false));
        let Panel::Import(state) = &app.panel else {
            panic!("missing import panel")
        };
        assert!(!state.apply_updates);
        let _ = app.update(if path_edit {
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
        let _ = app.update(Message::OpenImport);
        let _ = app.update(Message::ImportPathChanged(source.display().to_string()));
        let _ = app.update(Message::AnalyzeImport);
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
            assert!(messages.iter().any(|message| matches!(message, Message::SetImportResolution(id, row, actual) if *id == preview_id && *row == index && actual == &resolution)));
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
        assert!(
            messages
                .iter()
                .any(|message| matches!(message, Message::ApplyImport(id) if *id == preview_id))
        );
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
