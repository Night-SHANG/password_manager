use super::*;
use crate::domain::EntryDraft;
use iced_test::{Simulator, selector};

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

fn click(app: &mut App, label: &str) {
    let messages: Vec<_> = {
        let mut ui = simulator(app, (1280.0, 800.0));
        ui.click(label).unwrap();
        ui.into_messages().collect()
    };
    assert!(!messages.is_empty(), "click did not emit a message");
    for message in messages {
        let _ = app.update(message);
    }
}

fn capture(app: &App, name: &str, size: (f32, f32)) {
    let directory = std::path::PathBuf::from("target/gui-artifacts");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join(format!("{name}-{}x{}.png", size.0 as u32, size.1 as u32));
    // These are review captures, not accepted golden images. CI removes the
    // output directory before this test; generation is NOT a visual approval.
    simulator(app, size)
        .snapshot(&app.theme())
        .unwrap()
        .matches_image(path)
        .unwrap();
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
#[ignore = "Headless UI suite; run explicitly with the tiny-skia backend in CI"]
fn gui_authentication_modes_and_captures() {
    let mut app = App::initial();
    assert!(!app.dark_mode);
    assert!(simulator(&app, (960.0, 640.0)).find("确认主密码").is_err());
    capture(&app, "open-vault", (960.0, 640.0));
    click(&mut app, "创建新保险库");
    assert!(app.creating);
    assert!(simulator(&app, (960.0, 640.0)).find("确认主密码").is_ok());
    capture(&app, "create-vault", (960.0, 640.0));
    click(&mut app, "打开保险库");
    assert!(!app.creating);
}

#[test]
#[ignore = "Headless UI suite; run explicitly with the tiny-skia backend in CI"]
fn gui_table_selection_search_and_editor_buttons() {
    let (_dir, mut app) = fixture(3);
    {
        let mut ui = simulator(&app, (1280.0, 800.0));
        for heading in ["名称", "网站", "用户名", "密码", "分类"] {
            assert!(ui.find(heading).is_ok());
        }
        assert!(ui.find("synthetic-not-a-real-password").is_err());
    }
    click(&mut app, "示例条目 001");
    assert!(app.selected.is_some());
    click(&mut app, "编辑条目");
    assert!(matches!(&app.panel, Panel::Editor(_)));
    capture(&app, "edit-entry", (960.0, 640.0));
    // Footer buttons must be clickable even in the smallest supported window.
    let messages: Vec<_> = {
        let mut ui = simulator(&app, (960.0, 640.0));
        ui.click("取消编辑").unwrap();
        ui.into_messages().collect()
    };
    for message in messages {
        let _ = app.update(message);
    }
    assert!(matches!(&app.panel, Panel::Vault));
    let messages: Vec<_> = {
        let mut ui = simulator(&app, (1280.0, 800.0));
        ui.click(selector::id(app.search_id.clone())).unwrap();
        ui.typewrite("002");
        ui.into_messages().collect()
    };
    for message in messages {
        let _ = app.update(message);
    }
    assert_eq!(app.search, "002");
    {
        let mut ui = simulator(&app, (1280.0, 800.0));
        assert!(ui.find("示例条目 002").is_ok());
        assert!(ui.find("示例条目 000").is_err());
    }
    click(&mut app, "清空");
    assert!(app.search.is_empty());
    click(&mut app, "添加");
    assert!(matches!(&app.panel, Panel::Editor(state) if state.id.is_none()));
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
    let (_dir, mut app) = fixture(12);
    for size in [(960.0, 640.0), (1280.0, 800.0), (1600.0, 900.0)] {
        capture(&app, "table", size);
    }
    click(&mut app, "导入");
    assert!(matches!(&app.panel, Panel::Import(_)));
    capture(&app, "import", (960.0, 640.0));
    click(&mut app, "返回列表");
    click(&mut app, "设置");
    assert!(matches!(&app.panel, Panel::Settings(_)));
    capture(&app, "settings", (1280.0, 800.0));
    click(&mut app, "返回列表");
    let id = app.session.as_ref().unwrap().entries()[0].id;
    let _ = app.update(Message::ContextEntry(id));
    capture(&app, "context-actions", (960.0, 640.0));
    click(&mut app, "关闭菜单");
    assert!(!app.context_open);
    let _ = app.update(Message::DarkModeChanged(true));
    capture(&app, "table-dark", (1280.0, 800.0));
}

#[test]
fn several_hundred_rows_filter_without_revealing_secrets() {
    let (_dir, app) = fixture(500);
    let vault = app.session.as_ref().unwrap();
    assert_eq!(
        vault
            .entries()
            .iter()
            .filter(|entry| app.entry_visible(entry, ""))
            .count(),
        500
    );
    assert_eq!(
        vault
            .entries()
            .iter()
            .filter(|entry| app.entry_visible(entry, "499"))
            .count(),
        1
    );
}
