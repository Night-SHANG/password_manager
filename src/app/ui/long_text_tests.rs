use super::*;
use crate::domain::EntryDraft;
use iced_test::{Simulator, selector};

const SECRET: &str = "synthetic-long-text-password-only";
const SIZES: [(f32, f32); 3] = [(960.0, 640.0), (1280.0, 800.0), (1600.0, 900.0)];

fn fixture() -> (tempfile::TempDir, App, uuid::Uuid) {
    let directory = tempfile::tempdir().unwrap();
    let mut app = App::initial();
    let path = directory.path().join("synthetic-metadata.pmvault");
    let mut vault = VaultSession::create(&path, "synthetic-metadata-master").unwrap();
    let id = vault
        .add_entry(EntryDraft::login(
            "很长的中文名称😀".repeat(20),
            format!("https://example.test/{}", "long-path/".repeat(40)),
            "很长的账号".repeat(40),
            SECRET,
        ))
        .unwrap();
    vault.save().unwrap();
    app.vault_path = path.display().to_string();
    app.session = Some(vault);
    (directory, app, id)
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

fn path(name: &str) -> std::path::PathBuf {
    let directory = std::path::PathBuf::from("target/gui-artifacts");
    std::fs::create_dir_all(&directory).unwrap();
    directory.join(format!("{name}.png"))
}

fn stage(name: &str, phase: &str) {
    use std::io::Write;

    let _ = path(name);
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("target/gui-artifacts/capture-stages.txt")
        .unwrap();
    // Fixed scenario identifiers only, never metadata or credential contents.
    writeln!(file, "{phase} {name}").unwrap();
    file.flush().unwrap();
}

fn assert_inside(bounds: iced::Rectangle, size: (f32, f32)) {
    for value in [bounds.x, bounds.y, bounds.width, bounds.height] {
        assert!(value.is_finite());
    }
    assert!(bounds.width > 0.0 && bounds.height > 0.0);
    assert!(bounds.x >= 0.0 && bounds.y >= 0.0);
    assert!(bounds.x + bounds.width <= size.0 + 1.0);
    assert!(bounds.y + bounds.height <= size.1 + 1.0);
}

#[test]
#[ignore = "Headless UI suite; run explicitly with the tiny-skia backend in CI"]
fn gui_metadata_hover_changes_pixels_without_revealing_passwords() {
    let (_directory, mut app, id) = fixture();
    for dark in [false, true] {
        let _ = app.update(Message::DarkModeChanged(dark));
        for size in SIZES {
            let name = format!("metadata-hover-{dark}-{}", size.0 as u32);
            stage(&name, "BEGIN");
            let theme = app.theme();
            let mut ui = simulator(&app, size);
            let baseline = path(&format!("{name}-before"));
            let image = ui.snapshot(&theme).unwrap();
            assert!(image.matches_image(&baseline).unwrap());
            assert!(ui.find(SECRET).is_err());
            let bounds = ui
                .find(selector::id(format!("card-name-{id}")))
                .unwrap()
                .bounds();
            ui.point_at(bounds.center());
            let _ = ui.snapshot(&theme).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(450));
            let hovered = ui.snapshot(&theme).unwrap();
            assert!(!hovered.matches_image(&baseline).unwrap());
            assert!(hovered.matches_image(path(&name)).unwrap());
            assert!(ui.find(SECRET).is_err());
            ui.point_at((0.0, 0.0));
            let image = ui.snapshot(&theme).unwrap();
            assert!(image.matches_image(&baseline).unwrap());
            assert_eq!(ui.into_messages().count(), 0);
            assert!(app.revealed.is_none());
            stage(&name, "END");
        }
    }
}

#[test]
#[ignore = "Headless UI suite; run explicitly with the tiny-skia backend in CI"]
fn gui_username_and_website_hover_but_password_does_not() {
    let (_directory, app, id) = fixture();
    let theme = app.theme();
    for field in ["username", "website", "password"] {
        let name = format!("metadata-field-{field}");
        stage(&name, "BEGIN");
        let mut ui = simulator(&app, SIZES[0]);
        let bounds = ui
            .find(selector::id(format!("card-{field}-{id}")))
            .unwrap()
            .bounds();
        // Capture the hover styling before the delayed tooltip opens. This
        // prevents a website button's hover color from satisfying the test.
        ui.point_at(bounds.center());
        let baseline = path(&format!("{name}-before-delay"));
        let image = ui.snapshot(&theme).unwrap();
        assert!(image.matches_image(&baseline).unwrap());
        std::thread::sleep(std::time::Duration::from_millis(450));
        let hovered = ui.snapshot(&theme).unwrap();
        assert_eq!(hovered.matches_image(&baseline).unwrap(), field == "password");
        assert!(hovered.matches_image(path(&name)).unwrap());
        assert!(ui.find(SECRET).is_err());
        assert_eq!(ui.into_messages().count(), 0);
        stage(&name, "END");
    }
}

#[test]
#[ignore = "Headless UI suite; run explicitly with the tiny-skia backend in CI"]
fn gui_long_details_keep_actions_and_close_visible() {
    let (_directory, mut app, id) = fixture();
    let _ = app.update(Message::ContextEntry(id));
    for size in SIZES {
        let name = format!("metadata-details-{}", size.0 as u32);
        stage(&name, "BEGIN");
        let mut ui = simulator(&app, size);
        for target in ["context-panel", "context-details"] {
            let bounds = ui.find(selector::id(target)).unwrap().bounds();
            assert_inside(bounds, size);
        }
        for field in ["name", "username", "website", "category"] {
            let target = ui.find(selector::id(format!("context-{field}")));
            assert!(target.is_ok());
        }
        for label in ["复制账号", "显示密码", "编辑条目", "关闭菜单"] {
            let target = ui.find(label).unwrap();
            assert!(target.visible_bounds().is_some());
            assert_inside(target.bounds(), size);
        }
        assert!(ui.find(SECRET).is_err());
        assert!(
            ui.snapshot(&app.theme())
                .unwrap()
                .matches_image(path(&name))
                .unwrap()
        );
        stage(&name, "END");
    }
    let _ = app.update(Message::ToggleReveal);
    {
        let mut ui = simulator(&app, SIZES[0]);
        assert!(ui.find(SECRET).is_ok());
        let hide = ui.find("隐藏密码").unwrap();
        assert!(hide.visible_bounds().is_some());
        let bounds = ui.find("关闭菜单").unwrap().bounds();
        assert_inside(bounds, SIZES[0]);
        let name = "metadata-details-explicit-reveal";
        stage(name, "BEGIN");
        assert!(
            ui.snapshot(&app.theme())
                .unwrap()
                .matches_image(path(name))
                .unwrap()
        );
        stage(name, "END");
    }
    let messages = {
        let mut ui = simulator(&app, SIZES[0]);
        ui.click("关闭菜单").unwrap();
        ui.into_messages().collect::<Vec<_>>()
    };
    assert!(!messages.is_empty());
    for message in messages {
        let _ = app.update(message);
    }
    assert!(!app.context_open);
    let _ = app.update(Message::Lock);
    assert!(app.revealed.is_none());
    assert!(app.session.is_none());
    assert!(simulator(&app, SIZES[0]).find(SECRET).is_err());
}
