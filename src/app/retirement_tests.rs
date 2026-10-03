//! Real UI exits must hand the actual secret-bearing preview to worker disposal.
use super::*;
use std::sync::{atomic::Ordering, mpsc};

struct WorkerDrop(mpsc::Sender<(std::thread::ThreadId, Option<String>)>);
impl Drop for WorkerDrop {
    fn drop(&mut self) {
        let current = std::thread::current();
        let _ = self
            .0
            .send((current.id(), current.name().map(str::to_owned)));
    }
}

fn staged_import() -> (tempfile::TempDir, App, Uuid) {
    let (dir, mut app) = tests::fixture(1);
    let source = dir.path().join("synthetic-retirement.csv");
    std::fs::write(
        &source,
        "name,url,username,password,note\nIncoming,https://incoming.example.test,user,synthetic-secret,synthetic-note\n",
    )
    .unwrap();
    let _ = app.test_update(Message::OpenImport);
    let _ = app.test_update(Message::ImportPathChanged(source.display().to_string()));
    let _ = app.test_update(Message::AnalyzeImport);
    let Panel::Import(state) = &app.panel else {
        panic!("import panel did not open");
    };
    let preview = state.preview.as_ref().expect("real analyzed preview");
    assert_eq!(preview.rows().len(), 1);
    let id = preview.id();
    (dir, app, id)
}

fn assert_preview_retired(mut app: App, preview_id: Uuid, message: Message) -> App {
    let ui_thread = std::thread::current().id();
    let (drop_tx, drop_rx) = mpsc::channel();
    let observed = app
        .operations
        .service
        .as_ref()
        .unwrap()
        .expect_retired_preview_for_test(preview_id, Box::new(WorkerDrop(drop_tx)));
    let _ = app.test_update(message);
    assert!(
        observed.load(Ordering::Acquire),
        "UI exit dropped the actual analyzed preview instead of handing its owner to worker disposal"
    );
    let (drop_thread, name) = drop_rx.try_recv().expect("drained preview disposal");
    assert_ne!(
        drop_thread, ui_thread,
        "preview retirement ran on UI thread"
    );
    assert_eq!(name.as_deref(), Some("password-manager-vault-worker"));
    assert!(
        app.operations
            .authority
            .snapshot(std::time::Instant::now())
            .occupied
            .is_none(),
        "worker disposal did not acknowledge the actual drain"
    );
    assert!(app.operations.launch_retired.is_none());
    app
}

#[test]
fn retirement_import_path_edit_drops_actual_preview_on_worker() {
    let (_dir, app, id) = staged_import();
    let app = assert_preview_retired(app, id, Message::ImportPathChanged("changed.csv".into()));
    let Panel::Import(state) = &app.panel else {
        panic!("path edit dismissed import panel");
    };
    assert_eq!(state.path, "changed.csv");
    assert!(state.preview.is_none());
    assert!(state.resolutions.is_empty());
    assert!(state.apply_updates);
}

#[test]
fn retirement_navigation_drops_actual_preview_on_worker() {
    let (_dir, app, id) = staged_import();
    let app = assert_preview_retired(app, id, Message::SetNav(NavFilter::Favorites));
    assert!(matches!(app.panel, Panel::Vault));
    assert_eq!(app.nav, NavFilter::Favorites);
}

#[test]
fn retirement_category_delete_prompt_drops_actual_preview_on_worker() {
    let (_dir, app, id) = staged_import();
    let app = assert_preview_retired(app, id, Message::RequestDeleteCategory("其他".into()));
    assert!(matches!(&app.panel, Panel::DeleteCategory(name) if name == "其他"));
}

#[test]
fn retirement_other_valid_panel_exits_drop_actual_preview_on_worker() {
    for message in [
        Message::CancelPanel,
        Message::OpenImport,
        Message::OpenSettings,
        Message::NewEntry,
    ] {
        let (_dir, app, id) = staged_import();
        let _ = assert_preview_retired(app, id, message);
    }
}

#[test]
fn retirement_repeated_new_entry_preserves_existing_editor_draft() {
    let (_dir, mut app) = tests::fixture(1);
    let _ = app.test_update(Message::NewEntry);
    let _ = app.test_update(Message::EditorPasswordChanged(
        "synthetic-existing-draft".into(),
    ));
    let _ = app.test_update(Message::EditorNotesAction(text_editor::Action::Edit(
        text_editor::Edit::Paste(std::sync::Arc::new("synthetic-existing-note".into())),
    )));
    let _ = app.test_update(Message::NewEntry);
    let Panel::Editor(editor) = &app.panel else {
        panic!("repeated NewEntry dismissed existing editor");
    };
    assert_eq!(editor.password, "synthetic-existing-draft");
    assert_eq!(editor.notes, "synthetic-existing-note");
}

#[test]
fn retirement_invalid_edit_entry_keeps_staged_preview_and_panel() {
    let (_dir, mut app, preview_id) = staged_import();
    let entry_id = app.session.as_ref().unwrap().entries()[0].id;
    let _ = app.test_update(Message::EditEntry(entry_id));
    let Panel::Import(state) = &app.panel else {
        panic!("invalid EditEntry became valid by first replacing import panel");
    };
    assert_eq!(state.preview.as_ref().unwrap().id(), preview_id);
    assert!(app.selected.is_none());
    assert!(app.operations.launch_retired.is_none());
}
