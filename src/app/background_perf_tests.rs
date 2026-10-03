//! Explicit release-only synthetic UI probes. No real vault/credential fixtures.
use super::*;
use iced_test::{Simulator, selector};
use std::time::Instant;

fn simulator(app: &App) -> Simulator<'_, Message> {
    Simulator::with_size(
        iced_test::core::Settings {
            default_font: UI_FONT,
            default_text_size: iced::Pixels(14.0),
            ..iced_test::core::Settings::default()
        },
        (1280.0, 800.0),
        app.view(),
    )
}

fn conflict_preview(app: &App) -> ImportPreview {
    conflict_preview_rows(app, usize::MAX)
}

fn conflict_preview_rows(app: &App, rows: usize) -> ImportPreview {
    use crate::import::{ImportBatch, NormalizedImportItem, content_fingerprint};
    let session = app.session.as_ref().unwrap();
    let items = session
        .entries()
        .iter()
        .take(rows)
        .map(|entry| {
            let mut item = NormalizedImportItem {
                provider: "chrome_csv".into(),
                source_stable_id: None,
                name: entry.name.clone(),
                website: entry.website.clone(),
                username: entry.username.clone(),
                password: "synthetic-updated-only".into(),
                notes: String::new(),
                category: entry.category.clone(),
                favorite: false,
                fingerprint: [0; 32],
            };
            item.fingerprint = content_fingerprint(
                &item.name,
                &item.website,
                &item.username,
                &item.password,
                &item.notes,
                &item.category,
                item.favorite,
            );
            item
        })
        .collect();
    crate::import::plan::build_preview(
        session,
        ImportBatch {
            provider: "chrome_csv".into(),
            source_digest: [37; 32],
            items,
            invalid_rows: 0,
        },
    )
    .unwrap()
}

fn environment() -> serde_json::Value {
    let command = |program: &str, args: &[&str]| {
        std::process::Command::new(program)
            .args(args)
            .output()
            .ok()
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
    };
    serde_json::json!({
        "git_sha": command("git", &["rev-parse", "HEAD"]),
        "lock_sha256": command("sha256sum", &["Cargo.lock"]),
        "view_source_sha256": command("sha256sum", &["src/app/ui.rs","src/app/ui/forms.rs",
            "src/app/background_perf_tests.rs","src/app/view_index.rs","src/app/pagination.rs",
            "src/app.rs","src/app/operations.rs","src/operations/jobs.rs"]),
        "default_kdf": {"memory_kib":65536,"iterations":3,"parallelism":1},
        "os": command("uname", &["-a"]),
        "cpu_model": std::fs::read_to_string("/proc/cpuinfo").ok().and_then(|cpu|
            cpu.lines().find(|line|line.starts_with("model name")).map(str::to_owned)),
        "visible_logical_processors": std::thread::available_parallelism().ok().map(|value|value.get()),
        "memory_total": std::fs::read_to_string("/proc/meminfo").ok().and_then(|memory|
            memory.lines().find(|line|line.starts_with("MemTotal:")).map(str::to_owned)),
        "release": !cfg!(debug_assertions), "backend": std::env::var("ICED_TEST_BACKEND").ok(),
        "dimensions": [1280,800], "scale_factor": 2,
        "caveat": "Iced Simulator layout and actual snapshot pixels; no native event-loop/window frame claim",
    })
}

#[test]
#[ignore = "release synthetic current-card and conflict first-layout/render baseline"]
fn perf_background_views_baseline_1k() {
    if cfg!(debug_assertions) {
        panic!("run this harness with --release");
    }
    let output = std::path::Path::new("target/background-perf");
    std::fs::create_dir_all(output).unwrap();
    let (_dir, mut app) = tests::fixture(1000);
    let vault_bytes = std::fs::metadata(&app.vault_path).unwrap().len();
    let mut observations = Vec::new();
    for panel in ["cards", "conflicts"] {
        if panel == "conflicts" {
            let preview = conflict_preview(&app);
            assert_eq!(preview.summary().conflicts, 1000);
            let mut state = ImportState::new();
            state.preview = Some(preview);
            app.panel = Panel::Import(Box::new(state));
        }
        for sample in 0..13 {
            let start = Instant::now();
            let mut ui = simulator(&app);
            let layout_us = start.elapsed().as_micros();
            let draw = Instant::now();
            let image = ui.snapshot(&app.theme()).unwrap();
            let snapshot_us = draw.elapsed().as_micros();
            let frame_us = start.elapsed().as_micros();
            if sample == 3 {
                let _ = image
                    .matches_image(output.join(format!("view-baseline-1k-{panel}.png")))
                    .unwrap();
            }
            if sample >= 3 {
                observations.push(serde_json::json!({"panel":panel,"sample":sample-3,
                    "entries":1000,"vault_bytes":vault_bytes,"layout_us":layout_us,
                    "snapshot_us":snapshot_us,"frame_us":frame_us,
                    "misses_100ms":frame_us>100_000}));
            }
        }
    }
    let report = serde_json::json!({"environment":environment(),"warmups":3,
        "measured_per_panel":10,"samples":observations,
        "peak_rss_process_cumulative":std::fs::read_to_string("/proc/self/status").ok()
            .and_then(|status| status.lines().find(|line| line.starts_with("VmHWM:")).map(str::to_owned))});
    std::fs::write(
        output.join("view-baseline-1k.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!("VIEW_BASELINE {}", serde_json::to_string(&report).unwrap());
}

#[test]
#[ignore = "headless UI paging behavior, explicitly run with tiny-skia"]
fn gui_large_vault_cards_page_navigation_keeps_all_rows() {
    let (_dir, mut app) = tests::fixture(49);
    let ids: Vec<_> = app
        .session
        .as_ref()
        .unwrap()
        .entries()
        .iter()
        .map(|entry| entry.id)
        .collect();
    let messages = {
        let mut ui = simulator(&app);
        assert!(ui.find(selector::id(format!("card-{}", ids[0]))).is_ok());
        assert!(
            ui.find(selector::id(format!("card-{}", ids[24]))).is_err(),
            "render bounded first page"
        );
        ui.click("下一页")
            .expect("all rows remain reachable through explicit pagination");
        ui.into_messages().collect::<Vec<_>>()
    };
    for message in messages {
        app.test_update(message);
    }
    let messages = {
        let mut ui = simulator(&app);
        assert!(ui.find(selector::id(format!("card-{}", ids[24]))).is_ok());
        assert!(ui.find(selector::id(format!("card-{}", ids[0]))).is_err());
        ui.click("下一页").unwrap();
        ui.into_messages().collect::<Vec<_>>()
    };
    for message in messages {
        app.test_update(message);
    }
    let mut ui = simulator(&app);
    assert!(ui.find(selector::id(format!("card-{}", ids[48]))).is_ok());
    drop(ui);
    app.test_update(Message::SearchChanged("synthetic-user-0".into()));
    assert_eq!(
        app.card_page, 0,
        "search resets pagination and covers all original data"
    );
    let mut ui = simulator(&app);
    assert!(ui.find(selector::id(format!("card-{}", ids[0]))).is_ok());
    assert!(ui.find(selector::id(format!("card-{}", ids[48]))).is_err());
}

fn timed_drain(app: &mut App, task: Task<Message>) -> Vec<serde_json::Value> {
    use iced::futures::{StreamExt, stream::SelectAll};
    use iced_test::runtime::{Action, task::into_stream};
    let mut streams = SelectAll::new();
    let mut samples = Vec::new();
    if let Some(stream) = into_stream(task) {
        streams.push(stream);
    }
    iced::futures::executor::block_on(async {
        while let Some(action) = streams.next().await {
            if let Action::Output(message) = action {
                let phase = match &message {
                    Message::OperationSignal(crate::operations::OperationSignal::Finished(_)) => {
                        "result_install"
                    }
                    Message::OperationSignal(crate::operations::OperationSignal::Drained(_)) => {
                        "drain_ack"
                    }
                    _ => "runtime_dispatch",
                };
                let started = Instant::now();
                let followup = app.update(message);
                let elapsed_us = started.elapsed().as_micros();
                samples.push(serde_json::json!({"phase":phase,"handler_us":elapsed_us}));
                if let Some(stream) = into_stream(followup) {
                    streams.push(stream);
                }
            }
        }
    });
    samples
}

fn summary(samples: &[u128]) -> serde_json::Value {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let quantile =
        |percent: usize| sorted[((sorted.len() * percent).div_ceil(100)).saturating_sub(1)];
    serde_json::json!({"count":sorted.len(),"max_us":sorted.last(),
        "p95_us":quantile(95),"p99_us":quantile(99),"method":"nearest rank of measured samples"})
}

fn held_worker_probe(
    app: &mut App,
    output: &std::path::Path,
    entries: usize,
    cycle: usize,
    cancel: bool,
) -> serde_json::Value {
    use std::sync::mpsc;
    let destination = output.join(format!("synthetic-export-{entries}-{cycle}.csv"));
    app.test_update(Message::OpenSettings);
    app.test_update(Message::CsvPathChanged(destination.display().to_string()));
    app.test_update(Message::ConfirmPlaintextChanged(true));
    let (arrived_tx, arrived_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    crate::export::tests::set_worker_after_create(move || {
        arrived_tx
            .send(std::thread::current().name().map(str::to_owned))
            .unwrap();
        release_rx.recv().unwrap();
    });
    let submit_started = Instant::now();
    let task = app.update(Message::ExportPlaintextCsv);
    let submit_us = submit_started.elapsed().as_micros();
    let busy_started = Instant::now();
    let mut busy = simulator(app);
    assert!(busy.find("正在后台处理").is_ok());
    let image = busy.snapshot(&app.theme()).unwrap();
    let busy_frame_us = submit_started.elapsed().as_micros();
    let busy_layout_draw_us = busy_started.elapsed().as_micros();
    if cycle == 3 {
        let _ = image
            .matches_image(
                std::path::Path::new("target/background-perf").join(format!("busy-{entries}.png")),
            )
            .unwrap();
    }
    drop(busy);
    let worker_thread_name = arrived_rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("real named CSV worker must reach held post-create gate");
    assert_eq!(
        worker_thread_name.as_deref(),
        Some("password-manager-vault-worker")
    );
    assert!(app.operation_busy());
    let held_id = app
        .operations
        .active
        .as_ref()
        .expect("one active worker owner")
        .id;
    assert_eq!(
        app.operations.authority.snapshot(Instant::now()).occupied,
        Some(held_id)
    );
    let (input_tx, input_rx) = mpsc::channel();
    let producer = std::thread::Builder::new()
        .name("synthetic-input-producer".into())
        .spawn(move || {
            for sample in 0..1000 {
                input_tx.send((sample, Instant::now())).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        })
        .unwrap();
    let start = Instant::now();
    let mut raw = Vec::new();
    let mut input_latencies = Vec::new();
    let mut handlers = Vec::new();
    let mut frames = Vec::new();
    for (sample, enqueued) in input_rx {
        assert!(
            app.operation_busy(),
            "named worker remains held for every input sample"
        );
        assert_eq!(
            app.operations.active.as_ref().map(|active| active.id),
            Some(held_id)
        );
        assert_eq!(
            app.operations.authority.snapshot(Instant::now()).occupied,
            Some(held_id)
        );
        let handler_started = Instant::now();
        let message = match sample % 3 {
            0 => Message::SearchChanged("synthetic-input-ignored-while-busy".into()),
            1 => Message::SecurityTick(Instant::now()),
            _ => Message::WindowFocusChanged(true),
        };
        let _ = app.update(message);
        let handler_us = handler_started.elapsed().as_micros();
        let latency_us = enqueued.elapsed().as_micros();
        handlers.push(handler_us);
        input_latencies.push(latency_us);
        raw.push(serde_json::json!({"sample":sample,"enqueue_offset_us":enqueued.duration_since(start).as_micros(),
            "handler_us":handler_us,"enqueue_to_handled_us":latency_us}));
        if sample % 100 == 0 {
            let frame_started = Instant::now();
            let mut ui = simulator(app);
            let _ = ui.snapshot(&app.theme()).unwrap();
            frames.push(frame_started.elapsed().as_micros());
        }
    }
    producer.join().unwrap();
    let mut mask_frame_us = None;
    let mut mask_handler_us = None;
    let mut cancellation_started = None;
    let mut task = task;
    if cancel {
        let now = Instant::now();
        cancellation_started = Some(now);
        let mask_task = app.update(Message::Lock);
        mask_handler_us = Some(now.elapsed().as_micros());
        let mut ui = simulator(app);
        assert!(ui.find("已遮蔽，正在完成锁定").is_ok());
        let image = ui.snapshot(&app.theme()).unwrap();
        mask_frame_us = Some(now.elapsed().as_micros());
        if cycle == 3 {
            let _ = image
                .matches_image(
                    std::path::Path::new("target/background-perf")
                        .join(format!("masked-{entries}.png")),
                )
                .unwrap();
        }
        drop(ui);
        task = Task::batch([task, mask_task]);
    }
    let release_started = Instant::now();
    release_tx.send(()).unwrap();
    let completions = timed_drain(app, task);
    let release_to_cleanup_us = release_started.elapsed().as_micros();
    let cancel_to_cleanup_us = cancellation_started.map(|started| started.elapsed().as_micros());
    assert!(
        !app.operation_busy(),
        "worker terminal and cleanup acknowledgement must drain"
    );
    let next_frame_started = Instant::now();
    let mut ui = simulator(app);
    let final_image = ui.snapshot(&app.theme()).unwrap();
    let result_first_frame_us = next_frame_started.elapsed().as_micros();
    if cancel {
        assert!(
            app.operations
                .authority
                .snapshot(Instant::now())
                .fully_locked,
            "actual drained cancellation must establish full locked authority"
        );
        assert!(app.session.is_none());
        assert!(ui.find("解锁密码库").is_ok());
        assert!(ui.find("已遮蔽，正在完成锁定").is_err());
        if cycle == 3 {
            let _ = final_image
                .matches_image(
                    std::path::Path::new("target/background-perf")
                        .join(format!("final-locked-{entries}.png")),
                )
                .unwrap();
        }
    }
    drop(ui);
    let csv_bytes = std::fs::metadata(&destination).unwrap().len();
    std::fs::remove_file(destination).unwrap(); // synthetic temporary output only
    serde_json::json!({"entries":entries,"cycle":cycle,"cancel_after_claim":cancel,
        "submit_handler_us":submit_us,"first_busy_event_to_snapshot_us":busy_frame_us,
        "busy_layout_draw_us":busy_layout_draw_us,"input":summary(&input_latencies),
        "handlers":summary(&handlers),"busy_frames":frames,"raw_input_samples":raw,
        "mask_handler_us":mask_handler_us,"cancel_to_first_mask_snapshot_us":mask_frame_us,
        "cancel_to_cleanup_us":cancel_to_cleanup_us,"release_to_cleanup_us":release_to_cleanup_us,
        "completion_handlers":completions,"first_subsequent_frame_us":result_first_frame_us,
        "actual_csv_bytes":csv_bytes,"actual_worker_thread_name":worker_thread_name,
        "max_active_jobs_observed":1,
        "terminal_active_owner":app.operations.active.is_some(),
        "terminal_occupied":app.operations.authority.snapshot(Instant::now()).occupied.is_some(),"held_gate":"real named worker CSV create_new before write",
        "no_runtime_claim":"Producer timestamps + real App handlers + Simulator snapshots; native desktop event-to-frame remains separate"})
}

#[test]
#[ignore = "headless bounded import decisions preserve global resolution state and row order"]
fn gui_large_import_pages_preserve_all_rows_and_global_unresolved_count() {
    let (_dir, mut app) = tests::fixture(17);
    let preview = conflict_preview(&app);
    let preview_id = preview.id();
    let mut state = ImportState::new();
    state.preview = Some(preview);
    app.panel = Panel::Import(Box::new(state));
    {
        let mut ui = simulator(&app);
        assert!(ui.find(selector::id("import-row-0")).is_ok());
        assert!(
            ui.find(selector::id("import-row-8")).is_err(),
            "decision widgets must be bounded"
        );
    }
    app.test_update(Message::SetImportPage(preview_id, 1));
    {
        let mut ui = simulator(&app);
        assert!(ui.find(selector::id("import-row-8")).is_ok());
        assert!(ui.find(selector::id("import-row-0")).is_err());
    }
    for index in 8..16 {
        app.test_update(Message::SetImportResolution(
            preview_id,
            index,
            ConflictResolution::KeepLocal,
        ));
    }
    {
        let mut ui = simulator(&app);
        assert!(
            ui.find("还有 9 项需要选择处理方式。").is_ok(),
            "unresolved count includes every page"
        );
    }
    app.test_update(Message::SetImportPage(preview_id, 2));
    let mut ui = simulator(&app);
    assert!(ui.find(selector::id("import-row-16")).is_ok());
    assert!(ui.find(selector::id("import-row-15")).is_err());
}

#[test]
#[ignore = "headless candidate pagination preserves complete fan-out and original order"]
fn gui_large_import_candidate_pages_preserve_all_candidates() {
    let (_dir, mut app) = tests::fixture(17);
    let session = app.session.as_mut().unwrap();
    for entry in &mut session.body_mut().entries {
        entry.website = "https://shared-fanout.example.test".into();
        entry.username = "synthetic-shared-user".into();
    }
    session.save().unwrap();
    app.reset_unlocked_state();
    let preview = conflict_preview(&app);
    // All source rows retain their full candidate order. First page is enough
    // to prove candidate navigation; this does not shrink the accepted preview.
    let ids = match preview.rows()[0].class() {
        ImportClass::Conflict { existing_ids } => existing_ids.clone(),
        class => panic!("expected complete conflict class, got {class:?}"),
    };
    assert_eq!(ids.len(), 17);
    let preview_id = preview.id();
    let mut state = ImportState::new();
    state.preview = Some(preview);
    app.panel = Panel::Import(Box::new(state));
    {
        let mut ui = simulator(&app);
        assert!(
            ui.find(selector::id(format!("import-candidate-0-{}", ids[0])))
                .is_ok()
        );
        assert!(
            ui.find(selector::id(format!("import-candidate-0-{}", ids[8])))
                .is_err()
        );
    }
    app.test_update(Message::SetImportCandidatePage(preview_id, 0, 1));
    {
        let mut ui = simulator(&app);
        assert!(
            ui.find(selector::id(format!("import-candidate-0-{}", ids[8])))
                .is_ok()
        );
        assert!(
            ui.find(selector::id(format!("import-candidate-0-{}", ids[0])))
                .is_err()
        );
    }
    app.test_update(Message::SetImportCandidatePage(preview_id, 0, 2));
    let mut ui = simulator(&app);
    assert!(
        ui.find(selector::id(format!("import-candidate-0-{}", ids[16])))
            .is_ok()
    );
}

fn large_fixture(count: usize) -> (tempfile::TempDir, App, u128) {
    use crate::domain::EntryDraft;
    let started = Instant::now();
    let (directory, mut app) = tests::fixture(0);
    let session = app.session.as_mut().unwrap();
    for index in 0..count {
        let mut draft = EntryDraft::login(
            if index % 100 == 0 {
                format!("示例条目 {index:05} {}", "很长的中文名称😀".repeat(20))
            } else {
                format!("示例条目 {index:05}")
            },
            format!("https://account-{index}.example.test"),
            format!("synthetic-user-{index}"),
            "synthetic-not-a-real-password",
        );
        draft.category = format!("synthetic-category-{:02}", index % 40);
        draft.favorite = index % 7 == 0;
        if index % 100 == 0 {
            draft.secret.notes = "长 Unicode 👩🏽‍💻 备注 空格  ".repeat(40);
        }
        session.add_entry(draft).unwrap();
    }
    for (index, entry) in session.body_mut().entries.iter_mut().enumerate() {
        if index % 10 == 9 {
            entry.deleted_at_unix = Some(123);
        }
    }
    session.save().unwrap();
    app.reset_unlocked_state();
    (directory, app, started.elapsed().as_micros())
}

#[test]
#[ignore = "release 1k/10k/50k bounded cards/conflicts and real held-worker runtime probe"]
fn perf_background_views_responsiveness() {
    if cfg!(debug_assertions) {
        panic!("run this harness with --release");
    }
    let output = std::path::Path::new("target/background-perf");
    std::fs::create_dir_all(output).unwrap();
    let mut report = serde_json::json!({"environment":environment(),"warmups":3,"ordinary_measured_operations":10,
        "input_samples_per_held_worker":1000,"fixtures":[],
        "unmeasured":"Native Linux real-window, documented 4-core/8GiB/SSD host, Windows, fresh-process RSS attribution, and non-CSV worker category measurements belong to separate parent evidence"});
    let selected = std::env::var("PM_PERF_ENTRIES")
        .ok()
        .map(|value| value.parse::<usize>().expect("fixture size"));
    if let Some(count) = selected {
        assert!([1000, 10000, 50000].contains(&count));
    }
    for count in [1000, 10000, 50000]
        .into_iter()
        .filter(|count| selected.is_none_or(|selected| selected == *count))
    {
        let (directory, mut app, fixture_setup_us) = large_fixture(count);
        let vault_bytes = std::fs::metadata(&app.vault_path).unwrap().len();
        let mut layouts = Vec::new();
        for panel in ["cards", "mixed_conflict_deleted"] {
            if panel == "mixed_conflict_deleted" {
                let preview = conflict_preview(&app);
                assert_eq!(preview.unresolved_count(), count);
                let mut state = ImportState::new();
                state.preview = Some(preview);
                app.panel = Panel::Import(Box::new(state));
            }
            for sample in 0..13 {
                let started = Instant::now();
                let mut ui = simulator(&app);
                let layout_us = started.elapsed().as_micros();
                let draw_started = Instant::now();
                let image = ui.snapshot(&app.theme()).unwrap();
                let snapshot_us = draw_started.elapsed().as_micros();
                let frame_us = started.elapsed().as_micros();
                if sample == 3 {
                    let _ = image
                        .matches_image(output.join(format!("bounded-{count}-{panel}.png")))
                        .unwrap();
                }
                if sample >= 3 {
                    layouts.push(serde_json::json!({"panel":panel,"sample":sample-3,
                    "layout_us":layout_us,"snapshot_us":snapshot_us,"frame_us":frame_us,
                    "misses_100ms":frame_us>100_000}));
                }
            }
        }
        app.test_update(Message::CancelPanel);
        let mut source =
            csv::Writer::from_path(directory.path().join("synthetic-conflict-source.csv")).unwrap();
        source
            .write_record(["name", "url", "username", "password"])
            .unwrap();
        for entry in app.session.as_ref().unwrap().entries() {
            source
                .write_record([
                    entry.name.as_str(),
                    entry.website.as_str(),
                    entry.username.as_str(),
                    "synthetic-import-updated-only",
                ])
                .unwrap();
        }
        source.flush().unwrap();
        drop(source);
        let source_path = directory.path().join("synthetic-conflict-source.csv");
        let actual_source_bytes = std::fs::metadata(&source_path).unwrap().len();
        app.test_update(Message::OpenImport);
        app.test_update(Message::ImportPathChanged(
            source_path.display().to_string(),
        ));
        let mut real_import_adoptions = Vec::new();
        for sample in 0..13 {
            let started = Instant::now();
            let task = app.update(Message::AnalyzeImport);
            let submit_handler_us = started.elapsed().as_micros();
            let completions = timed_drain(&mut app, task);
            let completion_elapsed_us = started.elapsed().as_micros();
            let frame_started = Instant::now();
            let mut ui = simulator(&app);
            let image = ui.snapshot(&app.theme()).unwrap();
            let first_result_frame_us = frame_started.elapsed().as_micros();
            if sample == 3 {
                let _ = image
                    .matches_image(output.join(format!("adopted-conflicts-{count}.png")))
                    .unwrap();
            }
            drop(ui);
            let Panel::Import(state) = &app.panel else {
                panic!("import panel remains current");
            };
            assert!(state.preview.is_some());
            if sample >= 3 {
                real_import_adoptions.push(serde_json::json!({"sample":sample-3,
                "submit_handler_us":submit_handler_us,"worker_completion_elapsed_us":completion_elapsed_us,
                "actual_completion_handlers":completions,"first_result_layout_and_pixels_us":first_result_frame_us}));
            }
        }
        app.test_update(Message::CancelPanel);
        let mut interactions = Vec::new();
        for sample in 0..13 {
            for query in ["synthetic", "条目", "absent-synthetic-query", "account-499"] {
                let started = Instant::now();
                app.test_update(Message::SearchChanged(query.into()));
                let handler_us = started.elapsed().as_micros();
                let frame_started = Instant::now();
                let mut ui = simulator(&app);
                let _ = ui.snapshot(&app.theme()).unwrap();
                if sample >= 3 {
                    interactions.push(serde_json::json!({"sample":sample-3,"action":"search",
                    "query_kind":query,"handler_us":handler_us,"first_frame_us":frame_started.elapsed().as_micros()}));
                }
            }
            for nav in [
                NavFilter::All,
                NavFilter::Favorites,
                NavFilter::RecycleBin,
                NavFilter::Category("synthetic-category-01".into()),
            ] {
                let started = Instant::now();
                app.test_update(Message::SetNav(nav));
                let handler_us = started.elapsed().as_micros();
                let frame_started = Instant::now();
                let mut ui = simulator(&app);
                let _ = ui.snapshot(&app.theme()).unwrap();
                if sample >= 3 {
                    interactions.push(serde_json::json!({"sample":sample-3,"action":"nav",
                    "handler_us":handler_us,"first_frame_us":frame_started.elapsed().as_micros()}));
                }
            }
        }
        app.test_update(Message::SearchChanged(String::new()));
        app.test_update(Message::SetNav(NavFilter::All));
        // One incoming row with count matching targets exercises complete
        // candidate fan-out without manufacturing a count-by-count preview.
        for entry in &mut app.session.as_mut().unwrap().body_mut().entries {
            entry.website = "https://complete-fanout.example.test".into();
            entry.username = "synthetic-fanout-user".into();
        }
        app.session.as_mut().unwrap().save().unwrap();
        app.reset_unlocked_state();
        let fanout_started = Instant::now();
        let preview = conflict_preview_rows(&app, 1);
        let fanout_prepare_us = fanout_started.elapsed().as_micros();
        let permitted_candidates = preview.rows()[0].resolution_candidate_ids().len();
        assert_eq!(permitted_candidates, count - count / 10);
        let preview_id = preview.id();
        let mut state = ImportState::new();
        state.preview = Some(preview);
        app.panel = Panel::Import(Box::new(state));
        let mut fanout_frames = Vec::new();
        for sample in 0..13 {
            app.test_update(Message::SetImportCandidatePage(
                preview_id,
                0,
                if sample % 2 == 0 {
                    0
                } else {
                    permitted_candidates.saturating_sub(1) / ui::CANDIDATE_PAGE_SIZE
                },
            ));
            let started = Instant::now();
            let mut ui = simulator(&app);
            let image = ui.snapshot(&app.theme()).unwrap();
            let frame_us = started.elapsed().as_micros();
            if sample == 3 {
                let _ = image
                    .matches_image(output.join(format!("candidate-fanout-{count}.png")))
                    .unwrap();
            }
            if sample >= 3 {
                fanout_frames.push(frame_us);
            }
        }
        app.test_update(Message::CancelPanel);
        let actual_worker_encrypted_vault_bytes = std::fs::metadata(&app.vault_path).unwrap().len();
        let mut workers = Vec::new();
        for cycle in 0..13 {
            let cancel = cycle % 2 == 1;
            let result = held_worker_probe(&mut app, directory.path(), count, cycle, cancel);
            if cycle >= 3 {
                workers.push(result);
            }
            if app.session.is_none() {
                app.test_update(Message::MasterPasswordChanged(
                    "gui-synthetic-master-only".into(),
                ));
                app.test_update(Message::OpenVault);
                assert!(app.session.is_some());
            }
            if let Some(notice) = &app.export_notice {
                let generation = notice.generation;
                app.test_update(Message::AcknowledgeExportNotice(generation));
            }
            app.test_update(Message::CancelPanel);
        }
        report["fixtures"].as_array_mut().unwrap().push(serde_json::json!({"entries":count,
            "fixture_setup_including_default_kdf_us":fixture_setup_us,"actual_encrypted_vault_bytes":vault_bytes,
            "actual_worker_encrypted_vault_bytes":actual_worker_encrypted_vault_bytes,
            "actual_import_source_bytes":actual_source_bytes,"real_import_adoptions":real_import_adoptions,
            "layouts":layouts,"ordinary_search_nav_operations":interactions,"held_workers":workers,
            "fanout":{"incoming_rows":1,"complete_allowed_candidates":permitted_candidates,
                "test_fixture_prepare_us":fanout_prepare_us,"first_and_last_candidate_page_frames_us":fanout_frames},
            "process_cumulative_peak_rss":std::fs::read_to_string("/proc/self/status").ok()
                .and_then(|status|status.lines().find(|line|line.starts_with("VmHWM:")).map(str::to_owned))}));
        std::fs::write(
            output.join(format!(
                "view-responsiveness-{}.json",
                selected.map_or_else(|| "all".into(), |count| count.to_string())
            )),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
        println!("VIEW_RESPONSIVENESS_FIXTURE entries={count} vault_bytes={vault_bytes} complete");
    }
}

fn distinct_category_fixture(count: usize) -> (tempfile::TempDir, App) {
    let (directory, mut app) = tests::fixture(1);
    let session = app.session.as_mut().unwrap();
    session.body_mut().categories = (0..count)
        .map(|position| format!("synthetic-nav-category-{position:05}"))
        .collect();
    session.body_mut().entries[0].category = format!("synthetic-nav-category-{:05}", count - 1);
    session.save().unwrap();
    app.reset_unlocked_state();
    (directory, app)
}

#[test]
#[ignore = "single release worst-case existing sidebar 50k-category layout and pixels; no percentiles"]
fn perf_background_sidebar_50k_categories_baseline() {
    if cfg!(debug_assertions) {
        panic!("run with --release");
    }
    let (_directory, app) = distinct_category_fixture(50_000);
    let output = std::path::Path::new("target/background-perf");
    std::fs::create_dir_all(output).unwrap();
    let started = Instant::now();
    let mut ui = simulator(&app);
    let layout_us = started.elapsed().as_micros();
    let draw_started = Instant::now();
    let image = ui.snapshot(&app.theme()).unwrap();
    let snapshot_us = draw_started.elapsed().as_micros();
    let frame_us = started.elapsed().as_micros();
    let _ = image
        .matches_image(output.join("sidebar-50k-categories-baseline.png"))
        .unwrap();
    let report = serde_json::json!({"environment":environment(),"categories":50000,"entries":1,
        "sample_count":1,"warmups":0,"no_percentile":"Single demonstrated worst-case first layout/render",
        "layout_us":layout_us,"snapshot_us":snapshot_us,"first_frame_us":frame_us,
        "misses_100ms":frame_us>100_000,"actual_encrypted_vault_bytes":std::fs::metadata(&app.vault_path).unwrap().len(),
        "process_peak_rss":std::fs::read_to_string("/proc/self/status").ok()
            .and_then(|status|status.lines().find(|line|line.starts_with("VmHWM:")).map(str::to_owned))});
    std::fs::write(
        output.join("sidebar-50k-categories-baseline.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!(
        "SIDEBAR_BASELINE {}",
        serde_json::to_string(&report).unwrap()
    );
}

#[test]
#[ignore = "headless category pagination preserves complete category navigation and stable order"]
fn gui_large_sidebar_category_pages_preserve_access_and_order() {
    let (_directory, mut app) = distinct_category_fixture(49);
    let messages = {
        let mut ui = simulator(&app);
        assert!(ui.find("synthetic-nav-category-00000").is_ok());
        assert!(
            ui.find("synthetic-nav-category-00024").is_err(),
            "sidebar widgets must be bounded"
        );
        ui.click("下一页分类")
            .expect("all categories remain explicitly reachable");
        ui.into_messages().collect::<Vec<_>>()
    };
    for message in messages {
        app.test_update(message);
    }
    let messages = {
        let mut ui = simulator(&app);
        assert!(ui.find("synthetic-nav-category-00024").is_ok());
        assert!(ui.find("synthetic-nav-category-00000").is_err());
        ui.click("下一页分类").unwrap();
        ui.into_messages().collect::<Vec<_>>()
    };
    for message in messages {
        app.test_update(message);
    }
    let mut ui = simulator(&app);
    assert!(ui.find("synthetic-nav-category-00048").is_ok());
}

#[test]
fn pagination_hidden_card_actions_and_details_are_invalidated() {
    let (_directory, mut app) = tests::fixture(49);
    let first = app.session.as_ref().unwrap().entries()[0].id;
    app.test_update(Message::ContextEntry(first));
    app.test_update(Message::ToggleReveal);
    assert!(app.context_open && app.revealed.is_some());
    app.test_update(Message::SetCardPage(1));
    assert!(!app.context_open && app.revealed.is_none());
    assert!(
        !app.is_visible_workspace_target(first),
        "entry hidden by a page change is no longer an actionable target"
    );
    let favorite = app.session.as_ref().unwrap().entry(first).unwrap().favorite;
    app.test_update(Message::CardAction(first, CardAction::Favorite));
    assert_eq!(
        app.session.as_ref().unwrap().entry(first).unwrap().favorite,
        favorite
    );
    app.test_update(Message::ContextEntry(first));
    assert!(!app.context_open);
    app.test_update(Message::EditEntry(first));
    assert!(matches!(app.panel, Panel::Vault));
}

#[test]
fn pagination_card_page_clamps_after_result_changes_data_count() {
    let (_directory, mut app) = tests::fixture(49);
    let last = app.session.as_ref().unwrap().entries()[48].id;
    app.test_update(Message::SetCardPage(2));
    app.test_update(Message::ContextEntry(last));
    app.test_update(Message::MoveSelectedToRecycleBin);
    assert_eq!(app.session.as_ref().unwrap().active_entries().count(), 48);
    assert_eq!(
        app.card_page, 1,
        "adopted mutation must clamp the actual selected page to the last page"
    );
    assert!(app.revealed.is_none());
}

#[test]
fn pagination_search_and_category_cover_other_pages_in_body_order() {
    let (_directory, mut app) = tests::fixture(73);
    for (position, entry) in app
        .session
        .as_mut()
        .unwrap()
        .body_mut()
        .entries
        .iter_mut()
        .enumerate()
    {
        entry.category = if [1, 40, 72].contains(&position) {
            "synthetic selected category"
        } else {
            "其他"
        }
        .into();
    }
    app.session.as_mut().unwrap().save().unwrap();
    app.reset_unlocked_state();
    app.test_update(Message::SetCardPage(2));
    app.test_update(Message::SearchChanged("synthetic-user-6".into()));
    assert_eq!(app.card_page, 0);
    let expected: Vec<_> = std::iter::once(6).chain(60..70).collect();
    assert_eq!(app.filtered_entries.as_deref(), Some(expected.as_slice()));
    app.test_update(Message::SearchChanged(String::new()));
    app.test_update(Message::SetNav(NavFilter::Category(
        "synthetic selected category".into(),
    )));
    assert_eq!(app.card_page, 0);
    assert_eq!(
        app.view_index.as_ref().unwrap().positions(&app.nav),
        [1, 40, 72]
    );
    assert!(app.filtered_entries.is_none());
}

#[test]
fn pagination_keyboard_shortcut_messages_reach_primary_and_category_pages() {
    let (_directory, mut app) = tests::fixture(49);
    app.test_update(Message::NavigatePage(PageTarget::Primary, true));
    assert_eq!(app.card_page, 1);
    app.test_update(Message::NavigatePage(PageTarget::Primary, false));
    assert_eq!(app.card_page, 0);
    let (_directory, mut app) = distinct_category_fixture(49);
    app.test_update(Message::NavigatePage(PageTarget::Categories, true));
    assert_eq!(app.category_page, 1);
    app.test_update(Message::NavigatePage(PageTarget::Categories, false));
    assert_eq!(app.category_page, 0);
}

#[test]
fn pagination_keyboard_candidate_row_target_and_page_are_explicit() {
    let (_directory, mut app) = tests::fixture(17);
    for entry in &mut app.session.as_mut().unwrap().body_mut().entries {
        entry.website = "https://keyboard-fanout.example.test".into();
        entry.username = "synthetic-keyboard-fanout-user".into();
    }
    app.session.as_mut().unwrap().save().unwrap();
    app.reset_unlocked_state();
    let preview = conflict_preview(&app);
    let mut state = ImportState::new();
    state.preview = Some(preview);
    app.panel = Panel::Import(Box::new(state));
    assert_eq!(app.focused_candidate_row(), Some(0));
    app.test_update(Message::NavigatePage(PageTarget::DecisionFocus, true));
    assert_eq!(app.focused_candidate_row(), Some(1));
    app.test_update(Message::NavigatePage(PageTarget::Candidates, true));
    let Panel::Import(state) = &app.panel else {
        panic!("import panel remains current");
    };
    assert_eq!(state.candidate_pages.get(&1), Some(&1));
    assert!(!state.candidate_pages.contains_key(&0));
    assert!(state.resolutions.is_empty());
    app.test_update(Message::NavigatePage(PageTarget::Primary, true));
    assert_eq!(app.import_page, 1);
    assert_eq!(app.focused_candidate_row(), Some(8));
    app.test_update(Message::NavigatePage(PageTarget::Primary, false));
    assert_eq!(app.focused_candidate_row(), Some(0));
    let Panel::Import(state) = &app.panel else {
        panic!("import panel remains current");
    };
    assert_eq!(
        state.candidate_pages.get(&1),
        Some(&1),
        "candidate choices/page state persist across row pages"
    );
}

#[test]
#[ignore = "release bounded 50k-category first/last page pixels, 3warmups10measurements"]
fn perf_background_sidebar_50k_categories_bounded() {
    if cfg!(debug_assertions) {
        panic!("run with --release");
    }
    let (_directory, mut app) = distinct_category_fixture(50_000);
    let output = std::path::Path::new("target/background-perf");
    std::fs::create_dir_all(output).unwrap();
    let mut frames = Vec::new();
    let mut navigation_handlers = Vec::new();
    for sample in 0..13 {
        for page in [0, 50_000usize.div_ceil(ui::CATEGORY_PAGE_SIZE) - 1] {
            // The view fixture installs a page directly; the complete sequential
            // shortcut handler walk below is measured separately.
            app.category_page = page;
            let started = Instant::now();
            let mut ui = simulator(&app);
            let layout_us = started.elapsed().as_micros();
            let draw_started = Instant::now();
            let image = ui.snapshot(&app.theme()).unwrap();
            let snapshot_us = draw_started.elapsed().as_micros();
            let frame_us = started.elapsed().as_micros();
            if sample == 3 {
                let _ = image
                    .matches_image(output.join(format!("sidebar-50k-bounded-page-{page}.png")))
                    .unwrap();
            }
            if sample >= 3 {
                frames.push(serde_json::json!({"sample":sample-3,"page":page,
                "layout_us":layout_us,"snapshot_us":snapshot_us,"frame_us":frame_us,"misses_100ms":frame_us>100_000}));
            }
        }
    }
    app.category_page = 0;
    for _ in 0..50_000usize.div_ceil(ui::CATEGORY_PAGE_SIZE) - 1 {
        let started = Instant::now();
        app.test_update(Message::NavigatePage(PageTarget::Categories, true));
        navigation_handlers.push(started.elapsed().as_micros());
    }
    assert_eq!(
        app.category_page,
        50_000usize.div_ceil(ui::CATEGORY_PAGE_SIZE) - 1
    );
    let report = serde_json::json!({"environment":environment(),"categories":50000,"entries":1,
        "warmups":3,"measured_frames_per_first_last_page":10,"frames":frames,
        "sequential_category_page_handlers":summary(&navigation_handlers),
        "actual_encrypted_vault_bytes":std::fs::metadata(&app.vault_path).unwrap().len(),
        "process_peak_rss":std::fs::read_to_string("/proc/self/status").ok()
            .and_then(|status|status.lines().find(|line|line.starts_with("VmHWM:")).map(str::to_owned)),
        "caveat":"Current Simulator layout and actual pixels; native/reference host remains separate"});
    std::fs::write(
        output.join("sidebar-50k-categories-bounded.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!(
        "SIDEBAR_BOUNDED {}",
        serde_json::to_string(&report).unwrap()
    );
}

#[test]
fn pagination_duplicate_id_does_not_make_hidden_first_record_actionable() {
    let (_directory, mut app) = tests::fixture(2);
    let session = app.session.as_mut().unwrap();
    let mut duplicate = session.entries()[0].clone();
    let id = duplicate.id;
    duplicate.name = "synthetic later duplicate only match".into();
    session.body_mut().entries.push(duplicate);
    session.save().unwrap();
    app.reset_unlocked_state();
    app.test_update(Message::SearchChanged("later duplicate".into()));
    assert_eq!(app.filtered_entries.as_deref(), Some([2].as_slice()));
    assert!(
        !app.is_visible_workspace_target(id),
        "the existing first-ID target stays hidden when only a later duplicate matches the query"
    );
}
/// Samples real handlers while the named lane owns an actual completed job at
/// the test-only before-result-ready gate. These are explicitly not advertised
/// as 1,000 actively-computing KDF samples.
fn profile_held_inputs(app: &mut App, id: crate::operations::OperationId) -> serde_json::Value {
    use std::sync::mpsc;
    let (sender, receiver) = mpsc::channel();
    let started = Instant::now();
    let producer = std::thread::spawn(move || {
        for sample in 0..1000 {
            sender.send((sample, Instant::now())).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    });
    let mut raw = Vec::new();
    let mut handlers = Vec::new();
    let mut latency = Vec::new();
    let mut frames = Vec::new();
    for (sample, enqueued) in receiver {
        assert_eq!(
            app.operations.active.as_ref().map(|active| active.id),
            Some(id)
        );
        assert_eq!(
            app.operations.authority.snapshot(Instant::now()).occupied,
            Some(id)
        );
        let handler_started = Instant::now();
        let message = match sample % 3 {
            0 => Message::UserActivity(Instant::now()),
            1 => Message::SecurityTick(Instant::now()),
            _ => Message::WindowFocusChanged(true),
        };
        let _ = app.update(message);
        let handler_us = handler_started.elapsed().as_micros();
        let event_us = enqueued.elapsed().as_micros();
        handlers.push(handler_us);
        latency.push(event_us);
        raw.push(serde_json::json!({"sample":sample,"enqueued_offset_us":enqueued.duration_since(started).as_micros(),
            "handler_us":handler_us,"enqueue_to_handled_us":event_us}));
        if sample % 100 == 0 {
            let now = Instant::now();
            let mut ui = simulator(app);
            let _ = ui.snapshot(&app.theme()).unwrap();
            frames.push(now.elapsed().as_micros());
        }
    }
    producer.join().unwrap();
    serde_json::json!({"raw":raw,"handlers":summary(&handlers),"enqueue_to_handled":summary(&latency),
        "busy_frame_us":frames,"phase":"held after actual work, before result-ready", "same_single_job_verified":true})
}

fn real_operation_probe(
    app: &mut App,
    message: Message,
    label: &str,
    sample: usize,
) -> serde_json::Value {
    use std::sync::mpsc;
    let (arrived_sender, arrived_receiver) = mpsc::channel();
    let (release_sender, release_receiver) = mpsc::channel();
    app.operations
        .service
        .as_ref()
        .unwrap()
        .before_result_ready_for_test(move || {
            arrived_sender
                .send((
                    Instant::now(),
                    std::thread::current().name().map(str::to_owned),
                ))
                .unwrap();
            let _ = release_receiver.recv();
        });
    let entries_before = app.session.as_ref().map(|session| session.entries().len());
    let disk_bytes_before = std::fs::metadata(&app.vault_path)
        .ok()
        .map(|metadata| metadata.len());
    let started = Instant::now();
    let task = app.update(message);
    let submit_handler_us = started.elapsed().as_micros();
    assert!(
        app.operation_busy(),
        "actual named operation must be admitted"
    );
    let id = app.operations.active.as_ref().unwrap().id;
    let mut ui = simulator(app);
    assert!(ui.find("正在后台处理").is_ok());
    let image = ui.snapshot(&app.theme()).unwrap();
    let first_busy_frame_us = started.elapsed().as_micros();
    if sample == 3 {
        let _ = image
            .matches_image(
                std::path::Path::new("target/background-perf")
                    .join(format!("operation-{label}-busy-{}.png", std::process::id())),
            )
            .unwrap();
    }
    drop(ui);
    let (arrived, worker) = arrived_receiver
        .recv_timeout(std::time::Duration::from_secs(180))
        .expect("actual operation must reach real worker before-ready gate; timeout is failure");
    assert_eq!(worker.as_deref(), Some("password-manager-vault-worker"));
    let actual_work_before_barrier_us = arrived.duration_since(started).as_micros();
    let runtime = profile_held_inputs(app, id);
    let release_started = Instant::now();
    let injected_hold_us = release_started.duration_since(arrived).as_micros();
    release_sender.send(()).unwrap();
    let completion_handlers = timed_drain(app, task);
    let release_to_cleanup_us = release_started.elapsed().as_micros();
    let end_to_end_us = started.elapsed().as_micros();
    assert!(!app.operation_busy());
    assert!(
        app.operations
            .authority
            .snapshot(Instant::now())
            .occupied
            .is_none()
    );
    let frame_started = Instant::now();
    let mut ui = simulator(app);
    let image = ui.snapshot(&app.theme()).unwrap();
    let first_result_frame_us = frame_started.elapsed().as_micros();
    if sample == 3 {
        let _ = image
            .matches_image(std::path::Path::new("target/background-perf").join(format!(
                "operation-{label}-result-{}.png",
                std::process::id()
            )))
            .unwrap();
    }
    drop(ui);
    serde_json::json!({"sample":sample,"operation":label,"actual_worker":worker,"entries_before":entries_before,
        "entries_after":app.session.as_ref().map(|session|session.entries().len()),"disk_bytes_before":disk_bytes_before,
        "disk_bytes_after":std::fs::metadata(&app.vault_path).ok().map(|metadata|metadata.len()),
        "submit_handler_us":submit_handler_us,"actual_work_before_result_ready_barrier_us":actual_work_before_barrier_us,
        "first_busy_event_to_snapshot_us":first_busy_frame_us,"injected_result_ready_hold_us":injected_hold_us,
        "actual_end_to_end_excluding_injected_hold_us":end_to_end_us.saturating_sub(injected_hold_us),
        "release_to_cleanup_us":release_to_cleanup_us,"completion_handlers":completion_handlers,
        "first_subsequent_result_snapshot_us":first_result_frame_us,"runtime":runtime,
        "terminal_active_jobs":0,"terminal_result_lane_occupied":false,
        "ui_expected_live_session_owners":usize::from(app.session.is_some()),"unexpected_reveal_owner":app.revealed.is_some(),
        "peak_rss_process_cumulative":std::fs::read_to_string("/proc/self/status").ok()
            .and_then(|status|status.lines().find(|line|line.starts_with("VmHWM:")).map(str::to_owned))})
}

#[derive(Clone, Copy)]
enum ProfileOperation {
    Create,
    Open,
    Mutation,
    EditorSave,
    Save,
    Analyze,
    Apply,
    Backup,
    RestoreCurrent,
    RestoreNew,
    Inspection,
    Csv,
}
impl ProfileOperation {
    fn name(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Open => "open",
            Self::Mutation => "mutation",
            Self::EditorSave => "editor_save",
            Self::Save => "save",
            Self::Analyze => "analyze",
            Self::Apply => "apply",
            Self::Backup => "backup",
            Self::RestoreCurrent => "restore_current",
            Self::RestoreNew => "restore_new",
            Self::Inspection => "inspection",
            Self::Csv => "csv",
        }
    }
    fn all() -> [Self; 12] {
        [
            Self::Create,
            Self::Open,
            Self::Mutation,
            Self::EditorSave,
            Self::Save,
            Self::Analyze,
            Self::Apply,
            Self::Backup,
            Self::RestoreCurrent,
            Self::RestoreNew,
            Self::Inspection,
            Self::Csv,
        ]
    }
}

fn profile_open_original(app: &mut App, original: &std::path::Path) {
    if app
        .session
        .as_ref()
        .is_some_and(|session| session.path() == original)
    {
        app.test_update(Message::CancelPanel);
        return;
    }
    if app.session.is_some() {
        app.test_update(Message::Lock);
    }
    app.test_update(Message::AuthMode(false));
    app.test_update(Message::VaultPathChanged(original.display().to_string()));
    app.test_update(Message::MasterPasswordChanged(
        "gui-synthetic-master-only".into(),
    ));
    app.test_update(Message::OpenVault);
    assert!(app.session.is_some());
}

fn prepare_profile_operation(
    app: &mut App,
    directory: &std::path::Path,
    original: &std::path::Path,
    reference: &std::path::Path,
    operation: ProfileOperation,
    cycle: usize,
) -> (Message, Option<std::path::PathBuf>) {
    let name = operation.name();
    match operation {
        ProfileOperation::Create
        | ProfileOperation::Open
        | ProfileOperation::Inspection
        | ProfileOperation::RestoreNew => {
            if app.session.is_some() {
                app.test_update(Message::Lock);
            }
            if let Some(generation) = app.recovery.as_ref().map(|state| state.generation) {
                app.test_update(Message::CloseRecovery(generation));
            }
        }
        _ => profile_open_original(app, original),
    }
    match operation {
        ProfileOperation::Create => {
            let destination = directory.join(format!("profile-create-{cycle}.pmvault"));
            app.test_update(Message::AuthMode(true));
            app.test_update(Message::VaultPathChanged(destination.display().to_string()));
            app.test_update(Message::MasterPasswordChanged(
                "gui-synthetic-master-only".into(),
            ));
            app.test_update(Message::ConfirmPasswordChanged(
                "gui-synthetic-master-only".into(),
            ));
            (Message::CreateVault, Some(destination))
        }
        ProfileOperation::Open => {
            app.test_update(Message::AuthMode(false));
            app.test_update(Message::VaultPathChanged(original.display().to_string()));
            app.test_update(Message::MasterPasswordChanged(
                "gui-synthetic-master-only".into(),
            ));
            (Message::OpenVault, None)
        }
        ProfileOperation::Mutation => {
            app.test_update(Message::SetNav(NavFilter::All));
            app.test_update(Message::SearchChanged(String::new()));
            app.test_update(Message::SetCardPage(0));
            let id = app
                .session
                .as_ref()
                .unwrap()
                .active_entries()
                .next()
                .unwrap()
                .id;
            (Message::CardAction(id, CardAction::Favorite), None)
        }
        ProfileOperation::EditorSave => {
            app.test_update(Message::NewEntry);
            app.test_update(Message::EditorNameChanged(format!(
                "synthetic profile editor {cycle}"
            )));
            app.test_update(Message::EditorWebsiteChanged(format!(
                "https://editor-{cycle}.example.test"
            )));
            app.test_update(Message::EditorUsernameChanged(format!(
                "synthetic-editor-user-{cycle}"
            )));
            app.test_update(Message::EditorPasswordChanged(
                "synthetic editor password only".into(),
            ));
            (Message::SaveEditor, None)
        }
        ProfileOperation::Save => (Message::Save, None),
        ProfileOperation::Analyze | ProfileOperation::Apply => {
            let source = directory.join(format!("profile-{name}-source.csv"));
            let mut writer = csv::Writer::from_path(&source).unwrap();
            writer
                .write_record(["name", "url", "username", "password"])
                .unwrap();
            if matches!(operation, ProfileOperation::Analyze) {
                for entry in app.session.as_ref().unwrap().entries() {
                    writer
                        .write_record([
                            entry.name.as_str(),
                            entry.website.as_str(),
                            entry.username.as_str(),
                            "synthetic-profile-new-password",
                        ])
                        .unwrap();
                }
            } else {
                writer
                    .write_record([
                        format!("synthetic profile new {cycle}"),
                        format!("https://profile-added-{cycle}.example.test"),
                        format!("synthetic-profile-user-{cycle}"),
                        "synthetic profile password".into(),
                    ])
                    .unwrap();
            }
            writer.flush().unwrap();
            drop(writer);
            app.test_update(Message::OpenImport);
            app.test_update(Message::ImportPathChanged(source.display().to_string()));
            if matches!(operation, ProfileOperation::Analyze) {
                (Message::AnalyzeImport, None)
            } else {
                app.test_update(Message::AnalyzeImport);
                let Panel::Import(state) = &app.panel else {
                    panic!("import state");
                };
                let preview = state.preview.as_ref().unwrap();
                assert_eq!(preview.summary().new, 1);
                (Message::ApplyImport(preview.id()), None)
            }
        }
        ProfileOperation::Backup => {
            app.test_update(Message::OpenSettings);
            let destination = directory.join(format!("profile-backup-{cycle}.pmvault"));
            app.test_update(Message::BackupPathChanged(
                destination.display().to_string(),
            ));
            (Message::CreateBackup, Some(destination))
        }
        ProfileOperation::RestoreCurrent => {
            app.test_update(Message::OpenSettings);
            app.test_update(Message::RestorePathChanged(reference.display().to_string()));
            app.test_update(Message::RestorePasswordChanged(
                "gui-synthetic-master-only".into(),
            ));
            app.test_update(Message::ConfirmRestoreChanged(true));
            (Message::RestoreBackup, None)
        }
        ProfileOperation::Inspection => {
            app.test_update(Message::AuthMode(false));
            app.test_update(Message::VaultPathChanged(original.display().to_string()));
            (Message::OpenRecovery, None)
        }
        ProfileOperation::RestoreNew => {
            app.test_update(Message::AuthMode(false));
            app.test_update(Message::VaultPathChanged(original.display().to_string()));
            app.test_update(Message::OpenRecovery);
            let generation = app.recovery.as_ref().unwrap().generation;
            let destination = directory.join(format!("profile-restore-new-{cycle}.pmvault"));
            app.test_update(Message::RecoverySourceChanged(
                generation,
                reference.display().to_string(),
            ));
            app.test_update(Message::RecoveryDestinationChanged(
                generation,
                destination.display().to_string(),
            ));
            app.test_update(Message::RecoveryPasswordChanged(
                generation,
                "gui-synthetic-master-only".into(),
            ));
            (Message::RestoreRecoveryCopy(generation), Some(destination))
        }
        ProfileOperation::Csv => {
            app.test_update(Message::OpenSettings);
            let destination = directory.join(format!("profile-csv-{cycle}.csv"));
            app.test_update(Message::CsvPathChanged(destination.display().to_string()));
            app.test_update(Message::ConfirmPlaintextChanged(true));
            (Message::ExportPlaintextCsv, Some(destination))
        }
    }
}

fn all_operation_profiles(
    mut app: App,
    directory: &std::path::Path,
    fixture: &str,
) -> serde_json::Value {
    let original = std::path::PathBuf::from(&app.vault_path);
    let reference = directory.join("profile-reference.pmvault");
    std::fs::copy(&original, &reference).unwrap();
    let original_bytes = std::fs::metadata(&original).unwrap().len();
    // A measurement run can last >5min. This fixture-specific clock budget is
    // declared; production defaults and deadline regression tests are unchanged.
    app.idle_minutes = 30;
    app.reset_unlocked_state();
    let selected = std::env::var("PM_PERF_OPERATION").ok();
    if let Some(selected) = &selected {
        assert!(
            ProfileOperation::all()
                .iter()
                .any(|operation| operation.name() == selected),
            "unknown operation selector"
        );
    }
    let mut groups = Vec::new();
    for operation in ProfileOperation::all().into_iter().filter(|operation| {
        selected
            .as_ref()
            .is_none_or(|selected| selected == operation.name())
    }) {
        let mut samples = Vec::new();
        for cycle in 0..13 {
            let (message, output) = prepare_profile_operation(
                &mut app, directory, &original, &reference, operation, cycle,
            );
            let before = app.session.as_ref().map(|session| {
                (
                    session.revision(),
                    session.entries().len(),
                    session.operation_binding().instance,
                )
            });
            let mut observation = real_operation_probe(
                &mut app,
                message,
                &format!("{fixture}-{}", operation.name()),
                cycle,
            );
            match operation {
                ProfileOperation::Analyze => {
                    let Panel::Import(state) = &app.panel else {
                        panic!("analysis panel");
                    };
                    assert!(
                        state.preview.is_some(),
                        "actual analysis must install a preview"
                    );
                }
                ProfileOperation::Inspection => assert!(
                    app.recovery.is_some(),
                    "actual inspection must install its explicit listing"
                ),
                ProfileOperation::RestoreNew => {
                    assert!(app.session.is_none(), "copy-new remains locked")
                }
                _ => assert!(
                    app.session.is_some(),
                    "actual successful category must return its session"
                ),
            }
            assert!(
                app.operations.failure_notice.is_none()
                    && app.recovery_notice.is_none()
                    && app.export_notice.is_none(),
                "ordinary profile must not measure a retained failure as success"
            );
            assert!(
                !app.status.starts_with("操作未完成") && !app.status.starts_with("导出失败"),
                "ordinary profile must not silently count rejected work"
            );
            let after = app.session.as_ref().map(|session| {
                (
                    session.revision(),
                    session.entries().len(),
                    session.operation_binding().instance,
                )
            });
            match operation {
                ProfileOperation::Mutation => {
                    let before = before.unwrap();
                    let after = after.unwrap();
                    assert_eq!(after.0, before.0 + 1, "favorite must really publish");
                    assert_eq!(after.1, before.1);
                    assert_eq!(after.2, before.2);
                }
                ProfileOperation::EditorSave | ProfileOperation::Apply => {
                    let before = before.unwrap();
                    let after = after.unwrap();
                    assert_eq!(
                        after.0,
                        before.0 + 1,
                        "changed save/import must really publish"
                    );
                    assert_eq!(after.1, before.1 + 1, "this profile adds exactly one row");
                    assert_eq!(after.2, before.2);
                }
                ProfileOperation::Save
                | ProfileOperation::Analyze
                | ProfileOperation::Backup
                | ProfileOperation::Csv => {
                    assert_eq!(
                        after, before,
                        "read/export profiles preserve live session metadata"
                    );
                }
                ProfileOperation::RestoreCurrent => assert_ne!(
                    after.unwrap().2,
                    before.unwrap().2,
                    "successful restore must install the verified replacement instance"
                ),
                _ => {}
            }
            observation["verified_success_effect"] = serde_json::json!(true);
            observation["changed_import_rows"] =
                serde_json::json!(if matches!(operation, ProfileOperation::Apply) {
                    Some(1)
                } else {
                    None
                });
            if let Some(output) = output {
                let bytes = std::fs::metadata(&output)
                    .expect("actual operation output must exist")
                    .len();
                observation["actual_output_bytes"] = serde_json::json!(bytes);
                if app
                    .session
                    .as_ref()
                    .is_some_and(|session| session.path() == output.as_path())
                {
                    app.test_update(Message::Lock);
                }
                std::fs::remove_file(output).unwrap();
            }
            if cycle >= 3 {
                samples.push(observation);
            }
        }
        groups.push(serde_json::json!({"operation":operation.name(),"warmups":3,"measured":10,
            "samples":samples,"duration_percentiles":"none from10 operations; >=1000 input samples per operation are separately labeled"}));
        println!(
            "OPERATION_PROFILE fixture={fixture} operation={} measured=10",
            operation.name()
        );
    }
    if app.session.is_some() {
        app.test_update(Message::Lock);
    }
    app.test_drain_pending();
    assert!(
        app.operations
            .authority
            .snapshot(Instant::now())
            .occupied
            .is_none()
    );
    serde_json::json!({"fixture":fixture,"final_ui_live_session_owners":usize::from(app.session.is_some()),"final_worker_lane_occupied":false,"original_actual_encrypted_vault_bytes":original_bytes,"logical_idle_minutes_for_fixture":30,
        "groups":groups,"owner_accounting":"One admitted job and result lane per sample, terminal lane0, expected live UI session0or1. Exact parser/renderer allocator copies are not counted as secret owners.",
        "conservative_buffers":"Current encrypted session body/keys, original and tentative encrypted-body snapshots, current/backup/candidate encoded files, parser/captured sources, normalized items/preview, readback, guarded plaintext serialization/decryption/CSV owners and KDF scratch can coexist. Metadata index copies and renderer/parser internal buffers add memory. This is not a64MiB total-memory claim; process peak includes fixture and measurement instrumentation."})
}

#[test]
#[ignore = "release actual all-category3warmup10measurements and1000held-result input samples"]
fn perf_background_all_operation_categories() {
    if cfg!(debug_assertions) {
        panic!("run with --release");
    }
    let output = std::path::Path::new("target/background-perf");
    std::fs::create_dir_all(output).unwrap();
    let selected = std::env::var("PM_PERF_ENTRIES")
        .ok()
        .map(|value| value.parse::<usize>().unwrap());
    if let Some(size) = selected {
        assert!([1000, 10000, 50000].contains(&size));
    }
    for size in [1000, 10000, 50000]
        .into_iter()
        .filter(|size| selected.is_none_or(|selected| selected == *size))
    {
        let (directory, app, setup_us) = large_fixture(size);
        let result = all_operation_profiles(app, directory.path(), &size.to_string());
        let selected_operation =
            std::env::var("PM_PERF_OPERATION").unwrap_or_else(|_| "all".into());
        let report = serde_json::json!({"environment":environment(),"fixture_setup_us":setup_us,"profile":result,
            "unmeasured":"Native realwindow, documented referencehost, high1GiB KDF andnear64MiB vault are separate explicit probes"});
        std::fs::write(
            output.join(format!(
                "operation-profiles-{size}-{selected_operation}.json"
            )),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
    }
}

#[test]
#[ignore = "release near64MiB valid vault all-category profile and64MiB+1 rejection"]
fn perf_background_near_limit_vault_operations() {
    if cfg!(debug_assertions) {
        panic!("run with --release");
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("near-limit.pmvault");
    let setup_started = Instant::now();
    let (session, bytes) = crate::storage::performance_fixtures::build_near_limit_vault(
        &path,
        "gui-synthetic-master-only",
        crate::security::KdfConfig::default(),
    )
    .unwrap();
    let setup_us = setup_started.elapsed().as_micros();
    assert!(bytes <= 64 * 1024 * 1024);
    assert!(bytes >= 64 * 1024 * 1024 - 64 * 1024);
    let mut app = App::initial();
    app.vault_path = path.display().to_string();
    app.session = Some(session);
    app.reset_unlocked_state();
    let profile = all_operation_profiles(app, directory.path(), "near-64MiB");
    let overlimit = directory.path().join("over-limit.pmvault");
    let overlimit_bytes =
        crate::storage::performance_fixtures::write_overlimit_copy(&path, &overlimit).unwrap();
    assert_eq!(overlimit_bytes, 64 * 1024 * 1024 + 1);
    let mut rejected = App::initial();
    rejected.vault_path = overlimit.display().to_string();
    rejected.test_update(Message::MasterPasswordChanged(
        "gui-synthetic-master-only".into(),
    ));
    let overlimit_probe =
        real_operation_probe(&mut rejected, Message::OpenVault, "overlimit-open", 3);
    assert!(
        rejected.session.is_none(),
        "actual overlimit vault must be rejected"
    );
    let report = serde_json::json!({"environment":environment(),"fixture_setup_us":setup_us,"actual_near_vault_bytes":bytes,
        "actual_overlimit_bytes":overlimit_bytes,"profile":profile,"overlimit_actual_worker_rejection":overlimit_probe});
    std::fs::create_dir_all("target/background-perf").unwrap();
    std::fs::write(
        "target/background-perf/near-limit-vault-profiles.json",
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
}

#[test]
#[ignore = "explicit provisioned real1GiB accepted KDF on named Open worker;3samples,no durationp99"]
fn perf_background_high_memory_accepted_kdf() {
    if cfg!(debug_assertions) {
        panic!("run with --release");
    }
    assert!(
        std::env::var("PM_PERF_PROVISIONED_1G").ok().as_deref() == Some("1"),
        "requires explicit provisioned-host flag; otherwise this scenario remains unmeasured"
    );
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("high-kdf.pmvault");
    let config = crate::security::KdfConfig {
        memory_kib: 1024 * 1024,
        iterations: 3,
        parallelism: 1,
    };
    let setup_started = Instant::now();
    let session = crate::storage::performance_fixtures::create_synthetic_vault(
        &path,
        "gui-synthetic-master-only",
        config,
    )
    .unwrap();
    let setup_us = setup_started.elapsed().as_micros();
    drop(session);
    let mut app = App::initial();
    app.vault_path = path.display().to_string();
    app.idle_minutes = 30;
    let mut samples = Vec::new();
    for sample in 0..3 {
        if app.session.is_some() {
            app.test_update(Message::Lock);
        }
        app.test_update(Message::MasterPasswordChanged(
            "gui-synthetic-master-only".into(),
        ));
        samples.push(real_operation_probe(
            &mut app,
            Message::OpenVault,
            "high1GiB-kdf-open",
            sample + 3,
        ));
        assert!(
            app.session.is_some(),
            "accepted1GiB KDF must actually open on worker"
        );
    }
    app.test_update(Message::Lock);
    assert!(app.session.is_none());
    let exact_direct_kdf_phase = timed_kdf_phase(config, 0, 3);
    let report = serde_json::json!({"environment":environment(),"exact_direct_kdf_phase":exact_direct_kdf_phase,
        "fixture_kdf_setup_us":setup_us,"kdf":{
        "memory_kib":config.memory_kib,"iterations":config.iterations,"parallelism":config.parallelism},
        "actual_vault_bytes":std::fs::metadata(&path).unwrap().len(),"warmups":0,"sample_count":3,"samples":samples,
        "duration_percentiles":"none from3 controlled operations","rss_caveat":"Fresh process peak includes fixture setup KDF as well as actual named worker KDFs",
        "input_caveat":"1000samples per operation at result-ready barrier AFTER KDF. Firstbusy pixels and prebarrier workduration cover actual KDF; these are not1000actively-computing KDF latency samples."});
    std::fs::create_dir_all("target/background-perf").unwrap();
    std::fs::write(
        "target/background-perf/high-memory-kdf.json",
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
}

fn timed_kdf_phase(
    config: crate::security::KdfConfig,
    warmups: usize,
    measured: usize,
) -> serde_json::Value {
    let mut samples = Vec::new();
    for sample in 0..warmups + measured {
        let started = Instant::now();
        let key = zeroize::Zeroizing::new(
            crate::security::derive_kek(
                "synthetic KDF phase benchmark only",
                &[57; crate::security::SALT_LEN],
                config,
            )
            .unwrap(),
        );
        let duration_us = started.elapsed().as_micros();
        std::hint::black_box(&*key);
        drop(key);
        if sample >= warmups {
            samples.push(duration_us);
        }
    }
    serde_json::json!({"warmups":warmups,"sample_count":measured,"derive_kek_phase_us":samples,
        "includes":"actual Argon2 scratch allocation/initialization/hash and scratch/output cleanup in derive_kek",
        "excludes":"vault IO/AEAD/parser/worker dispatch and injected barriers",
        "execution":"direct test-thread phase benchmark; actual named Open worker timings reported separately",
        "duration_percentiles":"none from10 or3 operations","config":{"memory_kib":config.memory_kib,
            "iterations":config.iterations,"parallelism":config.parallelism}})
}

#[test]
#[ignore = "release exact default derive_kek phase3warmup10measurements,not wholefixture/IO"]
fn perf_background_default_kdf_phase() {
    if cfg!(debug_assertions) {
        panic!("run with --release");
    }
    let phase = timed_kdf_phase(crate::security::KdfConfig::default(), 3, 10);
    let report = serde_json::json!({"environment":environment(),"phase":phase,
        "process_peak_rss":std::fs::read_to_string("/proc/self/status").ok()
            .and_then(|status|status.lines().find(|line|line.starts_with("VmHWM:")).map(str::to_owned))});
    std::fs::create_dir_all("target/background-perf").unwrap();
    std::fs::write(
        "target/background-perf/default-kdf-phase.json",
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!(
        "DEFAULT_KDF_PHASE {}",
        serde_json::to_string(&report).unwrap()
    );
}

/// Input producer starts at real Open admission. Only handler intervals ending
/// before the named worker's actual work-completion timestamp count as active.
/// The result-ready hold is solely for ownership inspection after that timestamp.
#[test]
#[ignore = "release provisioned1GiB actual-work overlap;3runs,>=1000active events each"]
fn perf_background_active_high_memory_open_inputs() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use std::time::Duration;
    if cfg!(debug_assertions) {
        panic!("run with --release");
    }
    assert_eq!(std::env::var("PM_PERF_PROVISIONED_1G").as_deref(), Ok("1"));
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("active-high-kdf.pmvault");
    let config = crate::storage::performance_fixtures::HIGH_MEMORY_KDF;
    drop(
        crate::storage::performance_fixtures::create_synthetic_vault(
            &path,
            "gui-synthetic-master-only",
            config,
        )
        .unwrap(),
    );
    let output = std::path::Path::new("target/background-perf");
    std::fs::create_dir_all(output).unwrap();
    let mut app = App::initial();
    app.vault_path = path.display().to_string();
    app.idle_minutes = 30;
    let mut runs = Vec::new();
    for run in 0..3 {
        if app.session.is_some() {
            app.test_update(Message::Lock);
        }
        app.test_update(Message::MasterPasswordChanged(
            "gui-synthetic-master-only".into(),
        ));
        let work_done = Arc::new(AtomicBool::new(false));
        let hook_done = Arc::clone(&work_done);
        let (arrived_tx, arrived_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        app.operations
            .service
            .as_ref()
            .unwrap()
            .before_result_ready_for_test(move || {
                let completed = Instant::now();
                hook_done.store(true, Ordering::Release);
                arrived_tx
                    .send((completed, std::thread::current().name().map(str::to_owned)))
                    .unwrap();
                let _ = release_rx.recv();
            });
        let (input_tx, input_rx) = mpsc::channel();
        let started = Instant::now();
        let task = app.update(Message::OpenVault);
        let submit_us = started.elapsed().as_micros();
        let id = app.operations.active.as_ref().unwrap().id;
        let producer_done = Arc::clone(&work_done);
        let producer = std::thread::Builder::new()
            .name("synthetic-active-input-producer".into())
            .spawn(move || {
                let mut sample = 0;
                while !producer_done.load(Ordering::Acquire) {
                    input_tx.send((sample, Instant::now())).unwrap();
                    sample += 1;
                    std::thread::sleep(Duration::from_millis(1));
                    assert!(
                        started.elapsed() < Duration::from_secs(180),
                        "active-work timeout is failure"
                    );
                }
            })
            .unwrap();
        let frame_start = Instant::now();
        let mut ui = simulator(&app);
        assert!(ui.find("正在后台处理").is_ok());
        let image = ui.snapshot(&app.theme()).unwrap();
        let first_busy_end = Instant::now();
        let _ = image
            .matches_image(output.join(format!("active-high-kdf-busy-{run}.png")))
            .unwrap();
        drop(ui);
        let mut events = Vec::new();
        let mut frames = Vec::new();
        for (sample, enqueued) in input_rx {
            assert_eq!(
                app.operations.authority.snapshot(Instant::now()).occupied,
                Some(id)
            );
            assert_eq!(
                app.operations.active.as_ref().map(|active| active.id),
                Some(id)
            );
            assert!(app.session.is_none(), "one session owner remains on worker");
            let handler_start = Instant::now();
            let _ = app.update(match sample % 3 {
                0 => Message::UserActivity(handler_start),
                1 => Message::SecurityTick(handler_start),
                _ => Message::WindowFocusChanged(true),
            });
            let handler_end = Instant::now();
            events.push((sample, enqueued, handler_start, handler_end));
            if sample % 100 == 0 {
                let start = Instant::now();
                let mut ui = simulator(&app);
                let _ = ui.snapshot(&app.theme()).unwrap();
                frames.push((start, Instant::now()));
            }
        }
        producer.join().unwrap();
        let (completed, worker) = arrived_rx.recv_timeout(Duration::from_secs(180)).unwrap();
        assert_eq!(worker.as_deref(), Some("password-manager-vault-worker"));
        let mut active_handlers = Vec::new();
        let mut active_latencies = Vec::new();
        let mut raw = Vec::new();
        for (sample, enqueued, begin, end) in events {
            let active = end <= completed;
            let handler_us = end.duration_since(begin).as_micros();
            let latency_us = end.duration_since(enqueued).as_micros();
            if active {
                active_handlers.push(handler_us);
                active_latencies.push(latency_us);
            }
            raw.push(serde_json::json!({"sample":sample,"enqueued_offset_us":enqueued.duration_since(started).as_micros(),
                "handler_start_offset_us":begin.duration_since(started).as_micros(),"handler_end_offset_us":end.duration_since(started).as_micros(),
                "handler_us":handler_us,"enqueue_to_handled_us":latency_us,"wholly_before_actual_work_completion":active}));
        }
        assert!(
            active_handlers.len() >= 1000,
            "insufficient actual active samples; do not report fake p99"
        );
        assert!(
            first_busy_end < completed,
            "first busy pixels must overlap actual work"
        );
        let raw_frames: Vec<_> = frames.into_iter().map(|(begin,end)| serde_json::json!({
            "start_offset_us":begin.duration_since(started).as_micros(),"end_offset_us":end.duration_since(started).as_micros(),
            "layout_and_snapshot_us":end.duration_since(begin).as_micros(),"wholly_before_actual_work_completion":end<=completed})).collect();
        let release = Instant::now();
        release_tx.send(()).unwrap();
        let completion_handlers = timed_drain(&mut app, task);
        assert!(app.session.is_some());
        assert!(!app.operation_busy());
        assert!(
            app.operations
                .authority
                .snapshot(Instant::now())
                .occupied
                .is_none()
        );
        runs.push(serde_json::json!({"run":run,"worker":worker,"submit_handler_us":submit_us,
            "actual_work_completed_offset_us":completed.duration_since(started).as_micros(),
            "first_busy_layout_snapshot_us":first_busy_end.duration_since(frame_start).as_micros(),
            "first_busy_event_to_snapshot_us":first_busy_end.duration_since(started).as_micros(),
            "injected_hold_after_work_us":release.duration_since(completed).as_micros(),
            "active_handler_summary":summary(&active_handlers),"active_enqueue_to_handled_summary":summary(&active_latencies),
            "raw_events":raw,"frames":raw_frames,"completion_handlers":completion_handlers,
            "terminal_occupied":false,"expected_ui_session_owners":1}));
    }
    app.test_update(Message::Lock);
    assert!(app.session.is_none());
    let report = serde_json::json!({"environment":environment(),"kdf":{"memory_kib":config.memory_kib,"iterations":config.iterations,"parallelism":config.parallelism},
        "runs":runs,"operation_samples":3,"duration_percentiles":"none from3operations",
        "overlap_definition":"Handler end <= actual named Open work-completion timestamp. This interval includes real KDF and vault IO/verification; no injected delay occurs before work completion. Late queued samples are saved but excluded from active percentiles.",
        "process_peak_rss":std::fs::read_to_string("/proc/self/status").ok().and_then(|status|status.lines().find(|line|line.starts_with("VmHWM:")).map(str::to_owned)),
        "terminal_live_ui_session_owners":0,"terminal_occupied":app.operations.authority.snapshot(Instant::now()).occupied.is_some()});
    std::fs::write(
        output.join("active-high-memory-open-inputs.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
}

#[test]
#[ignore = "headless all supported sizes: existing cards, global import choices and categories across pages"]
fn gui_pagination_captures_all_supported_sizes() {
    let (_directory, mut app) = tests::fixture(49);
    let session = app.session.as_mut().unwrap();
    session.body_mut().categories = (0..49).map(|i| format!("分页分类 {i:03}")).collect();
    session.save().unwrap();
    app.reset_unlocked_state();
    let id = app.session.as_ref().unwrap().entries()[48].id;
    let output = std::path::Path::new("target/gui-artifacts");
    std::fs::create_dir_all(output).unwrap();
    for size in [(960.0, 640.0), (1280.0, 800.0), (1600.0, 900.0)] {
        app.test_update(Message::SetCardPage(2));
        app.test_update(Message::NavigatePage(PageTarget::Categories, true));
        app.test_update(Message::NavigatePage(PageTarget::Categories, true));
        let mut ui = Simulator::with_size(
            iced_test::core::Settings {
                default_font: UI_FONT,
                default_text_size: iced::Pixels(14.0),
                ..iced_test::core::Settings::default()
            },
            size,
            app.view(),
        );
        assert!(ui.find(selector::id(format!("card-{id}"))).is_ok());
        assert!(ui.find("第 3 / 3 页").is_ok());
        assert!(ui.find("分类第 3 / 3 页 · 共 49 个").is_ok());
        let _ = ui
            .snapshot(&app.theme())
            .unwrap()
            .matches_image(output.join(format!("pagination-cards-last-{}x{}.png", size.0, size.1)))
            .unwrap();
        drop(ui);
        app.test_update(Message::SearchChanged("synthetic-user-0".into()));
        assert_eq!(app.card_page, 0);
        let mut ui = Simulator::with_size(
            iced_test::core::Settings {
                default_font: UI_FONT,
                default_text_size: iced::Pixels(14.0),
                ..iced_test::core::Settings::default()
            },
            size,
            app.view(),
        );
        assert!(ui.find("第 1 / 1 页").is_ok());
        let _ = ui
            .snapshot(&app.theme())
            .unwrap()
            .matches_image(output.join(format!(
                "pagination-global-search-{}x{}.png",
                size.0, size.1
            )))
            .unwrap();
        drop(ui);
        app.test_update(Message::SearchChanged(String::new()));
    }
    let preview = conflict_preview(&app);
    let preview_id = preview.id();
    let mut state = ImportState::new();
    state.preview = Some(preview);
    app.panel = Panel::Import(Box::new(state));
    for row in 0..8 {
        app.test_update(Message::SetImportResolution(
            preview_id,
            row,
            ConflictResolution::KeepLocal,
        ));
    }
    for size in [(960.0, 640.0), (1280.0, 800.0), (1600.0, 900.0)] {
        app.test_update(Message::SetImportPage(preview_id, 6));
        let mut ui = Simulator::with_size(
            iced_test::core::Settings {
                default_font: UI_FONT,
                default_text_size: iced::Pixels(14.0),
                ..iced_test::core::Settings::default()
            },
            size,
            app.view(),
        );
        assert!(ui.find(selector::id("import-row-48")).is_ok());
        assert!(ui.find("还有 41 项需要选择处理方式。").is_ok());
        let _ = ui
            .snapshot(&app.theme())
            .unwrap()
            .matches_image(output.join(format!("pagination-import-last-{}x{}.png", size.0, size.1)))
            .unwrap();
        drop(ui);
        app.test_update(Message::SetImportPage(preview_id, 0));
        let Panel::Import(state) = &app.panel else {
            panic!("import")
        };
        assert_eq!(state.resolutions.len(), 8);
        let mut ui = Simulator::with_size(
            iced_test::core::Settings {
                default_font: UI_FONT,
                default_text_size: iced::Pixels(14.0),
                ..iced_test::core::Settings::default()
            },
            size,
            app.view(),
        );
        let _ = ui
            .snapshot(&app.theme())
            .unwrap()
            .matches_image(output.join(format!(
                "pagination-import-decisions-retained-{}x{}.png",
                size.0, size.1
            )))
            .unwrap();
    }
}

#[test]
#[ignore = "create new synthetic native paging fixture for an explicit desktop smoke, never overwrite"]
fn prepare_background_native_paging_fixture() {
    use std::io::Write;
    let output = std::path::Path::new("target/native-background-fixture");
    std::fs::create_dir(output).expect("new fixture directory must not exist");
    let (_directory, mut app) = tests::fixture(49);
    let session = app.session.as_mut().unwrap();
    session.body_mut().categories = (0..49)
        .map(|i| format!("synthetic-native-category-{i:03}"))
        .collect();
    for (i, entry) in session.body_mut().entries.iter_mut().enumerate() {
        entry.category = format!("synthetic-native-category-{i:03}");
        if i < 17 {
            entry.website = "https://synthetic-native-conflict.example.test".into();
            entry.username = "synthetic-native-user".into();
        }
    }
    session.save().unwrap();
    let mut vault = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("passwords.pmvault"))
        .unwrap();
    vault
        .write_all(&std::fs::read(&app.vault_path).unwrap())
        .unwrap();
    vault.sync_all().unwrap();
    let csv = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("native-import.csv"))
        .unwrap();
    let mut csv = csv::Writer::from_writer(csv);
    csv.write_record(["name", "url", "username", "password", "note"])
        .unwrap();
    for i in 0..17 {
        csv.write_record([
            format!("Synthetic imported {i:03}"),
            "https://synthetic-native-conflict.example.test".into(),
            "synthetic-native-user".into(),
            "synthetic-new-only".into(),
            "synthetic-note-only".into(),
        ])
        .unwrap();
    }
    csv.flush().unwrap();
    app.test_update(Message::Lock);
    assert!(app.session.is_none());
}

/// Bounded external-runner diagnostic: every phase is checkpointed before it
/// starts so a killed shaping process is an explicit timeout, never a pass.
#[test]
#[ignore = "release-only giant-field diagnostic; run each size in a time-bounded process"]
fn perf_background_single_entry_editor_diagnostic() {
    if cfg!(debug_assertions) {
        panic!("run with --release");
    }
    fn assert_send_static<T: Send + 'static>() {}
    assert_send_static::<text_editor::Content>();
    assert_send_static::<EditorState>();
    let mode = std::env::var("PM_EDITOR_MODE").unwrap_or_else(|_| "app".into());
    let length: usize = std::env::var("PM_EDITOR_BYTES")
        .unwrap_or_else(|_| "4096".into())
        .parse()
        .unwrap();
    let file = std::path::PathBuf::from(std::env::var("PM_EDITOR_REPORT").unwrap());
    let mut report = serde_json::json!({
        "mode":mode,"requested_notes_bytes":length,"samples":1,
        "duration_percentiles":"none; one diagnostic sample",
        "content_send_static":true,"editor_state_send_static":true,
        "current_phase":"fixture","phases_us":{},"completed":false,
    });
    let flush = |report: &serde_json::Value| {
        std::fs::write(&file, serde_json::to_vec_pretty(report).unwrap()).unwrap();
    };
    flush(&report);
    macro_rules! measure {
        ($phase:literal, $expression:expr) => {{
            report["current_phase"] = serde_json::json!($phase);
            flush(&report);
            let start = Instant::now();
            let value = $expression;
            report["phases_us"][$phase] = serde_json::json!(start.elapsed().as_micros());
            flush(&report);
            value
        }};
    }
    if mode == "content" {
        let notes = "x".repeat(length);
        let content: text_editor::Content = measure!(
            "content_construction",
            text_editor::Content::with_text(&notes)
        );
        measure!("content_drop", drop(content));
    } else {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("synthetic-single-entry.pmvault");
        let config = crate::security::KdfConfig {
            memory_kib: 8192,
            iterations: 1,
            parallelism: 1,
        };
        let (session, bytes) = if mode == "near-decrypt" {
            crate::storage::performance_fixtures::build_near_limit_vault(
                &path,
                "synthetic-editor-only",
                config,
            )
            .unwrap()
        } else {
            let mut session = crate::storage::performance_fixtures::create_synthetic_vault(
                &path,
                "synthetic-editor-only",
                config,
            )
            .unwrap();
            session
                .add_entry(crate::domain::EntryDraft {
                    name: "Synthetic editor diagnostic".into(),
                    website: "https://synthetic.invalid".into(),
                    username: "synthetic".into(),
                    category: "其他".into(),
                    favorite: false,
                    secret: crate::domain::SecretPayload::new("synthetic-only", "x".repeat(length)),
                    provenance: None,
                })
                .unwrap();
            session.save().unwrap();
            let bytes = std::fs::metadata(&path).unwrap().len() as usize;
            (session, bytes)
        };
        report["actual_encoded_vault_bytes"] = serde_json::json!(bytes);
        let id = session.entries()[0].id;
        let secret = measure!("decrypt_parse", session.reveal_secret(id).unwrap());
        report["actual_notes_bytes"] = serde_json::json!(secret.notes.len());
        measure!("secret_drop", drop(secret));
        let mut app = App::initial();
        app.idle_minutes = 30;
        app.vault_path = path.display().to_string();
        app.session = Some(session);
        app.reset_unlocked_state();
        app.selected = Some(id);
        app.context_open = true;
        let reveal = measure!("toggle_reveal_handler", app.update(Message::ToggleReveal));
        tests::drain_task(&mut app, reveal);
        assert!(app.revealed.is_some());
        app.test_update(Message::CloseContext);
        app.selected = Some(id);
        let copy = measure!("copy_password_handler", app.update(Message::CopyPassword));
        tests::drain_task(&mut app, copy);
        report["copy_scope"] = serde_json::json!(
            "Linux full handler through enqueue; no native clipboard completion claim"
        );
        if mode != "near-decrypt" {
            let edit = measure!("edit_entry_handler", app.update(Message::EditEntry(id)));
            tests::drain_task(&mut app, edit);
            assert!(matches!(app.panel, Panel::Editor(_)));
            let mut ui = measure!("editor_first_layout", simulator(&app));
            measure!("editor_first_snapshot", ui.snapshot(&app.theme()).unwrap());
            drop(ui);
            let action = measure!(
                "notes_action_handler",
                app.update(Message::EditorNotesAction(text_editor::Action::Move(
                    text_editor::Motion::DocumentEnd
                ),))
            );
            tests::drain_task(&mut app, action);
            let lock = measure!("lock_handler_with_editor_drop", app.update(Message::Lock));
            tests::drain_task(&mut app, lock);
        }
    }
    report["process_peak_rss"] = serde_json::json!(
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| status
                .lines()
                .find(|line| line.starts_with("VmHWM:"))
                .map(str::to_owned))
    );
    report["current_phase"] = serde_json::json!("complete");
    report["completed"] = serde_json::json!(true);
    flush(&report);
}
