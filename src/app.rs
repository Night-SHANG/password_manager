use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use iced::widget::{self, operation, text_editor};
use iced::{Element, Font, Length, Subscription, Task, Theme, keyboard};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::domain::EntryRecord;
use crate::export::{PlaintextExportAcknowledgement, export_plaintext_csv};
use crate::import::plan::{
    ConflictResolution, ImportApplyOptions, ImportClass, ImportPreview, apply_preview,
    build_preview,
};
use crate::import::stage_path;
use crate::platform::{self, SecurityEvent};
use crate::services::{PasswordGeneratorOptions, draft, generate_password, safe_web_url};
use crate::storage::VaultSession;
use crate::{AppError, Result};

mod actions;
mod export_notice;
mod picker;
mod recovery;
mod safety;
#[cfg(test)]
mod tests;
mod ui;

const UI_FONT: Font = Font::with_name("Microsoft YaHei UI");

pub fn run() -> iced::Result {
    iced::application(App::new, App::update, App::view)
        .title("密码管理器")
        .settings(iced::Settings {
            default_font: UI_FONT,
            default_text_size: iced::Pixels(14.0),
            ..iced::Settings::default()
        })
        .window(iced::window::Settings {
            size: iced::Size::new(1280.0, 800.0),
            min_size: Some(iced::Size::new(960.0, 640.0)),
            exit_on_close_request: false,
            ..iced::window::Settings::default()
        })
        .subscription(App::subscription)
        .theme(App::theme)
        .run()
}

struct App {
    closing: bool,
    export_notice: Option<export_notice::ExportNotice>,
    export_notice_generation: u64,
    export_close_prompt: Option<export_notice::ExportClosePrompt>,
    export_close_sequence: u64,
    pending_editor_cut: Option<PendingEditorCut>,
    clipboard_cleanup_failed: bool,
    clipboard_warning_generation: u64,
    clipboard_session: Option<platform::ClipboardSession>,
    clipboard_request: u64,
    last_activity: std::time::Instant,
    window_focused: bool,
    idle_minutes: u16,
    clipboard_seconds: u16,
    preferences_path: Option<std::path::PathBuf>,
    picker_pending: Option<picker::Pending>,
    picker_sequence: u64,
    recovery: Option<recovery::RecoveryState>,
    recovery_generation: u64,
    recovery_notice: Option<crate::storage::recovery::RecoveryInfo>,
    vault_path: String,
    master_password: String,
    confirm_password: String,
    creating: bool,
    auth_options_open: bool,
    category_editor_open: bool,
    session: Option<VaultSession>,
    search: String,
    search_id: widget::Id,
    nav: NavFilter,
    selected: Option<Uuid>,
    panel: Panel,
    context_open: bool,
    context_generation: u64,
    category_name: String,
    revealed: Option<RevealedPassword>,
    dark_mode: bool,
    screen_capture_protection_requested: bool,
    screen_capture_protection_active: bool,
    security_monitor_ready: bool,
    security_monitor_failed: bool,
    status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NavFilter {
    All,
    Favorites,
    RecycleBin,
    Category(String),
}

enum Panel {
    Vault,
    Editor(EditorState),
    Import(ImportState),
    Settings(SettingsState),
    DeleteEntry(Uuid),
    DeleteCategory(String),
}

struct EditorState {
    id: Option<Uuid>,
    name: String,
    website: String,
    username: String,
    password: String,
    notes: String,
    notes_editor: text_editor::Content,
    category: String,
    favorite: bool,
    password_visible: bool,
}

impl EditorState {
    fn new() -> Self {
        Self {
            id: None,
            name: String::new(),
            website: String::new(),
            username: String::new(),
            password: String::new(),
            notes: String::new(),
            notes_editor: text_editor::Content::new(),
            category: "其他".to_string(),
            favorite: false,
            password_visible: false,
        }
    }
}

impl Drop for EditorState {
    fn drop(&mut self) {
        self.password.zeroize();
        self.notes.zeroize();
        // Iced owns the editor's internal buffers; dropping Content is not a
        // promise that every toolkit or renderer allocation can be zeroized.
    }
}

struct ImportState {
    path: String,
    legacy_password: String,
    preview: Option<ImportPreview>,
    apply_updates: bool,
    resolutions: BTreeMap<usize, ConflictResolution>,
}

impl ImportState {
    fn new() -> Self {
        Self {
            path: String::new(),
            legacy_password: String::new(),
            preview: None,
            apply_updates: true,
            resolutions: BTreeMap::new(),
        }
    }
}

impl Drop for ImportState {
    fn drop(&mut self) {
        self.legacy_password.zeroize();
    }
}

struct SettingsState {
    backup_path: String,
    restore_path: String,
    restore_password: String,
    confirm_restore: bool,
    csv_path: String,
    confirm_plaintext: bool,
}

impl SettingsState {
    fn from_vault(session: &VaultSession) -> Self {
        let parent = session.path().parent().unwrap_or_else(|| Path::new("."));
        Self {
            backup_path: parent
                .join(format!("backup-{}.pmvault", now_unix()))
                .display()
                .to_string(),
            restore_path: String::new(),
            restore_password: String::new(),
            confirm_restore: false,
            csv_path: parent.join("passwords-export.csv").display().to_string(),
            confirm_plaintext: false,
        }
    }
}

impl Drop for SettingsState {
    fn drop(&mut self) {
        self.restore_password.zeroize();
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct RevealedPassword {
    #[zeroize(skip)]
    entry_id: Uuid,
    value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CardAction {
    CopyUsername,
    CopyPassword,
    Favorite,
    OpenWebsite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextActionKind {
    CopyUsername,
    CopyPassword,
    ToggleReveal,
    OpenWebsite,
    Edit,
    Favorite,
    Recycle,
    Restore,
    RequestPermanentDelete,
    Close,
}

#[derive(Clone)]
struct EditorCut {
    original: zeroize::Zeroizing<String>,
    replacement: zeroize::Zeroizing<String>,
}

struct PendingEditorCut {
    generation: u64,
    request: u64,
    change: EditorCut,
}

#[derive(Clone)]
enum Message {
    AcknowledgeClipboardCleanup(u64),
    SecurityTick(std::time::Instant),
    UserActivity(std::time::Instant),
    WindowFocusChanged(bool),
    IdleTimeoutChanged(u16),
    ClipboardTimeoutChanged(u16),
    PickPath(picker::Purpose),
    PathPicked(u64, std::result::Result<Option<std::path::PathBuf>, String>),
    OpenRecovery,
    CloseRecovery(u64),
    SelectRecoveryCopy(u64, usize),
    RecoverySourceChanged(u64, String),
    RecoveryDestinationChanged(u64, String),
    RecoveryPasswordChanged(u64, String),
    RestoreRecoveryCopy(u64),
    AuthMode(bool),
    ToggleAuthOptions,
    ToggleCategoryEditor,
    CardAction(Uuid, CardAction),
    VaultPathChanged(String),
    MasterPasswordChanged(String),
    ConfirmPasswordChanged(String),
    CreateVault,
    OpenVault,
    Save,
    Lock,
    FocusSearch,
    SearchChanged(String),
    SetNav(NavFilter),
    SelectEntry(Uuid),
    EditEntry(Uuid),
    ContextEntry(Uuid),
    ContextAction(Uuid, u64, ContextActionKind),
    CloseContext,
    NewEntry,
    EditSelected,
    EditorNameChanged(String),
    EditorWebsiteChanged(String),
    EditorUsernameChanged(String),
    EditorPasswordChanged(String),
    EditorNotesAction(text_editor::Action),
    EditorCategoryChanged(String),
    EditorFavoriteChanged(bool),
    ToggleEditorPasswordVisible(u64),
    CopyEditorPasswordSelection(u64, zeroize::Zeroizing<String>, Option<EditorCut>),
    GeneratePassword,
    SaveEditor,
    CancelPanel,
    ToggleReveal,
    CopyPassword,
    CopyUsername,
    OpenWebsite,
    ToggleSelectedFavorite,
    MoveSelectedToRecycleBin,
    RestoreSelected,
    RequestPermanentDelete,
    ConfirmPermanentDelete(Uuid),
    CategoryNameChanged(String),
    AddCategory,
    MoveCategory(String, bool),
    RequestDeleteCategory(String),
    ConfirmDeleteCategory(String),
    OpenImport,
    ImportPathChanged(String),
    ImportLegacyPasswordChanged(String),
    AnalyzeImport,
    ImportApplyUpdatesChanged(Uuid, bool),
    SetImportResolution(Uuid, usize, ConflictResolution),
    ApplyImport(Uuid),
    OpenSettings,
    BackupPathChanged(String),
    CreateBackup,
    RestorePathChanged(String),
    RestorePasswordChanged(String),
    ConfirmRestoreChanged(bool),
    RestoreBackup,
    CsvPathChanged(String),
    ConfirmPlaintextChanged(bool),
    ExportPlaintextCsv,
    AcknowledgeExportNotice(u64),
    CloseRequested(iced::window::Id),
    KeepOpen(u64),
    ConfirmExportExit(u64, u64),
    DarkModeChanged(bool),
    ScreenCaptureProtectionChanged(bool),
    ScreenCaptureProtectionApplied(std::result::Result<bool, String>),
    PlatformSecurity(SecurityEvent),
}

impl std::fmt::Debug for Message {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose passwords, clipboard text or editor content in debug output.
        formatter
            .debug_tuple("Message")
            .field(&std::mem::discriminant(self))
            .finish()
    }
}

impl App {
    fn initial() -> Self {
        Self {
            closing: false,
            export_notice: None,
            export_notice_generation: 0,
            export_close_prompt: None,
            export_close_sequence: 0,
            pending_editor_cut: None,
            clipboard_cleanup_failed: false,
            clipboard_warning_generation: 0,
            clipboard_session: None,
            clipboard_request: 0,
            last_activity: std::time::Instant::now(),
            window_focused: true,
            idle_minutes: 5,
            clipboard_seconds: 30,
            preferences_path: None,
            picker_pending: None,
            picker_sequence: 0,
            recovery: None,
            recovery_generation: 0,
            recovery_notice: None,
            vault_path: "passwords.pmvault".to_string(),
            master_password: String::new(),
            confirm_password: String::new(),
            creating: false,
            auth_options_open: false,
            category_editor_open: false,
            session: None,
            search: String::new(),
            search_id: widget::Id::unique(),
            nav: NavFilter::All,
            selected: None,
            panel: Panel::Vault,
            context_open: false,
            context_generation: 0,
            category_name: String::new(),
            revealed: None,
            dark_mode: false,
            screen_capture_protection_requested: true,
            screen_capture_protection_active: false,
            security_monitor_ready: false,
            security_monitor_failed: false,
            status: String::new(),
        }
    }

    fn new() -> (Self, Task<Message>) {
        let mut app = Self::initial();
        match crate::preferences::default_path() {
            Ok(path) => {
                let (preferences, warning) = crate::preferences::load(&path);
                app.idle_minutes = preferences.auto_lock_minutes;
                app.clipboard_seconds = preferences.clipboard_seconds;
                app.preferences_path = Some(path);
                app.status = warning.unwrap_or_default();
            }
            Err(warning) => app.status = warning,
        }
        app.check_startup_recovery();
        (
            app,
            platform::set_screen_capture_protection(true)
                .map(Message::ScreenCaptureProtectionApplied),
        )
    }

    fn theme(&self) -> Theme {
        if self.dark_mode {
            Theme::Dark
        } else {
            Theme::custom(
                "旧版浅色".to_string(),
                iced::theme::Palette {
                    background: iced::Color::from_rgb8(248, 249, 250),
                    text: iced::Color::from_rgb8(17, 24, 39),
                    primary: iced::Color::from_rgb8(37, 99, 235),
                    success: iced::Color::from_rgb8(16, 185, 129),
                    danger: iced::Color::from_rgb8(239, 68, 68),
                    warning: iced::theme::Palette::LIGHT.warning,
                },
            )
        }
    }

    fn subscription(&self) -> Subscription<Message> {
        let hotkeys = keyboard::listen().filter_map(|event| {
            let keyboard::Event::KeyPressed { key, modifiers, .. } = event else {
                return None;
            };
            if key == keyboard::Key::Named(keyboard::key::Named::Escape) {
                return Some(Message::CloseContext);
            }
            if !modifiers.command() {
                return None;
            }
            match key.as_ref() {
                keyboard::Key::Character(value) if value.eq_ignore_ascii_case("f") => {
                    Some(Message::FocusSearch)
                }
                keyboard::Key::Character(value) if value.eq_ignore_ascii_case("n") => {
                    Some(Message::NewEntry)
                }
                keyboard::Key::Character(value) if value.eq_ignore_ascii_case("s") => {
                    Some(Message::Save)
                }
                keyboard::Key::Character(value) if value.eq_ignore_ascii_case("l") => {
                    Some(Message::Lock)
                }
                _ => None,
            }
        });
        Subscription::batch([
            hotkeys,
            iced::event::listen_with(safety::runtime_event),
            if self.session.is_some() {
                iced::time::every(std::time::Duration::from_secs(1)).map(Message::SecurityTick)
            } else {
                Subscription::none()
            },
            platform::security_events().map(Message::PlatformSecurity),
        ])
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        self.security_tick(std::time::Instant::now());
        // Iced processes a message batch before executing window actions. Once
        // final close is admitted, no later message may unlock or start work.
        if self.closing
            && !matches!(
                &message,
                Message::PlatformSecurity(_)
                    | Message::SecurityTick(_)
                    | Message::WindowFocusChanged(_)
                    | Message::PathPicked(_, _)
                    | Message::ScreenCaptureProtectionApplied(_)
                    | Message::AcknowledgeClipboardCleanup(_)
            )
        {
            return Task::none();
        }
        // A close warning masks the vault and cannot be bypassed by queued
        // unlock/navigation/export or export acknowledgment from the old view.
        // Retired picker/settings completions still drain, and the independently
        // generation-checked clipboard warning remains actionable.
        if self.export_close_prompt.is_some()
            && !matches!(
                &message,
                Message::CloseRequested(_)
                    | Message::KeepOpen(_)
                    | Message::ConfirmExportExit(_, _)
                    | Message::PlatformSecurity(_)
                    | Message::SecurityTick(_)
                    | Message::WindowFocusChanged(_)
                    | Message::PathPicked(_, _)
                    | Message::ScreenCaptureProtectionApplied(_)
                    | Message::AcknowledgeClipboardCleanup(_)
            )
        {
            return Task::none();
        }
        if self.picker_pending.is_some()
            && matches!(
                &message,
                Message::CreateVault
                    | Message::OpenVault
                    | Message::AnalyzeImport
                    | Message::ApplyImport(_)
                    | Message::CreateBackup
                    | Message::RestoreBackup
                    | Message::RestoreRecoveryCopy(_)
                    | Message::ExportPlaintextCsv
            )
        {
            return Task::none();
        }
        // Invalidate, but retain the in-flight slot until the OS dialog returns.
        // This rejects stale results while preventing multiple native dialogs.
        if matches!(
            &message,
            Message::AuthMode(_)
                | Message::ToggleAuthOptions
                | Message::Lock
                | Message::SetNav(_)
                | Message::CancelPanel
                | Message::NewEntry
                | Message::EditEntry(_)
                | Message::EditSelected
                | Message::OpenImport
                | Message::OpenSettings
                | Message::RequestDeleteCategory(_)
                | Message::VaultPathChanged(_)
                | Message::ImportPathChanged(_)
                | Message::BackupPathChanged(_)
                | Message::RestorePathChanged(_)
                | Message::CsvPathChanged(_)
                | Message::CreateVault
                | Message::OpenVault
                | Message::AnalyzeImport
                | Message::ApplyImport(_)
                | Message::CreateBackup
                | Message::RestoreBackup
                | Message::ExportPlaintextCsv
        ) {
            self.invalidate_picker();
        }
        // A queued detail action must not operate on a selection that is now
        // hidden, locked, or outside the password workspace.
        if matches!(
            &message,
            Message::CopyPassword
                | Message::CopyUsername
                | Message::EditSelected
                | Message::OpenWebsite
                | Message::ToggleSelectedFavorite
                | Message::MoveSelectedToRecycleBin
                | Message::RestoreSelected
                | Message::RequestPermanentDelete
        ) && !self
            .selected
            .is_some_and(|id| self.is_visible_workspace_target(id))
        {
            return Task::none();
        }
        match message {
            Message::AcknowledgeExportNotice(generation) => self.acknowledge_export(generation),
            Message::CloseRequested(window) => return self.request_close(window),
            Message::KeepOpen(request) => self.keep_open(request),
            Message::ConfirmExportExit(request, generation) => {
                return self.confirm_export_exit(request, generation);
            }
            Message::AcknowledgeClipboardCleanup(generation) => {
                if generation == self.clipboard_warning_generation {
                    self.clipboard_cleanup_failed = false;
                    self.clipboard_warning_generation =
                        self.clipboard_warning_generation.wrapping_add(1);
                    self.status = "已确认手动处理剪贴板".into();
                }
            }
            Message::SecurityTick(now) => self.security_tick(now),
            Message::UserActivity(now) => self.user_activity(now),
            Message::WindowFocusChanged(focused) => self.window_focus_changed(focused),
            Message::IdleTimeoutChanged(minutes) => {
                self.change_security_preferences(minutes, self.clipboard_seconds)
            }
            Message::ClipboardTimeoutChanged(seconds) => {
                self.change_security_preferences(self.idle_minutes, seconds)
            }
            Message::PickPath(purpose) => return self.begin_picker(purpose),
            Message::PathPicked(id, result) => self.finish_picker(id, result),
            Message::OpenRecovery => self.open_recovery(),
            Message::CloseRecovery(generation) => {
                if self
                    .recovery
                    .as_ref()
                    .is_some_and(|s| s.generation == generation)
                {
                    self.dismiss_recovery();
                }
            }
            Message::SelectRecoveryCopy(generation, index) => {
                if let Some(state) = &mut self.recovery
                    && state.generation == generation
                    && let Some(copy) = state.listing.artifacts.get(index)
                {
                    state.source = copy.path.display().to_string();
                    state.password.zeroize();
                    self.invalidate_picker();
                }
            }
            Message::RecoverySourceChanged(generation, value) => {
                if let Some(state) = &mut self.recovery
                    && state.generation == generation
                {
                    state.source = value;
                    state.password.zeroize();
                    self.invalidate_picker();
                }
            }
            Message::RecoveryDestinationChanged(generation, value) => {
                if let Some(state) = &mut self.recovery
                    && state.generation == generation
                {
                    state.destination = value;
                    self.invalidate_picker();
                }
            }
            Message::RecoveryPasswordChanged(generation, mut value) => {
                if let Some(state) = &mut self.recovery
                    && state.generation == generation
                {
                    replace_secret(&mut state.password, std::mem::take(&mut value));
                }
                value.zeroize();
            }
            Message::RestoreRecoveryCopy(generation) => self.restore_recovery_copy(generation),
            Message::AuthMode(creating) => {
                self.dismiss_recovery();
                self.creating = creating;
                self.clear_password_fields();
                self.status.clear();
            }
            Message::ToggleAuthOptions => {
                self.dismiss_recovery();
                self.auth_options_open = !self.auth_options_open;
            }
            Message::ToggleCategoryEditor => {
                self.category_editor_open = !self.category_editor_open;
            }
            Message::CardAction(id, action) => {
                if !self.is_visible_workspace_target(id) {
                    return Task::none();
                }
                self.selected = Some(id);
                self.close_context();
                return self.update(match action {
                    CardAction::CopyUsername => Message::CopyUsername,
                    CardAction::CopyPassword => Message::CopyPassword,
                    CardAction::Favorite => Message::ToggleSelectedFavorite,
                    CardAction::OpenWebsite => Message::OpenWebsite,
                });
            }
            Message::VaultPathChanged(value) => {
                self.dismiss_recovery();
                self.recovery_notice = None;
                self.vault_path = value;
            }
            Message::MasterPasswordChanged(value) => {
                replace_secret(&mut self.master_password, value)
            }
            Message::ConfirmPasswordChanged(value) => {
                replace_secret(&mut self.confirm_password, value)
            }
            Message::CreateVault => self.create_vault(),
            Message::OpenVault => self.open_vault(),
            Message::Save => self.save_now(),
            Message::Lock => self.lock_with_status("保险库已锁定"),
            Message::FocusSearch => {
                if self.session.is_some() && matches!(&self.panel, Panel::Vault) {
                    return operation::focus(self.search_id.clone());
                }
            }
            Message::SearchChanged(value) => {
                self.search = value;
                self.close_context();
            }
            Message::SetNav(nav) => {
                self.nav = nav;
                self.selected = None;
                self.panel = Panel::Vault;
                self.close_context();
            }
            Message::SelectEntry(id) => {
                if !self.is_visible_workspace_target(id) {
                    return Task::none();
                }
                self.selected = Some(id);
                self.close_context();
            }
            Message::EditEntry(id) => {
                if !self.is_visible_workspace_target(id) {
                    return Task::none();
                }
                self.selected = Some(id);
                self.close_context();
                self.open_editor_for_selected();
            }
            Message::ContextEntry(id) => {
                if !self.is_visible_workspace_target(id) {
                    return Task::none();
                }
                self.close_context();
                self.selected = Some(id);
                self.context_open = true;
                self.revealed = None;
            }
            Message::ContextAction(id, generation, action) => {
                if !self.context_open
                    || self.context_generation != generation
                    || self.selected != Some(id)
                    || !self.is_visible_workspace_target(id)
                {
                    return Task::none();
                }
                return self.update(match action {
                    ContextActionKind::CopyUsername => Message::CopyUsername,
                    ContextActionKind::CopyPassword => Message::CopyPassword,
                    ContextActionKind::ToggleReveal => Message::ToggleReveal,
                    ContextActionKind::OpenWebsite => Message::OpenWebsite,
                    ContextActionKind::Edit => Message::EditSelected,
                    ContextActionKind::Favorite => Message::ToggleSelectedFavorite,
                    ContextActionKind::Recycle => Message::MoveSelectedToRecycleBin,
                    ContextActionKind::Restore => Message::RestoreSelected,
                    ContextActionKind::RequestPermanentDelete => Message::RequestPermanentDelete,
                    ContextActionKind::Close => Message::CloseContext,
                });
            }
            Message::CloseContext => self.close_context(),
            Message::NewEntry => {
                if self.session.is_some() && !matches!(&self.panel, Panel::Editor(_)) {
                    self.panel = Panel::Editor(EditorState::new());
                    self.close_context();
                }
            }
            Message::EditSelected => self.open_editor_for_selected(),
            Message::EditorNameChanged(value) => {
                if let Panel::Editor(s) = &mut self.panel {
                    s.name = value;
                }
            }
            Message::EditorWebsiteChanged(value) => {
                if let Panel::Editor(s) = &mut self.panel {
                    s.website = value;
                }
            }
            Message::EditorUsernameChanged(value) => {
                if let Panel::Editor(s) = &mut self.panel {
                    s.username = value;
                }
            }
            Message::EditorPasswordChanged(value) => {
                self.pending_editor_cut = None;
                if let Panel::Editor(s) = &mut self.panel {
                    replace_secret(&mut s.password, value);
                }
            }
            Message::EditorNotesAction(action) => {
                if let Panel::Editor(s) = &mut self.panel {
                    s.notes_editor.perform(action);
                    replace_secret(&mut s.notes, s.notes_editor.text());
                }
            }
            Message::EditorCategoryChanged(value) => {
                if let Panel::Editor(s) = &mut self.panel {
                    s.category = value;
                }
            }
            Message::EditorFavoriteChanged(value) => {
                if let Panel::Editor(s) = &mut self.panel {
                    s.favorite = value;
                }
            }
            Message::CopyEditorPasswordSelection(generation, value, cut) => {
                if self.session.is_some()
                    && generation == self.context_generation
                    && matches!(self.panel, Panel::Editor(_))
                {
                    self.pending_editor_cut = None;
                    self.clipboard_request = self.clipboard_request.wrapping_add(1);
                    if let Some(permit) = &self.clipboard_session {
                        match platform::enqueue_password_copy(
                            permit,
                            self.clipboard_request,
                            value,
                            u32::from(self.clipboard_seconds) * 1000,
                        ) {
                            Ok(()) => {
                                self.pending_editor_cut = cut.map(|change| PendingEditorCut {
                                    generation,
                                    request: self.clipboard_request,
                                    change,
                                });
                                self.status = "正在安全复制选中的密码内容…".into();
                            }
                            Err(error) => self.status = format!("安全复制失败：{error}"),
                        }
                    }
                }
            }
            Message::ToggleEditorPasswordVisible(generation) => {
                if !self.window_focused || generation != self.context_generation {
                    return Task::none();
                }
                if let Panel::Editor(s) = &mut self.panel {
                    s.password_visible = !s.password_visible;
                }
            }
            Message::GeneratePassword => {
                self.pending_editor_cut = None;
                if let Panel::Editor(s) = &mut self.panel {
                    match generate_password(PasswordGeneratorOptions::default()) {
                        Ok(value) => replace_secret(&mut s.password, value),
                        Err(error) => self.status = format!("生成失败：{error}"),
                    }
                }
            }
            Message::SaveEditor => self.save_editor(),
            Message::CancelPanel => {
                self.panel = Panel::Vault;
                self.close_context();
            }
            Message::ToggleReveal => self.toggle_reveal(),
            Message::CopyPassword => {
                self.close_context();
                self.clipboard_request = self.clipboard_request.wrapping_add(1);
                if let (Some(session), Some(permit), Some(id)) =
                    (&self.session, &self.clipboard_session, self.selected)
                {
                    match session.reveal_secret(id) {
                        Ok(secret) => {
                            let result = platform::enqueue_password_copy(
                                permit,
                                self.clipboard_request,
                                zeroize::Zeroizing::new(secret.password.clone()),
                                u32::from(self.clipboard_seconds) * 1000,
                            );
                            self.status = match result {
                                Ok(()) => "正在安全复制密码…".into(),
                                Err(error) => format!("安全复制失败：{error}"),
                            };
                        }
                        Err(error) => self.status = format!("复制失败：{error}"),
                    }
                }
            }
            Message::CopyUsername => {
                self.close_context();
                self.clipboard_request = self.clipboard_request.wrapping_add(1);
                if let (Some(entry), Some(permit)) =
                    (self.selected_entry(), &self.clipboard_session)
                {
                    self.status = match platform::enqueue_username_copy(
                        permit,
                        self.clipboard_request,
                        entry.username.clone(),
                    ) {
                        Ok(()) => "正在复制账号…".into(),
                        Err(error) => format!("安全复制失败：{error}"),
                    };
                }
            }
            Message::OpenWebsite => self.open_selected_website(),
            Message::ToggleSelectedFavorite => self.toggle_selected_favorite(),
            Message::MoveSelectedToRecycleBin => self.recycle_selected(false),
            Message::RestoreSelected => self.recycle_selected(true),
            Message::RequestPermanentDelete => {
                if let Some(id) = self.selected {
                    self.close_context();
                    self.panel = Panel::DeleteEntry(id);
                }
            }
            Message::ConfirmPermanentDelete(id) => self.delete_entry(id),
            Message::CategoryNameChanged(value) => self.category_name = value,
            Message::AddCategory => self.add_category(),
            Message::MoveCategory(name, up) => self.move_category(&name, up),
            Message::RequestDeleteCategory(name) => {
                self.close_context();
                self.panel = Panel::DeleteCategory(name);
            }
            Message::ConfirmDeleteCategory(name) => self.delete_category(&name),
            Message::OpenImport => {
                if self.session.is_some() {
                    self.close_context();
                    self.panel = Panel::Import(ImportState::new());
                }
            }
            Message::ImportPathChanged(value) => {
                if let Panel::Import(s) = &mut self.panel {
                    s.path = value;
                    s.preview = None;
                    s.resolutions.clear();
                    s.apply_updates = true;
                    s.legacy_password.zeroize();
                    s.legacy_password.clear();
                }
            }
            Message::ImportLegacyPasswordChanged(value) => {
                if let Panel::Import(s) = &mut self.panel {
                    replace_secret(&mut s.legacy_password, value);
                }
            }
            Message::AnalyzeImport => self.analyze_import(),
            Message::ImportApplyUpdatesChanged(preview_id, value) => {
                if let Panel::Import(s) = &mut self.panel
                    && s.preview.as_ref().is_some_and(|p| p.id() == preview_id)
                {
                    s.apply_updates = value;
                }
            }
            Message::SetImportResolution(preview_id, index, resolution) => {
                if let Panel::Import(s) = &mut self.panel
                    && s.preview.as_ref().is_some_and(|p| {
                        p.id() == preview_id && p.allows_resolution(index, &resolution)
                    })
                {
                    s.resolutions.insert(index, resolution);
                }
            }
            Message::ApplyImport(preview_id) => self.apply_import(preview_id),
            Message::OpenSettings => {
                if let Some(session) = &self.session {
                    self.panel = Panel::Settings(SettingsState::from_vault(session));
                    self.close_context();
                }
            }
            Message::BackupPathChanged(value) => {
                if let Panel::Settings(s) = &mut self.panel {
                    s.backup_path = value;
                }
            }
            Message::CreateBackup => self.create_backup(),
            Message::RestorePathChanged(value) => {
                if let Panel::Settings(s) = &mut self.panel {
                    s.restore_path = value;
                    s.confirm_restore = false;
                    s.restore_password.zeroize();
                    s.restore_password.clear();
                }
            }
            Message::RestorePasswordChanged(value) => {
                if let Panel::Settings(s) = &mut self.panel {
                    replace_secret(&mut s.restore_password, value);
                }
            }
            Message::ConfirmRestoreChanged(value) => {
                if let Panel::Settings(s) = &mut self.panel {
                    s.confirm_restore = value;
                }
            }
            Message::RestoreBackup => self.restore_backup(),
            Message::CsvPathChanged(value) => {
                if let Panel::Settings(s) = &mut self.panel {
                    s.csv_path = value;
                    s.confirm_plaintext = false;
                }
            }
            Message::ConfirmPlaintextChanged(value) => {
                if let Panel::Settings(s) = &mut self.panel {
                    s.confirm_plaintext = value;
                }
            }
            Message::ExportPlaintextCsv => self.export_plaintext(),
            Message::DarkModeChanged(value) => self.dark_mode = value,
            Message::ScreenCaptureProtectionChanged(value) => {
                self.screen_capture_protection_requested = value;
                return platform::set_screen_capture_protection(value)
                    .map(Message::ScreenCaptureProtectionApplied);
            }
            Message::ScreenCaptureProtectionApplied(result) => match result {
                Ok(active) => {
                    self.screen_capture_protection_requested = active;
                    self.screen_capture_protection_active = active;
                }
                Err(error) => {
                    self.screen_capture_protection_requested =
                        self.screen_capture_protection_active;
                    self.status = format!("截图保护设置失败：{error}");
                }
            },
            Message::PlatformSecurity(event) => match event {
                SecurityEvent::ClipboardCopyCompleted {
                    session,
                    request,
                    kind,
                    outcome,
                } => {
                    if self.session.is_some()
                        && self
                            .clipboard_session
                            .as_ref()
                            .is_some_and(|current| current.id() == session)
                        && request == self.clipboard_request
                    {
                        if kind == platform::ClipboardKind::Password {
                            self.finish_editor_cut(request, outcome);
                        }
                        if outcome == platform::ClipboardCopyOutcome::Copied {
                            // A verified new write supersedes the previously unconfirmed contents.
                            self.clipboard_cleanup_failed = false;
                            self.clipboard_warning_generation =
                                self.clipboard_warning_generation.wrapping_add(1);
                        }
                        self.status = match (kind, outcome) {
                            (
                                platform::ClipboardKind::Password,
                                platform::ClipboardCopyOutcome::Copied,
                            ) => "密码已复制，将仅在仍持有该次内容时按时清理".into(),
                            (
                                platform::ClipboardKind::Username,
                                platform::ClipboardCopyOutcome::Copied,
                            ) => "账号已复制".into(),
                            (_, platform::ClipboardCopyOutcome::Cancelled) => "复制已取消".into(),
                            (_, platform::ClipboardCopyOutcome::Failed) => {
                                "复制失败；请重试，勿依赖当前剪贴板内容".into()
                            }
                        };
                    }
                }
                SecurityEvent::MonitorReady => {
                    if self.security_monitor_failed {
                        self.status = "Windows 会话监控已恢复，请重新解锁".into();
                    }
                    self.security_monitor_failed = false;
                    self.security_monitor_ready = true;
                    if self.screen_capture_protection_requested
                        && !self.screen_capture_protection_active
                    {
                        return platform::set_screen_capture_protection(true)
                            .map(Message::ScreenCaptureProtectionApplied);
                    }
                }
                SecurityEvent::MonitorFailed => {
                    self.security_monitor_ready = false;
                    self.security_monitor_failed = true;
                    self.lock_with_status(
                        "Windows 会话监控初始化失败或已中断，保险库保持锁定；请重启软件后重试",
                    );
                }
                SecurityEvent::SessionLocked => self.lock_with_status("Windows 锁屏，保险库已锁定"),
                SecurityEvent::SessionLoggedOff => {
                    self.lock_with_status("Windows 注销，保险库已锁定")
                }
                SecurityEvent::SystemSuspending => self.lock_with_status("系统挂起，保险库已锁定"),
                SecurityEvent::ClipboardCleanupFailed => {
                    self.note_clipboard_cleanup_failure();
                }
            },
        }
        if let Some(warning) = self
            .session
            .as_ref()
            .and_then(VaultSession::maintenance_warning)
            && !self.status.contains(warning)
        {
            self.status = format!("{}；{}", self.status, warning);
        }
        Task::none()
    }
}

fn replace_secret(target: &mut String, value: String) {
    target.zeroize();
    *target = value;
}

impl Drop for App {
    fn drop(&mut self) {
        // Lock may already have relinquished the live token. The process-local
        // barrier also covers that retired receipt and queued cleanup.
        if platform::shutdown_clipboard().is_err() {
            eprintln!("clipboard_cleanup_incomplete_on_exit");
        }
        self.clear_password_fields();
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
