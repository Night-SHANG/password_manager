use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use iced::widget::{self, operation, text_editor};
use iced::{Element, Font, Length, Subscription, Task, Theme, clipboard, keyboard};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::domain::EntryRecord;
use crate::export::{PlaintextExportAcknowledgement, export_plaintext_csv};
use crate::import::plan::{
    ConflictResolution, ImportApplyOptions, ImportClass, ImportPreview, apply_preview, build_preview,
};
use crate::import::stage_path;
use crate::platform::{self, SecurityEvent};
use crate::services::{PasswordGeneratorOptions, draft, generate_password, safe_web_url};
use crate::storage::VaultSession;
use crate::{AppError, Result};

mod actions;
mod ui;
#[cfg(test)]
mod tests;

const PASSWORD_CLIPBOARD_TIMEOUT_MS: u32 = 30_000;
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
            ..iced::window::Settings::default()
        })
        .subscription(App::subscription)
        .theme(App::theme)
        .run()
}

struct App {
    vault_path: String,
    master_password: String,
    confirm_password: String,
    creating: bool,
    session: Option<VaultSession>,
    search: String,
    search_id: widget::Id,
    nav: NavFilter,
    selected: Option<Uuid>,
    panel: Panel,
    context_open: bool,
    category_name: String,
    revealed: Option<RevealedPassword>,
    dark_mode: bool,
    screen_capture_protection_requested: bool,
    screen_capture_protection_active: bool,
    security_monitor_ready: bool,
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
            backup_path: parent.join(format!("backup-{}.pmvault", now_unix())).display().to_string(),
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

#[derive(Clone)]
enum Message {
    AuthMode(bool),
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
    ToggleEditorPasswordVisible,
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
    ImportApplyUpdatesChanged(bool),
    SetImportResolution(usize, ConflictResolution),
    ApplyImport,
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
    DarkModeChanged(bool),
    ScreenCaptureProtectionChanged(bool),
    ScreenCaptureProtectionApplied(std::result::Result<bool, String>),
    PlatformSecurity(SecurityEvent),
    PasswordClipboardWritten,
}

impl std::fmt::Debug for Message {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose passwords, clipboard text or editor content in debug output.
        formatter.debug_tuple("Message").field(&std::mem::discriminant(self)).finish()
    }
}

impl App {
    fn initial() -> Self {
        Self {
            vault_path: "passwords.pmvault".to_string(),
            master_password: String::new(),
            confirm_password: String::new(),
            creating: false,
            session: None,
            search: String::new(),
            search_id: widget::Id::unique(),
            nav: NavFilter::All,
            selected: None,
            panel: Panel::Vault,
            context_open: false,
            category_name: String::new(),
            revealed: None,
            dark_mode: false,
            screen_capture_protection_requested: true,
            screen_capture_protection_active: false,
            security_monitor_ready: false,
            status: String::new(),
        }
    }

    fn new() -> (Self, Task<Message>) {
        (Self::initial(), platform::set_screen_capture_protection(true).map(Message::ScreenCaptureProtectionApplied))
    }

    fn theme(&self) -> Theme {
        if self.dark_mode {
            Theme::Dark
        } else {
            Theme::custom("旧版浅色".to_string(), iced::theme::Palette {
                background: iced::Color::from_rgb8(243, 244, 246),
                text: iced::Color::from_rgb8(17, 24, 39),
                primary: iced::Color::from_rgb8(37, 99, 235),
                success: iced::Color::from_rgb8(16, 185, 129),
                danger: iced::Color::from_rgb8(239, 68, 68),
            })
        }
    }

    fn subscription(&self) -> Subscription<Message> {
        let hotkeys = keyboard::listen().filter_map(|event| {
            let keyboard::Event::KeyPressed { key, modifiers, .. } = event else { return None; };
            if key == keyboard::Key::Named(keyboard::key::Named::Escape) {
                return Some(Message::CloseContext);
            }
            if !modifiers.command() { return None; }
            match key.as_ref() {
                keyboard::Key::Character(value) if value.eq_ignore_ascii_case("f") => Some(Message::FocusSearch),
                keyboard::Key::Character(value) if value.eq_ignore_ascii_case("n") => Some(Message::NewEntry),
                keyboard::Key::Character(value) if value.eq_ignore_ascii_case("s") => Some(Message::Save),
                keyboard::Key::Character(value) if value.eq_ignore_ascii_case("l") => Some(Message::Lock),
                _ => None,
            }
        });
        Subscription::batch([hotkeys, platform::security_events().map(Message::PlatformSecurity)])
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::AuthMode(creating) => { self.creating = creating; self.clear_password_fields(); self.status.clear(); }
            Message::VaultPathChanged(value) => self.vault_path = value,
            Message::MasterPasswordChanged(value) => replace_secret(&mut self.master_password, value),
            Message::ConfirmPasswordChanged(value) => replace_secret(&mut self.confirm_password, value),
            Message::CreateVault => self.create_vault(),
            Message::OpenVault => self.open_vault(),
            Message::Save => self.save_now(),
            Message::Lock => self.lock_with_status("保险库已锁定"),
            Message::FocusSearch => {
                if self.session.is_some() && matches!(&self.panel, Panel::Vault) {
                    return operation::focus(self.search_id.clone());
                }
            }
            Message::SearchChanged(value) => { self.search = value; self.context_open = false; self.revealed = None; }
            Message::SetNav(nav) => {
                self.nav = nav; self.selected = None; self.panel = Panel::Vault;
                self.context_open = false; self.revealed = None;
            }
            Message::SelectEntry(id) => { self.selected = Some(id); self.context_open = false; self.revealed = None; }
            Message::EditEntry(id) => { self.selected = Some(id); self.context_open = false; self.open_editor_for_selected(); }
            Message::ContextEntry(id) => { self.selected = Some(id); self.context_open = true; self.revealed = None; }
            Message::CloseContext => self.context_open = false,
            Message::NewEntry => {
                if self.session.is_some() && !matches!(&self.panel, Panel::Editor(_)) { self.panel = Panel::Editor(EditorState::new()); self.context_open = false; self.revealed = None; }
            }
            Message::EditSelected => self.open_editor_for_selected(),
            Message::EditorNameChanged(value) => { if let Panel::Editor(s) = &mut self.panel { s.name = value; } }
            Message::EditorWebsiteChanged(value) => { if let Panel::Editor(s) = &mut self.panel { s.website = value; } }
            Message::EditorUsernameChanged(value) => { if let Panel::Editor(s) = &mut self.panel { s.username = value; } }
            Message::EditorPasswordChanged(value) => { if let Panel::Editor(s) = &mut self.panel { replace_secret(&mut s.password, value); } }
            Message::EditorNotesAction(action) => {
                if let Panel::Editor(s) = &mut self.panel {
                    s.notes_editor.perform(action);
                    replace_secret(&mut s.notes, s.notes_editor.text());
                }
            }
            Message::EditorCategoryChanged(value) => { if let Panel::Editor(s) = &mut self.panel { s.category = value; } }
            Message::EditorFavoriteChanged(value) => { if let Panel::Editor(s) = &mut self.panel { s.favorite = value; } }
            Message::ToggleEditorPasswordVisible => { if let Panel::Editor(s) = &mut self.panel { s.password_visible = !s.password_visible; } }
            Message::GeneratePassword => {
                if let Panel::Editor(s) = &mut self.panel {
                    match generate_password(PasswordGeneratorOptions::default()) {
                        Ok(value) => replace_secret(&mut s.password, value),
                        Err(error) => self.status = format!("生成失败：{error}"),
                    }
                }
            }
            Message::SaveEditor => self.save_editor(),
            Message::CancelPanel => { self.panel = Panel::Vault; self.context_open = false; self.revealed = None; }
            Message::ToggleReveal => self.toggle_reveal(),
            Message::CopyPassword => {
                self.context_open = false;
                if let Some(session) = &self.session && let Some(id) = self.selected {
                    match session.reveal_secret(id) {
                        Ok(secret) => return clipboard::write::<Message>(secret.password.clone()).chain(Task::done(Message::PasswordClipboardWritten)),
                        Err(error) => self.status = format!("复制失败：{error}"),
                    }
                }
            }
            Message::CopyUsername => {
                self.context_open = false;
                if let Some(entry) = self.selected_entry() { return clipboard::write::<Message>(entry.username.clone()).discard(); }
            }
            Message::OpenWebsite => self.open_selected_website(),
            Message::ToggleSelectedFavorite => self.toggle_selected_favorite(),
            Message::MoveSelectedToRecycleBin => self.recycle_selected(false),
            Message::RestoreSelected => self.recycle_selected(true),
            Message::RequestPermanentDelete => { if let Some(id) = self.selected { self.context_open = false; self.panel = Panel::DeleteEntry(id); } }
            Message::ConfirmPermanentDelete(id) => self.delete_entry(id),
            Message::CategoryNameChanged(value) => self.category_name = value,
            Message::AddCategory => self.add_category(),
            Message::MoveCategory(name, up) => self.move_category(&name, up),
            Message::RequestDeleteCategory(name) => self.panel = Panel::DeleteCategory(name),
            Message::ConfirmDeleteCategory(name) => self.delete_category(&name),
            Message::OpenImport => { if self.session.is_some() { self.panel = Panel::Import(ImportState::new()); self.revealed = None; } }
            Message::ImportPathChanged(value) => { if let Panel::Import(s) = &mut self.panel { s.path = value; s.preview = None; s.resolutions.clear(); } }
            Message::ImportLegacyPasswordChanged(value) => { if let Panel::Import(s) = &mut self.panel { replace_secret(&mut s.legacy_password, value); } }
            Message::AnalyzeImport => self.analyze_import(),
            Message::ImportApplyUpdatesChanged(value) => { if let Panel::Import(s) = &mut self.panel { s.apply_updates = value; } }
            Message::SetImportResolution(index, resolution) => { if let Panel::Import(s) = &mut self.panel { s.resolutions.insert(index, resolution); } }
            Message::ApplyImport => self.apply_import(),
            Message::OpenSettings => { if let Some(session) = &self.session { self.panel = Panel::Settings(SettingsState::from_vault(session)); self.revealed = None; } }
            Message::BackupPathChanged(value) => { if let Panel::Settings(s) = &mut self.panel { s.backup_path = value; } }
            Message::CreateBackup => self.create_backup(),
            Message::RestorePathChanged(value) => { if let Panel::Settings(s) = &mut self.panel { s.restore_path = value; } }
            Message::RestorePasswordChanged(value) => { if let Panel::Settings(s) = &mut self.panel { replace_secret(&mut s.restore_password, value); } }
            Message::ConfirmRestoreChanged(value) => { if let Panel::Settings(s) = &mut self.panel { s.confirm_restore = value; } }
            Message::RestoreBackup => self.restore_backup(),
            Message::CsvPathChanged(value) => { if let Panel::Settings(s) = &mut self.panel { s.csv_path = value; } }
            Message::ConfirmPlaintextChanged(value) => { if let Panel::Settings(s) = &mut self.panel { s.confirm_plaintext = value; } }
            Message::ExportPlaintextCsv => self.export_plaintext(),
            Message::DarkModeChanged(value) => self.dark_mode = value,
            Message::ScreenCaptureProtectionChanged(value) => {
                self.screen_capture_protection_requested = value;
                return platform::set_screen_capture_protection(value).map(Message::ScreenCaptureProtectionApplied);
            }
            Message::ScreenCaptureProtectionApplied(result) => match result {
                Ok(active) => { self.screen_capture_protection_requested = active; self.screen_capture_protection_active = active; }
                Err(error) => { self.screen_capture_protection_requested = self.screen_capture_protection_active; self.status = format!("截图保护设置失败：{error}"); }
            },
            Message::PlatformSecurity(event) => match event {
                SecurityEvent::MonitorReady => {
                    self.security_monitor_ready = true;
                    if self.screen_capture_protection_requested && !self.screen_capture_protection_active {
                        return platform::set_screen_capture_protection(true).map(Message::ScreenCaptureProtectionApplied);
                    }
                }
                SecurityEvent::MonitorFailed => { self.security_monitor_ready = false; self.status = "Windows 会话监控不可用，请手动锁定保险库".to_string(); }
                SecurityEvent::SessionLocked => self.lock_with_status("Windows 锁屏，保险库已锁定"),
                SecurityEvent::SessionLoggedOff => self.lock_with_status("Windows 注销，保险库已锁定"),
                SecurityEvent::SystemSuspending => self.lock_with_status("系统挂起，保险库已锁定"),
                SecurityEvent::ClipboardCleanupFailed => self.status = "剪贴板清理失败，请手动覆盖剪贴板".to_string(),
            },
            Message::PasswordClipboardWritten => {
                let sequence = platform::clipboard_sequence_number();
                self.status = match platform::arm_clipboard_clear(sequence, PASSWORD_CLIPBOARD_TIMEOUT_MS) {
                    Ok(()) => "已发送复制请求，30 秒后尝试条件清理剪贴板".to_string(),
                    Err(error) => format!("已发送复制请求，自动清理未启用：{error}"),
                };
            }
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
        let _ = platform::clear_armed_clipboard_now();
        self.clear_password_fields();
    }
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}
