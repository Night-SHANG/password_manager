use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use iced::widget::{
    self, button, checkbox, column, container, operation, row, scrollable, text, text_input,
};
use iced::{Element, Length, Subscription, Task, Theme, clipboard, keyboard};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::domain::EntryRecord;
use crate::export::{PlaintextExportAcknowledgement, export_plaintext_csv};
use crate::import::plan::{
    ConflictResolution, ImportApplyOptions, ImportClass, ImportPreview, apply_preview,
    build_preview,
};
use crate::import::stage_path;
use crate::services::{PasswordGeneratorOptions, draft, generate_password, safe_web_url};
use crate::storage::VaultSession;
use crate::{AppError, Result};

pub fn run() -> iced::Result {
    iced::application(App::new, App::update, App::view)
        .title("密码管理器")
        .subscription(App::subscription)
        .theme(App::theme)
        .run()
}

struct App {
    vault_path: String,
    master_password: String,
    confirm_password: String,
    session: Option<VaultSession>,
    search: String,
    search_id: widget::Id,
    nav: NavFilter,
    selected: Option<Uuid>,
    panel: Panel,
    revealed: Option<RevealedPassword>,
    confirm_permanent_delete: Option<Uuid>,
    dark_mode: bool,
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
    Details,
    Editor(EditorState),
    Import(ImportState),
    Settings(SettingsState),
}

struct EditorState {
    id: Option<Uuid>,
    name: String,
    website: String,
    username: String,
    password: String,
    notes: String,
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
            category: "其他".to_string(),
            favorite: false,
            password_visible: false,
        }
    }
}

impl Drop for EditorState {
    fn drop(&mut self) {
        self.password.zeroize();
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

#[derive(Debug, Clone)]
enum Message {
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
    NewEntry,
    EditSelected,
    EditorNameChanged(String),
    EditorWebsiteChanged(String),
    EditorUsernameChanged(String),
    EditorPasswordChanged(String),
    EditorNotesChanged(String),
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
    ConfirmPermanentDelete,
    CancelPermanentDelete,
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
}

impl App {
    fn new() -> (Self, Task<Message>) {
        (
            Self {
                vault_path: "passwords.pmvault".to_string(),
                master_password: String::new(),
                confirm_password: String::new(),
                session: None,
                search: String::new(),
                search_id: widget::Id::unique(),
                nav: NavFilter::All,
                selected: None,
                panel: Panel::Details,
                revealed: None,
                confirm_permanent_delete: None,
                dark_mode: true,
                status: String::new(),
            },
            Task::none(),
        )
    }

    fn theme(&self) -> Theme {
        if self.dark_mode {
            Theme::Dark
        } else {
            Theme::Light
        }
    }

    fn subscription(&self) -> Subscription<Message> {
        keyboard::listen().filter_map(|event| {
            let keyboard::Event::KeyPressed { key, modifiers, .. } = event else {
                return None;
            };

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
        })
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::VaultPathChanged(value) => self.vault_path = value,
            Message::MasterPasswordChanged(value) => self.master_password = value,
            Message::ConfirmPasswordChanged(value) => self.confirm_password = value,
            Message::CreateVault => self.create_vault(),
            Message::OpenVault => self.open_vault(),
            Message::Save => self.save_now(),
            Message::Lock => self.lock(),
            Message::FocusSearch => {
                if self.session.is_some() {
                    self.panel = Panel::Details;
                    return operation::focus(self.search_id.clone());
                }
            }
            Message::SearchChanged(value) => self.search = value,
            Message::SetNav(nav) => {
                self.nav = nav;
                self.selected = None;
                self.panel = Panel::Details;
                self.clear_reveal();
                self.confirm_permanent_delete = None;
            }
            Message::SelectEntry(id) => {
                self.selected = Some(id);
                self.panel = Panel::Details;
                self.clear_reveal();
                self.confirm_permanent_delete = None;
            }
            Message::NewEntry => {
                if self.session.is_some() {
                    self.selected = None;
                    self.clear_reveal();
                    self.panel = Panel::Editor(EditorState::new());
                }
            }
            Message::EditSelected => self.open_editor_for_selected(),
            Message::EditorNameChanged(value) => {
                if let Panel::Editor(state) = &mut self.panel {
                    state.name = value;
                }
            }
            Message::EditorWebsiteChanged(value) => {
                if let Panel::Editor(state) = &mut self.panel {
                    state.website = value;
                }
            }
            Message::EditorUsernameChanged(value) => {
                if let Panel::Editor(state) = &mut self.panel {
                    state.username = value;
                }
            }
            Message::EditorPasswordChanged(value) => {
                if let Panel::Editor(state) = &mut self.panel {
                    state.password.zeroize();
                    state.password = value;
                }
            }
            Message::EditorNotesChanged(value) => {
                if let Panel::Editor(state) = &mut self.panel {
                    state.notes = value;
                }
            }
            Message::EditorCategoryChanged(value) => {
                if let Panel::Editor(state) = &mut self.panel {
                    state.category = value;
                }
            }
            Message::EditorFavoriteChanged(value) => {
                if let Panel::Editor(state) = &mut self.panel {
                    state.favorite = value;
                }
            }
            Message::ToggleEditorPasswordVisible => {
                if let Panel::Editor(state) = &mut self.panel {
                    state.password_visible = !state.password_visible;
                }
            }
            Message::GeneratePassword => {
                if let Panel::Editor(state) = &mut self.panel {
                    match generate_password(PasswordGeneratorOptions::default()) {
                        Ok(password) => {
                            state.password.zeroize();
                            state.password = password;
                            self.status = "已生成 20 位安全随机密码".to_string();
                        }
                        Err(error) => self.status = format!("生成失败：{error}"),
                    }
                }
            }
            Message::SaveEditor => self.save_editor(),
            Message::CancelPanel => {
                self.panel = Panel::Details;
                self.confirm_permanent_delete = None;
            }
            Message::ToggleReveal => self.toggle_reveal(),
            Message::CopyPassword => {
                if let Some(session) = self.session.as_ref()
                    && let Some(id) = self.selected
                {
                    match session.reveal_secret(id) {
                        Ok(secret) => {
                            self.status = "密码已复制到系统剪贴板".to_string();
                            return clipboard::write::<Message>(secret.password.clone()).discard();
                        }
                        Err(error) => self.status = format!("复制失败：{error}"),
                    }
                }
            }
            Message::CopyUsername => {
                if let Some(username) = self.selected_entry().map(|entry| entry.username.clone()) {
                    self.status = "用户名已复制".to_string();
                    return clipboard::write::<Message>(username).discard();
                }
            }
            Message::OpenWebsite => self.open_selected_website(),
            Message::ToggleSelectedFavorite => self.toggle_selected_favorite(),
            Message::MoveSelectedToRecycleBin => self.move_selected_to_recycle_bin(),
            Message::RestoreSelected => self.restore_selected(),
            Message::RequestPermanentDelete => {
                self.confirm_permanent_delete = self.selected;
            }
            Message::ConfirmPermanentDelete => self.permanently_delete_selected(),
            Message::CancelPermanentDelete => self.confirm_permanent_delete = None,
            Message::OpenImport => {
                if self.session.is_some() {
                    self.panel = Panel::Import(ImportState::new());
                    self.clear_reveal();
                }
            }
            Message::ImportPathChanged(value) => {
                if let Panel::Import(state) = &mut self.panel {
                    state.path = value;
                    state.preview = None;
                    state.resolutions.clear();
                }
            }
            Message::ImportLegacyPasswordChanged(value) => {
                if let Panel::Import(state) = &mut self.panel {
                    state.legacy_password.zeroize();
                    state.legacy_password = value;
                }
            }
            Message::AnalyzeImport => self.analyze_import(),
            Message::ImportApplyUpdatesChanged(value) => {
                if let Panel::Import(state) = &mut self.panel {
                    state.apply_updates = value;
                }
            }
            Message::SetImportResolution(index, resolution) => {
                if let Panel::Import(state) = &mut self.panel {
                    state.resolutions.insert(index, resolution);
                }
            }
            Message::ApplyImport => self.apply_import(),
            Message::OpenSettings => self.open_settings(),
            Message::BackupPathChanged(value) => {
                if let Panel::Settings(state) = &mut self.panel {
                    state.backup_path = value;
                }
            }
            Message::CreateBackup => self.create_backup(),
            Message::RestorePathChanged(value) => {
                if let Panel::Settings(state) = &mut self.panel {
                    state.restore_path = value;
                }
            }
            Message::RestorePasswordChanged(value) => {
                if let Panel::Settings(state) = &mut self.panel {
                    state.restore_password.zeroize();
                    state.restore_password = value;
                }
            }
            Message::ConfirmRestoreChanged(value) => {
                if let Panel::Settings(state) = &mut self.panel {
                    state.confirm_restore = value;
                }
            }
            Message::RestoreBackup => self.restore_backup(),
            Message::CsvPathChanged(value) => {
                if let Panel::Settings(state) = &mut self.panel {
                    state.csv_path = value;
                }
            }
            Message::ConfirmPlaintextChanged(value) => {
                if let Panel::Settings(state) = &mut self.panel {
                    state.confirm_plaintext = value;
                }
            }
            Message::ExportPlaintextCsv => self.export_plaintext_csv(),
            Message::DarkModeChanged(value) => self.dark_mode = value,
        }

        Task::none()
    }

    fn view(&self) -> Element<'_, Message> {
        if self.session.is_none() {
            return self.locked_view();
        }

        let session = self.session.as_ref().expect("session checked above");
        let sidebar = self.sidebar_view(session);
        let list = self.list_view(session);
        let content = match &self.panel {
            Panel::Details => self.details_view(session),
            Panel::Editor(state) => self.editor_view(state),
            Panel::Import(state) => self.import_view(session, state),
            Panel::Settings(state) => self.settings_view(session, state),
        };

        let layout = column![
            row![
                container(sidebar).padding(14).width(Length::FillPortion(1)),
                container(list).padding(14).width(Length::FillPortion(2)),
                container(scrollable(content))
                    .padding(18)
                    .width(Length::FillPortion(3)),
            ]
            .height(Length::Fill),
            container(text(&self.status).size(13))
                .padding(8)
                .width(Length::Fill)
        ];

        container(layout)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn locked_view(&self) -> Element<'_, Message> {
        let content = column![
            text("密码管理器").size(38),
            text("本地加密保险库 · Rust + Iced"),
            text_input(
                "保险库路径，例如 D:\\Passwords\\main.pmvault",
                &self.vault_path,
            )
            .on_input(Message::VaultPathChanged)
            .padding(10),
            text_input("主密码", &self.master_password)
                .on_input(Message::MasterPasswordChanged)
                .on_submit(Message::OpenVault)
                .secure(true)
                .padding(10),
            text_input(
                "再次输入主密码（仅创建新保险库时需要）",
                &self.confirm_password,
            )
            .on_input(Message::ConfirmPasswordChanged)
            .secure(true)
            .padding(10),
            row![
                button("创建新保险库").on_press(Message::CreateVault),
                button("打开保险库").on_press(Message::OpenVault)
            ]
            .spacing(10),
            text("主密码不会保存。没有恢复后门。").size(13),
            text(&self.status)
        ]
        .spacing(14);

        container(content)
            .padding(32)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn sidebar_view<'a>(&'a self, session: &'a VaultSession) -> Element<'a, Message> {
        let mut sidebar = column![
            text("保险库").size(24),
            button("全部").on_press(Message::SetNav(NavFilter::All)),
            button("收藏").on_press(Message::SetNav(NavFilter::Favorites)),
            button("回收站").on_press(Message::SetNav(NavFilter::RecycleBin)),
            text("分类").size(16),
        ]
        .spacing(8);

        for category in session.categories() {
            sidebar = sidebar.push(
                button(category.as_str())
                    .on_press(Message::SetNav(NavFilter::Category(category.clone())))
                    .width(Length::Fill),
            );
        }

        sidebar = sidebar.push(
            column![
                button("＋ 新建条目").on_press(Message::NewEntry),
                button("导入").on_press(Message::OpenImport),
                button("设置").on_press(Message::OpenSettings),
                button("保存").on_press(Message::Save),
                button("锁定").on_press(Message::Lock),
                text("快捷键：Ctrl+F / N / S / L").size(11),
            ]
            .spacing(8),
        );

        sidebar.into()
    }

    fn list_view<'a>(&'a self, session: &'a VaultSession) -> Element<'a, Message> {
        let search = text_input("搜索名称 / 网站 / 用户名", &self.search)
            .id(self.search_id.clone())
            .on_input(Message::SearchChanged)
            .padding(9);

        let query = self.search.to_lowercase();
        let mut list = column![text("条目").size(22), search].spacing(8);

        let entries: Vec<&EntryRecord> = session
            .entries()
            .iter()
            .filter(|entry| self.entry_visible(entry, &query))
            .collect();

        if entries.is_empty() {
            list = list.push(text("没有符合条件的条目").size(13));
        } else {
            for entry in entries {
                let favorite = if entry.favorite { "★ " } else { "" };
                let deleted = if entry.is_deleted() {
                    " [回收站]"
                } else {
                    ""
                };
                let label = column![
                    text(format!("{favorite}{}{}", entry.name, deleted)),
                    text(format!("{}  {}", entry.username, entry.website)).size(12)
                ]
                .spacing(2);

                list = list.push(
                    button(label)
                        .on_press(Message::SelectEntry(entry.id))
                        .width(Length::Fill),
                );
            }
        }

        scrollable(list).into()
    }

    fn details_view<'a>(&'a self, session: &'a VaultSession) -> Element<'a, Message> {
        let Some(id) = self.selected else {
            return column![
                text("选择一个条目").size(26),
                text(format!("Vault ID：{}", session.vault_id())),
                text(format!("Revision：{}", session.revision())),
                text(format!("路径：{}", session.path().display())),
                text(format!(
                    "有效条目：{} · 回收站：{}",
                    session.active_entries().count(),
                    session
                        .entries()
                        .iter()
                        .filter(|entry| entry.is_deleted())
                        .count()
                )),
            ]
            .spacing(10)
            .into();
        };

        let Some(entry) = session.entry(id) else {
            return text("条目不存在").into();
        };

        let password = self
            .revealed
            .as_ref()
            .filter(|revealed| revealed.entry_id == id)
            .map(|revealed| revealed.value.as_str())
            .unwrap_or("••••••••••••");

        let mut content = column![
            text(&entry.name).size(30),
            text(format!("网站：{}", entry.website)),
            row![
                text(format!("用户名：{}", entry.username)),
                button("复制用户名").on_press(Message::CopyUsername)
            ]
            .spacing(8),
            row![
                text(format!("密码：{password}")),
                button(if self.revealed.is_some() {
                    "隐藏"
                } else {
                    "显示"
                })
                .on_press(Message::ToggleReveal),
                button("复制密码").on_press(Message::CopyPassword)
            ]
            .spacing(8),
            text(format!("分类：{}", entry.category)),
            text(format!(
                "收藏：{}",
                if entry.favorite { "是" } else { "否" }
            )),
        ]
        .spacing(12);

        content = content.push(text("备注在编辑模式中按需解密显示。").size(12));

        if entry.is_deleted() {
            content = content.push(
                row![
                    button("恢复").on_press(Message::RestoreSelected),
                    button("永久删除").on_press(Message::RequestPermanentDelete)
                ]
                .spacing(8),
            );

            if self.confirm_permanent_delete == Some(id) {
                content = content.push(
                    column![
                        text("永久删除后无法从回收站恢复。"),
                        row![
                            button("确认永久删除").on_press(Message::ConfirmPermanentDelete),
                            button("取消").on_press(Message::CancelPermanentDelete)
                        ]
                        .spacing(8)
                    ]
                    .spacing(8),
                );
            }
        } else {
            content = content.push(
                row![
                    button("编辑").on_press(Message::EditSelected),
                    button(if entry.favorite {
                        "取消收藏"
                    } else {
                        "收藏"
                    })
                    .on_press(Message::ToggleSelectedFavorite),
                    button("打开网站").on_press(Message::OpenWebsite),
                    button("移到回收站").on_press(Message::MoveSelectedToRecycleBin)
                ]
                .spacing(8),
            );
        }

        content.into()
    }

    fn editor_view<'a>(&'a self, state: &'a EditorState) -> Element<'a, Message> {
        column![
            text(if state.id.is_some() {
                "编辑条目"
            } else {
                "新建条目"
            })
            .size(28),
            text_input("名称 *", &state.name)
                .on_input(Message::EditorNameChanged)
                .padding(9),
            text_input("网站，例如 https://example.com", &state.website)
                .on_input(Message::EditorWebsiteChanged)
                .padding(9),
            text_input("用户名", &state.username)
                .on_input(Message::EditorUsernameChanged)
                .padding(9),
            row![
                text_input("密码 *", &state.password)
                    .on_input(Message::EditorPasswordChanged)
                    .secure(!state.password_visible)
                    .padding(9),
                button(if state.password_visible {
                    "隐藏"
                } else {
                    "显示"
                })
                .on_press(Message::ToggleEditorPasswordVisible)
            ]
            .spacing(8),
            button("生成 20 位安全随机密码").on_press(Message::GeneratePassword),
            text_input("分类", &state.category)
                .on_input(Message::EditorCategoryChanged)
                .padding(9),
            text_input("备注", &state.notes)
                .on_input(Message::EditorNotesChanged)
                .padding(9),
            checkbox(state.favorite)
                .label("收藏")
                .on_toggle(Message::EditorFavoriteChanged),
            row![
                button("保存").on_press(Message::SaveEditor),
                button("取消").on_press(Message::CancelPanel)
            ]
            .spacing(8)
        ]
        .spacing(11)
        .into()
    }

    fn import_view<'a>(
        &'a self,
        session: &'a VaultSession,
        state: &'a ImportState,
    ) -> Element<'a, Message> {
        let mut content = column![
            text("导入密码").size(28),
            text("支持 Chrome / Google Password Manager CSV、CSV4/CSV6、旧 vault.enc、旧 passwords.db。"),
            text_input("导入文件路径", &state.path)
                .on_input(Message::ImportPathChanged)
                .padding(9),
            text_input("旧主密码（仅 vault.enc / passwords.db 需要）", &state.legacy_password)
                .on_input(Message::ImportLegacyPasswordChanged)
                .secure(true)
                .padding(9),
            row![
                button("分析并预览").on_press(Message::AnalyzeImport),
                button("返回").on_press(Message::CancelPanel)
            ]
            .spacing(8),
            text("源文件只读；普通导入不会因为源文件缺少条目而删除本地密码。").size(12),
        ]
        .spacing(11);

        if let Some(preview) = &state.preview {
            let summary = preview.summary();
            content = content.push(
                column![
                    text(format!("来源：{}", preview.provider)),
                    text(format!(
                        "新增 {} · 完全重复 {} · 更新候选 {} · 冲突 {} · 本地已删除 {} · 无效 {}",
                        summary.new,
                        summary.exact_duplicates,
                        summary.update_candidates,
                        summary.conflicts,
                        summary.locally_deleted,
                        summary.invalid
                    )),
                    text(if preview.same_source_file {
                        "检测到这份源文件以前已经导入过。"
                    } else {
                        "这是新的源文件版本或首次导入。"
                    }),
                    checkbox(state.apply_updates)
                        .label("应用可以安全确认的更新候选")
                        .on_toggle(Message::ImportApplyUpdatesChanged),
                ]
                .spacing(7),
            );

            let mut rows = column![text("需要关注的条目").size(18)].spacing(8);
            let mut attention = 0usize;

            for (index, row_state) in preview.rows.iter().enumerate() {
                match &row_state.class {
                    ImportClass::UpdateCandidate { existing_id } => {
                        attention += 1;
                        let local = session
                            .entry(*existing_id)
                            .map(|entry| entry.name.as_str())
                            .unwrap_or("未知条目");
                        rows = rows.push(text(format!(
                            "更新候选：{} → 本地 {}",
                            row_state.item.name, local
                        )));
                    }
                    ImportClass::Conflict { existing_ids }
                    | ImportClass::LocallyDeleted { existing_ids } => {
                        attention += 1;
                        let heading =
                            if matches!(&row_state.class, ImportClass::LocallyDeleted { .. }) {
                                "本地已删除"
                            } else {
                                "冲突"
                            };
                        let selected = state.resolutions.get(&index);
                        let mut block = column![
                            text(format!("{heading}：{}", row_state.item.name)),
                            text(format!(
                                "{} · {}",
                                row_state.item.username, row_state.item.website
                            ))
                            .size(12),
                            row![
                                button(
                                    if matches!(selected, Some(ConflictResolution::KeepLocal)) {
                                        "✓ 保留本地"
                                    } else {
                                        "保留本地"
                                    },
                                )
                                .on_press(
                                    Message::SetImportResolution(
                                        index,
                                        ConflictResolution::KeepLocal,
                                    )
                                ),
                                button(if matches!(selected, Some(ConflictResolution::KeepBoth)) {
                                    "✓ 两份都保留"
                                } else {
                                    "两份都保留"
                                })
                                .on_press(
                                    Message::SetImportResolution(
                                        index,
                                        ConflictResolution::KeepBoth,
                                    )
                                ),
                            ]
                            .spacing(6)
                        ]
                        .spacing(5);

                        for existing_id in existing_ids {
                            if let Some(entry) = session.entry(*existing_id) {
                                let chosen = matches!(
                                    selected,
                                    Some(ConflictResolution::UseImported(id)) if id == existing_id
                                );
                                block = block.push(
                                    button(text(if chosen {
                                        format!("✓ 使用导入值覆盖/恢复：{}", entry.name)
                                    } else {
                                        format!("使用导入值覆盖/恢复：{}", entry.name)
                                    }))
                                    .on_press(
                                        Message::SetImportResolution(
                                            index,
                                            ConflictResolution::UseImported(*existing_id),
                                        ),
                                    ),
                                );
                            }
                        }

                        rows = rows.push(container(block).padding(8));
                    }
                    ImportClass::New | ImportClass::ExactDuplicate { .. } => {}
                }
            }

            if attention == 0 {
                rows = rows.push(text("没有需要人工处理的冲突。"));
            }

            let unresolved = preview
                .rows
                .iter()
                .enumerate()
                .filter(|(index, row)| {
                    matches!(
                        &row.class,
                        ImportClass::Conflict { .. } | ImportClass::LocallyDeleted { .. }
                    ) && !state.resolutions.contains_key(index)
                })
                .count();

            content = content.push(scrollable(rows).height(Length::Fixed(320.0)));
            content = if unresolved == 0 {
                content.push(button("执行导入").on_press(Message::ApplyImport))
            } else {
                content.push(text(format!(
                    "还有 {unresolved} 个冲突/本地删除条目需要先选择处理方式。"
                )))
            };
        }

        content.into()
    }

    fn settings_view<'a>(
        &'a self,
        session: &'a VaultSession,
        state: &'a SettingsState,
    ) -> Element<'a, Message> {
        column![
            text("设置").size(28),
            text("安全"),
            text("Windows 会话自动锁、截图保护和条件剪贴板清理由 Batch D 的平台安全生命周期接入。")
                .size(12),
            text("保险库"),
            text(format!("Vault ID：{}", session.vault_id())),
            text(format!("Revision：{}", session.revision())),
            text(format!("路径：{}", session.path().display())),
            text("加密备份"),
            text_input("备份目标 .pmvault", &state.backup_path)
                .on_input(Message::BackupPathChanged)
                .padding(9),
            button("创建加密备份").on_press(Message::CreateBackup),
            text("恢复加密备份"),
            text_input("备份文件路径", &state.restore_path)
                .on_input(Message::RestorePathChanged)
                .padding(9),
            text_input("该备份的主密码", &state.restore_password)
                .on_input(Message::RestorePasswordChanged)
                .secure(true)
                .padding(9),
            checkbox(state.confirm_restore)
                .label("我确认用该备份替换当前保险库")
                .on_toggle(Message::ConfirmRestoreChanged),
            button("恢复并替换当前保险库").on_press(Message::RestoreBackup),
            text("兼容导出：明文 CSV"),
            text_input("CSV 导出路径", &state.csv_path)
                .on_input(Message::CsvPathChanged)
                .padding(9),
            checkbox(state.confirm_plaintext)
                .label("我理解 CSV 中密码和备注将以明文保存")
                .on_toggle(Message::ConfirmPlaintextChanged),
            button("导出明文 CSV").on_press(Message::ExportPlaintextCsv),
            button("打开导入工具").on_press(Message::OpenImport),
            text("外观"),
            checkbox(self.dark_mode)
                .label("深色模式")
                .on_toggle(Message::DarkModeChanged),
            text("诊断"),
            text(format!(
                "有效条目 {} · 回收站 {} · 分类 {}",
                session.active_entries().count(),
                session
                    .entries()
                    .iter()
                    .filter(|entry| entry.is_deleted())
                    .count(),
                session.categories().len()
            )),
            text(format!("应用版本：{}", env!("CARGO_PKG_VERSION"))),
            button("返回").on_press(Message::CancelPanel),
        ]
        .spacing(10)
        .into()
    }

    fn create_vault(&mut self) {
        if self.master_password != self.confirm_password {
            self.status = "两次输入的主密码不一致".to_string();
            return;
        }

        match VaultSession::create(self.vault_path.clone(), &self.master_password) {
            Ok(session) => {
                self.session = Some(session);
                self.status = "新保险库已创建并加密".to_string();
                self.clear_password_fields();
                self.reset_unlocked_state();
            }
            Err(error) => self.status = format!("创建失败：{error}"),
        }
    }

    fn open_vault(&mut self) {
        match VaultSession::open(self.vault_path.clone(), &self.master_password) {
            Ok(session) => {
                self.session = Some(session);
                self.status = "保险库已解锁".to_string();
                self.clear_password_fields();
                self.reset_unlocked_state();
            }
            Err(error) => self.status = format!("无法解锁：{error}"),
        }
    }

    fn reset_unlocked_state(&mut self) {
        self.nav = NavFilter::All;
        self.selected = None;
        self.panel = Panel::Details;
        self.search.clear();
        self.clear_reveal();
        self.confirm_permanent_delete = None;
    }

    fn save_now(&mut self) {
        if matches!(&self.panel, Panel::Editor(_)) {
            self.save_editor();
            return;
        }

        let Some(session) = self.session.as_ref() else {
            return;
        };

        self.status = match session.verify_current_file() {
            Ok(()) => format!("保险库已验证 · revision {}", session.revision()),
            Err(error) => format!("验证失败：{error}"),
        };
    }

    fn lock(&mut self) {
        self.session = None;
        self.reset_unlocked_state();
        self.clear_password_fields();
        self.status = "保险库已锁定".to_string();
    }

    fn open_editor_for_selected(&mut self) {
        let Some(session) = self.session.as_ref() else {
            return;
        };
        let Some(id) = self.selected else {
            return;
        };
        let Some(entry) = session.entry(id) else {
            self.status = "找不到该条目".to_string();
            return;
        };

        match session.reveal_secret(id) {
            Ok(secret) => {
                self.panel = Panel::Editor(EditorState {
                    id: Some(id),
                    name: entry.name.clone(),
                    website: entry.website.clone(),
                    username: entry.username.clone(),
                    password: secret.password.clone(),
                    notes: secret.notes.clone(),
                    category: entry.category.clone(),
                    favorite: entry.favorite,
                    password_visible: false,
                });
                self.clear_reveal();
            }
            Err(error) => self.status = format!("无法进入编辑：{error}"),
        }
    }

    fn save_editor(&mut self) {
        let Panel::Editor(state) = &self.panel else {
            return;
        };

        let entry_id = state.id;
        let draft = match draft(
            state.name.clone(),
            state.website.clone(),
            state.username.clone(),
            state.password.clone(),
            state.notes.clone(),
            state.category.clone(),
            state.favorite,
        ) {
            Ok(draft) => draft,
            Err(error) => {
                self.status = format!("无法保存：{error}");
                return;
            }
        };

        let result = self.mutate_and_save(|session| {
            if let Some(id) = entry_id {
                session.update_entry(id, draft)?;
                Ok(id)
            } else {
                session.add_entry(draft)
            }
        });

        match result {
            Ok(id) => {
                self.selected = Some(id);
                self.panel = Panel::Details;
                self.status = "条目已安全保存".to_string();
            }
            Err(error) => self.status = format!("保存失败：{error}"),
        }
    }

    fn toggle_reveal(&mut self) {
        let Some(id) = self.selected else {
            return;
        };

        if self
            .revealed
            .as_ref()
            .is_some_and(|revealed| revealed.entry_id == id)
        {
            self.clear_reveal();
            return;
        }

        let Some(session) = self.session.as_ref() else {
            return;
        };

        match session.reveal_secret(id) {
            Ok(secret) => {
                self.revealed = Some(RevealedPassword {
                    entry_id: id,
                    value: secret.password.clone(),
                });
            }
            Err(error) => self.status = format!("无法显示密码：{error}"),
        }
    }

    fn clear_reveal(&mut self) {
        self.revealed = None;
    }

    fn open_selected_website(&mut self) {
        let Some(website) = self.selected_entry().map(|entry| entry.website.clone()) else {
            return;
        };

        match safe_web_url(&website) {
            Ok(url) => {
                if let Err(error) = webbrowser::open(&url) {
                    self.status = format!("无法打开网站：{error}");
                }
            }
            Err(error) => self.status = format!("无法打开网站：{error}"),
        }
    }

    fn toggle_selected_favorite(&mut self) {
        let Some((id, favorite)) = self
            .selected_entry()
            .map(|entry| (entry.id, !entry.favorite))
        else {
            return;
        };

        self.status = match self.mutate_and_save(|session| {
            session.set_favorite(id, favorite)?;
            Ok(())
        }) {
            Ok(()) => "收藏状态已保存".to_string(),
            Err(error) => format!("保存失败：{error}"),
        };
    }

    fn move_selected_to_recycle_bin(&mut self) {
        let Some(id) = self.selected else {
            return;
        };

        self.status = match self.mutate_and_save(|session| {
            session.move_to_recycle_bin(id)?;
            Ok(())
        }) {
            Ok(()) => {
                self.selected = None;
                self.clear_reveal();
                "条目已移到回收站".to_string()
            }
            Err(error) => format!("删除失败：{error}"),
        };
    }

    fn restore_selected(&mut self) {
        let Some(id) = self.selected else {
            return;
        };

        self.status = match self.mutate_and_save(|session| {
            session.restore_from_recycle_bin(id)?;
            Ok(())
        }) {
            Ok(()) => "条目已恢复".to_string(),
            Err(error) => format!("恢复失败：{error}"),
        };
    }

    fn permanently_delete_selected(&mut self) {
        let Some(id) = self.selected else {
            return;
        };

        self.status = match self.mutate_and_save(|session| {
            session.permanently_delete(id)?;
            Ok(())
        }) {
            Ok(()) => {
                self.selected = None;
                self.confirm_permanent_delete = None;
                self.clear_reveal();
                "条目已永久删除".to_string()
            }
            Err(error) => format!("永久删除失败：{error}"),
        };
    }

    fn analyze_import(&mut self) {
        let (path, mut legacy_password) = match &self.panel {
            Panel::Import(state) => (state.path.clone(), state.legacy_password.clone()),
            _ => return,
        };

        let Some(session) = self.session.as_ref() else {
            return;
        };

        let password = (!legacy_password.is_empty()).then_some(legacy_password.as_str());
        let result =
            stage_path(Path::new(&path), password).and_then(|batch| build_preview(session, batch));
        legacy_password.zeroize();

        if let Panel::Import(state) = &mut self.panel {
            state.legacy_password.zeroize();
            state.legacy_password.clear();
            state.resolutions.clear();

            match result {
                Ok(preview) => {
                    let summary = preview.summary();
                    self.status = format!(
                        "预览完成：新增 {}，重复 {}，更新 {}，冲突 {}",
                        summary.new,
                        summary.exact_duplicates,
                        summary.update_candidates,
                        summary.conflicts + summary.locally_deleted
                    );
                    state.preview = Some(preview);
                }
                Err(error) => {
                    state.preview = None;
                    self.status = format!("导入分析失败：{error}");
                }
            }
        }
    }

    fn apply_import(&mut self) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let Panel::Import(state) = &mut self.panel else {
            return;
        };
        let Some(preview) = state.preview.as_ref() else {
            return;
        };

        let options = ImportApplyOptions {
            apply_update_candidates: state.apply_updates,
            conflict_resolutions: state.resolutions.clone(),
        };

        match apply_preview(session, preview, &options) {
            Ok(report) => {
                self.status = format!(
                    "导入完成：新增 {}，更新 {}，跳过 {}，未解决冲突 {}，待处理更新 {}，本地删除待处理 {}，无效 {}",
                    report.added,
                    report.updated,
                    report.skipped,
                    report.conflicts_unresolved,
                    report.updates_deferred,
                    report.locally_deleted_deferred,
                    report.invalid
                );

                if report.conflicts_unresolved == 0
                    && report.locally_deleted_deferred == 0
                    && report.updates_deferred == 0
                {
                    state.preview = None;
                    state.resolutions.clear();
                }
            }
            Err(error) => self.status = format!("导入失败并已回滚：{error}"),
        }
    }

    fn open_settings(&mut self) {
        let Some(session) = self.session.as_ref() else {
            return;
        };
        self.panel = Panel::Settings(SettingsState::from_vault(session));
        self.clear_reveal();
    }

    fn create_backup(&mut self) {
        let path = match &self.panel {
            Panel::Settings(state) => state.backup_path.clone(),
            _ => return,
        };
        let Some(session) = self.session.as_ref() else {
            return;
        };

        self.status = match session.export_encrypted_backup(Path::new(&path)) {
            Ok(()) => format!("加密备份已创建：{path}"),
            Err(error) => format!("备份失败：{error}"),
        };
    }

    fn restore_backup(&mut self) {
        let (source, mut password, confirmed) = match &self.panel {
            Panel::Settings(state) => (
                state.restore_path.clone(),
                state.restore_password.clone(),
                state.confirm_restore,
            ),
            _ => return,
        };

        if !confirmed {
            self.status = "恢复前必须勾选替换当前保险库确认".to_string();
            return;
        }

        let Some(current) = self.session.as_ref() else {
            return;
        };
        let destination = current.path().to_path_buf();

        let result = VaultSession::restore_encrypted_backup(
            Path::new(&source),
            &destination,
            &password,
            true,
        )
        .and_then(|()| VaultSession::open(destination.clone(), &password));
        password.zeroize();

        match result {
            Ok(session) => {
                self.session = Some(session);
                self.vault_path = destination.display().to_string();
                self.reset_unlocked_state();
                self.status = "加密备份已验证并恢复".to_string();
            }
            Err(error) => self.status = format!("恢复失败：{error}"),
        }

        if let Panel::Settings(state) = &mut self.panel {
            state.restore_password.zeroize();
            state.restore_password.clear();
        }
    }

    fn export_plaintext_csv(&mut self) {
        let (path, confirmed) = match &self.panel {
            Panel::Settings(state) => (state.csv_path.clone(), state.confirm_plaintext),
            _ => return,
        };

        if !confirmed {
            self.status = "必须先确认明文 CSV 风险".to_string();
            return;
        }

        let Some(session) = self.session.as_ref() else {
            return;
        };

        self.status = match export_plaintext_csv(
            session,
            Path::new(&path),
            PlaintextExportAcknowledgement::user_confirmed_risk(),
        ) {
            Ok(count) => format!("已导出 {count} 条到明文 CSV：{path}"),
            Err(error) => format!("CSV 导出失败：{error}"),
        };
    }

    fn selected_entry(&self) -> Option<&EntryRecord> {
        let id = self.selected?;
        self.session.as_ref()?.entry(id)
    }

    fn entry_visible(&self, entry: &EntryRecord, query: &str) -> bool {
        let nav_match = match &self.nav {
            NavFilter::All => !entry.is_deleted(),
            NavFilter::Favorites => entry.favorite && !entry.is_deleted(),
            NavFilter::RecycleBin => entry.is_deleted(),
            NavFilter::Category(category) => &entry.category == category && !entry.is_deleted(),
        };

        nav_match
            && (query.is_empty()
                || entry.name.to_lowercase().contains(query)
                || entry.website.to_lowercase().contains(query)
                || entry.username.to_lowercase().contains(query))
    }

    fn mutate_and_save<T>(
        &mut self,
        mutation: impl FnOnce(&mut VaultSession) -> Result<T>,
    ) -> Result<T> {
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| AppError::Input("保险库尚未解锁".to_string()))?;
        let snapshot = session.snapshot_body();

        match mutation(session) {
            Ok(value) => {
                if let Err(error) = session.save() {
                    session.restore_body(snapshot);
                    Err(error)
                } else {
                    Ok(value)
                }
            }
            Err(error) => {
                session.restore_body(snapshot);
                Err(error)
            }
        }
    }

    fn clear_password_fields(&mut self) {
        self.master_password.zeroize();
        self.master_password.clear();
        self.confirm_password.zeroize();
        self.confirm_password.clear();
    }
}

impl Drop for App {
    fn drop(&mut self) {
        self.clear_password_fields();
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
