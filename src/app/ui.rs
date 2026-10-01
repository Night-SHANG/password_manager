use iced::widget::{
    Space, button, checkbox, column, container, mouse_area, opaque, row, scrollable, stack, table,
    text, text_input,
};
use iced::{Alignment, Color};

use super::*;

const SIDEBAR_WIDTH: f32 = 250.0;
const COLUMN_WIDTHS: [f32; 5] = [180.0, 220.0, 160.0, 120.0, 80.0];
const HEADERS: [&str; 5] = ["名称", "网站", "用户名", "密码", "分类"];

fn field<'a>(
    label: &'a str,
    hint: &'a str,
    value: &'a str,
    message: impl Fn(String) -> Message + 'a,
) -> Element<'a, Message> {
    column![
        text(label).size(13),
        text_input(hint, value).on_input(message).padding(10)
    ]
    .spacing(5)
    .into()
}

fn secret_field<'a>(
    label: &'a str,
    value: &'a str,
    message: impl Fn(String) -> Message + 'a,
) -> Element<'a, Message> {
    column![
        text(label).size(13),
        text_input(label, value)
            .on_input(message)
            .secure(true)
            .padding(10)
    ]
    .spacing(5)
    .into()
}

fn card<'a>(content: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    container(content)
        .padding(22)
        .width(Length::Fill)
        .style(container::rounded_box)
        .into()
}

impl App {
    pub(super) fn view(&self) -> Element<'_, Message> {
        let Some(session) = &self.session else {
            return self.locked_view();
        };
        let content = match &self.panel {
            Panel::Vault => self.table_view(session),
            Panel::Editor(state) => self.editor_view(state),
            Panel::Import(state) => self.import_view(session, state),
            Panel::Settings(state) => self.settings_view(session, state),
            Panel::DeleteEntry(id) => self.confirmation(
                "永久删除条目",
                "只能永久删除回收站条目。此操作不能撤销；已有备份仍保留原数据。",
                Message::ConfirmPermanentDelete(*id),
            ),
            Panel::DeleteCategory(name) => self.confirmation(
                "删除分类",
                "分类中的全部条目（包括回收站条目）将移入“其他”，不会删除密码。",
                Message::ConfirmDeleteCategory(name.clone()),
            ),
        };
        let base: Element<'_, Message> = column![
            row![
                self.sidebar_view(session),
                container(content)
                    .padding(20)
                    .width(Length::Fill)
                    .height(Length::Fill)
            ]
            .height(Length::Fill),
            container(text(&self.status).size(13))
                .padding([8, 16])
                .width(Length::Fill),
        ]
        .height(Length::Fill)
        .into();
        if self.context_open && matches!(&self.panel, Panel::Vault) {
            stack![
                base,
                opaque(
                    container(
                        mouse_area(
                            container(self.context_view())
                                .padding(20)
                                .style(container::rounded_box)
                        )
                        .on_press(Message::CloseContext)
                    )
                    .center_x(Length::Fill)
                    .center_y(Length::Fill)
                    .style(|_| container::Style {
                        background: Some(Color::from_rgba(0.0, 0.0, 0.0, 0.18).into()),
                        ..container::Style::default()
                    })
                )
            ]
            .into()
        } else {
            base
        }
    }

    fn locked_view(&self) -> Element<'_, Message> {
        let submit = if self.creating {
            Message::CreateVault
        } else {
            Message::OpenVault
        };
        let mut form = column![
            text("密码管理器").size(30),
            text("本地加密保险库").size(14),
            row![
                button("打开保险库")
                    .on_press(Message::AuthMode(false))
                    .style(if self.creating {
                        button::secondary
                    } else {
                        button::primary
                    }),
                button("创建新保险库")
                    .on_press(Message::AuthMode(true))
                    .style(if self.creating {
                        button::primary
                    } else {
                        button::secondary
                    }),
            ]
            .spacing(10),
            field(
                "保险库文件路径",
                "例如 D:\\Passwords\\main.pmvault",
                &self.vault_path,
                Message::VaultPathChanged
            ),
            column![
                text("主密码").size(13),
                text_input("输入主密码", &self.master_password)
                    .on_input(Message::MasterPasswordChanged)
                    .on_submit(submit.clone())
                    .secure(true)
                    .padding(10)
            ]
            .spacing(5),
        ]
        .spacing(16);
        if self.creating {
            form = form.push(secret_field(
                "确认主密码",
                &self.confirm_password,
                Message::ConfirmPasswordChanged,
            ));
        }
        form = form
            .push(
                button(if self.creating {
                    "创建并进入"
                } else {
                    "解锁保险库"
                })
                .on_press(submit)
                .padding(12)
                .width(Length::Fill),
            )
            .push(text("主密码不会保存，也没有找回后门。请先用测试保险库验证此版本。").size(12))
            .push(text(&self.status).size(13));
        container(scrollable(
            container(card(form))
                .max_width(600)
                .padding(24)
                .center_x(Length::Fill),
        ))
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .into()
    }

    fn nav_button<'a>(
        &'a self,
        title: String,
        nav: NavFilter,
        count: usize,
    ) -> Element<'a, Message> {
        let selected = self.nav == nav;
        let enabled = matches!(&self.panel, Panel::Vault);
        button(
            row![
                text(title),
                Space::new().width(Length::Fill),
                text(count.to_string()).size(12)
            ]
            .align_y(Alignment::Center),
        )
        .on_press_maybe(enabled.then_some(Message::SetNav(nav)))
        .padding([10, 12])
        .width(Length::Fill)
        .style(move |theme, status| {
            if selected {
                button::primary(theme, status)
            } else {
                button::text(theme, status)
            }
        })
        .into()
    }

    fn sidebar_view<'a>(&'a self, session: &'a VaultSession) -> Element<'a, Message> {
        let enabled = matches!(&self.panel, Panel::Vault);
        let mut categories = column![
            self.nav_button(
                "全部".to_string(),
                NavFilter::All,
                session.active_entries().count()
            ),
            self.nav_button(
                "收藏".to_string(),
                NavFilter::Favorites,
                session.active_entries().filter(|e| e.favorite).count()
            ),
            self.nav_button(
                "回收站".to_string(),
                NavFilter::RecycleBin,
                session.entries().iter().filter(|e| e.is_deleted()).count()
            ),
            text("分类").size(12),
        ]
        .spacing(5);
        for name in session.categories() {
            categories = categories.push(
                self.nav_button(
                    name.clone(),
                    NavFilter::Category(name.clone()),
                    session
                        .active_entries()
                        .filter(|e| &e.category == name)
                        .count(),
                ),
            );
            if enabled && self.nav == NavFilter::Category(name.clone()) && name != "其他" {
                categories = categories.push(
                    row![
                        button("上移")
                            .on_press(Message::MoveCategory(name.clone(), true))
                            .style(button::text),
                        button("下移")
                            .on_press(Message::MoveCategory(name.clone(), false))
                            .style(button::text),
                        button("删除分类")
                            .on_press(Message::RequestDeleteCategory(name.clone()))
                            .style(button::danger),
                    ]
                    .spacing(2),
                );
            }
        }
        if enabled {
            categories = categories
                .push(
                    text_input("新分类名称", &self.category_name)
                        .on_input(Message::CategoryNameChanged)
                        .on_submit(Message::AddCategory)
                        .padding(8),
                )
                .push(
                    button("添加分类")
                        .on_press(Message::AddCategory)
                        .style(button::secondary)
                        .width(Length::Fill),
                );
        }
        let sidebar = column![
            text("密码管理器").size(20),
            text("本地加密 · 测试版本").size(12),
            scrollable(categories).height(Length::Fill),
            button("导入")
                .on_press_maybe(enabled.then_some(Message::OpenImport))
                .style(button::text)
                .width(Length::Fill),
            button("导出 / 备份")
                .on_press_maybe(enabled.then_some(Message::OpenSettings))
                .style(button::text)
                .width(Length::Fill),
            button("设置")
                .on_press_maybe(enabled.then_some(Message::OpenSettings))
                .style(button::text)
                .width(Length::Fill),
            button("锁定")
                .on_press(Message::Lock)
                .style(button::secondary)
                .width(Length::Fill),
            text("Ctrl+F 搜索  ·  Ctrl+L 锁定").size(11),
        ]
        .spacing(8);
        let dark = self.dark_mode;
        container(sidebar)
            .padding(16)
            .width(SIDEBAR_WIDTH)
            .height(Length::Fill)
            .style(move |theme| {
                let mut style = container::rounded_box(theme);
                if !dark {
                    style.background = Some(Color::from_rgb8(249, 250, 251).into());
                }
                style
            })
            .into()
    }

    fn table_cell<'a>(&'a self, entry: &'a EntryRecord, column: usize) -> Element<'a, Message> {
        let label = match column {
            0 => format!("{}{}", if entry.favorite { "★ " } else { "" }, entry.name),
            1 => entry.website.clone(),
            2 => entry.username.clone(),
            3 => "••••••".to_string(),
            _ => entry.category.clone(),
        };
        let selected = self.selected == Some(entry.id);
        let dark = self.dark_mode;
        let cell = container(text(label).size(13).wrapping(text::Wrapping::None))
            .padding([7, 8])
            .height(36)
            .width(Length::Fill)
            .clip(true)
            .style(move |theme: &Theme| {
                let palette = theme.extended_palette();
                container::Style {
                    background: Some(
                        if selected {
                            palette.primary.weak.color
                        } else if dark {
                            palette.background.base.color
                        } else {
                            Color::WHITE
                        }
                        .into(),
                    ),
                    text_color: Some(if selected {
                        palette.primary.weak.text
                    } else {
                        palette.background.base.text
                    }),
                    ..container::Style::default()
                }
            });
        mouse_area(cell)
            .on_press(Message::SelectEntry(entry.id))
            .on_double_click(Message::EditEntry(entry.id))
            .on_right_press(Message::ContextEntry(entry.id))
            .into()
    }

    fn table_view<'a>(&'a self, session: &'a VaultSession) -> Element<'a, Message> {
        let query = self.search.to_lowercase();
        let entries: Vec<&EntryRecord> = session
            .entries()
            .iter()
            .filter(|entry| self.entry_visible(entry, &query))
            .collect();
        let count = entries.len();
        let columns = (0..5).map(|index| {
            table::column(
                container(text(HEADERS[index]).size(13))
                    .height(40)
                    .padding([10, 8]),
                move |entry: &'a EntryRecord| self.table_cell(entry, index),
            )
            .width(COLUMN_WIDTHS[index])
        });
        let grid = table::table(columns, entries).padding(0).separator(1);
        let direction = scrollable::Direction::Both {
            vertical: scrollable::Scrollbar::default(),
            horizontal: scrollable::Scrollbar::default(),
        };
        let mut body = column![
            row![
                text_input("搜索名称 / 网站 / 用户名", &self.search)
                    .id(self.search_id.clone())
                    .on_input(Message::SearchChanged)
                    .padding(10)
                    .width(Length::Fill),
                button("清空")
                    .on_press(Message::SearchChanged(String::new()))
                    .style(button::secondary)
                    .padding(10),
                button("添加").on_press(Message::NewEntry).padding(10),
            ]
            .spacing(10)
            .align_y(Alignment::Center),
            text(format!("显示 {count} 条 · 双击编辑 · 右键快捷操作")).size(12),
            scrollable(grid).direction(direction).height(Length::Fill),
        ]
        .spacing(12);
        if count == 0 {
            body = body.push(text("没有符合条件的条目。可点击“添加”或“导入”。").size(14));
        }
        if let Some(entry) = self.selected_entry()
            && self.entry_visible(entry, &query)
        {
            body = body.push(self.selection_actions(entry));
        }
        body.into()
    }

    fn selection_actions<'a>(&'a self, entry: &'a EntryRecord) -> Element<'a, Message> {
        let mut actions = column![
            row![
                button("复制账号")
                    .on_press(Message::CopyUsername)
                    .style(button::secondary),
                button("复制密码")
                    .on_press(Message::CopyPassword)
                    .style(button::secondary),
                button(if self.revealed.is_some() {
                    "隐藏密码"
                } else {
                    "显示密码"
                })
                .on_press(Message::ToggleReveal)
                .style(button::secondary),
                button("打开网页")
                    .on_press(Message::OpenWebsite)
                    .style(button::secondary),
            ]
            .spacing(8),
        ]
        .spacing(8);
        if entry.is_deleted() {
            actions = actions.push(
                row![
                    button("恢复条目").on_press(Message::RestoreSelected),
                    button("永久删除")
                        .on_press(Message::RequestPermanentDelete)
                        .style(button::danger)
                ]
                .spacing(8),
            );
        } else {
            actions = actions.push(
                row![
                    button("编辑条目").on_press(Message::EditSelected),
                    button(if entry.favorite {
                        "取消收藏"
                    } else {
                        "收藏条目"
                    })
                    .on_press(Message::ToggleSelectedFavorite)
                    .style(button::secondary),
                    button("移到回收站")
                        .on_press(Message::MoveSelectedToRecycleBin)
                        .style(button::danger),
                ]
                .spacing(8),
            );
        }
        if let Some(secret) = &self.revealed
            && secret.entry_id == entry.id
        {
            actions = actions.push(text(secret.value.as_str()).size(14));
        }
        actions.into()
    }

    fn context_view(&self) -> Element<'_, Message> {
        let mut content = column![text("条目快捷操作").size(18)]
            .spacing(12)
            .width(520);
        if let Some(entry) = self.selected_entry() {
            content = content.push(self.selection_actions(entry));
        }
        content
            .push(
                button("关闭菜单")
                    .on_press(Message::CloseContext)
                    .style(button::secondary),
            )
            .into()
    }

    fn workspace<'a>(
        &'a self,
        title: &'a str,
        content: impl Into<Element<'a, Message>>,
    ) -> Element<'a, Message> {
        column![
            row![
                text(title).size(24),
                Space::new().width(Length::Fill),
                button("返回列表")
                    .on_press(Message::CancelPanel)
                    .style(button::secondary)
            ]
            .align_y(Alignment::Center),
            scrollable(container(content).max_width(900).width(Length::Fill)).height(Length::Fill),
        ]
        .spacing(16)
        .into()
    }

    fn editor_view<'a>(&'a self, state: &'a EditorState) -> Element<'a, Message> {
        let form = column![
            field(
                "名称 *",
                "条目名称",
                &state.name,
                Message::EditorNameChanged
            ),
            field(
                "网站",
                "https://example.com",
                &state.website,
                Message::EditorWebsiteChanged
            ),
            field(
                "用户名",
                "账号 / 邮箱",
                &state.username,
                Message::EditorUsernameChanged
            ),
            text("密码 *").size(13),
            row![
                text_input("输入密码", &state.password)
                    .on_input(Message::EditorPasswordChanged)
                    .secure(!state.password_visible)
                    .padding(10),
                button(if state.password_visible {
                    "隐藏"
                } else {
                    "显示"
                })
                .on_press(Message::ToggleEditorPasswordVisible)
                .style(button::secondary)
            ]
            .spacing(8),
            button("生成 20 位随机密码")
                .on_press(Message::GeneratePassword)
                .style(button::secondary),
            field(
                "分类",
                "分类名称",
                &state.category,
                Message::EditorCategoryChanged
            ),
            text("备注（支持多行）").size(13),
            text_editor(&state.notes_editor)
                .on_action(Message::EditorNotesAction)
                .height(160)
                .padding(10),
            checkbox(state.favorite)
                .label("收藏此条目")
                .on_toggle(Message::EditorFavoriteChanged),
        ]
        .spacing(10);
        column![
            text(if state.id.is_some() {
                "编辑条目"
            } else {
                "添加条目"
            })
            .size(24),
            scrollable(card(form)).height(Length::Fill),
            row![
                button("保存条目").on_press(Message::SaveEditor).padding(10),
                button("取消编辑")
                    .on_press(Message::CancelPanel)
                    .style(button::secondary)
                    .padding(10)
            ]
            .spacing(10),
        ]
        .spacing(16)
        .into()
    }

    fn import_view<'a>(
        &'a self,
        session: &'a VaultSession,
        state: &'a ImportState,
    ) -> Element<'a, Message> {
        let mut form = column![
            text("支持 Chrome CSV、旧版 CSV、vault.enc 和 passwords.db。源文件只读。").size(13),
            field(
                "导入文件路径",
                "密码导出文件路径",
                &state.path,
                Message::ImportPathChanged
            ),
            secret_field(
                "旧主密码（仅旧版加密格式需要）",
                &state.legacy_password,
                Message::ImportLegacyPasswordChanged
            ),
            button("分析并预览")
                .on_press(Message::AnalyzeImport)
                .padding(10),
        ]
        .spacing(14);
        if let Some(preview) = &state.preview {
            let summary = preview.summary();
            form = form
                .push(text(format!(
                    "新增 {} · 重复 {} · 更新 {} · 冲突 {} · 本地已删除 {} · 无效 {}",
                    summary.new,
                    summary.exact_duplicates,
                    summary.update_candidates,
                    summary.conflicts,
                    summary.locally_deleted,
                    summary.invalid
                )))
                .push(
                    checkbox(state.apply_updates)
                        .label("应用更新候选（未本地修改的已导入条目）")
                        .on_toggle(Message::ImportApplyUpdatesChanged),
                );
            let mut unresolved = 0;
            for (index, row) in preview.rows.iter().enumerate() {
                match &row.class {
                    ImportClass::Conflict { existing_ids }
                    | ImportClass::LocallyDeleted { existing_ids } => {
                        let choice = state.resolutions.get(&index);
                        if choice.is_none() {
                            unresolved += 1;
                        }
                        let mut decision = column![
                            text(format!(
                                "{}：{} · {}",
                                if matches!(&row.class, ImportClass::LocallyDeleted { .. }) {
                                    "本地已删除"
                                } else {
                                    "冲突"
                                },
                                row.item.name,
                                row.item.username
                            )),
                            row![
                                button(if matches!(choice, Some(ConflictResolution::KeepLocal)) {
                                    "已选：保留本地"
                                } else {
                                    "保留本地"
                                })
                                .on_press(Message::SetImportResolution(
                                    index,
                                    ConflictResolution::KeepLocal
                                ))
                                .style(button::secondary),
                                button(if matches!(choice, Some(ConflictResolution::KeepBoth)) {
                                    "已选：两份都保留"
                                } else {
                                    "两份都保留"
                                })
                                .on_press(Message::SetImportResolution(
                                    index,
                                    ConflictResolution::KeepBoth
                                ))
                                .style(button::secondary),
                            ]
                            .spacing(8),
                        ]
                        .spacing(8);
                        for id in existing_ids {
                            if let Some(entry) = session.entry(*id) {
                                let selected = matches!(choice, Some(ConflictResolution::UseImported(selected)) if selected == id);
                                decision = decision.push(
                                    button(text(format!(
                                        "{}使用导入值覆盖 / 恢复：{}",
                                        if selected { "已选：" } else { "" },
                                        entry.name
                                    )))
                                    .on_press(Message::SetImportResolution(
                                        index,
                                        ConflictResolution::UseImported(*id),
                                    ))
                                    .style(button::secondary),
                                );
                            }
                        }
                        form = form.push(card(decision));
                    }
                    ImportClass::UpdateCandidate { .. } => {
                        form = form.push(text(format!("更新候选：{}", row.item.name)).size(13))
                    }
                    _ => {}
                }
            }
            form = form.push(
                button("执行导入")
                    .on_press_maybe((unresolved == 0).then_some(Message::ApplyImport))
                    .padding(10),
            );
            if unresolved > 0 {
                form = form.push(text(format!("还有 {unresolved} 项需要选择处理方式。")));
            }
        }
        self.workspace("导入密码", card(form))
    }

    fn settings_view<'a>(
        &'a self,
        session: &'a VaultSession,
        state: &'a SettingsState,
    ) -> Element<'a, Message> {
        let form = column![
            card(column![
                text("外观与安全").size(18),
                checkbox(self.dark_mode).label("深色模式（默认使用旧版浅色）").on_toggle(Message::DarkModeChanged),
                checkbox(self.screen_capture_protection_requested).label("启用 Windows 常规截图保护").on_toggle(Message::ScreenCaptureProtectionChanged),
                text(format!("截图保护：{} · 会话监控：{}", if self.screen_capture_protection_active { "已启用" } else { "未启用" }, if self.security_monitor_ready { "已就绪" } else { "未就绪" })).size(12),
                text("截图保护不保证阻止所有捕获方式。锁屏或挂起时自动锁定；剪贴板清理能力需实际验证。").size(12),
            ].spacing(12)),
            card(column![
                text("加密备份").size(18),
                field("备份目标路径", "新的 .pmvault 文件", &state.backup_path, Message::BackupPathChanged),
                button("创建加密备份").on_press(Message::CreateBackup),
                text("恢复并替换当前保险库").size(16),
                field("备份文件路径", "已有备份的完整路径", &state.restore_path, Message::RestorePathChanged),
                secret_field("备份的主密码", &state.restore_password, Message::RestorePasswordChanged),
                checkbox(state.confirm_restore).label("确认用备份替换当前保险库（不是合并导入）").on_toggle(Message::ConfirmRestoreChanged),
                button("恢复备份").on_press_maybe(state.confirm_restore.then_some(Message::RestoreBackup)).style(button::danger),
            ].spacing(12)),
            card(column![
                text("兼容导出：明文 CSV").size(18),
                field("导出路径", "新的 .csv 文件", &state.csv_path, Message::CsvPathChanged),
                checkbox(state.confirm_plaintext).label("我理解导出文件中的密码和备注没有加密").on_toggle(Message::ConfirmPlaintextChanged),
                button("导出明文 CSV").on_press_maybe(state.confirm_plaintext.then_some(Message::ExportPlaintextCsv)).style(button::danger),
            ].spacing(12)),
            text(format!("版本 {} · 条目 {} · Revision {}", env!("CARGO_PKG_VERSION"), session.active_entries().count(), session.revision())).size(12),
            text(format!("保险库：{}", session.path().display())).size(12),
        ].spacing(16);
        self.workspace("设置 / 导出 / 备份", form)
    }

    fn confirmation<'a>(
        &'a self,
        title: &'a str,
        explanation: &'a str,
        action: Message,
    ) -> Element<'a, Message> {
        self.workspace(
            title,
            card(
                column![
                    text(explanation),
                    row![
                        button("确认操作").on_press(action).style(button::danger),
                        button("取消")
                            .on_press(Message::CancelPanel)
                            .style(button::secondary)
                    ]
                    .spacing(10)
                ]
                .spacing(20),
            ),
        )
    }
}
