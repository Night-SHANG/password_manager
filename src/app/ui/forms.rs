use iced::widget::column;

use super::*;

impl App {
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

    pub(super) fn editor_view<'a>(&'a self, state: &'a EditorState) -> Element<'a, Message> {
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
                secret_input::managed_password_input(
                    text_input("输入密码", &state.password)
                        .id("editor-password-input")
                        .on_input(Message::EditorPasswordChanged)
                        .secure(!state.password_visible)
                        .padding(10),
                    self.context_generation,
                    &state.password,
                    state.password_visible,
                ),
                button(if state.password_visible {
                    "隐藏"
                } else {
                    "显示"
                })
                .on_press(Message::ToggleEditorPasswordVisible(
                    self.context_generation
                ))
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

    pub(super) fn import_view<'a>(
        &'a self,
        session: &'a VaultSession,
        state: &'a ImportState,
    ) -> Element<'a, Message> {
        let mut form = column![
            text("支持 Chrome CSV、旧版 CSV、vault.enc 和 passwords.db。源文件只读。").size(13),
            self.path_field(
                "导入文件路径",
                "密码导出文件路径",
                &state.path,
                Message::ImportPathChanged,
                picker::Purpose::Import,
            ),
            secret_field(
                "旧主密码（仅旧版加密格式需要）",
                &state.legacy_password,
                Message::ImportLegacyPasswordChanged
            ),
            button("分析并预览")
                .on_press_maybe(
                    self.picker_pending
                        .is_none()
                        .then_some(Message::AnalyzeImport)
                )
                .padding(10),
        ]
        .spacing(14);
        if let Some(preview) = &state.preview {
            let summary = preview.summary();
            let preview_id = preview.id();
            form = form
                .push(text(format!(
                    "新增 {} · 已有重复 {} · 源内重复 {} · 更新 {} · 冲突 {} · 本地已删除 {} · 无效 {}",
                    summary.new,
                    summary.exact_duplicates,
                    summary.source_duplicates,
                    summary.update_candidates,
                    summary.conflicts,
                    summary.locally_deleted,
                    summary.invalid
                )))
                .push(
                    checkbox(state.apply_updates)
                        .label("应用更新候选（未本地修改的已导入条目）")
                        .on_toggle(move |value| Message::ImportApplyUpdatesChanged(preview_id, value)),
                );
            if summary.conflicts > 0 || summary.locally_deleted > 0 {
                form = form
                    .push(text("跳过只忽略当前来源行；其他行仍可能更新同一本地条目。").size(12));
            }
            let mut unresolved = 0;
            for (index, row) in preview.rows().iter().enumerate() {
                match row.class() {
                    ImportClass::Conflict { existing_ids }
                    | ImportClass::LocallyDeleted { existing_ids } => {
                        let choice = state.resolutions.get(&index);
                        if choice.is_none() {
                            unresolved += 1;
                        }
                        let mut decision = column![
                            text(format!(
                                "{}：{} · {}",
                                if matches!(row.class(), ImportClass::LocallyDeleted { .. }) {
                                    "本地已删除"
                                } else {
                                    "冲突"
                                },
                                row.item().name,
                                row.item().username
                            )),
                            row![
                                button(if matches!(choice, Some(ConflictResolution::KeepLocal)) {
                                    "已选：跳过此行"
                                } else {
                                    "跳过此行"
                                })
                                .on_press(Message::SetImportResolution(
                                    preview_id,
                                    index,
                                    ConflictResolution::KeepLocal
                                ))
                                .style(button::secondary),
                                button(if matches!(choice, Some(ConflictResolution::KeepBoth)) {
                                    "已选：导入为独立条目"
                                } else {
                                    "导入为独立条目"
                                })
                                .on_press(Message::SetImportResolution(
                                    preview_id,
                                    index,
                                    ConflictResolution::KeepBoth
                                ))
                                .style(button::secondary),
                            ]
                            .spacing(8),
                        ]
                        .spacing(8);
                        for id in existing_ids {
                            if let Some(entry) = session.entry(*id)
                                && preview
                                    .allows_resolution(index, &ConflictResolution::UseImported(*id))
                            {
                                let selected = matches!(choice, Some(ConflictResolution::UseImported(selected)) if selected == id);
                                decision = decision.push(
                                    button(text(format!(
                                        "{}使用导入值覆盖 / 恢复：{}",
                                        if selected { "已选：" } else { "" },
                                        entry.name
                                    )))
                                    .on_press(Message::SetImportResolution(
                                        preview_id,
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
                        form = form.push(text(format!("更新候选：{}", row.item().name)).size(13))
                    }
                    _ => {}
                }
            }
            form = form.push(
                button("执行导入")
                    .on_press_maybe(
                        (unresolved == 0 && self.picker_pending.is_none())
                            .then_some(Message::ApplyImport(preview_id)),
                    )
                    .padding(10),
            );
            if unresolved > 0 {
                form = form.push(text(format!("还有 {unresolved} 项需要选择处理方式。")));
            }
        }
        self.workspace("导入密码", card(form))
    }

    pub(super) fn settings_view<'a>(
        &'a self,
        session: &'a VaultSession,
        state: &'a SettingsState,
    ) -> Element<'a, Message> {
        let form = column![
            card(column![
                text("外观与安全").size(18),
                row![text("闲置自动锁定"), container(iced::widget::pick_list(&safety::IDLE_MINUTES[..], Some(self.idle_minutes), Message::IdleTimeoutChanged).width(100)).id("idle-timeout-setting"), text("分钟")].spacing(10).align_y(Alignment::Center),
                text("只计算本应用内的键盘、点击、滚动等操作；Windows 锁屏/睡眠锁定不可关闭，依赖系统监控就绪。").size(12),
                row![text("密码剪贴板清理"), container(iced::widget::pick_list(&safety::CLIPBOARD_SECONDS[..], Some(self.clipboard_seconds), Message::ClipboardTimeoutChanged).width(100)).id("clipboard-timeout-setting"), text("秒")].spacing(10).align_y(Alignment::Center),
                text("仅清理仍由本次复制持有的内容；失焦会重新遮罩密码，不自动整库锁定。").size(12),
                checkbox(self.dark_mode).label("深色模式（默认使用旧版浅色）").on_toggle(Message::DarkModeChanged),
                checkbox(self.screen_capture_protection_requested).label("启用 Windows 常规截图保护").on_toggle(Message::ScreenCaptureProtectionChanged),
                text(format!("截图保护：{} · 会话监控：{}", if self.screen_capture_protection_active { "已启用" } else { "未启用" }, if self.security_monitor_ready { "已就绪" } else { "未就绪" })).size(12),
                text("截图保护不保证阻止所有捕获方式。锁屏或挂起时自动锁定；剪贴板清理能力需实际验证。").size(12),
            ].spacing(12)),
            card(column![
                text("加密备份").size(18),
                self.path_field("备份目标路径", "新的 .pmvault 文件", &state.backup_path, Message::BackupPathChanged, picker::Purpose::Backup),
                button("创建加密备份").on_press_maybe(self.picker_pending.is_none().then_some(Message::CreateBackup)),
                text("恢复并替换当前保险库").size(16),
                self.path_field("备份文件路径", "已有备份的完整路径", &state.restore_path, Message::RestorePathChanged, picker::Purpose::Restore),
                secret_field("备份的主密码", &state.restore_password, Message::RestorePasswordChanged),
                checkbox(state.confirm_restore).label("确认用备份替换当前保险库（不是合并导入）").on_toggle(Message::ConfirmRestoreChanged),
                button("恢复备份").on_press_maybe((state.confirm_restore && self.picker_pending.is_none()).then_some(Message::RestoreBackup)).style(button::danger),
            ].spacing(12)),
            card(column![
                text("兼容导出：明文 CSV").size(18),
                self.path_field("导出路径", "新的 .csv 文件", &state.csv_path, Message::CsvPathChanged, picker::Purpose::Csv),
                checkbox(state.confirm_plaintext).label("我理解导出文件中的密码和备注没有加密").on_toggle(Message::ConfirmPlaintextChanged),
                button("导出明文 CSV").on_press_maybe((state.confirm_plaintext && self.picker_pending.is_none() && self.export_notice.is_none()).then_some(Message::ExportPlaintextCsv)).style(button::danger),
            ].spacing(12)),
            text(format!("版本 {} · 条目 {} · Revision {}", env!("CARGO_PKG_VERSION"), session.active_entries().count(), session.revision())).size(12),
            text(format!("保险库：{}", session.path().display())).size(12),
        ].spacing(16);
        self.workspace("设置 / 导出 / 备份", form)
    }

    pub(super) fn confirmation<'a>(
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
