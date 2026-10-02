use super::*;

impl App {
    pub(super) fn create_vault(&mut self) {
        if self.master_password != self.confirm_password {
            self.status = "两次输入的主密码不一致".to_string();
            return;
        }
        match VaultSession::create(self.vault_path.clone(), &self.master_password) {
            Ok(session) => {
                self.session = Some(session);
                self.clear_password_fields();
                self.reset_unlocked_state();
                self.status = "新保险库已创建并加密".to_string();
            }
            Err(error) => self.status = format!("创建失败：{error}"),
        }
    }

    pub(super) fn open_vault(&mut self) {
        match VaultSession::open(self.vault_path.clone(), &self.master_password) {
            Ok(session) => {
                self.session = Some(session);
                self.clear_password_fields();
                self.reset_unlocked_state();
                self.status = "保险库已解锁".to_string();
            }
            Err(error) => self.status = format!("无法解锁：{error}"),
        }
    }

    fn reset_unlocked_state(&mut self) {
        self.nav = NavFilter::All;
        self.selected = None;
        self.panel = Panel::Vault;
        self.close_context();
        self.search.clear();
        self.category_name.clear();
    }

    pub(super) fn clear_password_fields(&mut self) {
        self.master_password.zeroize();
        self.master_password.clear();
        self.confirm_password.zeroize();
        self.confirm_password.clear();
    }

    pub(super) fn lock_with_status(&mut self, status: &str) {
        let _ = platform::clear_armed_clipboard_now();
        self.session = None;
        self.reset_unlocked_state();
        self.clear_password_fields();
        self.creating = false;
        self.status = status.to_string();
    }

    pub(super) fn save_now(&mut self) {
        if matches!(&self.panel, Panel::Editor(_)) {
            self.save_editor();
        } else if let Some(session) = &self.session {
            self.status = match session.verify_current_file() {
                Ok(()) => "保险库已保存，磁盘文件校验通过".to_string(),
                Err(error) => format!("校验失败：{error}"),
            };
        }
    }

    pub(super) fn open_editor_for_selected(&mut self) {
        self.close_context();
        let Some(session) = &self.session else {
            return;
        };
        let Some(id) = self.selected else {
            return;
        };
        let Some(entry) = session.entry(id) else {
            return;
        };
        if entry.is_deleted() {
            return;
        }
        match session.reveal_secret(id) {
            Ok(secret) => {
                self.panel = Panel::Editor(EditorState {
                    id: Some(id),
                    name: entry.name.clone(),
                    website: entry.website.clone(),
                    username: entry.username.clone(),
                    password: secret.password.clone(),
                    notes: secret.notes.clone(),
                    notes_editor: text_editor::Content::with_text(&secret.notes),
                    category: entry.category.clone(),
                    favorite: entry.favorite,
                    password_visible: false,
                });
                self.revealed = None;
            }
            Err(error) => self.status = format!("无法编辑：{error}"),
        }
    }

    pub(super) fn save_editor(&mut self) {
        let Panel::Editor(state) = &self.panel else {
            return;
        };
        let id = state.id;
        let value = match draft(
            state.name.clone(),
            state.website.clone(),
            state.username.clone(),
            state.password.clone(),
            state.notes.clone(),
            state.category.clone(),
            state.favorite,
        ) {
            Ok(value) => value,
            Err(error) => {
                self.status = format!("无法保存：{error}");
                return;
            }
        };
        let result = self.mutate_and_save(|session| {
            if let Some(id) = id {
                session.update_entry(id, value)?;
                Ok(id)
            } else {
                session.add_entry(value)
            }
        });
        match result {
            Ok(id) => {
                self.selected = Some(id);
                self.panel = Panel::Vault;
                self.revealed = None;
                self.status = "条目已安全保存".to_string();
            }
            Err(error) => self.status = format!("保存失败：{error}"),
        }
    }

    pub(super) fn toggle_reveal(&mut self) {
        let Some(id) = self
            .selected
            .filter(|id| self.context_open && self.is_visible_workspace_target(*id))
        else {
            self.revealed = None;
            return;
        };
        if self
            .revealed
            .as_ref()
            .is_some_and(|value| value.entry_id == id)
        {
            self.revealed = None;
            return;
        }
        let Some(session) = &self.session else {
            return;
        };
        match session.reveal_secret(id) {
            Ok(secret) => {
                self.revealed = Some(RevealedPassword {
                    entry_id: id,
                    value: secret.password.clone(),
                })
            }
            Err(error) => self.status = format!("无法显示：{error}"),
        }
    }

    pub(super) fn open_selected_website(&mut self) {
        self.close_context();
        let Some(entry) = self.selected_entry() else {
            return;
        };
        let url = safe_web_url(&entry.website);
        self.status = match url {
            Ok(url) => match webbrowser::open(&url) {
                Ok(()) => "已请求系统浏览器打开网站".to_string(),
                Err(error) => format!("无法打开网站：{error}"),
            },
            Err(error) => format!("无法打开网站：{error}"),
        };
    }

    pub(super) fn toggle_selected_favorite(&mut self) {
        let Some((id, favorite)) = self.selected_entry().map(|e| (e.id, !e.favorite)) else {
            return;
        };
        self.close_context();
        self.status = match self.mutate_and_save(|session| session.set_favorite(id, favorite)) {
            Ok(()) => "收藏状态已保存".to_string(),
            Err(error) => format!("保存失败：{error}"),
        };
    }

    pub(super) fn recycle_selected(&mut self, restore: bool) {
        let Some(id) = self.selected else {
            return;
        };
        self.close_context();
        let result = self.mutate_and_save(|session| {
            if restore {
                session.restore_from_recycle_bin(id)
            } else {
                session.move_to_recycle_bin(id)
            }
        });
        match result {
            Ok(()) => {
                self.selected = None;
                self.revealed = None;
                self.status = if restore {
                    "条目已恢复"
                } else {
                    "条目已移到回收站"
                }
                .to_string();
            }
            Err(error) => self.status = format!("操作失败：{error}"),
        }
    }

    pub(super) fn delete_entry(&mut self, id: Uuid) {
        if !matches!(&self.panel, Panel::DeleteEntry(expected) if *expected == id) {
            return;
        }
        match self.mutate_and_save(|session| session.permanently_delete(id)) {
            Ok(()) => {
                self.selected = None;
                self.revealed = None;
                self.panel = Panel::Vault;
                self.status = "条目已永久删除；已有备份不受影响".to_string();
            }
            Err(error) => self.status = format!("永久删除失败：{error}"),
        }
    }

    pub(super) fn add_category(&mut self) {
        let name = self.category_name.trim().to_string();
        if name.is_empty() || ["全部", "收藏", "回收站"].contains(&name.as_str()) {
            self.status = "请输入有效且不与系统分组重复的分类名称".to_string();
            return;
        }
        let result = self.mutate_and_save(|session| {
            if session.categories().contains(&name) {
                return Err(AppError::Input("分类已存在".to_string()));
            }
            session.body_mut().categories.push(name.clone());
            Ok(())
        });
        self.status = match result {
            Ok(()) => {
                self.category_name.clear();
                "分类已创建".to_string()
            }
            Err(error) => format!("分类创建失败：{error}"),
        };
    }

    pub(super) fn move_category(&mut self, name: &str, up: bool) {
        self.status = match self.mutate_and_save(|session| {
            let categories = &mut session.body_mut().categories;
            let index = categories
                .iter()
                .position(|c| c == name)
                .ok_or_else(|| AppError::Input("分类不存在".to_string()))?;
            let target = if up {
                index.saturating_sub(1)
            } else {
                (index + 1).min(categories.len() - 1)
            };
            categories.swap(index, target);
            Ok(())
        }) {
            Ok(()) => "分类顺序已保存".to_string(),
            Err(error) => format!("排序失败：{error}"),
        };
    }

    pub(super) fn delete_category(&mut self, name: &str) {
        if name == "其他"
            || !matches!(&self.panel, Panel::DeleteCategory(expected) if expected == name)
        {
            return;
        }
        let result = self.mutate_and_save(|session| {
            let body = session.body_mut();
            if !body.categories.iter().any(|c| c == "其他") {
                body.categories.push("其他".to_string());
            }
            for entry in &mut body.entries {
                if entry.category == name {
                    entry.category = "其他".to_string();
                    entry.updated_at_unix = now_unix();
                }
            }
            body.categories.retain(|c| c != name);
            Ok(())
        });
        match result {
            Ok(()) => {
                self.panel = Panel::Vault;
                self.nav = NavFilter::All;
                self.status = "分类已删除，条目已移到“其他”".to_string();
            }
            Err(error) => self.status = format!("分类删除失败：{error}"),
        }
    }

    pub(super) fn analyze_import(&mut self) {
        let Panel::Import(state) = &mut self.panel else {
            return;
        };
        let Some(session) = &self.session else {
            return;
        };
        let password =
            (!state.legacy_password.is_empty()).then_some(state.legacy_password.as_str());
        let result = stage_path(Path::new(&state.path), password)
            .and_then(|batch| build_preview(session, batch));
        state.legacy_password.zeroize();
        state.legacy_password.clear();
        state.resolutions.clear();
        match result {
            Ok(preview) => {
                state.preview = Some(preview);
                self.status = "分析完成；尚未写入保险库，请先检查预览".to_string();
            }
            Err(error) => {
                state.preview = None;
                self.status = format!("导入分析失败：{error}");
            }
        }
    }

    pub(super) fn apply_import(&mut self) {
        let Some(session) = &mut self.session else {
            return;
        };
        let Panel::Import(state) = &mut self.panel else {
            return;
        };
        let Some(preview) = &state.preview else {
            return;
        };
        if preview.rows.iter().enumerate().any(|(i, row)| {
            matches!(
                &row.class,
                ImportClass::Conflict { .. } | ImportClass::LocallyDeleted { .. }
            ) && !state.resolutions.contains_key(&i)
        }) {
            self.status = "请先为全部冲突和本地删除条目选择处理方式".to_string();
            return;
        }
        let options = ImportApplyOptions {
            apply_update_candidates: state.apply_updates,
            conflict_resolutions: state.resolutions.clone(),
        };
        match apply_preview(session, preview, &options) {
            Ok(report) => {
                self.status = format!(
                    "已导入：新增 {}，更新 {}，跳过 {}，无效 {}，延后更新 {}。再次操作请重新分析源文件。",
                    report.added,
                    report.updated,
                    report.skipped,
                    report.invalid,
                    report.updates_deferred
                );
                // Never offer a stale preview for a second application after mutation.
                state.preview = None;
                state.resolutions.clear();
            }
            Err(error) => self.status = format!("导入失败：{error}"),
        }
    }

    pub(super) fn create_backup(&mut self) {
        let (Some(session), Panel::Settings(state)) = (&self.session, &self.panel) else {
            return;
        };
        self.status = match session.export_encrypted_backup(Path::new(&state.backup_path)) {
            Ok(()) => "加密备份已创建".to_string(),
            Err(error) => format!("备份失败：{error}"),
        };
    }

    pub(super) fn restore_backup(&mut self) {
        let (Some(session), Panel::Settings(state)) = (&self.session, &mut self.panel) else {
            return;
        };
        if !state.confirm_restore {
            self.status = "请先确认替换当前保险库".to_string();
            return;
        }
        let destination = session.path().to_path_buf();
        let result = VaultSession::restore_encrypted_backup(
            Path::new(&state.restore_path),
            &destination,
            &state.restore_password,
            true,
        )
        .and_then(|()| VaultSession::open(destination.clone(), &state.restore_password));
        state.restore_password.zeroize();
        state.restore_password.clear();
        match result {
            Ok(session) => {
                self.session = Some(session);
                self.vault_path = destination.display().to_string();
                self.reset_unlocked_state();
                self.status = "加密备份已恢复".to_string();
            }
            Err(error) => {
                self.status = format!("恢复失败：{error}");
            }
        }
    }

    pub(super) fn export_plaintext(&mut self) {
        let (Some(session), Panel::Settings(state)) = (&self.session, &self.panel) else {
            return;
        };
        if !state.confirm_plaintext {
            self.status = "请先确认明文 CSV 的风险".to_string();
            return;
        }
        self.status = match export_plaintext_csv(
            session,
            Path::new(&state.csv_path),
            PlaintextExportAcknowledgement::user_confirmed_risk(),
        ) {
            Ok(count) => format!("已导出 {count} 条到明文 CSV，请妥善保护导出文件"),
            Err(error) => format!("导出失败：{error}"),
        };
    }

    pub(super) fn close_context(&mut self) {
        self.context_open = false;
        self.context_generation = self.context_generation.wrapping_add(1);
        self.revealed = None;
    }

    pub(super) fn is_visible_workspace_target(&self, id: Uuid) -> bool {
        matches!(&self.panel, Panel::Vault)
            && self
                .session
                .as_ref()
                .and_then(|session| session.entry(id))
                .is_some_and(|entry| self.entry_visible(entry, &self.search.to_lowercase()))
    }

    pub(super) fn selected_entry(&self) -> Option<&EntryRecord> {
        self.session.as_ref()?.entry(self.selected?)
    }

    pub(super) fn entry_visible(&self, entry: &EntryRecord, query: &str) -> bool {
        let nav = match &self.nav {
            NavFilter::All => !entry.is_deleted(),
            NavFilter::Favorites => entry.favorite && !entry.is_deleted(),
            NavFilter::RecycleBin => entry.is_deleted(),
            NavFilter::Category(name) => !entry.is_deleted() && &entry.category == name,
        };
        nav && (query.is_empty()
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
        match mutation(session).and_then(|value| session.save().map(|()| value)) {
            Ok(value) => Ok(value),
            Err(error) => {
                session.restore_body(snapshot);
                Err(error)
            }
        }
    }
}
