use super::*;

impl App {
    pub(super) fn create_vault(&mut self) {
        self.start_auth(true);
    }

    pub(super) fn open_vault(&mut self) {
        self.start_auth(false);
    }

    pub(super) fn note_clipboard_cleanup_failure(&mut self) {
        self.close_context();
        if let Panel::Editor(editor) = &mut self.panel {
            editor.password_visible = false;
        }
        self.clipboard_cleanup_failed = true;
        self.clipboard_warning_generation = self.clipboard_warning_generation.wrapping_add(1);
    }

    pub(super) fn revoke_clipboard_session(&mut self) -> bool {
        self.pending_editor_cut = None;
        self.clipboard_request = self.clipboard_request.wrapping_add(1);
        let success = self
            .clipboard_session
            .take()
            .is_none_or(|permit| platform::revoke_and_clear_clipboard(&permit).is_ok());
        if !success {
            self.note_clipboard_cleanup_failure();
        }
        success
    }

    #[cfg(test)]
    pub(super) fn reset_unlocked_state(&mut self) -> bool {
        self.dismiss_recovery();
        let clipboard_ok = self.revoke_clipboard_session();
        if self.session.is_some() {
            self.clipboard_session = Some(platform::begin_clipboard_session());
        }
        self.last_activity = std::time::Instant::now();
        #[cfg(test)]
        if let Some(session) = &self.session {
            self.operations.authority.activate_session(
                session.operation_binding(),
                self.last_activity
                    + std::time::Duration::from_secs(u64::from(self.idle_minutes) * 60),
            );
            self.operations.session = operations::SessionUi::Present;
            self.view_index = Some(view_index::ViewIndex::build(session));
            self.filtered_entries = None;
        }

        self.invalidate_picker();
        self.card_page = 0;
        self.category_page = 0;
        self.import_page = 0;
        self.nav = NavFilter::All;
        self.selected = None;
        self.panel = Panel::Vault;
        self.close_context();
        self.search.clear();
        self.category_name.clear();
        clipboard_ok
    }

    pub(super) fn clear_password_fields(&mut self) {
        self.master_password.zeroize();
        self.master_password.clear();
        self.confirm_password.zeroize();
        self.confirm_password.clear();
    }

    pub(super) fn lock_with_status(&mut self, status: &str) {
        self.mask_for_operation_lock(status, true);
    }

    pub(super) fn save_now(&mut self) {
        if matches!(self.panel, Panel::Editor(_)) {
            self.save_editor();
        } else {
            self.start_verify();
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
        if self.operation_busy() {
            return;
        }
        let Panel::Editor(state) = &mut self.panel else {
            return;
        };
        let id = state.id;
        let draft = crate::domain::EntryDraft {
            name: std::mem::take(&mut state.name),
            website: std::mem::take(&mut state.website),
            username: std::mem::take(&mut state.username),
            category: std::mem::take(&mut state.category),
            favorite: state.favorite,
            secret: crate::domain::SecretPayload::new(
                std::mem::take(&mut state.password),
                std::mem::take(&mut state.notes),
            ),
            provenance: None,
        };
        self.start_mutation(
            crate::operations::VaultMutation::Upsert {
                id,
                draft: Box::new(draft),
            },
            "条目已安全保存",
        );
    }

    pub(super) fn toggle_reveal(&mut self) {
        if !self.window_focused {
            self.revealed = None;
            return;
        }
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
        self.start_mutation(
            crate::operations::VaultMutation::Favorite(id, favorite),
            "收藏状态已保存",
        );
    }

    pub(super) fn recycle_selected(&mut self, restore: bool) {
        let Some(id) = self.selected else {
            return;
        };
        self.close_context();
        self.start_mutation(
            if restore {
                crate::operations::VaultMutation::RestoreEntry(id)
            } else {
                crate::operations::VaultMutation::Recycle(id)
            },
            if restore {
                "条目已恢复"
            } else {
                "条目已移到回收站"
            },
        );
    }

    pub(super) fn delete_entry(&mut self, id: Uuid) {
        if !matches!(&self.panel,Panel::DeleteEntry(expected) if *expected==id) {
            return;
        }
        self.start_mutation(
            crate::operations::VaultMutation::DeleteEntry(id),
            "条目已永久删除；已有备份不受影响",
        );
    }

    pub(super) fn add_category(&mut self) {
        let name = std::mem::take(&mut self.category_name);
        self.start_mutation(
            crate::operations::VaultMutation::AddCategory(name),
            "分类已创建",
        );
    }

    pub(super) fn move_category(&mut self, name: &str, up: bool) {
        self.start_mutation(
            crate::operations::VaultMutation::MoveCategory(name.into(), up),
            "分类顺序已保存",
        );
    }

    pub(super) fn delete_category(&mut self, name: &str) {
        if name == "其他"
            || !matches!(&self.panel,Panel::DeleteCategory(expected) if expected==name)
        {
            return;
        }
        self.start_mutation(
            crate::operations::VaultMutation::DeleteCategory(name.into()),
            "分类已删除，条目已移到“其他”",
        );
    }

    pub(super) fn analyze_import(&mut self) {
        self.start_import_analysis();
    }

    pub(super) fn apply_import(&mut self, id: Uuid) {
        self.start_import_application(id);
    }

    pub(super) fn create_backup(&mut self) {
        self.start_backup();
    }

    pub(super) fn restore_backup(&mut self) {
        self.start_restore_current();
    }

    pub(super) fn export_plaintext(&mut self) {
        self.start_export();
    }

    pub(super) fn close_context(&mut self) {
        self.pending_editor_cut = None;
        self.context_open = false;
        self.context_generation = self.context_generation.wrapping_add(1);
        self.revealed = None;
    }

    pub(super) fn is_visible_workspace_target(&self, id: Uuid) -> bool {
        matches!(&self.panel, Panel::Vault) && self.card_target_visible(id)
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
}
