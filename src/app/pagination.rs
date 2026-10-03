//! Bounded navigation over complete worker-prepared metadata.
use super::*;
#[derive(Debug, Clone, Copy)]
pub(super) enum PageTarget {
    Primary,
    Categories,
    Candidates,
    DecisionFocus,
}
fn last(count: usize, size: usize) -> usize {
    count.saturating_sub(1) / size
}
fn shifted(page: usize, forward: bool, maximum: usize) -> usize {
    if forward {
        page.saturating_add(1).min(maximum)
    } else {
        page.saturating_sub(1).min(maximum)
    }
}
impl App {
    pub(super) fn clamp_view_pages(&mut self) {
        let count = match (&self.session, &self.view_index) {
            (Some(_), Some(index)) => self
                .filtered_entries
                .as_ref()
                .map_or_else(|| index.positions(&self.nav).len(), Vec::len),
            (Some(session), None) => session
                .entries()
                .iter()
                .filter(|entry| self.entry_visible(entry, &self.search.to_lowercase()))
                .count(),
            _ => 0,
        };
        self.card_page = self.card_page.min(last(count, ui::CARD_PAGE_SIZE));
        self.category_page = self.category_page.min(last(
            self.session.as_ref().map_or(0, |s| s.categories().len()),
            ui::CATEGORY_PAGE_SIZE,
        ));
        if let Panel::Import(state) = &mut self.panel {
            self.import_page = self.import_page.min(last(
                state.preview.as_ref().map_or(0, |p| p.display_rows().len()),
                ui::IMPORT_PAGE_SIZE,
            ));
        } else {
            self.import_page = 0;
        }
        if self
            .selected
            .is_some_and(|id| !self.is_visible_workspace_target(id))
            && matches!(self.panel, Panel::Vault)
        {
            self.selected = None;
            self.close_context();
        }
    }
    fn candidate_rows_on_page(&self) -> Vec<usize> {
        let Panel::Import(state) = &self.panel else {
            return Vec::new();
        };
        let Some(preview) = &state.preview else {
            return Vec::new();
        };
        let rows = preview.display_rows();
        let page = self.import_page.min(last(rows.len(), ui::IMPORT_PAGE_SIZE));
        let start = page * ui::IMPORT_PAGE_SIZE;
        rows[start..start.saturating_add(ui::IMPORT_PAGE_SIZE).min(rows.len())]
            .iter()
            .copied()
            .filter(|&index| {
                matches!(
                    preview.rows()[index].class(),
                    ImportClass::Conflict { .. } | ImportClass::LocallyDeleted { .. }
                )
            })
            .collect()
    }
    pub(super) fn focused_candidate_row(&self) -> Option<usize> {
        let rows = self.candidate_rows_on_page();
        let Panel::Import(state) = &self.panel else {
            return None;
        };
        state
            .candidate_focus
            .filter(|id| rows.contains(id))
            .or_else(|| rows.first().copied())
    }
    pub(super) fn navigate_page(&mut self, target: PageTarget, forward: bool) {
        if self.operation_busy() || self.session.is_none() {
            return;
        }
        match target {
            PageTarget::Primary if matches!(self.panel, Panel::Vault) => {
                let count = self.filtered_entries.as_ref().map_or_else(
                    || {
                        self.view_index
                            .as_ref()
                            .map_or(0, |i| i.positions(&self.nav).len())
                    },
                    Vec::len,
                );
                self.card_page = shifted(self.card_page, forward, last(count, ui::CARD_PAGE_SIZE));
                self.close_context();
                self.selected = None;
            }
            PageTarget::Primary => {
                if let Panel::Import(state) = &mut self.panel
                    && let Some(preview) = &state.preview
                {
                    self.import_page = shifted(
                        self.import_page,
                        forward,
                        last(preview.display_rows().len(), ui::IMPORT_PAGE_SIZE),
                    );
                    state.candidate_focus = None;
                }
            }
            PageTarget::Categories => {
                let count = self.session.as_ref().map_or(0, |s| s.categories().len());
                self.category_page = shifted(
                    self.category_page,
                    forward,
                    last(count, ui::CATEGORY_PAGE_SIZE),
                );
            }
            PageTarget::Candidates => {
                let Some(row) = self.focused_candidate_row() else {
                    return;
                };
                if let Panel::Import(state) = &mut self.panel
                    && let Some(preview) = &state.preview
                {
                    let count = preview.rows()[row].resolution_candidate_ids().len();
                    let page = state.candidate_pages.entry(row).or_default();
                    *page = shifted(*page, forward, last(count, ui::CANDIDATE_PAGE_SIZE));
                    state.candidate_focus = Some(row);
                }
            }
            PageTarget::DecisionFocus => {
                let rows = self.candidate_rows_on_page();
                if rows.is_empty() {
                    return;
                }
                let current = self
                    .focused_candidate_row()
                    .and_then(|id| rows.iter().position(|candidate| *candidate == id))
                    .unwrap_or(0);
                let next = shifted(current, forward, rows.len() - 1);
                if let Panel::Import(state) = &mut self.panel {
                    state.candidate_focus = Some(rows[next]);
                }
            }
        }
    }
}
