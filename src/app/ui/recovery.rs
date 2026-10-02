use super::*;
use iced::widget::column;
impl App {
    pub(super) fn recovery_view<'a>(
        &'a self,
        state: &'a crate::app::recovery::RecoveryState,
    ) -> Element<'a, Message> {
        let generation = state.generation;
        let mut copies = column![].spacing(8);
        for (index, copy) in state.listing.artifacts.iter().enumerate() {
            copies = copies.push(
                column![
                    text(&copy.role).size(12),
                    text(copy.path.display().to_string()).size(12),
                    button("选择此副本")
                        .on_press(Message::SelectRecoveryCopy(generation, index))
                        .style(button::secondary),
                ]
                .spacing(4),
            );
        }
        if state.listing.artifacts.is_empty() {
            copies = copies
                .push(text("未列出加密副本；可通过文件选择器或路径选择您保留的备份。").size(12));
        }
        let mut content = column![
            row![
                text("已锁定 · 恢复加密副本").size(24),
                Space::new().width(Length::Fill),
                button("返回解锁")
                    .on_press(Message::CloseRecovery(generation))
                    .style(button::secondary)
            ]
            .spacing(10),
            text(&state.listing.detail).size(13),
        ]
        .spacing(10);
        if self.clipboard_cleanup_failed {
            content = content.push(self.clipboard_warning());
        }
        if let Some(notice) = &self.recovery_notice {
            content = content.push(
                text(format!(
                    "阶段：{} · 当前文件观察：{}\n{}",
                    notice.stage,
                    notice.current,
                    notice.destination.display()
                ))
                .size(12),
            );
        }
        content = content.push(scrollable(copies).id("recovery-copies").height(110))
            .push(row![
                text_input("选择或输入加密源副本路径",&state.source).id("recovery-source").on_input(move |v| Message::RecoverySourceChanged(generation,v)).padding(8),
                button("选择恢复副本").on_press_maybe(self.picker_pending.is_none().then_some(Message::PickPath(picker::Purpose::RecoverySource))).style(button::secondary),
            ].spacing(8))
            .push(row![
                text_input("新的 .pmvault 文件位置（必须不存在）",&state.destination).id("recovery-destination").on_input(move |v| Message::RecoveryDestinationChanged(generation,v)).padding(8),
                button("选择新文件位置").on_press_maybe(self.picker_pending.is_none().then_some(Message::PickPath(picker::Purpose::RecoveryDestination))).style(button::secondary),
            ].spacing(8))
            .push(text_input("选定副本的主密码",&state.password).id("recovery-password").on_input(move |v| Message::RecoveryPasswordChanged(generation,v)).secure(true).padding(10))
            .push(text("此操作验证选定副本并只创建新文件。不会覆盖当前保险库，也不会删除任何恢复材料。").size(12))
            .push(button("验证并恢复到新文件").on_press_maybe((self.picker_pending.is_none() && (!cfg!(windows) || self.security_monitor_ready)).then_some(Message::RestoreRecoveryCopy(generation))).padding(10))
            .push(text(&self.status).size(12));
        container(scrollable(content).id("recovery-scroll"))
            .padding(24)
            .width(Length::Fill)
            .max_width(850)
            .max_height(600)
            .style(surface)
            .into()
    }
}
