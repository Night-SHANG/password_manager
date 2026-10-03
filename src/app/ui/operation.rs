use super::*;
use iced::widget::column;
impl App {
    pub(in crate::app) fn operation_view(&self) -> Element<'_, Message> {
        let snapshot = self
            .operations
            .authority
            .snapshot(std::time::Instant::now());
        let masking =
            snapshot.masked || matches!(self.operations.session, operations::SessionUi::Locking);
        let title = if self.operations.close_window.is_some() {
            "正在安全退出"
        } else if masking {
            "已遮蔽，正在完成锁定"
        } else {
            "正在后台处理"
        };
        let phase = match snapshot.phase {
            Some(crate::operations::Phase::Preparing) => "读取、验证或计算中…",
            Some(crate::operations::Phase::Ready) => "准备完成，等待写入授权…",
            Some(crate::operations::Phase::Committing) => "已开始写入，正在完成保存与验证…",
            Some(crate::operations::Phase::Finished | crate::operations::Phase::Draining) => {
                "处理结束，正在释放所持材料…"
            }
            None => "正在完成界面与材料清理…",
        };
        let mut content=column![text(title).size(24),text(phase).size(15),text(&self.status).wrapping(text::Wrapping::WordOrGlyph),text("取消不会立即中断密码计算或正在进行的系统调用。已开始的写入会先完成验证，之后才会确认锁定。").size(13).wrapping(text::Wrapping::WordOrGlyph)].spacing(16);
        if let Some(progress) = snapshot.progress {
            let label = match progress.phase {
                crate::operations::WorkPhase::Reading => "读取中",
                crate::operations::WorkPhase::ReadingEntries => "检查已有条目",
                crate::operations::WorkPhase::Deriving => "计算密码密钥（进度不确定）",
                crate::operations::WorkPhase::Analyzing => "分析导入行",
                crate::operations::WorkPhase::PreparingSave => "准备保存",
                crate::operations::WorkPhase::Publishing => "保存与验证",
                crate::operations::WorkPhase::Cleaning => "释放材料",
            };
            content = content.push(
                text(if let Some(total) = progress.total {
                    format!("{label}：{} / {total}", progress.completed)
                } else {
                    label.into()
                })
                .size(13),
            );
        }
        if !masking {
            content = content.push(
                row![
                    button("取消操作").on_press(Message::CancelPanel),
                    button("立即遮蔽并锁定").on_press(Message::Lock)
                ]
                .spacing(12),
            );
        }
        if let Some(warning) = &self.operations.failure_notice {
            content = content.push(text(warning).wrapping(text::Wrapping::WordOrGlyph));
        }
        content = content.push(self.clipboard_warning());
        container(card(content))
            .max_width(850)
            .padding(24)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into()
    }
}
