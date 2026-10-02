use super::*;
use crate::export::{ObservedTarget, OutputDisposition};
use iced::widget::column;

impl App {
    fn export_warning(&self, closing: bool) -> Element<'_, Message> {
        let Some(notice) = &self.export_notice else {
            return Space::new().height(0).into();
        };
        let failure = &notice.failure;
        let mut body = column![
            text("导出未确认成功。此操作没有删除输出；可能留下空文件、部分或完整的明文 CSV。")
                .size(13)
                .wrapping(text::Wrapping::WordOrGlyph),
            text("尝试导出的位置：").size(13),
            container(
                text(failure.target.display().to_string())
                    .size(14)
                    .wrapping(text::Wrapping::WordOrGlyph)
                    .width(Length::Fill)
            )
            .id("export-notice-path")
            .width(Length::Fill),
            text(format!("失败阶段：{:?} · {}", failure.stage, failure.cause))
                .size(12)
                .wrapping(text::Wrapping::WordOrGlyph),
        ]
        .spacing(7)
        .width(Length::Fill);
        if matches!(failure.output, OutputDisposition::MayRemain { observation } if observation.target != ObservedTarget::SameOwnedFileAtTarget)
        {
            body = body.push(text("原输出可能已被移动或路径已被替换，当前路径不能证明是本次创建的文件。请自行核对并妥善保护可能残留的明文。").size(13).wrapping(text::Wrapping::WordOrGlyph));
        }
        if let OutputDisposition::MayRemain { observation } = failure.output
            && let Some(error) = observation.error
        {
            body = body.push(text(format!("路径观察未完成：{error}")).size(12));
        }
        if closing {
            body = body.push(
                text("强制终止或重启后不会保留此提示。退出不会清理可能残留的明文文件。").size(13),
            );
        }
        let controls: Element<'_, Message> =
            if let Some(prompt) = self.export_close_prompt.filter(|_| closing) {
                row![
                    button("保持打开")
                        .on_press(Message::KeepOpen(prompt.request))
                        .style(button::secondary),
                    button("我理解明文可能残留，仍然退出")
                        .on_press(Message::ConfirmExportExit(
                            prompt.request,
                            notice.generation
                        ))
                        .style(button::danger),
                ]
                .spacing(12)
                .into()
            } else {
                button("我已了解并会处理可能残留的明文")
                    .on_press(Message::AcknowledgeExportNotice(notice.generation))
                    .style(button::danger)
                    .into()
            };
        container(
            column![
                text("明文导出未完成，文件可能仍然存在")
                    .size(18)
                    .wrapping(text::Wrapping::WordOrGlyph),
                scrollable(body.padding(iced::Padding::ZERO.right(14).bottom(8)))
                    .id("export-notice-scroll")
                    .height(if closing { 260 } else { 115 }),
                controls,
            ]
            .spacing(10)
            .width(Length::Fill),
        )
        .padding(14)
        .width(Length::Fill)
        .style(|theme: &Theme| {
            let mut style = surface(theme);
            style.border.color = theme.palette().danger;
            style.border.width = 2.0;
            style
        })
        .into()
    }

    pub(in crate::app) fn view(&self) -> Element<'_, Message> {
        if self.export_close_prompt.is_some() {
            return container(
                column![self.export_warning(true), self.clipboard_warning()]
                    .spacing(12)
                    .width(850),
            )
            .padding(24)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into();
        }
        if self.export_notice.is_some() {
            column![
                container(self.export_warning(false)).padding(iced::Padding::new(12.0).bottom(0)),
                container(self.workspace_view())
                    .height(Length::Fill)
                    .width(Length::Fill),
            ]
            .height(Length::Fill)
            .width(Length::Fill)
            .into()
        } else {
            self.workspace_view()
        }
    }
}
