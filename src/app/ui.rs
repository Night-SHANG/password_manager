use iced::widget::{
    Space, button, checkbox, column, container, mouse_area, opaque, row, scrollable, stack, text,
    text_input, tooltip,
};
use iced::{Alignment, Color};

use super::*;

mod forms;

#[cfg(test)]
mod long_text_tests;

const SIDEBAR_WIDTH: f32 = 250.0;
const CARD_WIDTH: f32 = 272.0;

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

fn surface(theme: &Theme) -> container::Style {
    let dark = matches!(theme, Theme::Dark);
    container::Style {
        background: Some(
            if dark {
                theme.extended_palette().background.weak.color
            } else {
                Color::WHITE
            }
            .into(),
        ),
        text_color: Some(theme.palette().text),
        border: iced::Border {
            color: if dark {
                theme.extended_palette().background.strong.color
            } else {
                Color::from_rgb8(225, 229, 235)
            },
            width: 1.0,
            radius: 12.0.into(),
        },
        ..container::Style::default()
    }
}

fn card<'a>(content: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    container(content)
        .padding(22)
        .width(Length::Fill)
        .style(surface)
        .into()
}

fn divider<'a>() -> Element<'a, Message> {
    container(Space::new().height(1))
        .width(Length::Fill)
        .style(|theme: &Theme| container::Style {
            background: Some(theme.extended_palette().background.strong.color.into()),
            ..container::Style::default()
        })
        .into()
}

fn card_button<'a>(label: &'a str, id: String, message: Message) -> Element<'a, Message> {
    container(
        button(text(label).size(12))
            .on_press(message)
            .style(button::secondary)
            .padding([8, 6])
            .width(72),
    )
    .id(id)
    .into()
}

fn card_line<'a>(label: &'a str, value: &'a str) -> Element<'a, Message> {
    row![
        text(label).size(13).width(42),
        container(text(value).size(13).wrapping(text::Wrapping::None))
            .width(Length::Fill)
            .clip(true),
    ]
    .align_y(Alignment::Center)
    .height(24)
    .into()
}

// Only borrowed, already-unlocked metadata is passed here. Passwords and notes
// never enter a hover widget. Very long values have a scrollable context view.
fn metadata_hint<'a>(
    content: impl Into<Element<'a, Message>>,
    value: &'a str,
) -> Element<'a, Message> {
    tooltip(
        content,
        column![
            container(
                text(value)
                    .size(13)
                    .wrapping(text::Wrapping::WordOrGlyph)
                    .width(Length::Fill)
            )
            .max_height(160)
            .clip(true),
            text("右键打开条目操作，滚动查看完整内容").size(11),
        ]
        .spacing(8)
        .width(340),
        tooltip::Position::Bottom,
    )
    .gap(6)
    .padding(12)
    .delay(std::time::Duration::from_millis(350))
    .snap_within_viewport(true)
    .style(surface)
    .into()
}

fn metadata_details(entry: &EntryRecord) -> Element<'_, Message> {
    let mut fields = column![].spacing(12).width(Length::Fill);
    for (id, label, value) in [
        ("name", "名称", entry.name.as_str()),
        ("username", "账号", entry.username.as_str()),
        ("website", "网址", entry.website.as_str()),
        ("category", "分类", entry.category.as_str()),
    ] {
        fields = fields.push(
            container(
                column![
                    text(label).size(12),
                    text(value)
                        .size(14)
                        .wrapping(text::Wrapping::WordOrGlyph)
                        .width(Length::Fill),
                ]
                .spacing(4)
                .width(Length::Fill),
            )
            .id(format!("context-{id}"))
            .width(Length::Fill),
        );
    }
    fields.into()
}

impl App {
    pub(super) fn view(&self) -> Element<'_, Message> {
        let Some(session) = &self.session else {
            return self.locked_view();
        };
        let content = match &self.panel {
            Panel::Vault => self.cards_view(session),
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
        let base: Element<'_, Message> = row![
            self.sidebar_view(session),
            column![
                container(content)
                    .padding(24)
                    .width(Length::Fill)
                    .height(Length::Fill),
                container(text(&self.status).size(12))
                    .padding([8, 24])
                    .width(Length::Fill),
            ]
            .width(Length::Fill)
            .height(Length::Fill),
        ]
        .width(Length::Fill)
        .height(Length::Fill)
        .into();
        if self.context_open && matches!(&self.panel, Panel::Vault) {
            stack![
                base,
                opaque(
                    container(
                        container(self.context_view())
                            .id("context-panel")
                            .padding(24)
                            .width(560)
                            .height(520)
                            .style(surface)
                    )
                    .padding(24)
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
            text("🔐")
                .size(if self.creating { 32 } else { 56 })
                .width(Length::Fill)
                .align_x(Alignment::Center),
            text(if self.creating {
                "创建密码库"
            } else {
                "解锁密码库"
            })
            .size(25)
            .width(Length::Fill)
            .align_x(Alignment::Center),
            text(if self.creating {
                "设置主密码以保护本地数据"
            } else {
                "请输入主密码以解密数据"
            })
            .size(13)
            .width(Length::Fill)
            .align_x(Alignment::Center),
            text_input("输入主密码", &self.master_password)
                .on_input(Message::MasterPasswordChanged)
                .on_submit(submit.clone())
                .secure(true)
                .padding(14)
                .size(16),
        ]
        .spacing(if self.creating { 10 } else { 16 });
        if self.creating {
            form = form.push(secret_field(
                "确认主密码",
                &self.confirm_password,
                Message::ConfirmPasswordChanged,
            ));
        }
        if self.creating || self.auth_options_open {
            form = form.push(field(
                "保险库文件路径",
                "例如 D:\\Passwords\\main.pmvault",
                &self.vault_path,
                Message::VaultPathChanged,
            ));
        }
        form = form
            .push(
                button(text(if self.creating {
                    "创建并进入"
                } else {
                    "解 锁"
                }))
                .on_press(submit)
                .padding(14)
                .width(Length::Fill),
            )
            .push(
                row![
                    button("打开保险库")
                        .on_press(Message::AuthMode(false))
                        .style(button::text),
                    button("创建新保险库")
                        .on_press(Message::AuthMode(true))
                        .style(button::text),
                ]
                .spacing(8),
            );
        if !self.creating {
            form = form.push(
                button(if self.auth_options_open {
                    "收起文件位置"
                } else {
                    "更换保险库文件"
                })
                .on_press(Message::ToggleAuthOptions)
                .style(button::text),
            );
        }
        form = form.push(text("本地加密 · 测试版本，请勿作为唯一密码副本").size(11));
        if !self.status.is_empty() {
            form = form.push(text(&self.status).size(12));
        }
        // Bound the card first, then center it in the full viewport. Only its
        // contents scroll on smaller windows; no unbounded horizontal layout.
        let auth = container(scrollable(form).height(Length::Shrink))
            .id("auth-card")
            .width(400)
            .max_height(580)
            .padding(if self.creating { 24 } else { 32 })
            .style(|theme: &Theme| {
                let mut style = surface(theme);
                style.shadow = iced::Shadow {
                    color: Color::from_rgba(0.0, 0.0, 0.0, 0.16),
                    offset: iced::Vector::new(0.0, 16.0),
                    blur_radius: 30.0,
                };
                style
            });
        container(auth)
            .padding(24)
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
                text("📁").size(13),
                container(text(title).size(13).wrapping(text::Wrapping::None))
                    .width(Length::Fill)
                    .clip(true),
                text(count.to_string()).size(12),
            ]
            .spacing(10)
            .align_y(Alignment::Center),
        )
        .on_press_maybe(enabled.then_some(Message::SetNav(nav)))
        .padding([10, 12])
        .width(Length::Fill)
        .style(move |theme: &Theme, status| {
            let mut style = button::text(theme, status);
            if selected {
                let palette = theme.extended_palette();
                style.background = Some(palette.primary.weak.color.into());
                style.text_color = palette.primary.strong.color;
            }
            style
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
            divider(),
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
                        button("上移").on_press(Message::MoveCategory(name.clone(), true)),
                        button("下移").on_press(Message::MoveCategory(name.clone(), false)),
                        button("删除")
                            .on_press(Message::RequestDeleteCategory(name.clone()))
                            .style(button::danger),
                    ]
                    .spacing(4),
                );
            }
        }
        let mut footer = column![
            divider(),
            button("+ 添加新分类")
                .on_press_maybe(enabled.then_some(Message::ToggleCategoryEditor))
                .style(button::text)
                .width(Length::Fill),
        ]
        .spacing(8);
        if self.category_editor_open && enabled {
            footer = footer.push(
                row![
                    text_input("新分类名称", &self.category_name)
                        .on_input(Message::CategoryNameChanged)
                        .on_submit(Message::AddCategory)
                        .padding(8),
                    button("添加").on_press(Message::AddCategory).padding(8),
                ]
                .spacing(6),
            );
        }
        let sidebar = column![
            row![text("🔐").size(26), text("密码管理器").size(20)]
                .spacing(12)
                .align_y(Alignment::Center),
            divider(),
            scrollable(categories).height(Length::Fill),
            footer,
            divider(),
            button("导入数据")
                .on_press_maybe(enabled.then_some(Message::OpenImport))
                .style(button::text)
                .width(Length::Fill),
            button("导出数据 / 备份")
                .on_press_maybe(enabled.then_some(Message::OpenSettings))
                .style(button::text)
                .width(Length::Fill),
            row![
                button("设置")
                    .on_press_maybe(enabled.then_some(Message::OpenSettings))
                    .style(button::text),
                button("锁定").on_press(Message::Lock).style(button::text),
            ]
            .spacing(16),
        ]
        .spacing(12);
        container(sidebar)
            .padding(16)
            .width(SIDEBAR_WIDTH)
            .height(Length::Fill)
            .style(|theme: &Theme| {
                let mut style = surface(theme);
                style.border.radius = 0.0.into();
                style
            })
            .into()
    }

    fn cards_view<'a>(&'a self, session: &'a VaultSession) -> Element<'a, Message> {
        let query = self.search.to_lowercase();
        let entries: Vec<_> = session
            .entries()
            .iter()
            .filter(|entry| self.entry_visible(entry, &query))
            .collect();
        let count = entries.len();
        let body: Element<'_, Message> = if entries.is_empty() {
            container(text("没有符合条件的密码。可添加密码或导入数据。").size(14))
                .padding(24)
                .width(Length::Fill)
                .into()
        } else {
            // Fixed-width cards + wrapping rows + vertical-only scrolling.
            // Unlike the replaced table, there is no Fill column in an
            // unbounded horizontal scroll viewport.
            row(entries.into_iter().map(|entry| self.password_card(entry)))
                .spacing(20)
                .width(Length::Fill)
                .wrap()
                .into()
        };
        column![
            row![
                text_input("搜索密码...", &self.search)
                    .id(self.search_id.clone())
                    .on_input(Message::SearchChanged)
                    .padding(12)
                    .width(Length::Fill),
                button("清空")
                    .on_press(Message::SearchChanged(String::new()))
                    .style(button::secondary)
                    .padding(12),
                button("+ 添加密码").on_press(Message::NewEntry).padding(12),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
            divider(),
            text(format!("显示 {count} 条 · 右键查看条目操作")).size(12),
            scrollable(body).height(Length::Fill).width(Length::Fill),
        ]
        .spacing(16)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }

    fn password_card<'a>(&'a self, entry: &'a EntryRecord) -> Element<'a, Message> {
        let id = entry.id;
        let selected = self.selected == Some(id);
        let content = column![
            row![
                metadata_hint(
                    container(text(&entry.name).size(17).wrapping(text::Wrapping::None))
                        .id(format!("card-name-{id}"))
                        .width(Length::Fill)
                        .clip(true),
                    &entry.name,
                ),
                button(text(if entry.favorite { "★" } else { "☆" }).size(20))
                    .on_press_maybe(
                        (!entry.is_deleted())
                            .then_some(Message::CardAction(id, CardAction::Favorite))
                    )
                    .style(button::text)
                    .padding(2),
            ]
            .align_y(Alignment::Center),
            metadata_hint(
                container(card_line("账号：", &entry.username)).id(format!("card-username-{id}")),
                &entry.username,
            ),
            container(card_line("密码：", "••••••••")).id(format!("card-password-{id}")),
            row![
                text("网址：").size(13).width(42),
                metadata_hint(
                    container(
                        button(text(&entry.website).size(13).wrapping(text::Wrapping::None))
                            .on_press(Message::CardAction(id, CardAction::OpenWebsite))
                            .style(button::text)
                            .padding(0)
                    )
                    .id(format!("card-website-{id}"))
                    .width(Length::Fill)
                    .clip(true),
                    &entry.website,
                ),
            ]
            .height(24)
            .align_y(Alignment::Center),
            divider(),
            row![
                card_button(
                    "复制账号",
                    format!("copy-user-{id}"),
                    Message::CardAction(id, CardAction::CopyUsername)
                ),
                card_button(
                    "复制密码",
                    format!("copy-password-{id}"),
                    Message::CardAction(id, CardAction::CopyPassword)
                ),
                card_button(
                    if entry.is_deleted() {
                        "操作"
                    } else {
                        "编辑"
                    },
                    format!("edit-{id}"),
                    if entry.is_deleted() {
                        Message::ContextEntry(id)
                    } else {
                        Message::EditEntry(id)
                    }
                ),
            ]
            .spacing(8),
        ]
        .spacing(12);
        let panel = container(content)
            .id(format!("card-{id}"))
            .padding(20)
            .width(CARD_WIDTH)
            .height(250)
            .clip(true)
            .style(move |theme: &Theme| {
                let mut style = surface(theme);
                if selected {
                    style.border.color = theme.palette().primary;
                }
                style
            });
        mouse_area(panel)
            .on_press(Message::SelectEntry(id))
            .on_double_click(Message::EditEntry(id))
            .on_right_press(Message::ContextEntry(id))
            .into()
    }

    fn selection_actions<'a>(&'a self, entry: &'a EntryRecord) -> Element<'a, Message> {
        let action = |kind| Message::ContextAction(entry.id, self.context_generation, kind);
        let mut actions = column![
            row![
                button("复制账号")
                    .on_press(action(ContextActionKind::CopyUsername))
                    .style(button::secondary),
                button("复制密码")
                    .on_press(action(ContextActionKind::CopyPassword))
                    .style(button::secondary),
                button(if self.revealed.is_some() {
                    "隐藏密码"
                } else {
                    "显示密码"
                })
                .on_press(action(ContextActionKind::ToggleReveal))
                .style(button::secondary),
                button("打开网页")
                    .on_press(action(ContextActionKind::OpenWebsite))
                    .style(button::secondary),
            ]
            .spacing(8),
        ]
        .spacing(12);
        if entry.is_deleted() {
            actions = actions.push(
                row![
                    button("恢复条目").on_press(action(ContextActionKind::Restore)),
                    button("永久删除")
                        .on_press(action(ContextActionKind::RequestPermanentDelete))
                        .style(button::danger),
                ]
                .spacing(8),
            );
        } else {
            actions = actions.push(
                row![
                    button("编辑条目").on_press(action(ContextActionKind::Edit)),
                    button(if entry.favorite {
                        "取消收藏"
                    } else {
                        "收藏条目"
                    })
                    .on_press(action(ContextActionKind::Favorite))
                    .style(button::secondary),
                    button("移到回收站")
                        .on_press(action(ContextActionKind::Recycle))
                        .style(button::danger),
                ]
                .spacing(8),
            );
        }
        actions.into()
    }

    fn context_view(&self) -> Element<'_, Message> {
        let mut content = column![text("条目快捷操作").size(18)].spacing(12);
        if let Some(entry) = self.selected_entry() {
            let mut details = column![].spacing(12).width(Length::Fill);
            if let Some(secret) = &self.revealed
                && secret.entry_id == entry.id
            {
                details = details.push(
                    column![
                        text("密码（已显式显示）").size(12),
                        text(secret.value.as_str())
                            .size(14)
                            .wrapping(text::Wrapping::WordOrGlyph)
                            .width(Length::Fill),
                    ]
                    .spacing(4),
                );
            }
            // Scrollable rounds its translation to whole logical pixels. Text
            // line heights can be fractional, so keep the last glyphs clear
            // of the clip edge even when the bottom offset rounds down.
            details = details
                .push(metadata_details(entry))
                .padding(iced::Padding::ZERO.bottom(8));
            content = content
                .push(
                    container(scrollable(details).spacing(8).height(Length::Fill))
                        .id("context-details")
                        .width(Length::Fill)
                        .height(Length::Fill),
                )
                .push(self.selection_actions(entry));
        }
        content
            .push(
                button("关闭菜单")
                    .on_press(self.selected.map_or(Message::CloseContext, |id| {
                        Message::ContextAction(
                            id,
                            self.context_generation,
                            ContextActionKind::Close,
                        )
                    }))
                    .style(button::secondary),
            )
            .into()
    }
}
