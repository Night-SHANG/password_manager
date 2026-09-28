use iced::widget::{button, column, container, row, scrollable, text, text_input};
use iced::{Element, Length, Task};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::storage::VaultSession;

pub fn run() -> iced::Result {
    iced::application(App::new, App::update, App::view)
        .title("密码管理器")
        .run()
}

struct App {
    vault_path: String,
    master_password: String,
    confirm_password: String,
    session: Option<VaultSession>,
    search: String,
    selected: Option<Uuid>,
    status: String,
}

#[derive(Debug, Clone)]
enum Message {
    VaultPathChanged(String),
    MasterPasswordChanged(String),
    ConfirmPasswordChanged(String),
    CreateVault,
    OpenVault,
    Lock,
    Save,
    SearchChanged(String),
    SelectEntry(Uuid),
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
                selected: None,
                status: String::new(),
            },
            Task::none(),
        )
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::VaultPathChanged(value) => self.vault_path = value,
            Message::MasterPasswordChanged(value) => self.master_password = value,
            Message::ConfirmPasswordChanged(value) => self.confirm_password = value,
            Message::CreateVault => self.create_vault(),
            Message::OpenVault => self.open_vault(),
            Message::Lock => self.lock(),
            Message::Save => {
                if let Some(session) = self.session.as_mut() {
                    self.status = match session.save() {
                        Ok(()) => format!("已安全保存 · revision {}", session.revision()),
                        Err(error) => format!("保存失败：{error}"),
                    };
                }
            }
            Message::SearchChanged(value) => self.search = value,
            Message::SelectEntry(id) => self.selected = Some(id),
        }

        Task::none()
    }

    fn view(&self) -> Element<'_, Message> {
        if self.session.is_some() {
            self.vault_view()
        } else {
            self.locked_view()
        }
    }

    fn locked_view(&self) -> Element<'_, Message> {
        let path = text_input(
            "保险库路径，例如 D:\\Passwords\\main.pmvault",
            &self.vault_path,
        )
        .on_input(Message::VaultPathChanged)
        .padding(10);

        let password = text_input("主密码", &self.master_password)
            .on_input(Message::MasterPasswordChanged)
            .secure(true)
            .padding(10);

        let confirm = text_input(
            "再次输入主密码（仅创建新保险库时需要）",
            &self.confirm_password,
        )
        .on_input(Message::ConfirmPasswordChanged)
        .secure(true)
        .padding(10);

        let content = column![
            text("密码管理器").size(36),
            text("本地加密保险库 · Rust + Iced"),
            path,
            password,
            confirm,
            row![
                button("创建新保险库").on_press(Message::CreateVault),
                button("打开保险库").on_press(Message::OpenVault)
            ]
            .spacing(10),
            text(&self.status)
        ]
        .spacing(14);

        container(content)
            .padding(28)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn vault_view(&self) -> Element<'_, Message> {
        let session = self.session.as_ref().expect("session checked above");

        let sidebar = column![
            text("保险库").size(24),
            text("全部"),
            text("收藏"),
            text("分类"),
            text("回收站"),
            button("保存").on_press(Message::Save),
            button("锁定").on_press(Message::Lock),
        ]
        .spacing(12);

        let search = text_input("搜索名称 / 网站 / 用户名", &self.search)
            .on_input(Message::SearchChanged)
            .padding(9);

        let query = self.search.to_lowercase();
        let mut list = column![text("条目").size(22), search].spacing(8);

        for entry in session.active_entries().filter(|entry| {
            query.is_empty()
                || entry.name.to_lowercase().contains(query.as_str())
                || entry.website.to_lowercase().contains(query.as_str())
                || entry.username.to_lowercase().contains(query.as_str())
        }) {
            let label = column![
                text(&entry.name),
                text(format!("{}  {}", entry.username, entry.website)).size(12)
            ]
            .spacing(2);

            list = list.push(
                button(label)
                    .on_press(Message::SelectEntry(entry.id))
                    .width(Length::Fill),
            );
        }

        let details: Element<'_, Message> = if let Some(id) = self.selected {
            if let Some(entry) = session.entries().iter().find(|entry| entry.id == id) {
                column![
                    text(&entry.name).size(28),
                    text(format!("网站：{}", entry.website)),
                    text(format!("用户名：{}", entry.username)),
                    text(format!("分类：{}", entry.category)),
                    text("密码：••••••••"),
                    text("敏感字段保持按需解密；复制 / Reveal 编辑器在正式 UI 批次接入。"),
                ]
                .spacing(12)
                .into()
            } else {
                text("条目不存在").into()
            }
        } else {
            column![
                text("选择一个条目").size(24),
                text(format!("Vault ID：{}", session.vault_id())),
                text(format!("Revision：{}", session.revision())),
                text(format!("路径：{}", session.path().display())),
            ]
            .spacing(10)
            .into()
        };

        let layout = column![
            row![
                container(sidebar).padding(16).width(Length::FillPortion(1)),
                container(scrollable(list))
                    .padding(16)
                    .width(Length::FillPortion(2)),
                container(details).padding(16).width(Length::FillPortion(3)),
            ]
            .height(Length::Fill),
            text(&self.status)
        ]
        .spacing(8);

        container(layout)
            .width(Length::Fill)
            .height(Length::Fill)
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
            }
            Err(error) => self.status = format!("无法解锁：{error}"),
        }
    }

    fn lock(&mut self) {
        self.session = None;
        self.selected = None;
        self.search.clear();
        self.clear_password_fields();
        self.status = "保险库已锁定".to_string();
    }

    fn clear_password_fields(&mut self) {
        self.master_password.zeroize();
        self.master_password.clear();
        self.confirm_password.zeroize();
        self.confirm_password.clear();
    }
}
