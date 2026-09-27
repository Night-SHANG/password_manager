import customtkinter as ctk
from tkinter import messagebox
from typing import Optional, Callable

from ..core.models import PasswordEntry, Category
from ..services.generator import PasswordGenerator, PasswordConfig
from .theme import COLORS, FONTS, center_window, get_colors


class EntryDialog(ctk.CTkToplevel):
    """添加/编辑条目对话框"""

    def __init__(
        self,
        parent,
        categories: list[Category],
        entry: Optional[PasswordEntry] = None,
        on_save: Optional[Callable] = None,
    ):
        super().__init__(parent)
        self.entry = entry
        self.on_save = on_save
        self.categories = categories
        self.result = None

        # 窗口配置
        title = "编辑条目" if entry else "添加条目"
        self.title(title)
        self.geometry("450x600")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        center_window(self, 450, 600)

        self._create_widgets()
        self._load_entry()

    def _create_widgets(self):
        """创建界面组件"""
        colors = get_colors()
        # 主容器
        main_frame = ctk.CTkFrame(self, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # 标题
        title_label = ctk.CTkLabel(
            main_frame,
            text="编辑条目" if self.entry else "添加新条目",
            font=FONTS["heading"],
        )
        title_label.pack(anchor="w", pady=(0, 15))

        # 表单区域
        form_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        form_frame.pack(fill="x")

        # 名称
        ctk.CTkLabel(form_frame, text="名称", font=FONTS["body"]).pack(anchor="w")
        self.name_entry = ctk.CTkEntry(form_frame, placeholder_text="例如：GitHub")
        self.name_entry.pack(fill="x", pady=(2, 10))

        # 网站
        ctk.CTkLabel(form_frame, text="网站", font=FONTS["body"]).pack(anchor="w")
        self.website_entry = ctk.CTkEntry(form_frame, placeholder_text="例如：github.com")
        self.website_entry.pack(fill="x", pady=(2, 10))

        # 用户名
        ctk.CTkLabel(form_frame, text="用户名", font=FONTS["body"]).pack(anchor="w")
        self.username_entry = ctk.CTkEntry(form_frame, placeholder_text="输入用户名或邮箱")
        self.username_entry.pack(fill="x", pady=(2, 10))

        # 密码
        ctk.CTkLabel(form_frame, text="密码", font=FONTS["body"]).pack(anchor="w")
        password_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        password_frame.pack(fill="x", pady=(2, 10))

        self.password_entry = ctk.CTkEntry(password_frame, show="•")
        self.password_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))

        self.show_password_btn = ctk.CTkButton(
            password_frame,
            text="显示",
            width=60,
            command=self._toggle_password_visibility,
        )
        self.show_password_btn.pack(side="left", padx=(0, 5))

        self.generate_btn = ctk.CTkButton(
            password_frame,
            text="生成",
            width=60,
            fg_color=colors["success"],
            hover_color="#059669",
            command=self._generate_password,
        )
        self.generate_btn.pack(side="left")

        # 密码强度指示
        self.strength_label = ctk.CTkLabel(form_frame, text="", font=FONTS["small"])
        self.strength_label.pack(anchor="w")
        self.password_entry.bind("<KeyRelease>", self._update_strength)

        # 分类
        ctk.CTkLabel(form_frame, text="分类", font=FONTS["body"]).pack(anchor="w", pady=(5, 0))
        category_names = [c.name for c in self.categories]
        self.category_var = ctk.StringVar(value="其他")
        self.category_combo = ctk.CTkComboBox(
            form_frame,
            values=category_names,
            variable=self.category_var,
            state="readonly",
            button_color=colors["primary"],
            button_hover_color=colors["primary_hover"]
        )
        self.category_combo.pack(fill="x", pady=(2, 10))

        # 按钮区域
        btn_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        btn_frame.pack(fill="x", pady=(15, 0))

        ctk.CTkButton(
            btn_frame,
            text="取消",
            text_color=colors["text_primary"],
            fg_color=colors["bg_dark"],
            hover_color=colors["border"],
            command=self.destroy,
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btn_frame,
            text="保存",
            fg_color=colors["primary"],
            hover_color=colors["primary_hover"],
            command=self._save,
        ).pack(side="right")

    def _load_entry(self):
        """加载已有条目数据"""
        if not self.entry:
            return

        self.name_entry.insert(0, self.entry.name)
        self.website_entry.insert(0, self.entry.website)
        self.username_entry.insert(0, self.entry.username)
        self.password_entry.insert(0, self.entry.password)
        self.category_var.set(self.entry.category)
        self._update_strength()

    def _toggle_password_visibility(self):
        """切换密码显示"""
        if self.password_entry.cget("show") == "•":
            self.password_entry.configure(show="")
            self.show_password_btn.configure(text="隐藏")
        else:
            self.password_entry.configure(show="•")
            self.show_password_btn.configure(text="显示")

    def _generate_password(self):
        """生成随机密码"""
        config = PasswordConfig(length=16)
        password = PasswordGenerator.generate(config)
        self.password_entry.delete(0, "end")
        self.password_entry.insert(0, password)
        self._update_strength()

    def _update_strength(self, event=None):
        """更新密码强度显示"""
        colors = get_colors()
        password = self.password_entry.get()
        if not password:
            self.strength_label.configure(text="")
            return

        score, desc = PasswordGenerator.calculate_strength(password)
        color_map = {
            "弱": colors["danger"],
            "中": colors["warning"],
            "强": colors["success"],
            "非常强": colors["success"],
        }
        self.strength_label.configure(
            text=f"密码强度: {desc}",
            text_color=color_map.get(desc, colors["text_muted"]),
        )

    def _save(self):
        """保存条目"""
        name = self.name_entry.get().strip()
        website = self.website_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        category = self.category_var.get()
        notes = ""

        if not password:
            messagebox.showwarning("提示", "密码不能为空", parent=self)
            return

        if self.entry:
            # 编辑模式
            self.entry.name = name
            self.entry.website = website
            self.entry.username = username
            self.entry.password = password
            self.entry.category = category
            self.entry.notes = notes
        else:
            # 新增模式
            self.entry = PasswordEntry(
                name=name,
                website=website,
                username=username,
                password=password,
                category=category,
                notes=notes,
            )

        self.result = self.entry
        if self.on_save:
            self.on_save(self.entry)
        self.destroy()
