import customtkinter as ctk
from typing import Optional

from .theme import COLORS, FONTS, center_window


class SettingsDialog(ctk.CTkToplevel):
    """设置对话框"""

    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent

        # 窗口配置
        self.title("设置")
        self.geometry("400x250")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        center_window(self, 400, 250)

        self._create_widgets()

    def _create_widgets(self):
        """创建界面"""
        # 主容器
        main_frame = ctk.CTkFrame(self, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # 标题
        ctk.CTkLabel(main_frame, text="设置", font=FONTS["heading"]).pack(anchor="w", pady=(0, 20))

        # 关于信息
        about_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        about_frame.pack(fill="x", pady=10)

        ctk.CTkLabel(about_frame, text="密码管理器 v2.0", font=FONTS["body"]).pack(anchor="w")
        ctk.CTkLabel(
            about_frame,
            text="安全存储您的密码",
            font=FONTS["small"],
            text_color=COLORS["text_muted"],
        ).pack(anchor="w", pady=(5, 0))

        # 关闭按钮
        ctk.CTkButton(
            main_frame,
            text="关闭",
            command=self.destroy,
        ).pack(side="bottom", pady=(20, 0))
