import os
import customtkinter as ctk
from tkinter import messagebox, filedialog
from typing import Optional, Callable

from ..services.password_service import PasswordService
from ..services.import_service import ImportService
from .theme import COLORS, FONTS, center_window, get_colors


class AuthView(ctk.CTkToplevel):
    """认证界面（登录/创建密码库）"""

    def __init__(self, parent, db_path: str, on_success: Callable):
        super().__init__(parent)
        self.db_path = db_path
        self.on_success = on_success
        self.service: Optional[PasswordService] = None

        # 窗口配置
        self.title("密码管理器 - 登录")
        self.geometry("400x500")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        center_window(self, 400, 500)

        self._create_widgets()

        # 检查是否已存在密码库
        if os.path.exists(db_path):
            self._show_login()
        else:
            self._show_create()

    def _create_widgets(self):
        """创建界面组件"""
        # 主容器
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.pack(fill="both", expand=True, padx=40, pady=30)

        # Logo区域
        logo_label = ctk.CTkLabel(
            self.main_frame,
            text="🔐",
            font=("", 48),
        )
        logo_label.pack(pady=(20, 5))

        self.title_label = ctk.CTkLabel(
            self.main_frame,
            text="密码管理器",
            font=FONTS["title"],
        )
        self.title_label.pack(pady=(0, 5))

        self.subtitle_label = ctk.CTkLabel(
            self.main_frame,
            text="安全存储您的密码",
            font=FONTS["body"],
            text_color=COLORS["text_muted"],
        )
        self.subtitle_label.pack(pady=(0, 30))

        # 表单区域
        self.form_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.form_frame.pack(fill="x")

        # 主密码
        ctk.CTkLabel(self.form_frame, text="主密码", font=FONTS["body"]).pack(anchor="w")
        self.password_entry = ctk.CTkEntry(self.form_frame, show="•", placeholder_text="输入主密码")
        self.password_entry.pack(fill="x", pady=(2, 10))
        self.password_entry.bind("<Return>", lambda e: self._on_submit())

        # 确认密码（仅创建模式显示）
        self.confirm_frame = ctk.CTkFrame(self.form_frame, fg_color="transparent")
        ctk.CTkLabel(self.confirm_frame, text="确认密码", font=FONTS["body"]).pack(anchor="w")
        self.confirm_entry = ctk.CTkEntry(self.confirm_frame, show="•", placeholder_text="再次输入密码")
        self.confirm_entry.pack(fill="x", pady=(2, 10))
        self.confirm_entry.bind("<Return>", lambda e: self._on_submit())

        # 按钮区域
        self.btn_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.btn_frame.pack(fill="x", pady=(20, 0))

        colors = get_colors()

        self.submit_btn = ctk.CTkButton(
            self.btn_frame,
            text="登录",
            font=FONTS["button"],
            fg_color=colors["primary"],
            hover_color=colors["primary_hover"],
            command=self._on_submit,
        )
        self.submit_btn.pack(fill="x", pady=(0, 10))

        # 导入选项（仅创建模式显示）
        self.import_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")

        ctk.CTkLabel(
            self.import_frame,
            text="已有数据？",
            font=FONTS["small"],
            text_color=colors["text_muted"],
        ).pack(pady=(10, 5))

        import_csv_btn = ctk.CTkButton(
            self.import_frame,
            text="从CSV导入",
            font=FONTS["small"],
            fg_color="transparent",
            border_width=1,
            border_color=colors["border"],
            command=self._import_csv,
        )
        import_csv_btn.pack(fill="x", pady=2)

        import_vault_btn = ctk.CTkButton(
            self.import_frame,
            text="从旧版vault.enc导入",
            font=FONTS["small"],
            fg_color="transparent",
            border_width=1,
            border_color=colors["border"],
            command=self._import_vault,
        )
        import_vault_btn.pack(fill="x", pady=2)

        # 错误提示
        self.error_label = ctk.CTkLabel(
            self.main_frame,
            text="",
            font=FONTS["small"],
            text_color=colors["danger"],
        )
        self.error_label.pack(pady=(10, 0))

    def _show_login(self):
        """显示登录界面"""
        self.title_label.configure(text="欢迎回来")
        self.subtitle_label.configure(text="输入主密码解锁密码库")
        self.submit_btn.configure(text="解锁")
        self.confirm_frame.pack_forget()
        self.import_frame.pack_forget()
        self.password_entry.focus()

    def _show_create(self):
        """显示创建界面"""
        self.title_label.configure(text="创建密码库")
        self.subtitle_label.configure(text="设置主密码保护您的密码")
        self.submit_btn.configure(text="创建")
        self.confirm_frame.pack(fill="x")
        self.import_frame.pack(fill="x")
        self.password_entry.focus()

    def _on_submit(self):
        """提交处理"""
        password = self.password_entry.get()
        if not password:
            self._show_error("请输入主密码")
            return

        if os.path.exists(self.db_path):
            # 登录模式
            self._login(password)
        else:
            # 创建模式
            confirm = self.confirm_entry.get()
            if password != confirm:
                self._show_error("两次密码不一致")
                return
            if len(password) < 6:
                self._show_error("密码至少6位")
                return
            self._create(password)

    def _login(self, password: str):
        """登录"""
        service = PasswordService(self.db_path)
        if service.open_vault(password):
            self.service = service
            self.on_success(service)
            self.destroy()
        else:
            self._show_error("密码错误")

    def _create(self, password: str):
        """创建新密码库"""
        service = PasswordService(self.db_path)
        service.init_vault(password)
        self.service = service
        self.on_success(service)
        self.destroy()

    def _import_csv(self):
        """导入CSV"""
        file_path = filedialog.askopenfilename(
            title="选择CSV文件",
            filetypes=[("CSV文件", "*.csv")],
        )
        if not file_path:
            return

        password = self.password_entry.get()
        confirm = self.confirm_entry.get()

        if not password:
            self._show_error("请先输入主密码")
            return
        if password != confirm:
            self._show_error("两次密码不一致")
            return
        if len(password) < 6:
            self._show_error("密码至少6位")
            return

        try:
            service = PasswordService(self.db_path)
            service.init_vault(password)

            import_service = ImportService(service)
            success, skipped = import_service.import_csv(file_path)

            self.service = service
            messagebox.showinfo(
                "导入完成",
                f"成功导入 {success} 条记录，跳过 {skipped} 条",
                parent=self,
            )
            self.on_success(service)
            self.destroy()
        except Exception as e:
            self._show_error(f"导入失败: {e}")

    def _import_vault(self):
        """导入旧版vault.enc"""
        file_path = filedialog.askopenfilename(
            title="选择vault.enc文件",
            filetypes=[("加密文件", "*.enc")],
        )
        if not file_path:
            return

        password = self.password_entry.get()
        confirm = self.confirm_entry.get()

        if not password:
            self._show_error("请先输入主密码")
            return
        if password != confirm:
            self._show_error("两次密码不一致")
            return
        if len(password) < 6:
            self._show_error("密码至少6位")
            return

        try:
            service = PasswordService(self.db_path)
            service.init_vault(password)

            import_service = ImportService(service)
            success, skipped = import_service.import_vault_enc(file_path, password)

            self.service = service
            messagebox.showinfo(
                "导入完成",
                f"成功导入 {success} 条记录，跳过 {skipped} 条",
                parent=self,
            )
            self.on_success(service)
            self.destroy()
        except Exception as e:
            self._show_error(f"导入失败: {e}")

    def _show_error(self, message: str):
        """显示错误信息"""
        self.error_label.configure(text=message)

    def _on_close(self):
        """关闭窗口"""
        self.destroy()
