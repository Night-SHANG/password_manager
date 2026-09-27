import customtkinter as ctk
from tkinter import messagebox, filedialog
from typing import Optional

from ..services.password_service import PasswordService
from ..services.export_service import ExportService
from ..services.import_service import ImportService
from .theme import COLORS, FONTS, setup_theme, center_window, get_colors
from .auth_view import AuthView
from .main_view import Sidebar, EntryList
from .entry_dialog import EntryDialog
from .settings_dialog import SettingsDialog


class App(ctk.CTk):
    """主应用窗口"""

    DB_PATH = "passwords.db"

    def __init__(self):
        super().__init__()

        setup_theme()

        self.title("密码管理器")
        self.geometry("1100x700")
        self.minsize(900, 600)
        center_window(self, 1100, 700)

        self.service: Optional[PasswordService] = None
        self.current_category = "全部"
        self.current_entries = []
        self._search_timer = None  # 搜索防抖定时器

        self._show_auth()

    def _show_auth(self):
        """显示认证界面"""
        self.withdraw()  # 隐藏主窗口
        auth = AuthView(self, self.DB_PATH, self._on_auth_success)
        # 使用轮询检查是否已关闭
        self._check_auth_closed(auth)

    def _check_auth_closed(self, auth):
        """检查认证窗口是否已关闭"""
        try:
            if auth.winfo_exists():
                self.after(100, lambda: self._check_auth_closed(auth))
            else:
                if not self.service:
                    self.destroy()
        except Exception:
            if not self.service:
                self.destroy()

    def _on_auth_success(self, service: PasswordService):
        """认证成功回调"""
        self.service = service
        self.deiconify()  # 显示主窗口
        self._create_widgets()
        self._refresh_data()

    def _create_widgets(self):
        """创建主界面"""
        # 主容器
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # 侧边栏
        self.sidebar = Sidebar(
            self, 
            on_category_select=self._on_category_select, 
            on_settings_click=self._open_settings, 
            on_add_category=self._add_category,
            on_delete_category=self._delete_category_click,
            on_reorder_category=self._reorder_category_click,
            on_import_click=self._import_data,
            on_export_click=self._export_data
        )
        self.sidebar.grid(row=0, column=0, sticky="nsew")

        # 右侧内容区
        content_frame = ctk.CTkFrame(self, fg_color="transparent")
        content_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        content_frame.grid_columnconfigure(0, weight=1)
        content_frame.grid_rowconfigure(0, weight=1)

        # 条目列表（全宽）
        self.entry_list = EntryList(
            content_frame,
            on_edit_entry=self._edit_entry,
            on_delete_entry=self._delete_entry,
            on_toggle_favorite_entry=self._toggle_favorite,
            on_toast=self._show_toast
        )
        self.entry_list.grid(row=0, column=0, sticky="nsew")

        # 绑定添加按钮
        self.entry_list.add_btn.configure(command=self._add_entry)

        # 绑定搜索
        self.entry_list.search_var.trace_add("write", lambda *args: self._on_search())

        # 状态栏
        colors = get_colors()
        self.status_bar = ctk.CTkFrame(self, height=30, fg_color=colors["sidebar_bg"], corner_radius=0)
        self.status_bar.grid(row=1, column=0, columnspan=2, sticky="ew")

        self.status_label = ctk.CTkLabel(
            self.status_bar,
            text="",
            font=FONTS["small"],
            text_color=colors["text_muted"],
        )
        self.status_label.pack(side="left", padx=15)

    def _refresh_data(self):
        """刷新数据"""
        if not self.service:
            return

        self._refresh_sidebar()
        self._load_entries()

    def _load_entries(self):
        """加载当前分类的条目"""
        if not self.service:
            return

        if self.current_category == "全部":
            entries = self.service.get_all_entries()
        elif self.current_category == "收藏":
            entries = self.service.get_favorite_entries()
        else:
            entries = self.service.get_entries_by_category(self.current_category)

        self.current_entries = entries
        self.entry_list.update_entries(entries)
        self._update_status()

    def _update_status(self):
        """更新状态栏"""
        count = len(self.current_entries)
        total = self.service.get_entry_count()
        self.status_label.configure(text=f"显示 {count} 条 / 共 {total} 条")

    def _on_category_select(self, category: str):
        """分类选择回调"""
        self.current_category = category
        self._load_entries()

    def _refresh_sidebar(self):
        """刷新侧边栏（使用SQL COUNT，不解密条目）"""
        if not self.service:
            return
        categories = self.service.get_categories()
        # 使用纯SQL计数，避免解密所有条目
        category_counts = self.service.get_category_counts()
        counts = {
            "全部": self.service.get_entry_count(),
            "收藏": self.service.get_favorite_count(),
        }
        for cat in categories:
            counts[cat.name] = category_counts.get(cat.name, 0)
        self.sidebar.update_categories(categories, counts)

    def _on_search(self):
        """搜索（300ms防抖，避免每次按键都解密全部条目）"""
        if self._search_timer:
            self.after_cancel(self._search_timer)
        self._search_timer = self.after(300, self._do_search)

    def _do_search(self):
        """实际执行搜索"""
        self._search_timer = None
        query = self.entry_list.search_var.get()
        if not query:
            self._load_entries()
            return

        entries = self.service.search_entries(query)
        self.current_entries = entries
        self.entry_list.update_entries(entries)
        self._update_status()

    def _add_entry(self):
        """添加条目"""
        categories = self.service.get_categories()
        dialog = EntryDialog(self, categories, on_save=self._save_new_entry)

    def _save_new_entry(self, entry):
        """保存新条目"""
        self.service.add_entry(entry)
        self._refresh_data()

    def _edit_entry(self, entry):
        """编辑条目"""
        categories = self.service.get_categories()
        EntryDialog(self, categories, entry=entry, on_save=self._save_edited_entry)

    def _save_edited_entry(self, entry):
        """保存编辑的条目"""
        self.service.update_entry(entry)
        self._refresh_data()

    def _delete_entry(self, entry):
        """删除条目"""
        if messagebox.askyesno("确认删除", f"确定要删除 '{entry.name}' 吗？"):
            self.service.delete_entry(entry.id)
            self._refresh_data()

    def _toggle_favorite(self, entry):
        """切换收藏"""
        self.service.toggle_favorite(entry.id)
        self._refresh_data()

    def _show_toast(self, message: str):
        """显示短暂提示信息在状态栏"""
        colors = get_colors()
        self.status_label.configure(text=message, text_color=colors["success"])
        if hasattr(self, "_toast_timer") and getattr(self, "_toast_timer", None):
            self.after_cancel(self._toast_timer)
        self._toast_timer = self.after(3000, self._restore_status)

    def _restore_status(self):
        """恢复状态栏原本的文本"""
        colors = get_colors()
        self.status_label.configure(text_color=colors["text_muted"])
        self._update_status()

    def _open_settings(self):
        """打开设置"""
        SettingsDialog(self)

    def _add_category(self, name: str):
        """添加自定义分类"""
        if self.service:
            self.service.add_category(name)
            self._refresh_data()

    def _delete_category_click(self, name: str):
        if messagebox.askyesno("确认删除", f"确定要删除分类 '{name}' 吗？\n该分类下的条目会被归入'其他'。"):
            self.service.delete_category(name)
            if self.current_category == name:
                self.current_category = "全部"
            self._refresh_data()

    def _reorder_category_click(self, name: str, direction: str):
        categories = self.service.get_categories()
        custom_cats = [c for c in categories if c.name != "其他"]
        
        for i, cat in enumerate(custom_cats):
            if cat.name == name:
                target_idx = i - 1 if direction == 'up' else i + 1
                if 0 <= target_idx < len(custom_cats):
                    swap_cat = custom_cats[target_idx]
                    current_order = cat.sort_order
                    swap_order = swap_cat.sort_order
                    
                    if current_order == 0 and swap_order == 0:
                        current_order = i + 100
                        swap_order = target_idx + 100
                        
                    self.service.update_category_order(cat.name, swap_order)
                    self.service.update_category_order(swap_cat.name, current_order)
                    self._refresh_data()
                break

    def _import_data(self):
        """导入数据"""
        if not self.service: return
        file_path = filedialog.askopenfilename(title="选择要导入的CSV文件", filetypes=[("CSV 文件", "*.csv")])
        if file_path:
            try:
                importer = ImportService(self.service)
                success_count, skipped_count = importer.import_csv(file_path)
                # 导入后重新加载缓存（ImportService直接操作了数据库，缓存不同步）
                self.service._load_cache()
                messagebox.showinfo("导入成功", f"成功导入 {success_count} 条记录，跳过 {skipped_count} 条")
                self._refresh_data()
            except Exception as e:
                messagebox.showerror("导入失败", str(e))

    def _export_data(self):
        """导出数据"""
        if not self.service: return
        file_path = filedialog.asksaveasfilename(title="导出为CSV文件", defaultextension=".csv", filetypes=[("CSV 文件", "*.csv")])
        if file_path:
            try:
                # ExportService 需要 Database 对象，并且需要解密后的条目
                entries = self.service.get_all_entries()
                exporter = ExportService(self.service.db)
                exporter.export_csv(file_path, entries)
                messagebox.showinfo("导出成功", "密码数据已成功导出")
            except Exception as e:
                messagebox.showerror("导出失败", str(e))
