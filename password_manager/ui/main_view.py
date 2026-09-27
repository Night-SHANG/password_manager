import tkinter as tk
import customtkinter as ctk
from tkinter import messagebox, filedialog
from typing import Optional

from tksheet import Sheet

from ..core.models import PasswordEntry, Category
from ..services.password_service import PasswordService
from ..services.export_service import ExportService
from .theme import COLORS, FONTS, get_colors
from .entry_dialog import EntryDialog


class Sidebar(ctk.CTkFrame):
    """侧边栏组件"""

    def __init__(self, parent, on_category_select: callable, on_settings_click: callable = None, 
                 on_add_category: callable = None, on_delete_category: callable = None, 
                 on_reorder_category: callable = None, on_import_click: callable = None, 
                 on_export_click: callable = None):
        super().__init__(parent, width=250, corner_radius=0)
        self.on_category_select = on_category_select
        self.on_settings_click = on_settings_click
        self.on_add_category = on_add_category
        self.on_delete_category = on_delete_category
        self.on_reorder_category = on_reorder_category
        self.on_import_click = on_import_click
        self.on_export_click = on_export_click
        self.pack_propagate(False)
        self.selected = "全部"
        self.category_items = {}  # 存储分类项的引用

        self._create_widgets()

    def _create_widgets(self):
        """创建界面"""
        colors = get_colors()
        self.configure(fg_color=colors["sidebar_bg"])

        # Logo
        logo_frame = ctk.CTkFrame(self, fg_color="transparent")
        logo_frame.pack(fill="x", padx=15, pady=(20, 15))

        ctk.CTkLabel(logo_frame, text="🔐", font=("", 24)).pack(side="left", padx=(0, 8))
        ctk.CTkLabel(logo_frame, text="密码管理器", font=FONTS["heading"]).pack(side="left")

        # 分隔线
        ctk.CTkFrame(self, height=1, fg_color=colors["border"]).pack(fill="x", padx=15, pady=10)

        # 分类列表容器
        self.category_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.category_frame.pack(fill="both", expand=True, padx=10)

        # 底部按钮
        bottom_frame = ctk.CTkFrame(self, fg_color="transparent")
        bottom_frame.pack(fill="x", side="bottom", padx=10, pady=15)

        ctk.CTkFrame(self, height=1, fg_color=COLORS["border"]).pack(fill="x", padx=15, side="bottom")

        # 导入按钮
        ctk.CTkButton(
            bottom_frame,
            text="📥 导入",
            font=FONTS["small"],
            fg_color="transparent",
            text_color=colors["text_secondary"],
            hover_color=COLORS["primary"],
            anchor="w",
            command=self._import,
        ).pack(fill="x", pady=2)

        # 导出按钮
        ctk.CTkButton(
            bottom_frame,
            text="📤 导出",
            font=FONTS["small"],
            fg_color="transparent",
            text_color=colors["text_secondary"],
            hover_color=COLORS["primary"],
            anchor="w",
            command=self._export,
        ).pack(fill="x", pady=2)

        # 设置按钮
        ctk.CTkButton(
            bottom_frame,
            text="⚙ 设置",
            font=FONTS["small"],
            fg_color="transparent",
            text_color=colors["text_secondary"],
            hover_color=COLORS["primary"],
            anchor="w",
            command=self._open_settings,
        ).pack(fill="x", pady=2)

    def update_categories(self, categories: list[Category], counts: dict):
        """更新分类列表"""
        colors = get_colors()
        # 只有当分类列表变化时才重新创建
        current_cats = set(self.category_items.keys())
        new_cats = {"全部", "收藏"} | {cat.name for cat in categories}

        if current_cats != new_cats:
            # 分类列表变化，重新创建
            for widget in self.category_frame.winfo_children():
                widget.destroy()
            self.category_items.clear()

            # 全部条目
            self._create_category_item("全部", "📋", counts.get("全部", 0))

            # 收藏
            self._create_category_item("收藏", "⭐", counts.get("收藏", 0))

            # 分隔线
            ctk.CTkFrame(self.category_frame, height=1, fg_color=COLORS["border"]).pack(fill="x", pady=5)

            # 分类列表
            for cat in categories:
                is_custom = cat.name != "其他"
                self._create_category_item(cat.name, cat.icon, counts.get(cat.name, 0), 
                                           is_custom=is_custom)

            # 添加自定义分类按钮
            add_btn = ctk.CTkButton(
                self.category_frame,
                text="+ 添加分类",
                font=FONTS["small"],
                fg_color="transparent",
                text_color=colors["text_secondary"],
                anchor="w",
                hover_color=COLORS["bg_light"],
                command=self._add_category,
            )
            add_btn.pack(fill="x", pady=2)
        else:
            # 只更新数量和状态
            for name, item in self.category_items.items():
                item["count_label"].configure(text=str(counts.get(name, 0)))
            self._update_selection()

    def _create_category_item(self, name: str, icon: str, count: int, is_custom: bool = False):
        """创建分类项"""
        colors = get_colors()
        is_selected = name == self.selected
        fg_color = colors["bg_medium"] if is_selected else "transparent"

        frame = ctk.CTkFrame(self.category_frame, fg_color=fg_color, corner_radius=6)
        frame.pack(fill="x", pady=1)

        btn = ctk.CTkButton(
            frame,
            text=f"{icon}  {name}",
            font=FONTS["body"],
            fg_color="transparent",
            text_color=colors["text_primary"],
            anchor="w",
            hover_color=colors["bg_light"],
            command=lambda n=name: self._select_category(n),
        )
        btn.pack(side="left", fill="x", expand=True, padx=5, pady=4)

        # 数量标签（默认显示）
        count_label = ctk.CTkLabel(
            frame,
            text=str(count),
            font=FONTS["small"],
            text_color=colors["text_muted"],
        )
        count_label.pack(side="right", padx=(0, 10))

        # 操作按钮容器（默认隐藏，hover时显示）
        action_frame = ctk.CTkFrame(frame, fg_color="transparent")

        # 存储引用
        self.category_items[name] = {
            "frame": frame, 
            "count_label": count_label,
            "action_frame": action_frame,
        }

        # 自定义分类：添加 hover 操作按钮
        if is_custom:
            # 上移按钮
            ctk.CTkButton(
                action_frame, text="▲", width=24, height=24,
                font=("", 10), fg_color="transparent",
                text_color=colors["text_muted"],
                hover_color=colors["bg_light"],
                command=lambda n=name: self._move_category(n, 'up'),
            ).pack(side="left", padx=1)

            # 下移按钮
            ctk.CTkButton(
                action_frame, text="▼", width=24, height=24,
                font=("", 10), fg_color="transparent",
                text_color=colors["text_muted"],
                hover_color=colors["bg_light"],
                command=lambda n=name: self._move_category(n, 'down'),
            ).pack(side="left", padx=1)

            # 删除按钮
            ctk.CTkButton(
                action_frame, text="✕", width=24, height=24,
                font=("", 10), fg_color="transparent",
                text_color=colors["danger"],
                hover_color=colors["bg_light"],
                command=lambda n=name: self._delete_category_item(n),
            ).pack(side="left", padx=1)

            # 绑定 hover 事件
            def on_enter(event, n=name):
                item = self.category_items.get(n)
                if item:
                    item["count_label"].pack_forget()
                    item["action_frame"].pack(side="right", padx=(0, 5))

            def on_leave(event, n=name):
                item = self.category_items.get(n)
                if item:
                    item["action_frame"].pack_forget()
                    item["count_label"].pack(side="right", padx=(0, 10))

            frame.bind("<Enter>", on_enter)
            frame.bind("<Leave>", on_leave)

    def _move_category(self, name: str, direction: str):
        """移动分类"""
        if self.on_reorder_category:
            self.on_reorder_category(name, direction)

    def _delete_category_item(self, name: str):
        """删除分类"""
        if self.on_delete_category:
            self.on_delete_category(name)

    def _select_category(self, name: str):
        """选择分类"""
        self.selected = name
        self._update_selection()
        self.on_category_select(name)

    def _add_category(self):
        """添加自定义分类"""
        dialog = ctk.CTkInputDialog(text="请输入分类名称：", title="添加分类")
        name = dialog.get_input()
        if name and name.strip():
            if self.on_add_category:
                self.on_add_category(name.strip())

    def _update_selection(self):
        """更新选中状态"""
        colors = get_colors()
        for name, item in self.category_items.items():
            is_selected = name == self.selected
            fg_color = colors["bg_medium"] if is_selected else "transparent"
            item["frame"].configure(fg_color=fg_color)

    def _import(self):
        """导入"""
        if self.on_import_click:
            self.on_import_click()

    def _export(self):
        """导出"""
        if self.on_export_click:
            self.on_export_click()

    def _open_settings(self):
        """打开设置"""
        if self.on_settings_click:
            self.on_settings_click()


class EntryList(ctk.CTkFrame):
    """条目列表组件（使用 tksheet 高性能表格）"""

    # 表格列定义
    COLUMNS = ["名称", "网站", "用户名", "密码", "分类"]
    COL_WIDTHS = [180, 220, 160, 120, 80]

    def __init__(self, parent, on_edit_entry: callable = None, on_delete_entry: callable = None,
                 on_toggle_favorite_entry: callable = None, on_toast: callable = None):
        super().__init__(parent, fg_color="transparent")
        self.on_edit_entry = on_edit_entry
        self.on_delete_entry = on_delete_entry
        self.on_toggle_favorite_entry = on_toggle_favorite_entry
        self.on_toast = on_toast
        self.entries: list[PasswordEntry] = []

        self._create_widgets()

    def _create_widgets(self):
        """创建界面"""
        colors = get_colors()

        # 搜索和操作栏
        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.pack(fill="x", pady=(0, 10))

        # 搜索框
        self.search_var = ctk.StringVar()
        self.search_var.trace_add("write", lambda *args: self._on_search())
        self.search_entry = ctk.CTkEntry(
            toolbar,
            textvariable=self.search_var,
            placeholder_text="🔍 搜索条目...",
            font=FONTS["body"],
        )
        self.search_entry.pack(side="left", fill="x", expand=True)

        self.clear_search_btn = ctk.CTkButton(
            toolbar,
            text="清空",
            font=FONTS["button"],
            fg_color="transparent",
            text_color=COLORS["text_primary"],
            hover_color=COLORS["bg_dark"],
            border_width=1,
            border_color=COLORS["border"],
            width=60,
            command=self._clear_search,
        )
        self.clear_search_btn.pack(side="left", padx=(5, 10))

        # 添加按钮
        self.add_btn = ctk.CTkButton(
            toolbar,
            text="+ 添加",
            font=FONTS["button"],
            fg_color=COLORS["primary"],
            hover_color=COLORS["primary_hover"],
            width=80,
        )
        self.add_btn.pack(side="right")

        # tksheet 表格（高性能，Canvas渲染，支持百万行）
        self.sheet = Sheet(
            self,
            headers=self.COLUMNS,
            show_x_scrollbar=False,
            show_y_scrollbar=True,
            # 浅色主题配色
            table_bg="#FFFFFF",
            table_fg="#111827",
            header_bg="#F3F4F6",
            header_fg="#111827",
            header_border_fg="#D1D5DB",
            index_bg="#F3F4F6",
            index_fg="#111827",
            top_left_bg="#F3F4F6",
            frame_bg="#F3F4F6",
            table_grid_fg="#E5E7EB",
            header_grid_fg="#D1D5DB",
            # 选中样式
            table_selected_cells_bg="#DBEAFE",
            table_selected_cells_fg="#111827",
            table_selected_rows_bg="#DBEAFE",
            table_selected_rows_fg="#111827",
            table_selected_columns_bg="#DBEAFE",
            table_selected_columns_fg="#111827",
            # 字体
            font=("Microsoft YaHei UI", 12, "normal"),
            header_font=("Microsoft YaHei UI", 12, "bold"),
            # 行高
            default_row_height=36,
            default_header_height=40,
        )
        self.sheet.pack(fill="both", expand=True)

        # 设置列宽
        for i, width in enumerate(self.COL_WIDTHS):
            self.sheet.column_width(column=i, width=width)

        # 启用行选择模式
        self.sheet.enable_bindings(
            "single_select",
            "row_select",
            "copy",
            "column_width_resize",
            "double_click_column_resize",
            "right_click_popup_menu",
        )

        # 右键菜单
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="👤 复制账号", command=self._copy_username)
        self.context_menu.add_command(label="🔑 复制密码", command=self._copy_password)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="🌐 打开网页", command=self._open_website)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="⭐ 切换收藏", command=self._toggle_favorite)
        self.context_menu.add_command(label="✏️ 编辑", command=self._edit_selected)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="🗑️ 删除", command=self._delete_selected)

        # 绑定右键菜单
        self.sheet.bind("<Button-3>", self._show_context_menu)
        # 绑定双击编辑
        self.sheet.bind("<Double-Button-1>", self._on_double_click)

    def update_entries(self, entries: list[PasswordEntry]):
        """更新条目列表（重新填充表格数据）"""
        self.entries = entries

        # 转为表格数据
        data = []
        for entry in entries:
            prefix = "⭐ " if entry.is_favorite else ""
            data.append([
                f"{prefix}{entry.name or entry.website}",
                entry.website,
                entry.username,
                "••••••",  # 密码默认隐藏
                entry.category,
            ])

        # 一次性设置数据（tksheet 的高效接口）
        self.sheet.set_sheet_data(data)

        # 恢复列宽
        for i, width in enumerate(self.COL_WIDTHS):
            self.sheet.column_width(column=i, width=width)

    def _get_selected_entry(self) -> Optional[PasswordEntry]:
        """获取当前选中的条目"""
        selected = self.sheet.get_currently_selected()
        if selected:
            row = selected.row
            if 0 <= row < len(self.entries):
                return self.entries[row]
        return None

    def _show_context_menu(self, event):
        """显示右键菜单"""
        # 先选中点击的行
        row = self.sheet.identify_row(event)
        if row is not None and row >= 0 and row < len(self.entries):
            self.sheet.select_row(row)
            self.context_menu.tk_popup(event.x_root, event.y_root)

    def _on_double_click(self, event):
        """双击编辑"""
        entry = self._get_selected_entry()
        if entry and self.on_edit_entry:
            self.on_edit_entry(entry)

    def _copy_password(self):
        """复制密码"""
        entry = self._get_selected_entry()
        if entry:
            self.clipboard_clear()
            self.clipboard_append(entry.password)
            if self.on_toast:
                self.on_toast("✔ 密码已复制到剪贴板")

    def _copy_username(self):
        """复制账号"""
        entry = self._get_selected_entry()
        if entry:
            self.clipboard_clear()
            self.clipboard_append(entry.username)
            if self.on_toast:
                self.on_toast("✔ 账号已复制到剪贴板")

    def _open_website(self):
        """打开网页"""
        entry = self._get_selected_entry()
        if entry and entry.website:
            import webbrowser
            url = entry.website
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
            webbrowser.open(url)

    def _toggle_favorite(self):
        """切换收藏"""
        entry = self._get_selected_entry()
        if entry and self.on_toggle_favorite_entry:
            self.on_toggle_favorite_entry(entry)

    def _edit_selected(self):
        """编辑选中条目"""
        entry = self._get_selected_entry()
        if entry and self.on_edit_entry:
            self.on_edit_entry(entry)

    def _delete_selected(self):
        """删除选中条目"""
        entry = self._get_selected_entry()
        if entry and self.on_delete_entry:
            self.on_delete_entry(entry)

    def _clear_search(self):
        """清空搜索框"""
        self.search_var.set("")

    def _on_search(self):
        """搜索"""
        # 由主窗口处理实际搜索逻辑
        pass
