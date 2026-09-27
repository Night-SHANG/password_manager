import customtkinter as ctk


# 颜色方案（浅色主题专用）
COLORS = {
    "primary": "#2563EB",       # 主色调（蓝色）
    "primary_hover": "#1D4ED8",
    "success": "#10B981",       # 成功（绿色）
    "warning": "#F59E0B",       # 警告（黄色）
    "danger": "#EF4444",        # 危险（红色）
    "bg_dark": "#F3F4F6",       # 深色背景
    "bg_medium": "#E5E7EB",     # 中等背景
    "bg_light": "#D1D5DB",      # 浅色背景
    "text_primary": "#111827",  # 主文字（深色）
    "text_secondary": "#374151",# 次要文字
    "text_muted": "#6B7280",    # 弱化文字（加深，确保可读）
    "border": "#D1D5DB",        # 边框
    "sidebar_bg": "#F9FAFB",    # 侧边栏背景
    "card_bg": "#FFFFFF",       # 卡片背景
    "favorite": "#FBBF24",      # 收藏星标
}


def get_colors() -> dict:
    """获取颜色（兼容旧代码）"""
    return COLORS


def setup_theme():
    """初始化主题配置"""
    ctk.set_appearance_mode("light")
    ctk.set_default_color_theme("blue")


def center_window(window, width: int, height: int):
    """让窗口在屏幕中央显示"""
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2
    window.geometry(f"{width}x{height}+{x}+{y}")


def get_font(size: int = 13, weight: str = "normal") -> tuple:
    """获取字体配置"""
    return ("Microsoft YaHei UI", size, weight)


# 字体预设
FONTS = {
    "title": get_font(18, "bold"),
    "heading": get_font(15, "bold"),
    "body": get_font(13),
    "small": get_font(11),
    "button": get_font(13),
    "mono": ("Consolas", 13),
}
