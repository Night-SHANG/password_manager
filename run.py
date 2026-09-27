import sys
import os
import threading
import socket
import uvicorn
import webview


def get_app_dir():
    """获取程序资源目录（web 目录、图标等内置资源的位置）"""
    if getattr(sys, 'frozen', False):
        # PyInstaller 6.x 文件夹模式：资源在 _internal 目录中
        # sys._MEIPASS 指向 _internal 目录
        return sys._MEIPASS
    else:
        # 开发环境，获取脚本所在目录
        return os.path.dirname(os.path.abspath(__file__))


def get_data_dir():
    """获取用户数据目录（passwords.db 等用户文件的位置，和 EXE 同级）"""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port


def get_center_position(width, height):
    """获取屏幕居中的窗口坐标"""
    try:
        import ctypes
        user32 = ctypes.windll.user32
        screen_w = user32.GetSystemMetrics(0)
        screen_h = user32.GetSystemMetrics(1)
        x = (screen_w - width) // 2
        y = (screen_h - height) // 2
        return x, y
    except Exception:
        return None, None


def main():
    try:
        # 1. 确定目录
        app_dir = get_app_dir()    # 程序资源（web、icon.ico）
        data_dir = get_data_dir()  # 用户数据（passwords.db）
        os.chdir(data_dir)

        # 2. 配置路径
        db_path = os.path.join(data_dir, "passwords.db")
        web_dir = os.path.join(app_dir, "web")
        icon_path = os.path.join(app_dir, "icon.ico")

        # 3. 将路径注入 API 模块（必须在 import 之前设置）
        os.environ['PM_DB_PATH'] = db_path
        os.environ['PM_WEB_DIR'] = web_dir

        # 4. 延迟导入 API 模块（等环境变量设置完毕后再加载）
        from password_manager.api.main import app, API_TOKEN

        # 5. 寻找空闲端口
        port = find_free_port()

        # 6. 在后台线程启动 FastAPI 服务
        def start_server():
            uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")

        server_thread = threading.Thread(target=start_server, daemon=True)
        server_thread.start()

        # 7. 构建安全的本地访问 URL
        url = f"http://127.0.0.1:{port}/web/index.html?port={port}&token={API_TOKEN}"

        # 8. 计算窗口居中位置
        win_w, win_h = 1200, 800
        x, y = get_center_position(win_w, win_h)

        # 9. 启动 WebView 窗口（如果图标存在则设置图标）
        window_kwargs = dict(
            title="密码管理器",
            url=url,
            width=win_w,
            height=win_h,
            x=x,
            y=y,
            min_size=(900, 600),
            background_color='#f9fafb'
        )
        window = webview.create_window(**window_kwargs)
        webview.start(debug=False)

    except Exception as e:
        print(f"Error starting application: {e}")
        import traceback
        traceback.print_exc()
        input("Press Enter to exit...")


if __name__ == "__main__":
    main()
