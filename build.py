"""打包脚本 - 使用Nuitka"""
import subprocess
import sys
import os


def build():
    """打包为exe"""
    cmd = [
        sys.executable, "-m", "nuitka",
        "--standalone",
        "--onefile",
        "--windows-console-mode=disable",
        "--windows-icon-from-ico=icon.ico" if os.path.exists("icon.ico") else "",
        "--include-package=customtkinter",
        "--include-package=cryptography",
        "--output-filename=密码管理器.exe",
        "run.py",
    ]

    # 移除空字符串
    cmd = [c for c in cmd if c]

    print("开始打包...")
    print(" ".join(cmd))

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        print("打包成功！")
        print(f"输出文件: 密码管理器.exe")
    else:
        print("打包失败:")
        print(result.stderr)


if __name__ == "__main__":
    build()
