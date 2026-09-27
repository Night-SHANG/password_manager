import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog  # 添加导入文件对话框
import webbrowser
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import json
import os
import random
import string
import csv  # 添加CSV文件处理

class PasswordManager:
    def __init__(self, master_password, salt=None):
        self.salt = salt if salt else os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        self.cipher = Fernet(key)
        self.passwords = []

    def encrypt_data(self, data):
        """加密数据"""
        return self.cipher.encrypt(json.dumps(data).encode())

    def decrypt_data(self, encrypted_data):
        """解密数据"""
        return json.loads(self.cipher.decrypt(encrypted_data).decode())

    def save_to_file(self, filename):
        """保存到文件"""
        data = {
            'salt': base64.b64encode(self.salt).decode(),
            'passwords': base64.b64encode(self.encrypt_data(self.passwords)).decode()
        }
        with open(filename, 'w') as f:
            json.dump(data, f)

    @classmethod
    def load_from_file(cls, filename, master_password):
        """从文件加载"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                salt = base64.b64decode(data['salt'])
                encrypted = base64.b64decode(data['passwords'])
        except (FileNotFoundError, json.JSONDecodeError):
            return None

        try:
            pm = cls(master_password, salt)
            pm.passwords = pm.decrypt_data(encrypted)
            return pm
        except:
            return None

    def generate_random_password(self, length=12):
        """生成随机密码"""
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(characters) for i in range(length))

class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.pm = None
        self.current_item = None  # 记录当前选中的条目
        self.initialize_auth()
        
        if self.pm:
            self.root.title("安全密码管理器")
            self.root.geometry("1000x700")
            self.create_widgets()
        else:
            self.root.destroy()

    def initialize_auth(self):
        """汉化验证流程"""
        FILENAME = "vault.enc"
        # 创建一个新的顶级窗口来调整对话框的大小
        top = tk.Toplevel(self.root)
        top.geometry("300x100")
        top.withdraw()  # 隐藏窗口
        master_pwd = simpledialog.askstring("主密码验证", "请输入您的主密码：", show='*', parent=top)
        top.destroy()  # 销毁临时窗口
        
        if not master_pwd:
            self.root.destroy()
            return
            
        self.pm = PasswordManager.load_from_file(FILENAME, master_pwd)
        if not self.pm:
            if messagebox.askyesno("欢迎新用户", "是否创建新的密码库？\n注意：如果创建新的密码库，之前的密码库将会被覆盖。"):
                self.pm = PasswordManager(master_pwd)
                self.pm.save_to_file(FILENAME)
                messagebox.showinfo("提示", "新密码库创建成功！")
            else:
                self.root.destroy()

    def create_widgets(self):
        """创建界面组件"""
        # 左侧输入面板
        input_frame = ttk.LabelFrame(self.root, text="添加新条目", padding=10)
        input_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)
        
        # 输入字段
        ttk.Label(input_frame, text="名称：").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.name_entry = ttk.Entry(input_frame, width=25)
        self.name_entry.grid(row=0, column=1, pady=5)
        
        ttk.Label(input_frame, text="网站：").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.website_entry = ttk.Entry(input_frame, width=25)
        self.website_entry.grid(row=1, column=1, pady=5)
        
        ttk.Label(input_frame, text="用户名：").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.username_entry = ttk.Entry(input_frame, width=25)
        self.username_entry.grid(row=2, column=1, pady=5)
        
        ttk.Label(input_frame, text="密码：").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.password_entry = ttk.Entry(input_frame, width=25, show='*')
        self.password_entry.grid(row=3, column=1, pady=5)
        
        ttk.Button(input_frame, text="添加条目", command=self.add_entry).grid(row=4, columnspan=2, pady=10)
        ttk.Button(input_frame, text="生成随机密码", command=self.generate_password).grid(row=5, columnspan=2, pady=10)
        ttk.Button(input_frame, text="复制密码", command=self.copy_current_password).grid(row=6, columnspan=2, pady=10)
        ttk.Button(input_frame, text="导入Chrome密码", command=self.import_chrome_passwords).grid(row=7, columnspan=2, pady=10)  # 添加导入Chrome密码按钮
        ttk.Button(input_frame, text="导出所有密码", command=self.export_all_passwords).grid(row=8, columnspan=2, pady=10)  # 添加导出所有密码按钮
        
        # 条目数量标签
        self.entry_count_label = ttk.Label(input_frame, text="条目数量: 0")
        self.entry_count_label.grid(row=9, columnspan=2, pady=10)  # 放置在左侧输入面板底部

        # 右侧列表区域
        list_frame = ttk.Frame(self.root)
        list_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 搜索框
        search_frame = ttk.Frame(list_frame)
        search_frame.pack(fill=tk.X, pady=5)
        
        self.search_var = tk.StringVar()
        self.search_var.trace_add('write', lambda *args: self.search_entries())  # 绑定事件
        ttk.Entry(search_frame, textvariable=self.search_var, width=30).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(search_frame, text="清除搜索", command=self.clear_search).pack(side=tk.LEFT, padx=5)  # 添加清除搜索按钮
        
        # 密码列表
        self.tree = ttk.Treeview(list_frame, 
                               columns=('Name', 'Website', 'Username', 'Password'), 
                               show='headings',
                               selectmode='browse')
        
        # 列配置
        columns = [
            ('Name', '名称', 150),
            ('Website', '网站', 250),
            ('Username', '用户名', 150),
            ('Password', '密码', 150)
        ]
        for col_id, col_text, width in columns:
            self.tree.heading(col_id, text=col_text)
            self.tree.column(col_id, width=width, anchor=tk.W)
        
        # 滚动条
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # 事件绑定
        self.tree.bind('<Button-1>', self.on_click)
        
        # 右键菜单
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="打开网站", command=self.open_website)
        self.context_menu.add_command(label="删除条目", command=self.delete_entry)
        self.context_menu.add_command(label="复制密码", command=self.copy_selected_password)
        self.context_menu.add_command(label="复制用户名", command=self.copy_selected_username)  # 添加复制用户名选项
        self.context_menu.add_command(label="复制网站", command=self.copy_selected_website)  # 添加复制网站选项
        self.tree.bind('<Button-3>', self.show_context_menu)

        self.refresh_list()

    def on_click(self, event):
        """处理单击事件"""
        item = self.tree.identify_row(event.y)
        if item:
            # 如果选中新的条目，将之前显示为明文的密码重新加密显示
            if self.current_item and self.current_item != item:
                values = self.tree.item(self.current_item, 'values')
                if values[3] != "******":
                    self.tree.item(self.current_item, values=(values[0], values[1], values[2], "******"))
            
            # 切换选中条目的密码显示状态
            if item == self.current_item:
                self.toggle_password_display(item)
            else:
                self.tree.selection_set(item)
                self.current_item = item

    def toggle_password_display(self, item):
        """切换密码显示状态"""
        values = self.tree.item(item, 'values')
        try:
            entry = next(e for e in self.pm.passwords 
                         if e.get('name', '') == values[0] and e['website'] == values[1] and e['username'] == values[2])
        except StopIteration:
            return
        
        # 切换密码显示状态
        if values[3] == "******":
            self.tree.item(item, values=(values[0], values[1], values[2], entry['password']))
        else:
            self.tree.item(item, values=(values[0], values[1], values[2], "******"))

    def add_entry(self):
        """添加条目"""
        name = self.name_entry.get()
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not password:
            messagebox.showwarning("输入错误", "密码字段不能为空")
            return
        
        # 检查是否存在相同网站和用户名的条目
        for entry in self.pm.passwords:
            if entry['website'] == website and entry['username'] == username:
                messagebox.showwarning("重复条目", "该网站下已存在相同用户名的密码")
                return
            
        self.pm.passwords.append({
            'name': name,
            'website': website,
            'username': username,
            'password': password
        })
        self.pm.save_to_file("vault.enc")
        self.refresh_list()
        
        # 清空输入
        self.name_entry.delete(0, tk.END)
        self.website_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        messagebox.showinfo("操作成功", "条目已成功添加！")

    def refresh_list(self):
        """刷新列表"""
        self.current_item = None  # 重置当前选中的条目
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        for entry in self.pm.passwords:
            self.tree.insert('', 'end', values=(
                entry.get('name', ''),
                entry['website'],
                entry['username'],
                "******"  # 密码占位符
            ))
        
        # 更新条目数量标签
        self.entry_count_label.config(text=f"条目数量: {len(self.pm.passwords)}")

    def copy_password(self, password):
        """复制密码到剪贴板"""
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        messagebox.showinfo("复制成功", "密码已复制到剪贴板")

    def search_entries(self):
        """搜索功能"""
        query = self.search_var.get().lower()
        self.refresh_list()
        first_item = None
        for item in self.tree.get_children():
            values = self.tree.item(item, 'values')
            try:
                entry = next(e for e in self.pm.passwords 
                             if e.get('name', '') == values[0] and e['website'] == values[1] and e['username'] == values[2])
            except StopIteration:
                continue
            decrypted_password = entry['password']
            if query not in values[0].lower() and query not in values[1].lower() and query not in values[2].lower() and query not in decrypted_password.lower():
                self.tree.detach(item)
            else:
                if first_item is None:
                    first_item = item
                self.tree.selection_set(item)  # 确保搜索结果中的条目可以被选中
        
        if first_item:
            self.tree.selection_set(first_item)  # 选中搜索结果中的第一个条目
            self.tree.focus(first_item)  # 确保焦点在第一个条目上
            self.current_item = first_item  # 更新当前选中的条目

    def open_website(self):
        """打开网站"""
        item = self.tree.selection()[0]
        website = self.tree.item(item, 'values')[1]
        if not website.startswith(('http://', 'https://')):
            website = 'https://' + website
        webbrowser.open(website)

    def delete_entry(self):
        """删除条目"""
        item = self.tree.selection()[0]
        values = self.tree.item(item, 'values')
        
        self.pm.passwords = [
            e for e in self.pm.passwords 
            if not (e['website'] == values[1] and e['username'] == values[2])
        ]
        self.pm.save_to_file("vault.enc")
        self.refresh_list()
        messagebox.showinfo("操作成功", "条目已删除")

    def show_context_menu(self, event):
        """右键菜单"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def copy_selected_password(self):
        """复制选中的密码"""
        item = self.tree.selection()[0]
        values = self.tree.item(item, 'values')
        try:
            entry = next(e for e in self.pm.passwords 
                         if e['website'] == values[1] and e['username'] == values[2])
        except StopIteration:
            return
        self.copy_password(entry['password'])

    def copy_selected_username(self):
        """复制选中的用户名"""
        item = self.tree.selection()[0]
        username = self.tree.item(item, 'values')[2]
        self.copy_to_clipboard(username, "用户名")

    def copy_selected_website(self):
        """复制选中的网站"""
        item = self.tree.selection()[0]
        website = self.tree.item(item, 'values')[1]
        self.copy_to_clipboard(website, "网站")

    def copy_to_clipboard(self, text, label):
        """复制文本到剪贴板"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("复制成功", f"{label}已复制到剪贴板")

    def generate_password(self):
        """生成随机密码"""
        random_password = self.pm.generate_random_password()
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, random_password)
        messagebox.showinfo("生成的密码", f"生成的随机密码是：{random_password}")

    def copy_current_password(self):
        """复制当前输入框中的密码或选中的密码"""
        password = self.password_entry.get()
        if password:
            self.copy_password(password)
        else:
            selected_items = self.tree.selection()
            if selected_items:
                self.copy_selected_password()
            else:
                messagebox.showwarning("复制失败", "密码输入框为空且未选中任何条目")

    def clear_search(self):
        """清除搜索框"""
        self.search_var.set("")
        self.refresh_list()

    def import_chrome_passwords(self):
        """导入Chrome密码"""
        file_path = filedialog.askopenfilename(
            title="选择Chrome密码CSV文件",
            filetypes=[("CSV文件", "*.csv")]
        )
        if not file_path:
            return

        try:
            with open(file_path, newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    website = row['url']
                    username = row['username']
                    password = row['password']
                    name = row.get('name', 'Chrome Import')
                    
                    # 检查是否存在相同网站和用户名的条目
                    if any(e['website'] == website and e['username'] == username for e in self.pm.passwords):
                        continue
                    
                    self.pm.passwords.append({
                        'name': name,
                        'website': website,
                        'username': username,
                        'password': password
                    })
            self.pm.save_to_file("vault.enc")
            self.refresh_list()
            messagebox.showinfo("导入成功", "Chrome密码已成功导入！")
        except Exception as e:
            messagebox.showerror("导入失败", f"导入Chrome密码时出错：{e}")

    def export_all_passwords(self):
        """导出所有密码"""
        file_path = filedialog.asksaveasfilename(
            title="导出所有密码",
            defaultextension=".csv",
            filetypes=[("CSV文件", "*.csv")]
        )
        if not file_path:
            return

        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['name', 'url', 'username', 'password']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for entry in self.pm.passwords:
                    writer.writerow({
                        'name': entry.get('name', ''),
                        'url': entry['website'],
                        'username': entry['username'],
                        'password': entry['password']
                    })
            messagebox.showinfo("导出成功", "所有密码已成功导出！")
        except Exception as e:
            messagebox.showerror("导出失败", f"导出所有密码时出错：{e}")

if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()  # 隐藏主窗口
    app = PasswordManagerGUI(root)
    root.deiconify()  # 显示主窗口
    root.mainloop()