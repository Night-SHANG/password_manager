import sqlite3
from typing import List, Optional
from .models import PasswordEntry, Category, DEFAULT_CATEGORIES


class Database:
    """SQLite数据库管理器"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = None

    def connect(self):
        """连接数据库"""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")

    def close(self):
        """关闭连接"""
        if self.conn:
            self.conn.close()
            self.conn = None

    def init_tables(self):
        """初始化表结构"""
        cursor = self.conn.cursor()

        # 密码库元数据表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vault_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)

        # 分类表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                icon TEXT DEFAULT '📁',
                sort_order INTEGER DEFAULT 0
            )
        """)
        
        # 兼容旧版本：尝试添加 sort_order 字段（如果已存在则忽略）
        try:
            cursor.execute("ALTER TABLE categories ADD COLUMN sort_order INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass

        # 密码条目表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT DEFAULT '',
                website TEXT DEFAULT '',
                username TEXT DEFAULT '',
                password TEXT NOT NULL,
                category TEXT DEFAULT '其他',
                notes TEXT DEFAULT '',
                is_favorite INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (category) REFERENCES categories(name) ON DELETE SET DEFAULT
            )
        """)

        # 创建索引
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_entries_category ON entries(category)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_entries_favorite ON entries(is_favorite)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_entries_website ON entries(website)")

        self.conn.commit()

    def init_default_categories(self):
        """初始化默认分类"""
        cursor = self.conn.cursor()
        for cat in DEFAULT_CATEGORIES:
            cursor.execute(
                "INSERT OR IGNORE INTO categories (name, icon, sort_order) VALUES (?, ?, ?)",
                (cat.name, cat.icon, cat.sort_order),
            )
        self.conn.commit()

    # ---------- 元数据操作 ----------

    def set_meta(self, key: str, value: str):
        """设置元数据"""
        self.conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)",
            (key, value),
        )
        self.conn.commit()

    def get_meta(self, key: str) -> Optional[str]:
        """获取元数据"""
        row = self.conn.execute(
            "SELECT value FROM vault_meta WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else None

    # ---------- 分类操作 ----------

    def get_categories(self) -> List[Category]:
        """获取所有分类"""
        rows = self.conn.execute("SELECT * FROM categories ORDER BY sort_order ASC, name ASC").fetchall()
        return [Category.from_dict(dict(row)) for row in rows]

    def add_category(self, name: str, icon: str = "📁", sort_order: int = 0) -> bool:
        """添加分类"""
        try:
            self.conn.execute(
                "INSERT INTO categories (name, icon, sort_order) VALUES (?, ?, ?)", (name, icon, sort_order)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def delete_category(self, name: str):
        """删除分类，相关条目归入'其他'"""
        self.conn.execute(
            "UPDATE entries SET category = '其他' WHERE category = ?", (name,)
        )
        self.conn.execute("DELETE FROM categories WHERE name = ?", (name,))
        self.conn.commit()

    def rename_category(self, old_name: str, new_name: str) -> bool:
        """重命名分类"""
        try:
            self.conn.execute(
                "UPDATE categories SET name = ? WHERE name = ?", (new_name, old_name)
            )
            self.conn.execute(
                "UPDATE entries SET category = ? WHERE category = ?",
                (new_name, old_name),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def update_category_order(self, name: str, sort_order: int) -> bool:
        """更新分类排序"""
        try:
            self.conn.execute(
                "UPDATE categories SET sort_order = ? WHERE name = ?", (sort_order, name)
            )
            self.conn.commit()
            return True
        except Exception:
            return False

    # ---------- 条目操作 ----------

    def add_entry(self, entry: PasswordEntry) -> int:
        """添加条目，返回ID"""
        cursor = self.conn.execute(
            """INSERT INTO entries (name, website, username, password, category, notes, is_favorite, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                entry.name,
                entry.website,
                entry.username,
                entry.password,
                entry.category,
                entry.notes,
                1 if entry.is_favorite else 0,
                entry.created_at,
                entry.updated_at,
            ),
        )
        self.conn.commit()
        return cursor.lastrowid

    def update_entry(self, entry: PasswordEntry):
        """更新条目"""
        self.conn.execute(
            """UPDATE entries SET name=?, website=?, username=?, password=?,
            category=?, notes=?, is_favorite=?, updated_at=? WHERE id=?""",
            (
                entry.name,
                entry.website,
                entry.username,
                entry.password,
                entry.category,
                entry.notes,
                1 if entry.is_favorite else 0,
                entry.updated_at,
                entry.id,
            ),
        )
        self.conn.commit()

    def delete_entry(self, entry_id: int):
        """删除条目"""
        self.conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
        self.conn.commit()

    def get_entry(self, entry_id: int) -> Optional[PasswordEntry]:
        """获取单个条目"""
        row = self.conn.execute(
            "SELECT * FROM entries WHERE id = ?", (entry_id,)
        ).fetchone()
        if row:
            data = dict(row)
            data["is_favorite"] = bool(data["is_favorite"])
            return PasswordEntry.from_dict(data)
        return None

    def get_all_entries(self) -> List[PasswordEntry]:
        """获取所有条目"""
        rows = self.conn.execute(
            "SELECT * FROM entries ORDER BY is_favorite DESC, updated_at DESC"
        ).fetchall()
        result = []
        for row in rows:
            data = dict(row)
            data["is_favorite"] = bool(data["is_favorite"])
            result.append(PasswordEntry.from_dict(data))
        return result

    def get_entries_by_category(self, category: str) -> List[PasswordEntry]:
        """按分类获取条目"""
        rows = self.conn.execute(
            "SELECT * FROM entries WHERE category = ? ORDER BY is_favorite DESC, updated_at DESC",
            (category,),
        ).fetchall()
        result = []
        for row in rows:
            data = dict(row)
            data["is_favorite"] = bool(data["is_favorite"])
            result.append(PasswordEntry.from_dict(data))
        return result

    def get_favorite_entries(self) -> List[PasswordEntry]:
        """获取收藏条目"""
        rows = self.conn.execute(
            "SELECT * FROM entries WHERE is_favorite = 1 ORDER BY updated_at DESC"
        ).fetchall()
        return [PasswordEntry.from_dict({**dict(row), "is_favorite": True}) for row in rows]

    def search_entries(self, query: str) -> List[PasswordEntry]:
        """搜索条目"""
        pattern = f"%{query}%"
        rows = self.conn.execute(
            """SELECT * FROM entries
            WHERE name LIKE ? OR website LIKE ? OR username LIKE ? OR notes LIKE ?
            ORDER BY is_favorite DESC, updated_at DESC""",
            (pattern, pattern, pattern, pattern),
        ).fetchall()
        result = []
        for row in rows:
            data = dict(row)
            data["is_favorite"] = bool(data["is_favorite"])
            result.append(PasswordEntry.from_dict(data))
        return result

    def get_entry_count(self) -> int:
        """获取条目数量"""
        row = self.conn.execute("SELECT COUNT(*) as cnt FROM entries").fetchone()
        return row["cnt"]

    def get_category_counts(self) -> dict:
        """用SQL直接统计每个分类的条目数量，不需要加载/解密条目"""
        rows = self.conn.execute(
            "SELECT category, COUNT(*) as cnt FROM entries GROUP BY category"
        ).fetchall()
        return {row["category"]: row["cnt"] for row in rows}

    def get_favorite_count(self) -> int:
        """获取收藏条目数量"""
        row = self.conn.execute(
            "SELECT COUNT(*) as cnt FROM entries WHERE is_favorite = 1"
        ).fetchone()
        return row["cnt"]

    def toggle_favorite(self, entry_id: int):
        """切换收藏状态"""
        self.conn.execute(
            "UPDATE entries SET is_favorite = NOT is_favorite WHERE id = ?", (entry_id,)
        )
        self.conn.commit()

    def entry_exists(self, website: str, username: str) -> bool:
        """检查是否存在相同网站+用户名的条目"""
        row = self.conn.execute(
            "SELECT 1 FROM entries WHERE website = ? AND username = ?",
            (website, username),
        ).fetchone()
        return row is not None
