import os
from datetime import datetime
from typing import List, Optional

from ..core.crypto import CryptoManager
from ..core.database import Database
from ..core.models import PasswordEntry, Category


class PasswordService:
    """密码管理服务层（带内存缓存）"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.db = Database(db_path)
        self.crypto: Optional[CryptoManager] = None
        self._cache: List[PasswordEntry] = []  # 解密后的内存缓存
        self._cache_loaded = False

    def init_vault(self, master_password: str) -> bool:
        """初始化新密码库"""
        self.db.connect()
        self.db.init_tables()

        crypto = CryptoManager(master_password)

        # 保存salt和验证数据
        self.db.set_meta("salt", crypto.get_salt_base64())
        self.db.set_meta("verify", crypto.encrypt("verify"))
        self.db.set_meta("created_at", datetime.now().isoformat())
        self.db.set_meta("updated_at", datetime.now().isoformat())

        self.db.init_default_categories()
        self.crypto = crypto
        self._cache = []
        self._cache_loaded = True
        return True

    def open_vault(self, master_password: str) -> bool:
        """打开现有密码库"""
        if not os.path.exists(self.db_path):
            return False

        self.db.connect()
        self.db.init_tables()

        salt_b64 = self.db.get_meta("salt")
        verify_data = self.db.get_meta("verify")

        if not salt_b64 or not verify_data:
            self.db.close()
            return False

        if not CryptoManager.verify_password(master_password, salt_b64, verify_data):
            self.db.close()
            return False

        self.crypto = CryptoManager.from_salt_base64(master_password, salt_b64)
        # 登录成功后一次性解密所有条目到内存
        self._load_cache()
        return True

    def _load_cache(self):
        """一次性解密所有条目到内存缓存"""
        entries = self.db.get_all_entries()
        self._cache = [self._decrypt_entry(e) for e in entries]
        self._cache_loaded = True

    def close(self):
        """关闭密码库"""
        self.db.close()
        self.crypto = None
        self._cache = []
        self._cache_loaded = False

    # ---------- 条目操作 ----------

    def add_entry(self, entry: PasswordEntry) -> int:
        """添加条目（同时更新数据库和缓存）"""
        encrypted_entry = self._encrypt_entry(entry)
        entry_id = self.db.add_entry(encrypted_entry)
        entry.id = entry_id
        self._cache.append(entry)
        self._update_timestamp()
        return entry_id

    def update_entry(self, entry: PasswordEntry):
        """更新条目（同时更新数据库和缓存）"""
        encrypted_entry = self._encrypt_entry(entry)
        self.db.update_entry(encrypted_entry)
        # 更新缓存中对应的条目
        for i, cached in enumerate(self._cache):
            if cached.id == entry.id:
                self._cache[i] = entry
                break
        self._update_timestamp()

    def delete_entry(self, entry_id: int):
        """删除条目（同时更新数据库和缓存）"""
        self.db.delete_entry(entry_id)
        self._cache = [e for e in self._cache if e.id != entry_id]
        self._update_timestamp()

    def get_entry(self, entry_id: int) -> Optional[PasswordEntry]:
        """获取单个条目（从缓存）"""
        for e in self._cache:
            if e.id == entry_id:
                return e
        return None

    def get_all_entries(self) -> List[PasswordEntry]:
        """获取所有条目（从缓存，按名称排序）"""
        return sorted(self._cache, 
                       key=lambda e: e.name.lower(), 
                       reverse=False)

    def get_entries_by_category(self, category: str) -> List[PasswordEntry]:
        """按分类获取条目（从缓存）"""
        return [e for e in self._cache if e.category == category]

    def get_favorite_entries(self) -> List[PasswordEntry]:
        """获取收藏条目（从缓存）"""
        return [e for e in self._cache if e.is_favorite]

    def search_entries(self, query: str) -> List[PasswordEntry]:
        """搜索条目（从缓存，内存过滤）"""
        if not query:
            return self.get_all_entries()

        query_lower = query.lower()
        return [
            e for e in self._cache
            if query_lower in e.name.lower()
            or query_lower in e.website.lower()
            or query_lower in e.username.lower()
            or query_lower in e.notes.lower()
            or query_lower in e.password.lower()
        ]

    def toggle_favorite(self, entry_id: int):
        """切换收藏状态（同时更新数据库和缓存）"""
        self.db.toggle_favorite(entry_id)
        for e in self._cache:
            if e.id == entry_id:
                e.is_favorite = not e.is_favorite
                break
        self._update_timestamp()

    def get_entry_count(self) -> int:
        """获取条目数量（从缓存）"""
        return len(self._cache)

    def get_category_counts(self) -> dict:
        """获取每个分类的条目数量（从缓存）"""
        counts = {}
        for e in self._cache:
            counts[e.category] = counts.get(e.category, 0) + 1
        return counts

    def get_favorite_count(self) -> int:
        """获取收藏条目数量（从缓存）"""
        return sum(1 for e in self._cache if e.is_favorite)

    # ---------- 分类操作 ----------

    def get_categories(self) -> List[Category]:
        """获取所有分类"""
        return self.db.get_categories()

    def add_category(self, name: str, icon: str = "📁") -> bool:
        """添加分类"""
        categories = self.get_categories()
        custom_cats = [c for c in categories if c.name != "其他"]
        max_order = max([c.sort_order for c in custom_cats], default=10)
        return self.db.add_category(name, icon, sort_order=max_order + 1)

    def delete_category(self, name: str):
        """删除分类（同时更新缓存中的分类归属）"""
        self.db.delete_category(name)
        for e in self._cache:
            if e.category == name:
                e.category = "其他"

    def rename_category(self, old_name: str, new_name: str) -> bool:
        """重命名分类（同时更新缓存）"""
        result = self.db.rename_category(old_name, new_name)
        if result:
            for e in self._cache:
                if e.category == old_name:
                    e.category = new_name
        return result

    def update_category_order(self, name: str, sort_order: int) -> bool:
        """更新分类排序"""
        return self.db.update_category_order(name, sort_order)

    # ---------- 内部方法 ----------

    def _encrypt_entry(self, entry: PasswordEntry) -> PasswordEntry:
        """加密条目中的密码字段"""
        encrypted = PasswordEntry(
            id=entry.id,
            name=entry.name,
            website=entry.website,
            username=entry.username,
            password=self.crypto.encrypt(entry.password),
            category=entry.category,
            notes=entry.notes,
            is_favorite=entry.is_favorite,
            created_at=entry.created_at,
            updated_at=entry.updated_at,
        )
        return encrypted

    def _decrypt_entry(self, entry: PasswordEntry) -> PasswordEntry:
        """解密条目中的密码字段"""
        try:
            decrypted = PasswordEntry(
                id=entry.id,
                name=entry.name,
                website=entry.website,
                username=entry.username,
                password=self.crypto.decrypt(entry.password),
                category=entry.category,
                notes=entry.notes,
                is_favorite=entry.is_favorite,
                created_at=entry.created_at,
                updated_at=entry.updated_at,
            )
            return decrypted
        except Exception:
            return entry

    def _update_timestamp(self):
        """更新密码库时间戳"""
        self.db.set_meta("updated_at", datetime.now().isoformat())
