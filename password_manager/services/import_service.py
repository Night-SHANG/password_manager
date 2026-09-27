import csv
import json
import base64
from datetime import datetime
from typing import List, Tuple

from ..core.models import PasswordEntry
from .password_service import PasswordService


class ImportService:
    """导入服务"""

    def __init__(self, password_service: PasswordService):
        self.ps = password_service

    def _find_existing_entry(self, website: str, username: str):
        """从缓存中查找已存在的条目（按网址+账号匹配）"""
        for e in self.ps._cache:
            if e.website == website and e.username == username:
                return e
        return None

    def import_csv(self, file_path: str, strategy: str = "skip") -> Tuple[int, int, int]:
        """导入CSV文件，返回 (新增数, 跳过数, 更新数)
        
        strategy: 
            "skip" - 跳过已存在的条目（默认）
            "overwrite" - 用导入文件中的密码覆盖已存在的条目
        """
        success = 0
        skipped = 0
        updated = 0

        with open(file_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # 支持多种CSV格式
                website = row.get("url", row.get("website", row.get("URL", "")))
                username = row.get("username", row.get("user", row.get("Username", "")))
                password = row.get("password", row.get("Password", ""))
                name = row.get("name", row.get("Name", row.get("title", "")))

                if not website and not username and not password:
                    skipped += 1
                    continue

                # 检查重复
                if self.ps.db.entry_exists(website, username):
                    if strategy == "overwrite":
                        # 覆盖模式：查找已有条目并更新密码
                        existing = self._find_existing_entry(website, username)
                        if existing and existing.password != password:
                            existing.password = password
                            existing.name = name or existing.name
                            existing.updated_at = datetime.now().isoformat()
                            self.ps.update_entry(existing)
                            updated += 1
                        else:
                            # 密码相同，无需更新
                            skipped += 1
                    else:
                        skipped += 1
                    continue

                entry = PasswordEntry(
                    name=name or website,
                    website=website,
                    username=username,
                    password=password,
                    category="其他",
                    created_at=datetime.now().isoformat(),
                    updated_at=datetime.now().isoformat(),
                )
                self.ps.add_entry(entry)
                success += 1

        return success, skipped, updated

    def import_chrome_csv(self, file_path: str) -> Tuple[int, int]:
        """导入Chrome导出的CSV"""
        return self.import_csv(file_path)

    def import_json(self, file_path: str) -> Tuple[int, int]:
        """导入JSON格式"""
        success = 0
        skipped = 0

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, list):
            entries = data
        elif isinstance(data, dict) and "entries" in data:
            entries = data["entries"]
        elif isinstance(data, dict) and "passwords" in data:
            entries = data["passwords"]
        else:
            return 0, 0

        for item in entries:
            website = item.get("website", item.get("url", ""))
            username = item.get("username", "")
            password = item.get("password", "")
            name = item.get("name", "")

            if not password:
                skipped += 1
                continue

            if self.ps.db.entry_exists(website, username):
                skipped += 1
                continue

            entry = PasswordEntry(
                name=name or website,
                website=website,
                username=username,
                password=password,
                category=item.get("category", "其他"),
                notes=item.get("notes", ""),
                created_at=datetime.now().isoformat(),
                updated_at=datetime.now().isoformat(),
            )
            self.ps.add_entry(entry)
            success += 1

        return success, skipped

    def import_vault_enc(self, file_path: str, master_password: str) -> Tuple[int, int]:
        """导入旧版vault.enc文件"""
        try:
            with open(file_path, "r") as f:
                data = json.load(f)

            salt_b64 = data.get("salt")
            passwords_b64 = data.get("passwords")

            if not salt_b64 or not passwords_b64:
                return 0, 0

            # 使用旧版加密方式解密
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

            salt = base64.b64decode(salt_b64)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=480000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
            cipher = Fernet(key)

            encrypted = base64.b64decode(passwords_b64)
            passwords = json.loads(cipher.decrypt(encrypted).decode())

            success = 0
            skipped = 0

            for item in passwords:
                website = item.get("website", "")
                username = item.get("username", "")
                password = item.get("password", "")
                name = item.get("name", "")

                if self.ps.db.entry_exists(website, username):
                    skipped += 1
                    continue

                entry = PasswordEntry(
                    name=name or website,
                    website=website,
                    username=username,
                    password=password,
                    category="其他",
                    created_at=datetime.now().isoformat(),
                    updated_at=datetime.now().isoformat(),
                )
                self.ps.add_entry(entry)
                success += 1

            return success, skipped

        except Exception as e:
            raise Exception(f"导入vault.enc失败: {e}")
