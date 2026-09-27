import csv
import json
from datetime import datetime
from typing import List

from ..core.models import PasswordEntry
from ..core.database import Database


class ExportService:
    """导出服务"""

    def __init__(self, db: Database):
        self.db = db

    def export_csv(self, file_path: str, entries: List[PasswordEntry] = None):
        """导出为CSV格式"""
        if entries is None:
            entries = self.db.get_all_entries()

        with open(file_path, "w", newline="", encoding="utf-8") as f:
            fieldnames = ["name", "url", "username", "password", "category", "notes"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for entry in entries:
                writer.writerow({
                    "name": entry.name,
                    "url": entry.website,
                    "username": entry.username,
                    "password": entry.password,
                    "category": entry.category,
                    "notes": entry.notes,
                })

    def export_json(self, file_path: str, entries: List[PasswordEntry] = None):
        """导出为JSON格式"""
        if entries is None:
            entries = self.db.get_all_entries()

        data = {
            "exported_at": datetime.now().isoformat(),
            "count": len(entries),
            "entries": [e.to_dict() for e in entries],
        }

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def export_encrypted_json(self, file_path: str, crypto, entries: List[PasswordEntry] = None):
        """导出为加密JSON格式"""
        if entries is None:
            entries = self.db.get_all_entries()

        # 加密每个密码
        encrypted_entries = []
        for entry in entries:
            encrypted_entry = entry.to_dict()
            encrypted_entry["password"] = crypto.encrypt(entry.password)
            encrypted_entries.append(encrypted_entry)

        data = {
            "exported_at": datetime.now().isoformat(),
            "salt": crypto.get_salt_base64(),
            "count": len(entries),
            "entries": encrypted_entries,
        }

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
