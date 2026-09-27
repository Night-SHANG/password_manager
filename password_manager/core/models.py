from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class PasswordEntry:
    """密码条目数据模型"""
    id: Optional[int] = None
    name: str = ""
    website: str = ""
    username: str = ""
    password: str = ""
    category: str = "其他"
    notes: str = ""
    is_favorite: bool = False
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "website": self.website,
            "username": self.username,
            "password": self.password,
            "category": self.category,
            "notes": self.notes,
            "is_favorite": self.is_favorite,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PasswordEntry":
        return cls(
            id=data.get("id"),
            name=data.get("name", ""),
            website=data.get("website", ""),
            username=data.get("username", ""),
            password=data.get("password", ""),
            category=data.get("category", "其他"),
            notes=data.get("notes", ""),
            is_favorite=data.get("is_favorite", False),
            created_at=data.get("created_at", datetime.now().isoformat()),
            updated_at=data.get("updated_at", datetime.now().isoformat()),
        )


@dataclass
class Category:
    """分类数据模型"""
    id: Optional[int] = None
    name: str = ""
    icon: str = "📁"
    sort_order: int = 0

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "icon": self.icon, "sort_order": self.sort_order}

    @classmethod
    def from_dict(cls, data: dict) -> "Category":
        return cls(
            id=data.get("id"),
            name=data.get("name", ""),
            icon=data.get("icon", "📁"),
            sort_order=data.get("sort_order", 0),
        )


# 默认分类
DEFAULT_CATEGORIES = [
    Category(name="其他", icon="📁", sort_order=999),
]
