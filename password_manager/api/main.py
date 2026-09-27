import os
import secrets
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

from password_manager.services.password_service import PasswordService
from password_manager.core.models import PasswordEntry, Category
from password_manager.services.import_service import ImportService
from password_manager.services.export_service import ExportService
import tkinter as tk
from tkinter import filedialog
from fastapi.staticfiles import StaticFiles

app = FastAPI()

# 挂载静态资源（路径由 run.py 通过环境变量注入）
web_dir = os.environ.get('PM_WEB_DIR', os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "web"))
app.mount("/web", StaticFiles(directory=web_dir), name="web")


# 跨域设置（允许本地WebView访问）
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 生成一个随机的 API 访问令牌，防止本地其他程序恶意请求
API_TOKEN = secrets.token_hex(16)

# 初始化服务（路径由 run.py 通过环境变量注入）
DB_PATH = os.environ.get('PM_DB_PATH', "passwords.db")
service = PasswordService(DB_PATH)

def verify_token(authorization: str = Header(None)):
    """验证内部 API 令牌"""
    if not authorization or authorization.replace("Bearer ", "") != API_TOKEN:
        raise HTTPException(status_code=403, detail="Unauthorized API Access")

# ----- 请求与响应模型 -----

class LoginRequest(BaseModel):
    password: str

class InitRequest(BaseModel):
    password: str

class CategoryRequest(BaseModel):
    name: str
    icon: Optional[str] = "📁"

class CategoryOrderRequest(BaseModel):
    name: str
    sort_order: int

class EntryRequest(BaseModel):
    name: str
    website: str
    username: str
    password: str
    category: str
    notes: Optional[str] = ""

class EntryUpdateRequest(EntryRequest):
    id: int
    is_favorite: bool

# ----- 路由 -----

@app.get("/api/config")
def get_config():
    """获取启动配置（前端用于判断是否已初始化等）"""
    has_db = os.path.exists(DB_PATH)
    return {"has_db": has_db, "is_unlocked": service.crypto is not None}

@app.post("/api/init")
def init_vault(req: InitRequest):
    if service.init_vault(req.password):
        service.open_vault(req.password)  # 初始化后直接解锁
        return {"success": True}
    raise HTTPException(400, "Initialization failed")

@app.post("/api/login")
def login(req: LoginRequest):
    if service.open_vault(req.password):
        return {"success": True}
    raise HTTPException(401, "Invalid password")

# 以下接口需要令牌验证
@app.get("/api/stats", dependencies=[Depends(verify_token)])
def get_stats():
    return {
        "total": service.get_entry_count(),
        "favorite": service.get_favorite_count(),
        "categories": service.get_category_counts()
    }

@app.get("/api/categories", dependencies=[Depends(verify_token)])
def get_categories():
    return [c.__dict__ for c in service.get_categories()]

@app.post("/api/categories", dependencies=[Depends(verify_token)])
def add_category(req: CategoryRequest):
    if service.add_category(req.name, req.icon):
        return {"success": True}
    raise HTTPException(400, "Category already exists")

@app.delete("/api/categories/{name}", dependencies=[Depends(verify_token)])
def delete_category(name: str):
    service.delete_category(name)
    return {"success": True}

@app.put("/api/categories/reorder", dependencies=[Depends(verify_token)])
def reorder_categories(reqs: List[CategoryOrderRequest]):
    for req in reqs:
        service.update_category_order(req.name, req.sort_order)
    return {"success": True}

@app.get("/api/entries", dependencies=[Depends(verify_token)])
def get_entries(category: Optional[str] = None, search: Optional[str] = None):
    if search:
        entries = service.search_entries(search)
    elif category == "全部" or not category:
        entries = service.get_all_entries()
    elif category == "收藏":
        entries = service.get_favorite_entries()
    else:
        entries = service.get_entries_by_category(category)
    return [e.__dict__ for e in entries]

@app.post("/api/entries", dependencies=[Depends(verify_token)])
def add_entry(req: EntryRequest):
    entry = PasswordEntry(
        id=0,
        name=req.name,
        website=req.website,
        username=req.username,
        password=req.password,
        category=req.category,
        notes=req.notes
    )
    entry_id = service.add_entry(entry)
    return {"success": True, "id": entry_id}

@app.put("/api/entries/{entry_id}", dependencies=[Depends(verify_token)])
def update_entry(entry_id: int, req: EntryUpdateRequest):
    existing = service.get_entry(entry_id)
    if not existing:
        raise HTTPException(404, "Entry not found")
        
    entry = PasswordEntry(
        id=entry_id,
        name=req.name,
        website=req.website,
        username=req.username,
        password=req.password,
        category=req.category,
        notes=req.notes,
        is_favorite=req.is_favorite,
        created_at=existing.created_at,
        updated_at=existing.updated_at
    )
    service.update_entry(entry)
    return {"success": True}

@app.delete("/api/entries/{entry_id}", dependencies=[Depends(verify_token)])
def delete_entry(entry_id: int):
    service.delete_entry(entry_id)
    return {"success": True}

@app.post("/api/entries/{entry_id}/favorite", dependencies=[Depends(verify_token)])
def toggle_favorite(entry_id: int):
    service.toggle_favorite(entry_id)
    return {"success": True}

# 文件导入导出通过系统对话框
@app.post("/api/import", dependencies=[Depends(verify_token)])
def import_csv(strategy: str = "skip"):
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(title="选择要导入的CSV文件", filetypes=[("CSV 文件", "*.csv")])
    root.destroy()
    
    if not file_path:
        return {"success": False, "msg": "已取消"}
        
    importer = ImportService(service)
    success_count, skipped_count, updated_count = importer.import_csv(file_path, strategy)
    service._load_cache()  # 重新加载缓存
    return {"success": True, "success_count": success_count, "skipped_count": skipped_count, "updated_count": updated_count}

@app.post("/api/export", dependencies=[Depends(verify_token)])
def export_csv():
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.asksaveasfilename(title="导出为CSV文件", defaultextension=".csv", filetypes=[("CSV 文件", "*.csv")])
    root.destroy()
    
    if not file_path:
        return {"success": False, "msg": "已取消"}
        
    entries = service.get_all_entries()
    exporter = ExportService(service.db)
    exporter.export_csv(file_path, entries)
    return {"success": True}
