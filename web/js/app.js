// 获取URL参数中的API端口和Token
const urlParams = new URLSearchParams(window.location.search);
const API_PORT = urlParams.get('port') || 8000;
const API_TOKEN = urlParams.get('token') || '';
const API_BASE = `http://127.0.0.1:${API_PORT}/api`;

let currentCategory = '全部';
let allEntries = [];
let allCategories = [];
let searchTimeout = null;

const searchInput = document.getElementById('search-input');
const clearSearchBtn = document.getElementById('clear-search-btn');

// --- API 请求封装 ---
async function apiCall(endpoint, method = 'GET', body = null) {
    const headers = {
        'Authorization': `Bearer ${API_TOKEN}`,
        'Content-Type': 'application/json'
    };
    
    const options = { method, headers };
    if (body) options.body = JSON.stringify(body);
    
    try {
        const res = await fetch(`${API_BASE}${endpoint}`, options);
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '请求失败');
        return data;
    } catch (e) {
        console.error(e);
        throw e;
    }
}

// --- 初始化与认证 ---
async function checkStatus() {
    try {
        const res = await fetch(`${API_BASE}/config`);
        const data = await res.json();
        const authScreen = document.getElementById('auth-screen');
        const title = document.getElementById('auth-title');
        const subtitle = document.getElementById('auth-subtitle');
        const btn = document.getElementById('auth-btn');
        
        if (data.is_unlocked) {
            authScreen.classList.add('hidden');
            loadData();
        } else if (!data.has_db) {
            title.innerText = '初始化密码库';
            subtitle.innerText = '请设置您的主密码（务必牢记）';
            btn.innerText = '创 建';
            btn.onclick = () => doAuth('/init');
            setTimeout(() => document.getElementById('auth-password').focus(), 500);
        } else {
            title.innerText = '解锁密码库';
            subtitle.innerText = '请输入主密码以解密数据';
            btn.innerText = '解 锁';
            btn.onclick = () => doAuth('/login');
            setTimeout(() => document.getElementById('auth-password').focus(), 500);
        }
    } catch (e) {
        setTimeout(checkStatus, 500); // 重试
    }
}

async function doAuth(endpoint) {
    const pwd = document.getElementById('auth-password').value;
    const err = document.getElementById('auth-error');
    if (!pwd) return;
    
    try {
        await fetch(`${API_BASE}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: pwd })
        }).then(async r => {
            if(!r.ok) throw new Error(await r.text());
        });
        document.getElementById('auth-screen').classList.add('hidden');
        loadData();
    } catch (e) {
        err.classList.remove('hidden');
    }
}

document.getElementById('auth-password').addEventListener('keyup', (e) => {
    if (e.key === 'Enter') document.getElementById('auth-btn').click();
});

// --- 数据加载 ---
async function loadData() {
    await loadCategories();
    await loadEntries();
}

async function loadCategories() {
    try {
        const stats = await apiCall('/stats');
        allCategories = await apiCall('/categories');
        
        // 更新固定分类计数
        document.getElementById('count-全部').innerText = stats.total;
        document.getElementById('count-收藏').innerText = stats.favorite;
        
        // 渲染自定义分类
        const container = document.getElementById('custom-categories');
        const otherContainer = document.getElementById('other-category-container');
        container.innerHTML = '';
        otherContainer.innerHTML = '';
        
        allCategories.forEach(cat => {
            const isActive = currentCategory === cat.name ? 'active' : '';
            const count = stats.categories[cat.name] || 0;
            const li = document.createElement('li');
            li.dataset.name = cat.name;
            
            if (cat.name === '其他') {
                li.className = 'category-item';
                li.innerHTML = `
                    <button class="category-btn ${isActive} w-full flex items-center justify-between px-3 py-2 rounded-md text-sm text-gray-600 hover:bg-gray-100 hover:text-gray-900 transition-colors" data-category="${cat.name}">
                        <div class="flex items-center"><span class="mr-2 w-6 text-center">${cat.icon || '📁'}</span><span class="truncate max-w-[100px]">${cat.name}</span></div>
                        <div class="flex items-center">
                            <span class="text-xs bg-gray-100 border border-gray-200 text-gray-500 px-2 py-0.5 rounded-full count-badge">${count}</span>
                        </div>
                    </button>
                `;
                otherContainer.appendChild(li);
                return;
            }
            
            li.className = 'category-item group relative';
            li.innerHTML = `
                <button class="category-btn ${isActive} w-full flex items-center justify-between px-3 py-2 rounded-md text-sm text-gray-600 hover:bg-gray-100 hover:text-gray-900 transition-colors" data-category="${cat.name}">
                    <div class="flex items-center drag-handle cursor-grab"><span class="mr-2 w-6 text-center">${cat.icon || '📁'}</span><span class="truncate max-w-[100px]">${cat.name}</span></div>
                    <div class="flex items-center">
                        <span class="delete-btn mr-2 text-red-500 hover:text-red-600 cursor-pointer" onclick="deleteCategory('${cat.name}', event)">✕</span>
                        <span class="text-xs bg-gray-100 border border-gray-200 text-gray-500 px-2 py-0.5 rounded-full count-badge">${count}</span>
                    </div>
                </button>
            `;
            container.appendChild(li);
        });
        
        // 绑定分类点击事件
        document.querySelectorAll('.category-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                if(e.target.closest('.delete-btn')) return;
                document.querySelectorAll('.category-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                currentCategory = btn.dataset.category;
                
                // 切换分类时，清空搜索框的内容
                searchInput.value = '';
                clearSearchBtn.classList.add('hidden');
                
                loadEntries();
            });
        });
        
        // 初始化拖拽
        Sortable.create(container, {
            animation: 150,
            handle: '.drag-handle',
            ghostClass: 'sortable-ghost',
            onEnd: async function () {
                const items = container.querySelectorAll('li');
                const req = Array.from(items).map((item, idx) => ({
                    name: item.dataset.name,
                    sort_order: idx + 1
                }));
                await apiCall('/categories/reorder', 'PUT', req);
            }
        });
        
    } catch (e) {
        showToast('加载分类失败', true);
    }
}

async function loadEntries() {
    try {
        const query = searchInput.value;
        const url = `/entries?category=${encodeURIComponent(currentCategory)}&search=${encodeURIComponent(query)}`;
        allEntries = await apiCall(url);
        renderEntries();
    } catch (e) {
        showToast('加载密码失败', true);
    }
}

function renderEntries() {
    const grid = document.getElementById('cards-grid');
    const empty = document.getElementById('empty-state');
    grid.innerHTML = '';
    
    if (allEntries.length === 0) {
        empty.classList.remove('hidden');
        return;
    }
    empty.classList.add('hidden');
    
    allEntries.forEach(entry => {
        const card = document.createElement('div');
        card.className = 'password-card bg-white border border-gray-200 rounded-xl p-5 flex flex-col justify-between shadow-sm';
        
        const favIcon = entry.is_favorite ? '⭐' : '☆';
        const favColor = entry.is_favorite ? 'text-yellow-500' : 'text-gray-300 hover:text-yellow-500';
        
        card.innerHTML = `
            <div>
                <div class="flex justify-between items-start mb-4">
                    <h3 class="font-bold text-lg text-gray-900 truncate pr-2" title="${entry.name || entry.website}">${entry.name || entry.website}</h3>
                    <button class="${favColor} text-xl transition-colors" onclick="toggleFavorite(${entry.id})">${favIcon}</button>
                </div>
                <div class="space-y-3 mb-5">
                    <div class="flex items-center text-sm text-gray-500">
                        <span class="w-12">账号：</span>
                        <span class="truncate flex-1 text-gray-800 font-medium">${entry.username}</span>
                    </div>
                    <div class="flex items-center text-sm text-gray-500">
                        <span class="w-12">密码：</span>
                        <span class="flex-1 text-gray-800 blur-text tracking-widest font-mono font-medium" onclick="copyText('${entry.password.replace(/'/g, "\\'")}', '密码')">${entry.password}</span>
                    </div>
                    ${entry.website ? `
                    <div class="flex items-center text-sm text-gray-500">
                        <span class="w-12">网址：</span>
                        <span class="truncate flex-1 text-blue-600 hover:underline cursor-pointer font-medium" onclick="window.open('${entry.website.startsWith('http') ? entry.website : 'https://'+entry.website}', '_blank')">${entry.website}</span>
                    </div>` : ''}
                </div>
            </div>
            
            <div class="flex gap-2 mt-2 pt-4 border-t border-gray-100">
                <button onclick="copyText('${entry.username.replace(/'/g, "\\'")}', '账号')" class="flex-1 bg-gray-50 hover:bg-gray-100 border border-gray-200 text-gray-700 py-1.5 rounded-md text-sm transition-colors font-medium">复制账号</button>
                <button onclick="copyText('${entry.password.replace(/'/g, "\\'")}', '密码')" class="flex-1 bg-gray-50 hover:bg-gray-100 border border-gray-200 text-gray-700 py-1.5 rounded-md text-sm transition-colors font-medium">复制密码</button>
                <button onclick="editEntry(${entry.id})" class="flex-1 bg-gray-50 hover:bg-gray-100 border border-gray-200 text-gray-700 py-1.5 rounded-md text-sm transition-colors font-medium">编辑</button>
            </div>
        `;
        grid.appendChild(card);
    });
}

// --- 交互操作 ---

async function toggleFavorite(id) {
    await apiCall(`/entries/${id}/favorite`, 'POST');
    loadData();
}

async function deleteCategory(name, event) {
    event.stopPropagation();
    if (confirm(`确定要删除分类 '${name}' 吗？其下的密码将被归入“其他”。`)) {
        await apiCall(`/categories/${name}`, 'DELETE');
        if (currentCategory === name) currentCategory = '全部';
        loadData();
    }
}

document.getElementById('add-category-btn').addEventListener('click', async () => {
    const name = prompt('请输入新分类名称：');
    if (name && name.trim()) {
        try {
            await apiCall('/categories', 'POST', { name: name.trim(), icon: '📁' });
            loadData();
        } catch (e) {
            showToast(e.message, true);
        }
    }
});

// 搜索逻辑与防抖
searchInput.addEventListener('input', () => {
    if (searchInput.value.length > 0) {
        clearSearchBtn.classList.remove('hidden');
    } else {
        clearSearchBtn.classList.add('hidden');
    }
    
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(loadEntries, 300);
});

// 清空搜索框
clearSearchBtn.addEventListener('click', () => {
    searchInput.value = '';
    clearSearchBtn.classList.add('hidden');
    loadEntries();
});

// 复制到剪贴板
async function copyText(text, type) {
    try {
        await navigator.clipboard.writeText(text);
        showToast(`${type}已复制`);
    } catch (err) {
        const el = document.createElement('textarea');
        el.value = text;
        document.body.appendChild(el);
        el.select();
        document.execCommand('copy');
        document.body.removeChild(el);
        showToast(`${type}已复制`);
    }
}

// Toast 提示
function showToast(msg, isError = false) {
    const toast = document.getElementById('toast');
    document.getElementById('toast-msg').innerText = msg;
    document.getElementById('toast-icon').innerText = isError ? '❌' : '✔';
    
    if(isError) {
        toast.firstElementChild.classList.replace('bg-gray-800', 'bg-red-600');
    } else {
        toast.firstElementChild.classList.replace('bg-red-600', 'bg-gray-800');
    }
    
    toast.classList.remove('translate-y-20', 'opacity-0');
    setTimeout(() => {
        toast.classList.add('translate-y-20', 'opacity-0');
    }, 2500);
}

// 导入导出
document.getElementById('import-btn').addEventListener('click', () => {
    const modal = document.getElementById('modal-container');
    modal.innerHTML = `
        <div class="bg-white w-[460px] rounded-xl shadow-2xl flex flex-col overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-200 flex justify-between items-center bg-gray-50">
                <h3 class="text-lg font-bold text-gray-900">选择导入策略</h3>
                <button onclick="document.getElementById('modal-container').classList.add('hidden')" class="text-gray-400 hover:text-gray-600">✕</button>
            </div>
            <div class="p-6 space-y-3">
                <button onclick="doImport('skip')" class="w-full text-left p-4 border border-gray-200 rounded-lg hover:border-blue-400 hover:bg-blue-50 transition-all group">
                    <div class="font-bold text-gray-900 mb-1 group-hover:text-blue-700">跳过已存在</div>
                    <div class="text-sm text-gray-500">只导入新密码。已存在的条目保持不变，不会被覆盖。</div>
                </button>
                <button onclick="doImport('overwrite')" class="w-full text-left p-4 border border-gray-200 rounded-lg hover:border-orange-400 hover:bg-orange-50 transition-all group">
                    <div class="font-bold text-gray-900 mb-1 group-hover:text-orange-700">覆盖已存在</div>
                    <div class="text-sm text-gray-500">如果导入文件中的密码有变化，用新密码替换本地旧密码。</div>
                </button>
            </div>
        </div>
    `;
    modal.classList.remove('hidden');
    modal.classList.add('flex');
});

async function doImport(strategy) {
    document.getElementById('modal-container').classList.add('hidden');
    try {
        const res = await apiCall(`/import?strategy=${strategy}`, 'POST');
        if (res.success) {
            let msg = `新增 ${res.success_count} 条`;
            if (res.updated_count > 0) msg += `，更新 ${res.updated_count} 条`;
            if (res.skipped_count > 0) msg += `，跳过 ${res.skipped_count} 条`;
            showToast(msg);
            loadData();
        }
    } catch(e) {}
}

document.getElementById('export-btn').addEventListener('click', async () => {
    try {
        const res = await apiCall('/export', 'POST');
        if (res.success) showToast('导出成功');
    } catch(e) {}
});

// --- 表单与编辑 ---
async function editEntry(id) {
    const entry = allEntries.find(e => e.id === id);
    if (!entry) return;
    
    const modal = document.getElementById('modal-container');
    const catOptions = allCategories.map(c => `<option value="${c.name}" ${c.name === entry.category ? 'selected' : ''}>${c.name}</option>`).join('');
    
    modal.innerHTML = `
        <div class="bg-white w-[500px] rounded-xl shadow-2xl flex flex-col overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-200 flex justify-between items-center bg-gray-50">
                <h3 class="text-lg font-bold text-gray-900">编辑密码</h3>
                <button onclick="document.getElementById('modal-container').classList.add('hidden')" class="text-gray-400 hover:text-gray-600">✕</button>
            </div>
            <div class="p-6 space-y-4">
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">名称</label>
                    <input type="text" id="edit-name" value="${entry.name}" class="w-full bg-gray-50 border border-gray-300 rounded-md px-3 py-2 text-gray-900 focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">网站</label>
                    <input type="text" id="edit-website" value="${entry.website}" class="w-full bg-gray-50 border border-gray-300 rounded-md px-3 py-2 text-gray-900 focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">账号</label>
                    <input type="text" id="edit-username" value="${entry.username}" class="w-full bg-gray-50 border border-gray-300 rounded-md px-3 py-2 text-gray-900 focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">密码</label>
                    <input type="text" id="edit-password" value="${entry.password}" class="w-full bg-gray-50 border border-gray-300 rounded-md px-3 py-2 text-gray-900 font-mono focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">分类</label>
                    <select id="edit-category" class="w-full bg-gray-50 border border-gray-300 rounded-md px-3 py-2 text-gray-900 focus:outline-none focus:ring-2 focus:ring-blue-500">
                        ${catOptions}
                        ${!allCategories.find(c=>c.name==='其他') ? `<option value="其他" ${'其他' === entry.category ? 'selected' : ''}>其他</option>` : ''}
                    </select>
                </div>
            </div>
            <div class="px-6 py-4 border-t border-gray-200 flex justify-between bg-gray-50">
                <button onclick="deleteEntry(${entry.id})" class="text-red-600 hover:bg-red-50 px-4 py-2 rounded-md transition-colors font-medium">删除</button>
                <div class="space-x-3">
                    <button onclick="document.getElementById('modal-container').classList.add('hidden')" class="px-4 py-2 text-gray-600 hover:text-gray-900 font-medium transition-colors">取消</button>
                    <button onclick="saveEdit(${entry.id}, ${entry.is_favorite})" class="bg-blue-600 hover:bg-blue-700 text-white px-5 py-2 rounded-md font-medium transition-colors shadow-sm">保存</button>
                </div>
            </div>
        </div>
    `;
    modal.classList.remove('hidden');
    modal.classList.add('flex');
}

async function saveEdit(id, is_fav) {
    const req = {
        id: id,
        name: document.getElementById('edit-name').value,
        website: document.getElementById('edit-website').value,
        username: document.getElementById('edit-username').value,
        password: document.getElementById('edit-password').value,
        category: document.getElementById('edit-category').value,
        notes: '',
        is_favorite: is_fav
    };
    await apiCall(`/entries/${id}`, 'PUT', req);
    document.getElementById('modal-container').classList.add('hidden');
    loadData();
    showToast('保存成功');
}

async function deleteEntry(id) {
    if (confirm('确定要删除这条密码吗？')) {
        await apiCall(`/entries/${id}`, 'DELETE');
        document.getElementById('modal-container').classList.add('hidden');
        loadData();
        showToast('已删除');
    }
}

document.getElementById('add-entry-btn').addEventListener('click', () => {
    const modal = document.getElementById('modal-container');
    const catOptions = allCategories.map(c => `<option value="${c.name}" ${c.name === currentCategory ? 'selected' : ''}>${c.name}</option>`).join('');
    
    modal.innerHTML = `
        <div class="bg-white w-[500px] rounded-xl shadow-2xl flex flex-col overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-200 flex justify-between items-center bg-gray-50">
                <h3 class="text-lg font-bold text-gray-900">添加新密码</h3>
                <button onclick="document.getElementById('modal-container').classList.add('hidden')" class="text-gray-400 hover:text-gray-600">✕</button>
            </div>
            <div class="p-6 space-y-4">
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">名称</label>
                    <input type="text" id="add-name" class="w-full bg-gray-50 border border-gray-300 rounded-md px-3 py-2 text-gray-900 focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">网站</label>
                    <input type="text" id="add-website" class="w-full bg-gray-50 border border-gray-300 rounded-md px-3 py-2 text-gray-900 focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">账号</label>
                    <input type="text" id="add-username" class="w-full bg-gray-50 border border-gray-300 rounded-md px-3 py-2 text-gray-900 focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">密码</label>
                    <div class="flex gap-2">
                        <input type="text" id="add-password" class="w-full bg-gray-50 border border-gray-300 rounded-md px-3 py-2 text-gray-900 font-mono focus:outline-none focus:ring-2 focus:ring-blue-500">
                        <button onclick="document.getElementById('add-password').value = Math.random().toString(36).slice(-10) + Math.random().toString(36).slice(-8).toUpperCase() + '!@#'" class="bg-gray-200 hover:bg-gray-300 text-gray-700 px-4 rounded-md text-sm font-medium whitespace-nowrap transition-colors">生成</button>
                    </div>
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">分类</label>
                    <select id="add-category" class="w-full bg-gray-50 border border-gray-300 rounded-md px-3 py-2 text-gray-900 focus:outline-none focus:ring-2 focus:ring-blue-500">
                        ${catOptions}
                        ${!allCategories.find(c=>c.name==='其他') ? `<option value="其他" ${'其他' === currentCategory ? 'selected' : ''}>其他</option>` : ''}
                    </select>
                </div>
            </div>
            <div class="px-6 py-4 border-t border-gray-200 flex justify-end space-x-3 bg-gray-50">
                <button onclick="document.getElementById('modal-container').classList.add('hidden')" class="px-4 py-2 text-gray-600 hover:text-gray-900 font-medium transition-colors">取消</button>
                <button onclick="saveNewEntry()" class="bg-blue-600 hover:bg-blue-700 text-white px-5 py-2 rounded-md font-medium transition-colors shadow-sm">保存</button>
            </div>
        </div>
    `;
    modal.classList.remove('hidden');
    modal.classList.add('flex');
});

async function saveNewEntry() {
    const req = {
        name: document.getElementById('add-name').value,
        website: document.getElementById('add-website').value,
        username: document.getElementById('add-username').value,
        password: document.getElementById('add-password').value,
        category: document.getElementById('add-category').value,
        notes: ''
    };
    if(!req.name && !req.website) {
        showToast('名称和网站不能同时为空', true);
        return;
    }
    await apiCall(`/entries`, 'POST', req);
    document.getElementById('modal-container').classList.add('hidden');
    loadData();
    showToast('添加成功');
}

// 启动检测
checkStatus();
