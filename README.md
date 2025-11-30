# Choosy Backend API

菜谱管理系统后端 API，使用 FastAPI 和 SQLAlchemy 构建。

## 项目结构

```
backend/
├── app/                    # 主应用目录
│   ├── __init__.py
│   ├── main.py            # FastAPI 应用入口
│   ├── core/              # 核心配置
│   │   ├── __init__.py
│   │   ├── config.py      # 应用配置
│   │   └── database.py    # 数据库配置
│   ├── models/            # 数据库模型
│   │   ├── __init__.py
│   │   └── recipe.py      # 菜谱相关模型
│   ├── schemas/           # Pydantic 数据模型
│   │   ├── __init__.py
│   │   └── recipe.py      # 菜谱相关 schema
│   ├── services/          # 业务逻辑层
│   │   ├── __init__.py
│   │   └── recipe.py      # 菜谱服务
│   └── api/               # API 路由层
│       ├── __init__.py
│       ├── deps.py        # 依赖注入
│       └── v1/            # API v1 版本
│           ├── __init__.py
│           └── recipes.py # 菜谱 API 路由
├── pyproject.toml         # 项目配置
└── README.md             # 项目文档
```

## 安装和运行

### 1. 安装依赖

#### 方式一：使用 uv（推荐）

```bash
# 确保安装了 uv
pip install uv

# 同步依赖
uv sync
```

#### 方式二：使用 pip

```bash
# 如果没有 uv，可以使用 pip
pip install -r requirements.txt
```

#### 方式三：使用安装脚本（推荐用于新环境）

```bash
# 自动安装所有依赖
./install.sh
```

### 2. 运行开发服务器

#### 使用 uv 运行

```bash
# 开发模式
uv run choosy-dev

# 或生产模式
uv run choosy-server
```

#### 直接运行

```bash
# 开发模式
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 18000

# 或生产模式（推荐）
uvicorn app.main:app --host 0.0.0.0 --port 18000
```

### 3. 访问 API

- API 文档: http://localhost:18000/docs
- 健康检查: http://localhost:18000/health
- API 根路径: http://localhost:18000/

## API 端点

### 菜谱管理

- `GET /api/v1/recipes` - 获取菜谱列表（支持分类筛选、搜索、分页）
- `POST /api/v1/recipes` - 创建新菜谱
- `GET /api/v1/recipes/{recipe_id}` - 获取菜谱详情
- `PUT /api/v1/recipes/{recipe_id}` - 更新菜谱
- `DELETE /api/v1/recipes/{recipe_id}` - 删除菜谱
- `GET /api/v1/recipes/categories/list` - 获取所有分类
- `POST /api/v1/recipes/batch` - 批量创建菜谱

### 查询参数

#### 获取菜谱列表
- `category`: 按分类筛选
- `search`: 搜索关键词（搜索菜谱名称和描述）
- `limit`: 返回数量限制（默认 100，最大 500）
- `offset`: 分页偏移量（默认 0）

## 数据库

使用 SQLite 数据库，默认存储在 `recipes.db` 文件中。

首次运行时会自动创建数据库表结构。

## 环境变量

可以通过 `.env` 文件配置：

```env
# 应用配置
DEBUG=true
HOST=0.0.0.0
PORT=18000

# 数据库配置
DATABASE_URL=sqlite:///./recipes.db

# CORS 配置
CORS_ORIGINS=["*"]
```

## 开发

### 添加新功能

1. 在 `models/` 中定义数据库模型
2. 在 `schemas/` 中定义 Pydantic 数据模型
3. 在 `services/` 中实现业务逻辑
4. 在 `api/` 中定义路由

### 数据库迁移

目前使用 SQLAlchemy 的 `create_all()` 方法自动创建表。在生产环境中，建议使用 Alembic 进行数据库迁移。

## 部署

### 使用 Docker

```dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY . .
RUN pip install uv && uv sync --no-dev

EXPOSE 18000

CMD ["uv", "run", "server"]
```

### 生产部署

```bash
# 安装生产依赖
uv sync --no-dev

# 运行生产服务器
uv run server
```
