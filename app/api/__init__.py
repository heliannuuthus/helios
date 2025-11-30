"""
API 路由层
"""
from fastapi import APIRouter

from app.api import recipes

api_router = APIRouter(prefix="/api")

api_router.include_router(recipes.router, prefix="/recipes")
