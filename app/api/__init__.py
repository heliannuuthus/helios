"""
API 路由层
"""
from fastapi import APIRouter

from app.api import recipes, auth

api_router = APIRouter(prefix="/api")

api_router.include_router(auth.router, prefix="/auth")
api_router.include_router(recipes.router, prefix="/recipes")
