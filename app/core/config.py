"""
应用配置管理
"""
from pydantic_settings import BaseSettings
from typing import List
import os

class Settings(BaseSettings):
    """应用配置"""
    
    # 应用信息
    APP_NAME: str = "Choosy API"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    
    # 服务器配置
    HOST: str = "0.0.0.0"
    PORT: int = 18000
    
    # 数据库配置
    DATABASE_URL: str = "sqlite:///./db/recipes.db"
    
    # CORS 配置
    CORS_ORIGINS: List[str] = ["*"]  # 开发环境允许所有来源，生产环境应限制具体域名
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: List[str] = ["*"]
    CORS_ALLOW_HEADERS: List[str] = ["*"]
    
    DASHSCOPE_API_KEY: str = os.getenv("DASHSCOPE_API_KEY", "")
    
    # 微信小程序配置
    WX_APPID: str = os.getenv("WX_APPID", "")
    WX_SECRET: str = os.getenv("WX_SECRET", "")
    
    # JWT 配置
    ACCESS_TOKEN_EXPIRE_SECONDS: int = 60 * 60 * 2  # 2 小时
    REFRESH_TOKEN_EXPIRE_DAYS: int = 365  # 1 年
    MAX_REFRESH_TOKENS_PER_USER: int = 10  # 每用户最多 10 个 refresh_token
    
    # JWK 密钥（从环境变量读取 JSON 字符串）
    JWS_KEY: str = os.getenv("JWS_KEY", "")  # Ed25519 私钥（包含公钥）
    JWE_KEY: str = os.getenv("JWE_KEY", "")  # A256GCM 对称密钥
    
    class Config:
        env_file = ".env"
        extra = "ignore"


# 创建全局配置实例
settings = Settings()

