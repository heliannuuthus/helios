"""
RefreshToken 模型

每个用户最多同时存在 10 个 refresh_token
"""
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Index

from app.core.database import Base


class RefreshToken(Base):
    """刷新令牌"""
    __tablename__ = "refresh_tokens"

    # 主键
    _id = Column(String(32), primary_key=True)
    
    # 用户标识（手机号的 hash，用于关联用户）
    uid = Column(String(64), nullable=False, index=True)
    
    # 刷新令牌（格式: {platform}:{base62随机字符串}）
    token = Column(String(128), nullable=False, unique=True, index=True)
    
    # 加密的身份信息（用于生成新的 access_token）
    encrypted_identity = Column(String(2048), nullable=False)
    
    # 过期时间
    expires_at = Column(DateTime, nullable=False)
    
    # 创建时间
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # 更新时间
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    __table_args__ = (
        # 按用户和创建时间排序（用于清理旧 token）
        Index('ix_refresh_tokens_uid_created', 'uid', 'created_at'),
    )
