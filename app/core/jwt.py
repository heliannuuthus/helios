"""
JWT 服务

双 token 设计：
- access_token: JWT (JWS)，短期有效（2小时），用于 API 认证
- refresh_token: 随机字符串，长期有效（1年），存储在数据库

Token 结构：
- access_token 外层：JWS 签名（Ed25519）
- access_token payload.sub：JWE 加密的用户身份信息

身份信息结构：
- userid: {platform}:{openid}
- sub: 手机号
- nickname/picture: 可选
"""
import time
import json
import os
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional
from jose import jwt, jwe
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.jwk import get_jws_key, get_jwe_key, b64url_encode, b64url_decode


def _generate_id() -> str:
    """生成主键 _id（32 字符 hex）"""
    return secrets.token_hex(16)


def _hash_mobile(mobile: str) -> str:
    """
    生成手机号的 hash 值（用作 uid）
    使用 SHA256，返回 64 字符 hex
    """
    return hashlib.sha256(mobile.encode()).hexdigest()


def _encrypt_identity(
    platform: str,
    openid: str,
    mobile: str,
    nickname: Optional[str] = None,
    picture: Optional[str] = None,
) -> str:
    """加密用户身份信息为 JWE"""
    identity = {
        "userid": f"{platform}:{openid}",
        "sub": mobile,
    }
    if nickname:
        identity["nickname"] = nickname
    if picture:
        identity["picture"] = picture

    jwe_key = get_jwe_key()
    key_bytes = b64url_decode(jwe_key["k"])

    encrypted = jwe.encrypt(
        json.dumps(identity).encode(),
        key_bytes,
        algorithm="dir",
        encryption="A256GCM",
    )

    return encrypted.decode() if isinstance(encrypted, bytes) else encrypted


def _decrypt_identity(encrypted_sub: str) -> Optional[dict]:
    """解密用户身份信息"""
    try:
        jwe_key = get_jwe_key()
        key_bytes = b64url_decode(jwe_key["k"])
        plaintext = jwe.decrypt(encrypted_sub, key_bytes)
        return json.loads(plaintext)
    except Exception as e:
        print(f"解密身份信息失败: {e}")
        return None


def _create_access_token(encrypted_sub: str) -> str:
    """创建 access_token (JWT)"""
    now = int(time.time())
    payload = {
        "iss": settings.APP_NAME,
        "sub": encrypted_sub,
        "iat": now,
        "exp": now + settings.ACCESS_TOKEN_EXPIRE_SECONDS,
        "jti": b64url_encode(os.urandom(16)),
    }

    jws_key = get_jws_key()
    return jwt.encode(
        payload,
        jws_key,
        algorithm="EdDSA",
        headers={"kid": jws_key["kid"]},
    )


# Base62 字符集
BASE62_CHARS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _base62_encode(data: bytes) -> str:
    """Base62 编码"""
    num = int.from_bytes(data, 'big')
    if num == 0:
        return BASE62_CHARS[0]
    
    result = []
    while num > 0:
        num, remainder = divmod(num, 62)
        result.append(BASE62_CHARS[remainder])
    
    return ''.join(reversed(result))


def _generate_refresh_token(platform: str) -> str:
    """
    生成 refresh_token
    格式: {platform}:{base62随机字符串}
    例如: wx:3kTMd9sK2pLqNvRwXy
    """
    random_bytes = os.urandom(24)  # 192 bits
    token_body = _base62_encode(random_bytes)
    return f"{platform}:{token_body}"


def _cleanup_old_refresh_tokens(db: Session, uid: str) -> None:
    """清理用户超出限制的旧 refresh_token"""
    from app.models.refresh_token import RefreshToken
    
    # 获取用户所有 token，按创建时间倒序
    tokens = db.query(RefreshToken).filter(
        RefreshToken.uid == uid
    ).order_by(RefreshToken.created_at.desc()).all()
    
    # 保留最新的 N 个，删除其余的
    max_tokens = settings.MAX_REFRESH_TOKENS_PER_USER
    if len(tokens) >= max_tokens:
        # 删除旧的 token
        tokens_to_delete = tokens[max_tokens - 1:]  # 留一个位置给新 token
        for token in tokens_to_delete:
            db.delete(token)
        db.flush()


def generate_token(
    db: Session,
    platform: str,
    openid: str,
    mobile: str,
    nickname: Optional[str] = None,
    picture: Optional[str] = None,
) -> dict:
    """
    生成 access_token 和 refresh_token
    
    Args:
        db: 数据库会话
        platform: 平台标识 (wx/alipay)
        openid: 平台用户唯一标识
        mobile: 手机号
    
    Returns:
        {
            "access_token": "...",
            "refresh_token": "...",
            "token_type": "Bearer",
            "expires_in": 7200,
        }
    """
    from app.models.refresh_token import RefreshToken
    
    encrypted_sub = _encrypt_identity(platform, openid, mobile, nickname, picture)
    
    # 生成 access_token
    access_token = _create_access_token(encrypted_sub)
    
    # 生成 refresh_token
    refresh_token = _generate_refresh_token(platform)
    expires_at = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    # 计算 uid（手机号 hash）
    uid = _hash_mobile(mobile)
    
    # 清理旧的 refresh_token
    _cleanup_old_refresh_tokens(db, uid)
    
    # 存储 refresh_token
    db_token = RefreshToken(
        _id=_generate_id(),
        uid=uid,
        token=refresh_token,
        encrypted_identity=encrypted_sub,
        expires_at=expires_at,
    )
    db.add(db_token)
    db.commit()
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_SECONDS,
    }


def verify_access_token(token: str) -> Optional[dict]:
    """
    验证 access_token 并解密身份信息
    
    Returns:
        {
            "userid": "wx-xxxxx",
            "sub": "138xxxx",      # 手机号
            "uid": "sha256hash",   # 手机号 hash
            "nickname": "...",
            "picture": "...",
            "iat": 1234567890,
            "exp": 1234567890,
        }
    """
    try:
        jws_key = get_jws_key()
        payload = jwt.decode(
            token,
            jws_key,
            algorithms=["EdDSA"],
            options={"verify_aud": False},
        )

        encrypted_sub = payload.get("sub")
        if not encrypted_sub:
            return None

        identity = _decrypt_identity(encrypted_sub)
        if not identity:
            return None

        # 计算 uid
        mobile = identity.get("sub", "")
        uid = _hash_mobile(mobile) if mobile else ""

        return {
            **identity,
            "uid": uid,
            "iat": payload.get("iat"),
            "exp": payload.get("exp"),
            "jti": payload.get("jti"),
        }
    except Exception as e:
        print(f"Token 验证失败: {e}")
        return None


def refresh_tokens(db: Session, refresh_token: str) -> Optional[dict]:
    """
    用 refresh_token 换取新的 token 对
    
    Args:
        db: 数据库会话
        refresh_token: 刷新令牌
    
    Returns:
        同 generate_token 返回格式，失败返回 None
    """
    from app.models.refresh_token import RefreshToken
    
    # 查找 refresh_token
    db_token = db.query(RefreshToken).filter(
        RefreshToken.token == refresh_token
    ).first()
    
    if not db_token:
        return None
    
    # 检查是否过期
    if db_token.expires_at < datetime.utcnow():
        # 删除过期的 token
        db.delete(db_token)
        db.commit()
        return None
    
    # 解密身份信息
    identity = _decrypt_identity(db_token.encrypted_identity)
    if not identity:
        return None
    
    # 删除旧的 refresh_token
    db.delete(db_token)
    db.flush()
    
    # 从 userid 解析 platform 和 openid
    userid = identity.get("userid", "")
    if "-" not in userid:
        return None
    
    platform, openid = userid.split("-", 1)
    mobile = identity.get("sub", "")
    nickname = identity.get("nickname")
    picture = identity.get("picture")
    
    # 生成新的 token 对
    return generate_token(db, platform, openid, mobile, nickname, picture)


def revoke_refresh_token(db: Session, refresh_token: str) -> bool:
    """
    撤销 refresh_token
    
    Returns:
        是否成功撤销
    """
    from app.models.refresh_token import RefreshToken
    
    result = db.query(RefreshToken).filter(
        RefreshToken.token == refresh_token
    ).delete()
    db.commit()
    
    return result > 0


def revoke_all_refresh_tokens(db: Session, uid: str) -> int:
    """
    撤销用户所有 refresh_token（用于登出所有设备）
    
    Args:
        uid: 用户标识（手机号 hash）
    
    Returns:
        删除的 token 数量
    """
    from app.models.refresh_token import RefreshToken
    
    result = db.query(RefreshToken).filter(
        RefreshToken.uid == uid
    ).delete()
    db.commit()
    
    return result


def get_userid(token: str) -> Optional[str]:
    """从 access_token 中获取 userid"""
    payload = verify_access_token(token)
    return payload.get("userid") if payload else None


def get_uid(token: str) -> Optional[str]:
    """从 access_token 中获取 uid（手机号 hash）"""
    payload = verify_access_token(token)
    return payload.get("uid") if payload else None
