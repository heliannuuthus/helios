"""
认证相关 API
"""
from fastapi import APIRouter, HTTPException, Header, Depends
from sqlalchemy.orm import Session
from typing import Optional
import logging

from app.core.config import settings
from app.core.database import get_db
from app.core.jwt import verify_access_token, refresh_tokens
from app.schemas.user import WxLoginRequest, TokenResponse, RefreshRequest
from app.services.auth import AuthService

router = APIRouter(tags=["auth"])
logger = logging.getLogger(__name__)


def get_current_user(authorization: Optional[str] = Header(None)) -> Optional[dict]:
    """
    从 Authorization header 获取当前用户信息（仅接受 access_token）
    
    返回解密后的用户信息:
    {
        "userid": "wx-xxxxx",
        "sub": "138xxxx",      # 手机号
        "nickname": "...",
        "picture": "...",
    }
    """
    if not authorization:
        return None

    if authorization.startswith("Bearer "):
        token = authorization[7:]
    else:
        token = authorization

    return verify_access_token(token)


def require_auth(authorization: Optional[str] = Header(None)) -> dict:
    """要求登录的依赖"""
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="未登录或登录已过期")
    return user


@router.post("/wx-login", response_model=TokenResponse)
async def wx_login(
    request: WxLoginRequest,
    db: Session = Depends(get_db),
):
    """
    微信小程序登录
    
    需要同时传入 login_code 和 phone_code：
    - login_code: wx.login() 获取，用于拿 openid
    - phone_code: wx.getPhoneNumber() 获取，用于拿手机号
    
    返回 access_token 和 refresh_token
    """
    if not settings.WX_APPID or not settings.WX_SECRET:
        logger.error("微信配置缺失: WX_APPID 或 WX_SECRET 未设置")
        raise HTTPException(status_code=500, detail="服务器配置错误")

    try:
        wx_result = await AuthService.wx_code2session(request.login_code)
        openid = wx_result["openid"]
        
        mobile = await AuthService.get_phone_number(request.phone_code)
        
        tokens = AuthService.generate_token(
            db=db,
            platform="wx",
            openid=openid,
            mobile=mobile,
        )

        return TokenResponse(**tokens)
    except Exception as e:
        logger.error(f"微信登录失败: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    request: RefreshRequest,
    db: Session = Depends(get_db),
):
    """
    刷新 token
    
    用 refresh_token 换取新的 access_token 和 refresh_token
    """
    tokens = refresh_tokens(db, request.refresh_token)
    if not tokens:
        raise HTTPException(status_code=401, detail="refresh_token 无效或已过期")
    
    return TokenResponse(**tokens)


@router.post("/logout")
async def logout(
    request: RefreshRequest,
    db: Session = Depends(get_db),
):
    """
    登出（撤销 refresh_token）
    """
    from app.core.jwt import revoke_refresh_token
    revoke_refresh_token(db, request.refresh_token)
    return {"message": "已登出"}


@router.post("/logout-all")
async def logout_all(
    db: Session = Depends(get_db),
    user: dict = Depends(require_auth),
):
    """
    登出所有设备（撤销用户所有 refresh_token）
    """
    from app.core.jwt import revoke_all_refresh_tokens
    count = revoke_all_refresh_tokens(db, user["uid"])
    return {"message": f"已登出所有设备，共撤销 {count} 个会话"}
