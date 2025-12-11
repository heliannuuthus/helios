"""
认证服务
"""
from typing import Optional
import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.jwt import generate_token, verify_access_token, get_userid


class AuthService:
    """认证服务"""

    # 微信接口
    WX_CODE2SESSION_URL = "https://api.weixin.qq.com/sns/jscode2session"
    WX_GET_PHONE_URL = "https://api.weixin.qq.com/wxa/business/getuserphonenumber"

    @staticmethod
    async def wx_code2session(code: str) -> dict:
        """
        调用微信 code2session 接口
        返回 openid 和 session_key
        """
        params = {
            "appid": settings.WX_APPID,
            "secret": settings.WX_SECRET,
            "js_code": code,
            "grant_type": "authorization_code",
        }

        async with httpx.AsyncClient() as client:
            response = await client.get(AuthService.WX_CODE2SESSION_URL, params=params)
            result = response.json()

        if "errcode" in result and result["errcode"] != 0:
            raise Exception(f"微信登录失败: {result.get('errmsg', '未知错误')}")

        return result

    @staticmethod
    async def get_wx_access_token() -> str:
        """获取微信 access_token"""
        url = "https://api.weixin.qq.com/cgi-bin/token"
        params = {
            "grant_type": "client_credential",
            "appid": settings.WX_APPID,
            "secret": settings.WX_SECRET,
        }

        async with httpx.AsyncClient() as client:
            response = await client.get(url, params=params)
            result = response.json()

        if "errcode" in result and result["errcode"] != 0:
            raise Exception(f"获取 access_token 失败: {result.get('errmsg', '未知错误')}")

        return result["access_token"]

    @staticmethod
    async def get_phone_number(code: str) -> str:
        """通过 code 获取用户手机号"""
        access_token = await AuthService.get_wx_access_token()

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{AuthService.WX_GET_PHONE_URL}?access_token={access_token}",
                json={"code": code},
            )
            result = response.json()

        if result.get("errcode", 0) != 0:
            raise Exception(f"获取手机号失败: {result.get('errmsg', '未知错误')}")

        return result["phone_info"]["phoneNumber"]

    @staticmethod
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
        
        Returns:
            {
                "access_token": "...",
                "refresh_token": "...",
                "token_type": "Bearer",
                "expires_in": 7200,
            }
        """
        return generate_token(db, platform, openid, mobile, nickname, picture)

    @staticmethod
    def verify(token: str) -> Optional[dict]:
        """验证 access_token 并返回用户信息"""
        return verify_access_token(token)

    @staticmethod
    def get_userid_from_token(token: str) -> Optional[str]:
        """从 token 中获取 userid"""
        return get_userid(token)
