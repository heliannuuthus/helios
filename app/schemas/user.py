"""
用户相关的 Pydantic 模型
"""
from pydantic import BaseModel
from typing import Optional


class WxLoginRequest(BaseModel):
    """微信登录请求"""
    login_code: str   # wx.login() 返回的 code，用于获取 openid
    phone_code: str   # wx.getPhoneNumber() 返回的 code，用于获取手机号


class TokenResponse(BaseModel):
    """Token 响应"""
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int  # access_token 有效期（秒）


class RefreshRequest(BaseModel):
    """刷新 token 请求"""
    refresh_token: str


class UserInfo(BaseModel):
    """用户信息（从 token 解析）"""
    userid: str           # platform-openid
    mobile: Optional[str] = None  # sub 字段，手机号
    nickname: Optional[str] = None
    picture: Optional[str] = None
