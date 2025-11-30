"""
菜谱相关的 Pydantic 模型
"""
from typing import List, Optional
from pydantic import BaseModel, ConfigDict


# 食材模型
class IngredientBase(BaseModel):
    """食材基础模型"""
    name: str
    quantity: Optional[float] = None
    unit: Optional[str] = None
    text_quantity: str
    notes: Optional[str] = None


class IngredientCreate(IngredientBase):
    """创建食材模型"""
    pass


class IngredientResponse(IngredientBase):
    """食材响应模型"""
    id: int
    
    model_config = ConfigDict(from_attributes=True)


# 步骤模型
class StepBase(BaseModel):
    """步骤基础模型"""
    step: int
    description: str


class StepCreate(StepBase):
    """创建步骤模型"""
    pass


class StepResponse(StepBase):
    """步骤响应模型"""
    id: int
    
    model_config = ConfigDict(from_attributes=True)


# 菜谱模型
class RecipeBase(BaseModel):
    """菜谱基础模型"""
    name: str
    description: Optional[str] = None
    source_path: Optional[str] = None
    image_path: Optional[str] = None
    images: List[str] = []
    category: str
    difficulty: int
    tags: List[str] = []
    servings: int
    prep_time_minutes: Optional[int] = None
    cook_time_minutes: Optional[int] = None
    total_time_minutes: Optional[int] = None


class RecipeCreate(RecipeBase):
    """创建菜谱模型"""
    id: str
    ingredients: List[IngredientCreate] = []
    steps: List[StepCreate] = []
    additional_notes: List[str] = []


class RecipeUpdate(BaseModel):
    """更新菜谱模型"""
    name: Optional[str] = None
    description: Optional[str] = None
    source_path: Optional[str] = None
    image_path: Optional[str] = None
    images: Optional[List[str]] = None
    category: Optional[str] = None
    difficulty: Optional[int] = None
    tags: Optional[List[str]] = None
    servings: Optional[int] = None
    prep_time_minutes: Optional[int] = None
    cook_time_minutes: Optional[int] = None
    total_time_minutes: Optional[int] = None
    ingredients: Optional[List[IngredientCreate]] = None
    steps: Optional[List[StepCreate]] = None
    additional_notes: Optional[List[str]] = None


class RecipeResponse(RecipeBase):
    """菜谱响应模型"""
    id: str
    ingredients: List[IngredientResponse] = []
    steps: List[StepResponse] = []
    additional_notes: List[str] = []
    
    model_config = ConfigDict(from_attributes=True)


class RecipeListItem(BaseModel):
    """菜谱列表项模型（简化版）"""
    id: str
    name: str
    description: Optional[str] = None
    category: str
    difficulty: int
    tags: List[str] = []
    image_path: Optional[str] = None
    total_time_minutes: Optional[int] = None
    
    model_config = ConfigDict(from_attributes=True)

