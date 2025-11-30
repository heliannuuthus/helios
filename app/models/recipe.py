"""
菜谱相关数据库模型
"""
from sqlalchemy import Column, Integer, String, Float, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship

from app.core.database import Base


class Recipe(Base):
    """菜谱表"""
    __tablename__ = "recipes"

    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False, index=True)
    description = Column(Text)
    source_path = Column(String)
    image_path = Column(String, nullable=True)
    images = Column(JSON, default=list)  # 存储图片数组
    category = Column(String, index=True)
    difficulty = Column(Integer)
    tags = Column(JSON, default=list)  # 存储标签数组
    servings = Column(Integer)
    prep_time_minutes = Column(Integer, nullable=True)
    cook_time_minutes = Column(Integer, nullable=True)
    total_time_minutes = Column(Integer, nullable=True)

    # 关联关系
    ingredients = relationship(
        "Ingredient",
        back_populates="recipe",
        cascade="all, delete-orphan",
        lazy="joined"
    )
    steps = relationship(
        "Step",
        back_populates="recipe",
        cascade="all, delete-orphan",
        order_by="Step.step",
        lazy="joined"
    )
    additional_notes = relationship(
        "AdditionalNote",
        back_populates="recipe",
        cascade="all, delete-orphan",
        lazy="joined"
    )


class Ingredient(Base):
    """食材表"""
    __tablename__ = "ingredients"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    recipe_id = Column(String, ForeignKey("recipes.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String, nullable=False)
    quantity = Column(Float, nullable=True)
    unit = Column(String, nullable=True)
    text_quantity = Column(String, nullable=False)
    notes = Column(String, nullable=True)

    # 关联关系
    recipe = relationship("Recipe", back_populates="ingredients")


class Step(Base):
    """步骤表"""
    __tablename__ = "steps"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    recipe_id = Column(String, ForeignKey("recipes.id", ondelete="CASCADE"), nullable=False, index=True)
    step = Column(Integer, nullable=False)  # 步骤序号
    description = Column(Text, nullable=False)

    # 关联关系
    recipe = relationship("Recipe", back_populates="steps")


class AdditionalNote(Base):
    """小贴士表"""
    __tablename__ = "additional_notes"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    recipe_id = Column(String, ForeignKey("recipes.id", ondelete="CASCADE"), nullable=False, index=True)
    note = Column(Text, nullable=False)

    # 关联关系
    recipe = relationship("Recipe", back_populates="additional_notes")

