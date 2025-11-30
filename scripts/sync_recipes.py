#!/usr/bin/env python3
"""
从 https://weilei.site/all_recipes.json 接口同步菜谱数据到 SQLite 数据库
"""
import sys
import os
import asyncio
import logging
from typing import List, Dict, Any

import httpx

# 添加项目根目录到 Python 路径
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from app.core.database import SessionLocal, init_db
from app.models.recipe import Recipe, Ingredient, Step, AdditionalNote

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def fetch_recipes_from_api() -> List[Dict[str, Any]]:
    """
    从 API 接口获取菜谱数据

    Returns:
        List[Dict[str, Any]]: 菜谱数据列表

    Raises:
        Exception: 获取数据失败时抛出异常
    """
    url = "https://weilei.site/all_recipes.json"
    logger.info(f"正在从 {url} 获取菜谱数据...")

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()

            if not isinstance(data, list):
                raise ValueError("API 返回的数据格式不正确，应为数组")

            logger.info(f"成功获取 {len(data)} 个菜谱")
            return data

        except httpx.HTTPError as e:
            logger.error(f"网络请求失败: {e}")
            raise
        except ValueError as e:
            logger.error(f"数据解析失败: {e}")
            raise


def clear_existing_data(db):
    """
    清空现有数据（可选，用于完全重新同步）

    Args:
        db: 数据库会话
    """
    logger.info("清空现有数据...")

    # 删除顺序很重要，先删子表，再删主表
    db.query(AdditionalNote).delete()
    db.query(Step).delete()
    db.query(Ingredient).delete()
    db.query(Recipe).delete()

    db.commit()
    logger.info("现有数据已清空")


def save_recipe_to_db(db, recipe_data: Dict[str, Any]):
    """
    将单个菜谱数据保存到数据库

    Args:
        db: 数据库会话
        recipe_data: 菜谱数据字典
    """
    try:
        # 创建主菜谱记录
        recipe = Recipe(
            id=recipe_data['id'],
            name=recipe_data['name'],
            description=recipe_data.get('description'),
            source_path=recipe_data.get('source_path'),
            image_path=recipe_data.get('image_path'),
            images=recipe_data.get('images', []),
            category=recipe_data.get('category'),
            difficulty=recipe_data.get('difficulty'),
            tags=recipe_data.get('tags', []),
            servings=recipe_data.get('servings'),
            prep_time_minutes=recipe_data.get('prep_time_minutes'),
            cook_time_minutes=recipe_data.get('cook_time_minutes'),
            total_time_minutes=recipe_data.get('total_time_minutes')
        )

        db.add(recipe)
        db.flush()  # 获取 recipe.id 用于关联

        # 添加食材
        for ingredient_data in recipe_data.get('ingredients', []):
            ingredient = Ingredient(
                recipe_id=recipe.id,
                name=ingredient_data['name'],
                quantity=ingredient_data.get('quantity'),
                unit=ingredient_data.get('unit'),
                text_quantity=ingredient_data.get('text_quantity', ''),
                notes=ingredient_data.get('notes')
            )
            db.add(ingredient)

        # 添加步骤
        for step_data in recipe_data.get('steps', []):
            step = Step(
                recipe_id=recipe.id,
                step=step_data['step'],
                description=step_data['description']
            )
            db.add(step)

        # 添加小贴士
        for note_text in recipe_data.get('additional_notes', []):
            note = AdditionalNote(
                recipe_id=recipe.id,
                note=note_text
            )
            db.add(note)

        db.commit()
        logger.debug(f"菜谱 '{recipe.name}' 已保存")

    except Exception as e:
        db.rollback()
        logger.error(f"保存菜谱 '{recipe_data.get('name', 'unknown')}' 失败: {e}")
        raise


async def sync_recipes(clear_first: bool = False):
    """
    同步菜谱数据到数据库

    Args:
        clear_first: 是否先清空现有数据
    """
    logger.info("开始同步菜谱数据...")

    # 获取数据
    recipes_data = await fetch_recipes_from_api()

    # 初始化数据库会话
    db = SessionLocal()

    try:
        # 初始化数据库（创建表）
        init_db()

        if clear_first:
            clear_existing_data(db)

        # 保存数据
        success_count = 0
        for recipe_data in recipes_data:
            try:
                save_recipe_to_db(db, recipe_data)
                success_count += 1
            except Exception as e:
                logger.error(f"保存菜谱失败，跳过: {e}")
                continue

        logger.info(f"同步完成！成功保存 {success_count}/{len(recipes_data)} 个菜谱")

    except Exception as e:
        logger.error(f"同步过程中发生错误: {e}")
        raise
    finally:
        db.close()


async def amain():
    """异步主函数"""
    import argparse

    parser = argparse.ArgumentParser(description='同步菜谱数据到数据库')
    parser.add_argument('--clear', action='store_true',
                       help='先清空现有数据再同步')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='显示详细日志')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        await sync_recipes(clear_first=args.clear)
        logger.info("同步任务完成！")
    except Exception as e:
        logger.error(f"同步失败: {e}")
        sys.exit(1)


def main():
    """主函数入口"""
    asyncio.run(amain())


if __name__ == "__main__":
    main()
