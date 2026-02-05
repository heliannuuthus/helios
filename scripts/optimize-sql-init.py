#!/usr/bin/env python3
"""
优化 SQL 初始化脚本，将单独的 INSERT 语句合并为批量 INSERT
"""

import re
import sys
from collections import defaultdict
from pathlib import Path


def parse_insert(line: str) -> tuple[str, str, str] | None:
    """
    解析 INSERT 语句，返回 (表名, 字段列表, 值)
    """
    # 匹配带字段名的 INSERT: INSERT INTO table (fields) VALUES (...)
    match = re.match(
        r"INSERT INTO (\S+)\s*\(([^)]+)\)\s*VALUES\s*\((.+)\);?\s*$",
        line,
        re.IGNORECASE | re.DOTALL,
    )
    if match:
        return match.group(1), match.group(2).strip(), match.group(3).strip()

    # 匹配不带字段名的 INSERT: INSERT INTO table VALUES (...)
    match = re.match(
        r"INSERT INTO (\S+)\s+VALUES\s*\((.+)\);?\s*$", line, re.IGNORECASE | re.DOTALL
    )
    if match:
        return match.group(1), None, match.group(2).strip()

    return None


def optimize_sql(input_path: Path, output_path: Path, batch_size: int = 100):
    """
    优化 SQL 文件，合并 INSERT 语句
    """
    with open(input_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # 按表分组的 INSERT 数据
    # key: (table_name, fields) -> list of values
    table_inserts: dict[tuple[str, str | None], list[str]] = defaultdict(list)

    # 非 INSERT 语句保持原样
    other_lines: list[tuple[int, str]] = []  # (位置, 内容)

    # 记录每个表第一次出现的位置
    table_first_pos: dict[str, int] = {}

    current_insert = ""
    in_multiline = False

    for i, line in enumerate(lines):
        # 处理多行 INSERT（值中包含换行）
        if in_multiline:
            current_insert += line
            if line.rstrip().endswith(";"):
                in_multiline = False
                result = parse_insert(current_insert)
                if result:
                    table, fields, values = result
                    key = (table, fields)
                    if table not in table_first_pos:
                        table_first_pos[table] = i
                    table_inserts[key].append(values)
                current_insert = ""
            continue

        stripped = line.strip()

        # 跳过空行
        if not stripped:
            other_lines.append((i, line))
            continue

        # 注释行
        if stripped.startswith("--"):
            other_lines.append((i, line))
            continue

        # USE 语句等
        if stripped.upper().startswith(("USE ", "SET ", "CREATE ", "ALTER ", "DROP ")):
            other_lines.append((i, line))
            continue

        # INSERT 语句
        if stripped.upper().startswith("INSERT INTO"):
            if not stripped.endswith(";"):
                # 多行 INSERT
                in_multiline = True
                current_insert = line
                continue

            result = parse_insert(stripped)
            if result:
                table, fields, values = result
                key = (table, fields)
                if table not in table_first_pos:
                    table_first_pos[table] = i
                table_inserts[key].append(values)
            else:
                # 解析失败，保持原样
                other_lines.append((i, line))
        else:
            other_lines.append((i, line))

    # 生成输出
    output_lines = []

    # 写入文件头
    output_lines.append("-- Zwei 模块初始化数据\n")
    output_lines.append("-- 注意：此文件会在 schema.sql 之后执行\n")
    output_lines.append("-- 格式已优化：合并为批量 INSERT 语句\n")
    output_lines.append("\n")
    output_lines.append("USE `zwei`;\n")
    output_lines.append("\n")

    # 按表的首次出现顺序排序
    sorted_tables = sorted(table_inserts.keys(), key=lambda k: table_first_pos.get(k[0], 0))

    for table, fields in sorted_tables:
        values_list = table_inserts[(table, fields)]
        if not values_list:
            continue

        # 写入表注释
        output_lines.append(f"-- ==================== {table} ====================\n")
        output_lines.append("\n")

        # 分批写入
        for batch_start in range(0, len(values_list), batch_size):
            batch = values_list[batch_start : batch_start + batch_size]

            if fields:
                output_lines.append(f"INSERT INTO {table} ({fields}) VALUES\n")
            else:
                output_lines.append(f"INSERT INTO {table} VALUES\n")

            for j, val in enumerate(batch):
                # 移除值末尾的分号（如果有）
                val = val.rstrip().rstrip(";")
                if j < len(batch) - 1:
                    output_lines.append(f"  ({val}),\n")
                else:
                    output_lines.append(f"  ({val});\n")

            output_lines.append("\n")

    with open(output_path, "w", encoding="utf-8") as f:
        f.writelines(output_lines)

    # 统计
    total_inserts = sum(len(v) for v in table_inserts.values())
    total_batches = sum(
        (len(v) + batch_size - 1) // batch_size for v in table_inserts.values()
    )
    print(f"优化完成:")
    print(f"  - 原始 INSERT 语句数: {total_inserts}")
    print(f"  - 优化后批量语句数: {total_batches}")
    print(f"  - 涉及表数: {len(set(k[0] for k in table_inserts.keys()))}")
    print(f"  - 输出文件: {output_path}")


def main():
    if len(sys.argv) < 2:
        # 默认处理 zwei/init.sql
        input_path = Path(__file__).parent.parent / "sql" / "zwei" / "init.sql"
        output_path = input_path  # 直接覆盖
    else:
        input_path = Path(sys.argv[1])
        output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else input_path

    if not input_path.exists():
        print(f"错误: 文件不存在 {input_path}")
        sys.exit(1)

    optimize_sql(input_path, output_path)


if __name__ == "__main__":
    main()
