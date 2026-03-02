"""为没有封面的小说随机分配默认封面

查找 novels 表中 cover_url 为 NULL 的记录，
随机分配 deafult_cover_1 ~ deafult_cover_6 中的一个。

用法:
    python assign_default_covers.py            # dry-run 模式
    python assign_default_covers.py --execute  # 实际执行
"""

import argparse
import random
import sys

import pymysql

# ============================================================================
# 数据库配置
# ============================================================================
MYSQL_HOST = "manbo-db.cx2e6myqq4nb.ap-northeast-1.rds.amazonaws.com"
MYSQL_PORT = 3306
MYSQL_USER = "admin"
MYSQL_PASSWORD = "C7jZq!!C7S$|ld<Ck!r<bpJGsdE6"
MYSQL_DB = "manbo_db"

# ============================================================================
# 默认封面配置
# ============================================================================
NUM_DEFAULT_COVERS = 6
S3_BUCKET = "manbo.chat"


def get_cover_url(idx: int) -> str:
    """生成第 idx 个默认封面的 S3 URL"""
    return f"s3://{S3_BUCKET}/covers/deafult_cover_{idx}.webp"


def get_db_connection():
    return pymysql.connect(
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DB,
        charset="utf8mb4",
        autocommit=False,
    )


def main():
    parser = argparse.ArgumentParser(description="为没有封面的小说随机分配默认封面")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="实际执行更新（默认为 dry-run 模式）",
    )
    args = parser.parse_args()

    mode = "EXECUTE" if args.execute else "DRY-RUN"

    print("=" * 60)
    print("  为无封面小说分配默认封面")
    print("=" * 60)
    print(f"  模式: {mode}")
    print(f"  默认封面数量: {NUM_DEFAULT_COVERS}")
    print("=" * 60)

    db = get_db_connection()

    try:
        with db.cursor() as cursor:
            # 查找 novels 表中没有封面的记录
            cursor.execute(
                "SELECT id, title FROM novels WHERE cover_url IS NULL OR cover_url = ''"
            )
            novels_without_cover = cursor.fetchall()

            # 查找 import_novels 表中没有封面的记录
            cursor.execute(
                "SELECT novel_id FROM import_novels WHERE cover_url IS NULL OR cover_url = ''"
            )
            import_novels_without_cover = {row[0] for row in cursor.fetchall()}

        total = len(novels_without_cover)
        print(f"\n  找到 {total} 部没有封面的小说")

        if total == 0:
            print("\n  所有小说都已有封面，无需操作。")
            return

        # 为每部小说随机分配一个默认封面
        assignments = []
        for novel_id, title in novels_without_cover:
            cover_idx = random.randint(1, NUM_DEFAULT_COVERS)
            cover_url = get_cover_url(cover_idx)
            also_import = novel_id in import_novels_without_cover
            assignments.append((novel_id, title, cover_url, cover_idx, also_import))

        # 打印分配方案
        print(f"\n  分配方案:")
        print("-" * 60)
        for novel_id, title, cover_url, cover_idx, also_import in assignments:
            display_title = title[:30] + "..." if len(title) > 30 else title
            import_mark = " [+import_novels]" if also_import else ""
            print(f"  {novel_id[:8]}.. | {display_title:<34} | cover_{cover_idx}{import_mark}")
        print("-" * 60)

        if not args.execute:
            print(f"\n  这是 dry-run 模式，未执行任何操作。")
            print(f"  添加 --execute 参数以实际执行更新。")
            return

        # 执行更新
        updated_novels = 0
        updated_imports = 0

        with db.cursor() as cursor:
            for novel_id, title, cover_url, cover_idx, also_import in assignments:
                cursor.execute(
                    "UPDATE novels SET cover_url = %s WHERE id = %s",
                    (cover_url, novel_id),
                )
                updated_novels += cursor.rowcount

                if also_import:
                    cursor.execute(
                        "UPDATE import_novels SET cover_url = %s WHERE novel_id = %s",
                        (cover_url, novel_id),
                    )
                    updated_imports += cursor.rowcount

        db.commit()

        print(f"\n  更新完成:")
        print(f"    novels 表更新: {updated_novels} 条")
        print(f"    import_novels 表更新: {updated_imports} 条")

    except Exception as e:
        db.rollback()
        print(f"\n  错误: {e}")
        sys.exit(1)
    finally:
        db.close()

    print("=" * 60)


if __name__ == "__main__":
    main()
