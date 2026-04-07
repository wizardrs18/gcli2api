"""
小说订阅迁移脚本
将旧版本小说（如 斗罗大陆、斗罗大陆0.9）的订阅(favorites)和评论(comments)
复制到 2.0 版本小说下。

用法:
    python migrate_novel_subscriptions.py              # 交互模式
    python migrate_novel_subscriptions.py --keyword 斗罗大陆  # 指定关键词
    python migrate_novel_subscriptions.py --dry-run    # 仅预览，不执行
"""

import uuid
import argparse
from datetime import datetime
from zoneinfo import ZoneInfo

import mysql.connector
from dotenv import dotenv_values

# ---------- 数据库连接 ----------

def get_connection():
    env = dotenv_values("../.env.local")
    conn = mysql.connector.connect(
        host=env.get("MYSQL_HOST", "localhost"),
        port=int(env.get("MYSQL_PORT", 3306)),
        user=env.get("MYSQL_USER", "root"),
        password=env.get("MYSQL_PASSWORD", ""),
        database=env.get("MYSQL_NAME", "manbo_db"),
        charset="utf8mb4",
    )
    return conn


# ---------- 查找小说 ----------

def find_novels(conn, keyword: str):
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT id, title, status, created_at FROM novels WHERE title LIKE %s ORDER BY created_at",
        (f"%{keyword}%",),
    )
    rows = cursor.fetchall()
    cursor.close()
    return rows


# ---------- 统计 ----------

def count_favorites(conn, novel_ids: list[str]):
    if not novel_ids:
        return 0
    placeholders = ",".join(["%s"] * len(novel_ids))
    cursor = conn.cursor()
    cursor.execute(f"SELECT COUNT(*) FROM favorites WHERE novel_id IN ({placeholders})", novel_ids)
    count = cursor.fetchone()[0]
    cursor.close()
    return count


def count_comments(conn, novel_ids: list[str]):
    if not novel_ids:
        return 0
    placeholders = ",".join(["%s"] * len(novel_ids))
    cursor = conn.cursor()
    cursor.execute(f"SELECT COUNT(*) FROM comments WHERE novel_id IN ({placeholders})", novel_ids)
    count = cursor.fetchone()[0]
    cursor.close()
    return count


# ---------- 迁移 favorites ----------

def migrate_favorites(conn, source_novel_ids: list[str], target_novel_id: str, dry_run: bool = False):
    if not source_novel_ids:
        return 0

    placeholders = ",".join(["%s"] * len(source_novel_ids))
    cursor = conn.cursor(dictionary=True)

    # 获取源 favorites
    cursor.execute(
        f"SELECT user_id, contribution_keys, max_branch_count, created_at "
        f"FROM favorites WHERE novel_id IN ({placeholders})",
        source_novel_ids,
    )
    source_favorites = cursor.fetchall()

    # 获取目标已有的 user_id（避免唯一约束冲突）
    cursor.execute(
        "SELECT user_id FROM favorites WHERE novel_id = %s",
        (target_novel_id,),
    )
    existing_user_ids = {row["user_id"] for row in cursor.fetchall()}

    # 去重：同一个 user 在多个旧版本可能都有记录，取 contribution_keys 最大的
    user_best = {}
    for fav in source_favorites:
        uid = fav["user_id"]
        if uid in existing_user_ids:
            continue
        if uid not in user_best or fav["contribution_keys"] > user_best[uid]["contribution_keys"]:
            user_best[uid] = fav

    to_insert = list(user_best.values())

    if dry_run:
        cursor.close()
        return len(to_insert)

    inserted = 0
    for fav in to_insert:
        new_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO favorites (id, user_id, novel_id, contribution_keys, max_branch_count, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (new_id, fav["user_id"], target_novel_id, fav["contribution_keys"], fav["max_branch_count"], fav["created_at"]),
        )
        inserted += 1

    cursor.close()
    return inserted


# ---------- 迁移 comments ----------

def migrate_comments(conn, source_novel_ids: list[str], target_novel_id: str, dry_run: bool = False):
    if not source_novel_ids:
        return 0

    placeholders = ",".join(["%s"] * len(source_novel_ids))
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        f"SELECT user_id, content, like_count, created_at, updated_at "
        f"FROM comments WHERE novel_id IN ({placeholders})",
        source_novel_ids,
    )
    source_comments = cursor.fetchall()

    # 获取目标已有的评论，用 (user_id, content) 去重，防止重复运行产生重复评论
    cursor.execute(
        "SELECT user_id, content FROM comments WHERE novel_id = %s",
        (target_novel_id,),
    )
    existing_comments = {(row["user_id"], row["content"]) for row in cursor.fetchall()}

    to_insert = [c for c in source_comments if (c["user_id"], c["content"]) not in existing_comments]

    if dry_run:
        cursor.close()
        return len(to_insert)

    inserted = 0
    for comment in to_insert:
        new_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO comments (id, novel_id, user_id, content, like_count, created_at, updated_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (new_id, target_novel_id, comment["user_id"], comment["content"],
             comment["like_count"], comment["created_at"], comment["updated_at"]),
        )
        inserted += 1

    cursor.close()
    return inserted


# ---------- 主流程 ----------

def main():
    parser = argparse.ArgumentParser(description="小说订阅/评论迁移脚本")
    parser.add_argument("--keyword", default="斗罗大陆", help="搜索关键词 (默认: 斗罗大陆)")
    parser.add_argument("--dry-run", action="store_true", help="仅预览，不执行迁移")
    args = parser.parse_args()

    conn = get_connection()
    print(f"已连接数据库\n")

    # 1. 查找小说
    novels = find_novels(conn, args.keyword)
    if not novels:
        print(f"未找到包含 '{args.keyword}' 的小说")
        conn.close()
        return

    print(f"找到 {len(novels)} 本相关小说：")
    print("-" * 80)
    for i, n in enumerate(novels):
        fav_count = count_favorites(conn, [n["id"]])
        comment_count = count_comments(conn, [n["id"]])
        print(f"  [{i}] {n['title']:<20s}  ID: {n['id']}  订阅: {fav_count}  评论: {comment_count}")
    print("-" * 80)

    # 2. 选择目标（2.0 版本）
    target_idx = input("\n请输入目标小说（2.0版本）的编号: ").strip()
    try:
        target_idx = int(target_idx)
        target_novel = novels[target_idx]
    except (ValueError, IndexError):
        print("无效的编号，退出")
        conn.close()
        return

    # 源小说 = 除目标外的所有小说
    source_novels = [n for i, n in enumerate(novels) if i != target_idx]
    source_ids = [n["id"] for n in source_novels]

    print(f"\n目标小说: {target_novel['title']} ({target_novel['id']})")
    print(f"源小说:   {', '.join(n['title'] for n in source_novels)}")

    # 3. 预览
    fav_to_migrate = migrate_favorites(conn, source_ids, target_novel["id"], dry_run=True)
    comments_to_migrate = migrate_comments(conn, source_ids, target_novel["id"], dry_run=True)

    print(f"\n将迁移:")
    print(f"  - 订阅(favorites): {fav_to_migrate} 条（已去重，跳过已存在的）")
    print(f"  - 评论(comments):  {comments_to_migrate} 条")

    if args.dry_run:
        print("\n[DRY-RUN] 预览完毕，未执行任何修改")
        conn.close()
        return

    # 4. 确认执行
    confirm = input("\n确认执行迁移？(y/N): ").strip().lower()
    if confirm != "y":
        print("已取消")
        conn.close()
        return

    # 5. 执行迁移
    fav_inserted = migrate_favorites(conn, source_ids, target_novel["id"])
    print(f"  订阅迁移完成: {fav_inserted} 条")

    comments_inserted = migrate_comments(conn, source_ids, target_novel["id"])
    print(f"  评论迁移完成: {comments_inserted} 条")

    print("\n迁移完成!")
    conn.close()


if __name__ == "__main__":
    main()
