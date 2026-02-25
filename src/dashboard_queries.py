"""
Dashboard SQL aggregation queries for novel platform business metrics.
All functions take an aiomysql.Pool and return dicts.
"""

from decimal import Decimal

from log import log


def _sanitize(row: dict) -> dict:
    """Convert Decimal values to int/float for JSON serialization."""
    out = {}
    for k, v in row.items():
        if isinstance(v, Decimal):
            out[k] = int(v) if v == v.to_integral_value() else float(v)
        else:
            out[k] = v
    return out


async def _fetchone(pool, sql):
    """Execute a query and return the first row as a dict."""
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(sql)
            columns = [d[0] for d in cur.description]
            row = await cur.fetchone()
            return _sanitize(dict(zip(columns, row))) if row else {}


async def _fetchall(pool, sql):
    """Execute a query and return all rows as list of dicts."""
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(sql)
            columns = [d[0] for d in cur.description]
            rows = await cur.fetchall()
            return [_sanitize(dict(zip(columns, row))) for row in rows]


async def get_user_stats(pool) -> dict:
    """User statistics: total, today, 7d, paying, inviters."""
    sql = """
        SELECT
            COUNT(*) AS total_users,
            SUM(CASE WHEN created_at >= CURDATE() THEN 1 ELSE 0 END) AS today_users,
            SUM(CASE WHEN created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY) THEN 1 ELSE 0 END) AS week_users,
            SUM(CASE WHEN has_recharged = 1 THEN 1 ELSE 0 END) AS paying_users,
            SUM(CASE WHEN invite_count > 0 THEN 1 ELSE 0 END) AS inviters
        FROM users
    """
    return await _fetchone(pool, sql)


async def get_revenue_stats(pool) -> dict:
    """Revenue statistics from user_point_records."""
    sql = """
        SELECT
            COALESCE(SUM(CASE WHEN type='recharge' AND status='completed' THEN amount ELSE 0 END), 0) AS total_revenue,
            COALESCE(SUM(CASE WHEN type='recharge' AND status='completed' AND created_at >= CURDATE() THEN amount ELSE 0 END), 0) AS today_revenue,
            COALESCE(SUM(CASE WHEN type='recharge' AND status='completed' AND created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY) THEN amount ELSE 0 END), 0) AS week_revenue,
            COALESCE(SUM(CASE WHEN type='recharge' AND status='completed' THEN points ELSE 0 END), 0) AS recharge_points,
            COALESCE(SUM(CASE WHEN type='consumption' THEN ABS(points) ELSE 0 END), 0) AS consumption_points,
            COALESCE((SELECT SUM(invite_bonus_total) FROM users), 0) AS invite_bonus_points
        FROM user_point_records
    """
    return await _fetchone(pool, sql)


async def get_novel_stats(pool) -> dict:
    """Novel and chapter statistics."""
    novels_sql = """
        SELECT
            COUNT(*) AS total_novels,
            SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) AS active_novels,
            SUM(CASE WHEN status='crowdfunding' THEN 1 ELSE 0 END) AS crowdfunding_novels,
            SUM(CASE WHEN status='importing' THEN 1 ELSE 0 END) AS importing_novels,
            SUM(CASE WHEN created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY) THEN 1 ELSE 0 END) AS new_novels_7d,
            COALESCE(SUM(current_crowdfunding_amount), 0) AS cf_raised_keys
        FROM novels
    """
    chapters_sql = """
        SELECT
            COUNT(*) AS total_chapters,
            ROUND(COALESCE(COUNT(*) / NULLIF((SELECT COUNT(*) FROM novels), 0), 0), 1) AS avg_chapters_per_novel
        FROM chapters
    """
    novels = await _fetchone(pool, novels_sql)
    chapters = await _fetchone(pool, chapters_sql)
    novels.update(chapters)
    return novels


async def get_engagement_stats(pool) -> dict:
    """Game session and message engagement statistics."""
    games_sql = """
        SELECT
            COUNT(*) AS total_games,
            SUM(CASE WHEN updated_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY) THEN 1 ELSE 0 END) AS active_games_7d
        FROM games
    """
    messages_sql = """
        SELECT
            COUNT(*) AS total_messages,
            SUM(CASE WHEN created_at >= CURDATE() THEN 1 ELSE 0 END) AS today_messages,
            ROUND(COALESCE(COUNT(*) / NULLIF((SELECT COUNT(*) FROM games), 0), 0), 1) AS avg_msgs_per_game
        FROM messages
    """
    games = await _fetchone(pool, games_sql)
    messages = await _fetchone(pool, messages_sql)
    games.update(messages)
    return games


async def get_import_stats(pool) -> dict:
    """Import novel task statistics."""
    sql = """
        SELECT
            COUNT(*) AS total_imports,
            SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) AS completed_imports,
            SUM(CASE WHEN status='processing' THEN 1 ELSE 0 END) AS processing_imports,
            SUM(CASE WHEN status='parsing' THEN 1 ELSE 0 END) AS parsing_imports,
            SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) AS error_imports,
            SUM(CASE WHEN status='waiting' THEN 1 ELSE 0 END) AS waiting_imports
        FROM import_novels
    """
    return await _fetchone(pool, sql)


async def get_api_key_stats(pool) -> dict:
    """API key usage statistics."""
    sql = """
        SELECT
            COUNT(*) AS total_keys,
            SUM(CASE WHEN is_disabled = 1 THEN 1 ELSE 0 END) AS disabled_keys,
            COALESCE(SUM(successful_requests), 0) AS success_requests,
            COALESCE(SUM(failed_requests), 0) AS failed_requests
        FROM api_keys
    """
    return await _fetchone(pool, sql)


async def get_community_stats(pool) -> dict:
    """Community engagement: comments, favorites, contributions."""
    comments_sql = """
        SELECT
            COUNT(*) AS total_comments,
            SUM(CASE WHEN created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY) THEN 1 ELSE 0 END) AS comments_7d
        FROM comments
    """
    favorites_sql = """
        SELECT
            COUNT(*) AS total_favorites,
            COALESCE(SUM(contribution_keys), 0) AS contribution_keys
        FROM favorites
    """
    comments = await _fetchone(pool, comments_sql)
    favorites = await _fetchone(pool, favorites_sql)
    comments.update(favorites)
    return comments


async def get_all_dashboard_stats(pool) -> dict:
    """Collect all dashboard stats sequentially to avoid pool contention."""
    result = {}
    sections = [
        ("users", get_user_stats),
        ("revenue", get_revenue_stats),
        ("novels", get_novel_stats),
        ("engagement", get_engagement_stats),
        ("imports", get_import_stats),
        ("api_keys", get_api_key_stats),
        ("community", get_community_stats),
    ]

    for name, fn in sections:
        try:
            result[name] = await fn(pool)
        except Exception as e:
            log.error(f"Dashboard query error [{name}]: {e}")
            result[name] = {"error": str(e)}

    return result
