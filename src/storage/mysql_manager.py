
"""
MySQL 存储管理器 - 直接操作 novel_backend 的 api_keys 表

gcli2api 作为管理面板，通过此后端读写共享的 MySQL api_keys 表。
novel_backend 作为生产运行时使用同一张表。

核心映射：gcli2api 的 filename 参数 = api_keys.id 列
"""

import asyncio
import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import aiomysql

from log import log


class MySQLManager:
    """MySQL 存储后端，直接操作 api_keys 表"""

    # gcli2api 状态字段常量
    STATE_FIELDS = {
        "error_codes",
        "disabled",
        "last_success",
        "user_email",
        "model_cooldowns",
    }

    def __init__(self):
        self._pool: Optional[aiomysql.Pool] = None
        self._initialized = False
        self._lock = asyncio.Lock()


    async def initialize(self) -> None:
        """初始化 MySQL 连接池

        连接参数获取优先级：
        1. MYSQL_URI 环境变量（完整连接字符串，如 mysql://user:pass@host:port/db）
        2. MYSQL_HOST/PORT/USER/PASSWORD/NAME 分离环境变量（与 novel_backend 共用同一组配置）
        """
        if self._initialized:
            return

        async with self._lock:
            if self._initialized:
                return

            try:
                conn_params = self._resolve_connection_params()

                self._pool = await aiomysql.create_pool(
                    host=conn_params["host"],
                    port=conn_params["port"],
                    user=conn_params["user"],
                    password=conn_params["password"],
                    db=conn_params["db"],
                    charset="utf8mb4",
                    autocommit=True,
                    minsize=1,
                    maxsize=5,
                )

                # Test connection
                async with self._pool.acquire() as conn:
                    async with conn.cursor() as cur:
                        await cur.execute("SELECT 1")

                self._initialized = True
                log.info(f"MySQL storage initialized: {conn_params['host']}:{conn_params['port']}/{conn_params['db']}")

            except Exception as e:
                log.error(f"Error initializing MySQL: {e}")
                raise

    @staticmethod
    def _resolve_connection_params() -> Dict[str, Any]:
        """解析 MySQL 连接参数

        优先级：
        1. MYSQL_URI（完整连接字符串）
        2. MYSQL_HOST/PORT/USER/PASSWORD/NAME（与 novel_backend DatabaseConfig 共用）
        """
        mysql_uri = os.getenv("MYSQL_URI", "")
        if mysql_uri:
            return MySQLManager._parse_mysql_uri(mysql_uri)

        # 使用与 novel_backend 相同的 MYSQL_* 分离环境变量
        host = os.getenv("MYSQL_HOST", "")
        if not host:
            raise ValueError(
                "MySQL not configured. Set either MYSQL_URI or MYSQL_HOST/PORT/USER/PASSWORD/NAME"
            )

        return {
            "host": host,
            "port": int(os.getenv("MYSQL_PORT", "3306")),
            "user": os.getenv("MYSQL_USER", "root"),
            "password": os.getenv("MYSQL_PASSWORD", ""),
            "db": os.getenv("MYSQL_NAME", "manbo_db"),
        }

    @staticmethod
    def _parse_mysql_uri(uri: str) -> Dict[str, Any]:
        """Parse mysql://user:pass@host:port/db format"""
        # Strip scheme
        uri = uri.replace("mysql+asyncmy://", "").replace("mysql+aiomysql://", "").replace("mysql://", "")

        # Split user:pass@host:port/db
        if "@" in uri:
            user_pass, host_db = uri.rsplit("@", 1)
        else:
            user_pass, host_db = "", uri

        if ":" in user_pass:
            user, password = user_pass.split(":", 1)
        else:
            user, password = user_pass, ""

        if "/" in host_db:
            host_port, db = host_db.split("/", 1)
        else:
            host_port, db = host_db, "manbo_db"

        # Strip query params from db
        if "?" in db:
            db = db.split("?", 1)[0]

        if ":" in host_port:
            host, port_str = host_port.split(":", 1)
            port = int(port_str)
        else:
            host, port = host_port, 3306

        return {
            "host": host,
            "port": port,
            "user": user,
            "password": password,
            "db": db,
        }

    async def close(self) -> None:
        """关闭连接池"""
        if self._pool:
            self._pool.close()
            await self._pool.wait_closed()
            self._pool = None
        self._initialized = False
        log.debug("MySQL storage closed")

    def _ensure_initialized(self):
        if not self._initialized or not self._pool:
            raise RuntimeError("MySQL manager not initialized")

    @staticmethod
    def _strip_ext(filename: str) -> str:
        """filename.json → filename（存入 DB 前去掉后缀）"""
        return filename[:-5] if filename.endswith(".json") else filename

    @staticmethod
    def _add_ext(db_id: str) -> str:
        """filename → filename.json（从 DB 读出后加回后缀）"""
        return db_id if db_id.endswith(".json") else db_id + ".json"

    # ============ 字段映射工具 ============

    @staticmethod
    def _gcli2api_to_mysql(filename: str, credential_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        将 gcli2api 格式的凭证数据转换为 MySQL api_keys 行数据

        gcli2api credential_data 包含完整的 OAuth 凭证：
        {token, client_id, client_secret, refresh_token, project_id, expiry, scopes, token_uri, ...}

        拆分为：
        - access_token 列: credential_data.token
        - token_expiry 列: credential_data.expiry
        - credential_data JSON: 其余静态字段
        """
        row = {
            "id": filename,
            "credential_type": "OAUTH",
            "key_type": "FREE",
        }

        # Extract volatile fields to dedicated columns
        access_token = credential_data.get("token") or credential_data.get("access_token")
        if access_token:
            row["access_token"] = access_token

        expiry_val = credential_data.get("expiry") or credential_data.get("token_expiry")
        if expiry_val:
            if isinstance(expiry_val, (int, float)):
                # Unix timestamp -> datetime
                row["token_expiry"] = datetime.fromtimestamp(expiry_val, tz=timezone.utc)
            elif isinstance(expiry_val, str):
                try:
                    row["token_expiry"] = datetime.fromisoformat(expiry_val.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    pass

        # Build static credential_data JSON (exclude volatile fields)
        static_keys_to_exclude = {"token", "access_token", "expiry", "token_expiry"}
        static_data = {k: v for k, v in credential_data.items() if k not in static_keys_to_exclude}
        row["credential_data"] = json.dumps(static_data)

        return row

    @staticmethod
    def _mysql_to_gcli2api(row: Dict[str, Any]) -> Dict[str, Any]:
        """
        将 MySQL api_keys 行转换为 gcli2api 格式

        重组完整的 credential_data，并添加状态信息
        """
        # Parse static credential_data JSON
        cred_data_raw = row.get("credential_data", "{}")
        try:
            credential_data = json.loads(cred_data_raw) if isinstance(cred_data_raw, str) else cred_data_raw
        except json.JSONDecodeError:
            credential_data = {}

        # Merge volatile columns back as gcli2api field names
        access_token = row.get("access_token")
        if access_token:
            credential_data["token"] = access_token

        token_expiry = row.get("token_expiry")
        if token_expiry:
            if isinstance(token_expiry, datetime):
                credential_data["expiry"] = token_expiry.timestamp()
            elif isinstance(token_expiry, (int, float)):
                credential_data["expiry"] = token_expiry

        return credential_data

    # ============ StorageBackend 协议方法 ============

    async def store_credential(self, filename: str, credential_data: Dict[str, Any], mode: str = "geminicli") -> bool:
        """存储或更新凭证 → INSERT/UPDATE api_keys"""
        self._ensure_initialized()
        filename = self._strip_ext(filename)

        if mode != "geminicli":
            log.warning(f"MySQL backend only supports geminicli mode, got: {mode}")
            return False

        try:
            row = self._gcli2api_to_mysql(filename, credential_data)

            async with self._pool.acquire() as conn:
                async with conn.cursor() as cur:
                    # Check if exists
                    await cur.execute("SELECT id FROM api_keys WHERE id = %s", (filename,))
                    existing = await cur.fetchone()

                    if existing:
                        # Update existing (preserve runtime stats)
                        await cur.execute("""
                            UPDATE api_keys
                            SET credential_data = %s,
                                access_token = %s,
                                token_expiry = %s,
                                credential_type = %s,
                                updated_at = NOW()
                            WHERE id = %s
                        """, (
                            row["credential_data"],
                            row.get("access_token"),
                            row.get("token_expiry"),
                            row["credential_type"],
                            filename,
                        ))
                    else:
                        # Insert new
                        await cur.execute("""
                            INSERT INTO api_keys
                            (id, credential_type, credential_data, access_token, token_expiry,
                             key_type, is_disabled, total_requests, successful_requests,
                             failed_requests, created_at, updated_at)
                            VALUES (%s, %s, %s, %s, %s, %s, 0, 0, 0, 0, NOW(), NOW())
                        """, (
                            row["id"],
                            row["credential_type"],
                            row["credential_data"],
                            row.get("access_token"),
                            row.get("token_expiry"),
                            row["key_type"],
                        ))

            log.debug(f"Stored credential: {filename}")
            return True

        except Exception as e:
            log.error(f"Error storing credential {filename}: {e}")
            return False

    async def get_credential(self, filename: str, mode: str = "geminicli") -> Optional[Dict[str, Any]]:
        """获取凭证数据 → SELECT from api_keys WHERE id = ?"""
        self._ensure_initialized()
        filename = self._strip_ext(filename)

        if mode != "geminicli":
            return None

        try:
            async with self._pool.acquire() as conn:
                async with conn.cursor(aiomysql.DictCursor) as cur:
                    await cur.execute(
                        "SELECT * FROM api_keys WHERE id = %s", (filename,)
                    )
                    row = await cur.fetchone()

                    if row:
                        return self._mysql_to_gcli2api(row)
                    return None

        except Exception as e:
            log.error(f"Error getting credential {filename}: {e}")
            return None

    async def list_credentials(self, mode: str = "geminicli") -> List[str]:
        """列出所有凭证 ID"""
        self._ensure_initialized()

        if mode != "geminicli":
            return []

        try:
            async with self._pool.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT id FROM api_keys WHERE credential_type = 'OAUTH' ORDER BY created_at"
                    )
                    rows = await cur.fetchall()
                    return [self._add_ext(row[0]) for row in rows]

        except Exception as e:
            log.error(f"Error listing credentials: {e}")
            return []

    async def delete_credential(self, filename: str, mode: str = "geminicli") -> bool:
        """删除凭证 → DELETE FROM api_keys WHERE id = ?"""
        self._ensure_initialized()
        filename = self._strip_ext(filename)

        if mode != "geminicli":
            return False

        try:
            async with self._pool.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute("DELETE FROM api_keys WHERE id = %s", (filename,))
                    deleted = cur.rowcount > 0

            if deleted:
                log.debug(f"Deleted credential: {filename}")
            else:
                log.warning(f"No credential found to delete: {filename}")
            return deleted

        except Exception as e:
            log.error(f"Error deleting credential {filename}: {e}")
            return False

    # ============ 状态管理 ============

    async def update_credential_state(self, filename: str, state_updates: Dict[str, Any], mode: str = "geminicli") -> bool:
        """更新凭证状态 → UPDATE api_keys SET ... WHERE id = ?"""
        self._ensure_initialized()
        filename = self._strip_ext(filename)

        if mode != "geminicli":
            return False

        try:
            set_clauses = []
            values = []

            for key, value in state_updates.items():
                if key == "disabled":
                    set_clauses.append("is_disabled = %s")
                    values.append(1 if value else 0)
                elif key == "user_email":
                    set_clauses.append("user_email = %s")
                    values.append(value)
                elif key == "error_codes":
                    # Map to last_error_code (store last error code from the list)
                    if isinstance(value, list) and value:
                        last_code = value[-1] if value else None
                        if isinstance(last_code, (int, str)):
                            set_clauses.append("last_error_code = %s")
                            try:
                                values.append(int(last_code))
                            except (ValueError, TypeError):
                                values.append(None)
                    elif not value:
                        set_clauses.append("last_error_code = %s")
                        values.append(None)
                elif key == "last_success":
                    set_clauses.append("last_success_at = %s")
                    if isinstance(value, (int, float)):
                        values.append(datetime.fromtimestamp(value, tz=timezone.utc))
                    else:
                        values.append(value)
                elif key == "model_cooldowns":
                    # Map model_cooldowns dict to cooldown_until (use max cooldown)
                    if isinstance(value, dict) and value:
                        current_time = time.time()
                        active = {k: v for k, v in value.items() if v > current_time}
                        if active:
                            max_cd = max(active.values())
                            set_clauses.append("cooldown_until = %s")
                            values.append(datetime.fromtimestamp(max_cd, tz=timezone.utc))
                        else:
                            set_clauses.append("cooldown_until = %s")
                            values.append(None)
                    else:
                        set_clauses.append("cooldown_until = %s")
                        values.append(None)

            if not set_clauses:
                return True

            set_clauses.append("updated_at = NOW()")
            values.append(filename)

            async with self._pool.acquire() as conn:
                async with conn.cursor() as cur:
                    sql = f"UPDATE api_keys SET {', '.join(set_clauses)} WHERE id = %s"
                    await cur.execute(sql, values)
                    return cur.rowcount > 0

        except Exception as e:
            log.error(f"Error updating credential state {filename}: {e}")
            return False

    async def get_credential_state(self, filename: str, mode: str = "geminicli") -> Dict[str, Any]:
        """获取凭证状态"""
        self._ensure_initialized()
        filename = self._strip_ext(filename)

        if mode != "geminicli":
            return {}

        try:
            async with self._pool.acquire() as conn:
                async with conn.cursor(aiomysql.DictCursor) as cur:
                    await cur.execute("""
                        SELECT is_disabled, last_error_code, last_success_at,
                               user_email, cooldown_until
                        FROM api_keys WHERE id = %s
                    """, (filename,))
                    row = await cur.fetchone()

                    if row:
                        return self._row_to_state(row)

                    # Default state
                    return {
                        "disabled": False,
                        "error_codes": [],
                        "last_success": time.time(),
                        "user_email": None,
                        "model_cooldowns": {},
                    }

        except Exception as e:
            log.error(f"Error getting credential state {filename}: {e}")
            return {}

    async def get_all_credential_states(self, mode: str = "geminicli") -> Dict[str, Dict[str, Any]]:
        """获取所有凭证状态"""
        self._ensure_initialized()

        if mode != "geminicli":
            return {}

        try:
            async with self._pool.acquire() as conn:
                async with conn.cursor(aiomysql.DictCursor) as cur:
                    await cur.execute("""
                        SELECT id, is_disabled, last_error_code, last_success_at,
                               user_email, cooldown_until
                        FROM api_keys
                        WHERE credential_type = 'OAUTH'
                    """)
                    rows = await cur.fetchall()

                    states = {}
                    for row in rows:
                        states[self._add_ext(row["id"])] = self._row_to_state(row)
                    return states

        except Exception as e:
            log.error(f"Error getting all credential states: {e}")
            return {}

    @staticmethod
    def _row_to_state(row: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a MySQL row to gcli2api state format"""
        # Build error_codes list from last_error_code
        error_codes = []
        if row.get("last_error_code"):
            error_codes = [int(row["last_error_code"])]

        # Convert last_success_at to timestamp
        last_success = time.time()
        last_success_at = row.get("last_success_at")
        if last_success_at and isinstance(last_success_at, datetime):
            last_success = last_success_at.timestamp()

        # Convert cooldown_until to model_cooldowns format
        model_cooldowns = {}
        cooldown_until = row.get("cooldown_until")
        if cooldown_until and isinstance(cooldown_until, datetime):
            cd_ts = cooldown_until.timestamp()
            if cd_ts > time.time():
                # Use a generic key since MySQL doesn't track per-model cooldowns
                model_cooldowns["_global"] = cd_ts

        return {
            "disabled": bool(row.get("is_disabled", 0)),
            "error_codes": error_codes,
            "last_success": last_success,
            "user_email": row.get("user_email"),
            "model_cooldowns": model_cooldowns,
        }

    # ============ 凭证摘要与监控 ============

    async def get_credentials_summary(
        self,
        offset: int = 0,
        limit: Optional[int] = None,
        status_filter: str = "all",
        mode: str = "geminicli",
        error_code_filter: Optional[str] = None,
        cooldown_filter: Optional[str] = None
    ) -> Dict[str, Any]:
        """获取凭证摘要信息（用于管理面板展示）"""
        self._ensure_initialized()

        if mode != "geminicli":
            return {"items": [], "total": 0, "offset": offset, "limit": limit, "stats": {"total": 0, "normal": 0, "disabled": 0}}

        try:
            async with self._pool.acquire() as conn:
                async with conn.cursor(aiomysql.DictCursor) as cur:
                    # Global stats (unfiltered)
                    await cur.execute("""
                        SELECT
                            COUNT(*) as total,
                            SUM(CASE WHEN is_disabled = 0 THEN 1 ELSE 0 END) as normal,
                            SUM(CASE WHEN is_disabled = 1 THEN 1 ELSE 0 END) as disabled
                        FROM api_keys
                        WHERE credential_type = 'OAUTH'
                    """)
                    stats_row = await cur.fetchone()
                    global_stats = {
                        "total": int(stats_row["total"] or 0),
                        "normal": int(stats_row["normal"] or 0),
                        "disabled": int(stats_row["disabled"] or 0),
                    }

                    # Build filtered query
                    where_clauses = ["credential_type = 'OAUTH'"]
                    params = []

                    if status_filter == "enabled":
                        where_clauses.append("is_disabled = 0")
                    elif status_filter == "disabled":
                        where_clauses.append("is_disabled = 1")

                    if error_code_filter and str(error_code_filter).strip().lower() != "all":
                        try:
                            code = int(error_code_filter)
                            where_clauses.append("last_error_code = %s")
                            params.append(code)
                        except ValueError:
                            pass

                    if cooldown_filter == "in_cooldown":
                        where_clauses.append("cooldown_until IS NOT NULL AND cooldown_until > NOW()")
                    elif cooldown_filter == "no_cooldown":
                        where_clauses.append("(cooldown_until IS NULL OR cooldown_until <= NOW())")

                    where_sql = " AND ".join(where_clauses)

                    # Count total matching
                    await cur.execute(f"SELECT COUNT(*) as cnt FROM api_keys WHERE {where_sql}", params)
                    total_row = await cur.fetchone()
                    total_count = int(total_row["cnt"])

                    # Fetch page
                    order_sql = "ORDER BY created_at"
                    limit_sql = ""
                    page_params = list(params)
                    if limit is not None:
                        limit_sql = f"LIMIT %s OFFSET %s"
                        page_params.extend([limit, offset])

                    await cur.execute(
                        f"""SELECT id, is_disabled, last_error_code, last_success_at,
                                   user_email, cooldown_until,
                                   total_requests, successful_requests, failed_requests
                            FROM api_keys
                            WHERE {where_sql}
                            {order_sql} {limit_sql}""",
                        page_params,
                    )
                    rows = await cur.fetchall()

                    current_time = time.time()
                    items = []
                    for row in rows:
                        error_codes = [int(row["last_error_code"])] if row.get("last_error_code") else []

                        last_success_val = current_time
                        if row.get("last_success_at") and isinstance(row["last_success_at"], datetime):
                            last_success_val = row["last_success_at"].timestamp()

                        active_cooldowns = {}
                        if row.get("cooldown_until") and isinstance(row["cooldown_until"], datetime):
                            cd_ts = row["cooldown_until"].timestamp()
                            if cd_ts > current_time:
                                active_cooldowns["_global"] = cd_ts

                        items.append({
                            "filename": self._add_ext(row["id"]),
                            "disabled": bool(row.get("is_disabled", 0)),
                            "error_codes": error_codes,
                            "last_success": last_success_val,
                            "user_email": row.get("user_email"),
                            "rotation_order": 0,
                            "model_cooldowns": active_cooldowns,
                            "total_requests": int(row.get("total_requests", 0)),
                            "successful_requests": int(row.get("successful_requests", 0)),
                            "failed_requests": int(row.get("failed_requests", 0)),
                        })

                    return {
                        "items": items,
                        "total": total_count,
                        "offset": offset,
                        "limit": limit,
                        "stats": global_stats,
                    }

        except Exception as e:
            log.error(f"Error getting credentials summary: {e}")
            return {
                "items": [],
                "total": 0,
                "offset": offset,
                "limit": limit,
                "stats": {"total": 0, "normal": 0, "disabled": 0},
            }

    async def get_duplicate_credentials_by_email(self, mode: str = "geminicli") -> Dict[str, Any]:
        """获取按邮箱分组的重复凭证信息"""
        self._ensure_initialized()

        if mode != "geminicli":
            return {"email_groups": {}, "duplicate_groups": [], "duplicate_count": 0,
                    "no_email_files": [], "no_email_count": 0, "unique_email_count": 0, "total_count": 0}

        try:
            async with self._pool.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute("""
                        SELECT id, user_email
                        FROM api_keys
                        WHERE credential_type = 'OAUTH'
                        ORDER BY id
                    """)
                    rows = await cur.fetchall()

                    email_to_files = {}
                    no_email_files = []

                    for cred_id, user_email in rows:
                        ext_id = self._add_ext(cred_id)
                        if user_email:
                            if user_email not in email_to_files:
                                email_to_files[user_email] = []
                            email_to_files[user_email].append(ext_id)
                        else:
                            no_email_files.append(ext_id)

                    duplicate_groups = []
                    total_duplicate_count = 0

                    for email, files in email_to_files.items():
                        if len(files) > 1:
                            duplicate_groups.append({
                                "email": email,
                                "kept_file": files[0],
                                "duplicate_files": files[1:],
                                "duplicate_count": len(files) - 1,
                            })
                            total_duplicate_count += len(files) - 1

                    return {
                        "email_groups": email_to_files,
                        "duplicate_groups": duplicate_groups,
                        "duplicate_count": total_duplicate_count,
                        "no_email_files": no_email_files,
                        "no_email_count": len(no_email_files),
                        "unique_email_count": len(email_to_files),
                        "total_count": len(rows),
                    }

        except Exception as e:
            log.error(f"Error getting duplicate credentials by email: {e}")
            return {
                "email_groups": {},
                "duplicate_groups": [],
                "duplicate_count": 0,
                "no_email_files": [],
                "no_email_count": 0,
                "unique_email_count": 0,
                "total_count": 0,
            }

    # ============ 凭证选取 ============

    async def get_next_available_credential(
        self, mode: str = "geminicli", model_key: Optional[str] = None
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        """
        随机获取一个可用凭证

        查询条件：is_disabled=0 AND (cooldown_until IS NULL OR cooldown_until < NOW())
        """
        self._ensure_initialized()

        if mode != "geminicli":
            return None

        try:
            async with self._pool.acquire() as conn:
                async with conn.cursor(aiomysql.DictCursor) as cur:
                    await cur.execute("""
                        SELECT id, credential_data, access_token, token_expiry
                        FROM api_keys
                        WHERE credential_type = 'OAUTH'
                          AND is_disabled = 0
                          AND (cooldown_until IS NULL OR cooldown_until < NOW())
                        ORDER BY RAND()
                        LIMIT 1
                    """)
                    row = await cur.fetchone()

                    if row:
                        credential_data = self._mysql_to_gcli2api(row)
                        return self._add_ext(row["id"]), credential_data
                    return None

        except Exception as e:
            log.error(f"Error getting next available credential: {e}")
            return None

    # ============ 冷却管理 ============

    async def set_model_cooldown(
        self,
        filename: str,
        model_key: str,
        cooldown_until: Optional[float],
        mode: str = "geminicli"
    ) -> bool:
        """
        设置冷却时间

        MySQL api_keys 使用单一 cooldown_until 列（不区分模型），
        映射为更新该列。
        """
        self._ensure_initialized()
        filename = self._strip_ext(filename)

        if mode != "geminicli":
            return False

        try:
            async with self._pool.acquire() as conn:
                async with conn.cursor() as cur:
                    if cooldown_until is None:
                        await cur.execute(
                            "UPDATE api_keys SET cooldown_until = NULL, updated_at = NOW() WHERE id = %s",
                            (filename,),
                        )
                    else:
                        cd_dt = datetime.fromtimestamp(cooldown_until, tz=timezone.utc)
                        await cur.execute(
                            "UPDATE api_keys SET cooldown_until = %s, updated_at = NOW() WHERE id = %s",
                            (cd_dt, filename),
                        )
                    return cur.rowcount > 0

        except Exception as e:
            log.error(f"Error setting model cooldown for {filename}: {e}")
            return False

    # ============ 数据库信息 ============

    async def get_database_info(self) -> Dict[str, Any]:
        """获取数据库信息"""
        self._ensure_initialized()

        try:
            async with self._pool.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute("SELECT COUNT(*) FROM api_keys WHERE credential_type = 'OAUTH'")
                    row = await cur.fetchone()
                    oauth_count = int(row[0]) if row else 0

                    await cur.execute("SELECT COUNT(*) FROM api_keys WHERE credential_type = 'API_KEY'")
                    row = await cur.fetchone()
                    apikey_count = int(row[0]) if row else 0

            return {
                "backend_type": "mysql",
                "oauth_credentials": oauth_count,
                "api_key_credentials": apikey_count,
                "pool_size": self._pool.size if self._pool else 0,
            }

        except Exception as e:
            log.error(f"Error getting database info: {e}")
            return {"backend_type": "mysql", "error": str(e)}
