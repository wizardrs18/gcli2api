"""Novel management routes - forwards requests to novel_backend admin API"""

import json
import os
import re
import uuid

from fastapi import APIRouter, Depends, Path, Query, Request, UploadFile, File
from fastapi.responses import JSONResponse

from config import get_novel_backend_url, get_novel_admin_api_key
from log import log
from src.httpx_client import get_async, post_async, put_async, http_client
from src.storage_adapter import get_storage_adapter
from src.utils import verify_panel_token

router = APIRouter(prefix="/novel")


@router.get("/imports")
async def list_imports(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    _token: str = Depends(verify_panel_token),
):
    """Forward import list request to novel_backend admin API, enrich with novels data.

    Aggregates all upstream pages into a single response so the caller can
    filter then paginate client-side. The page/page_size params are accepted
    for backward compatibility but the response always contains the full set.
    """
    backend_url = await get_novel_backend_url()
    admin_key = await get_novel_admin_api_key()
    headers = {"X-Admin-Key": admin_key}

    try:
        chunk = 100
        all_items: list = []
        cur_page = 1
        total = 0
        last_resp_status = 200
        last_resp_json: dict = {}
        while True:
            url = f"{backend_url}/api/v1/admin/import?page={cur_page}&page_size={chunk}"
            resp = await get_async(url, headers=headers)
            last_resp_status = resp.status_code
            last_resp_json = resp.json() if resp.content else {}
            if last_resp_status != 200:
                return JSONResponse(content=last_resp_json, status_code=last_resp_status)
            data = (last_resp_json or {}).get("data") or {}
            items = data.get("items") or []
            total = data.get("total") or 0
            all_items.extend(items)
            if not items or len(items) < chunk or len(all_items) >= total or cur_page >= 200:
                break
            cur_page += 1

        result = dict(last_resp_json) if isinstance(last_resp_json, dict) else {"code": 200}
        result["data"] = {
            "items": all_items,
            "total": total or len(all_items),
            "page": 1,
            "pageSize": len(all_items),
        }

        # Enrich items with visibility, cover_url and description from novels table
        try:
            items = result.get("data", {}).get("items", [])
            novel_ids = [item["novel_id"] for item in items if item.get("novel_id")]
            if novel_ids:
                adapter = await get_storage_adapter()
                if adapter.get_backend_type() == "mysql":
                    pool = adapter._backend._pool
                    if pool:
                        placeholders = ",".join(["%s"] * len(novel_ids))
                        async with pool.acquire() as conn:
                            async with conn.cursor() as cur:
                                await cur.execute(
                                    f"SELECT id, visibility, cover_url FROM novels WHERE id IN ({placeholders})",
                                    novel_ids,
                                )
                                rows = await cur.fetchall()
                        novel_map = {row[0]: {"visibility": row[1], "cover_url": row[2]} for row in rows}
                        for item in items:
                            nid = item.get("novel_id")
                            if nid and nid in novel_map:
                                item["visibility"] = novel_map[nid]["visibility"]
                                item["cover_url"] = novel_map[nid]["cover_url"]

                        # Best-effort description enrichment (column may not exist on all schemas)
                        try:
                            async with pool.acquire() as conn:
                                async with conn.cursor() as cur:
                                    await cur.execute(
                                        f"SELECT id, description FROM novels WHERE id IN ({placeholders})",
                                        novel_ids,
                                    )
                                    desc_rows = await cur.fetchall()
                            desc_map = {r[0]: r[1] for r in desc_rows}
                            for item in items:
                                nid = item.get("novel_id")
                                if nid and nid in desc_map:
                                    item["description"] = desc_map[nid]
                        except Exception as desc_err:
                            log.warning(f"Failed to enrich imports with description: {desc_err}")
        except Exception as e:
            log.warning(f"Failed to enrich imports with novel data: {e}")

        return JSONResponse(content=result, status_code=last_resp_status)
    except Exception as e:
        log.error(f"Failed to forward list imports request: {e}")
        return JSONResponse(
            content={"detail": "Failed to connect to novel backend"},
            status_code=502,
        )


@router.post("/imports/{novel_id}/retry")
async def retry_import(
    novel_id: str,
    _token: str = Depends(verify_panel_token),
):
    """Forward import retry request to novel_backend admin API"""
    backend_url = await get_novel_backend_url()
    admin_key = await get_novel_admin_api_key()

    url = f"{backend_url}/api/v1/admin/import/{novel_id}/retry"
    headers = {"X-Admin-Key": admin_key}

    try:
        resp = await post_async(url, headers=headers)
        return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except Exception as e:
        log.error(f"Failed to forward retry import request: {e}")
        return JSONResponse(
            content={"detail": "Failed to connect to novel backend"},
            status_code=502,
        )


@router.post("/imports/{novel_id}/pause")
async def pause_import(
    novel_id: str,
    _token: str = Depends(verify_panel_token),
):
    """Forward import pause request to novel_backend admin API"""
    backend_url = await get_novel_backend_url()
    admin_key = await get_novel_admin_api_key()

    url = f"{backend_url}/api/v1/admin/import/{novel_id}/pause"
    headers = {"X-Admin-Key": admin_key}

    try:
        resp = await post_async(url, headers=headers)
        return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except Exception as e:
        log.error(f"Failed to forward pause import request: {e}")
        return JSONResponse(
            content={"detail": "Failed to connect to novel backend"},
            status_code=502,
        )


@router.post("/imports/{novel_id}/reimport")
async def reimport_novel(
    novel_id: str,
    _token: str = Depends(verify_panel_token),
):
    """Forward reimport request to novel_backend admin API"""
    backend_url = await get_novel_backend_url()
    admin_key = await get_novel_admin_api_key()

    url = f"{backend_url}/api/v1/admin/import/{novel_id}/reimport"
    headers = {"X-Admin-Key": admin_key}

    try:
        resp = await post_async(url, headers=headers)
        return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except Exception as e:
        log.error(f"Failed to forward reimport request: {e}")
        return JSONResponse(
            content={"detail": "Failed to connect to novel backend"},
            status_code=502,
        )


@router.get("/imports/{novel_id}/updates")
async def get_import_updates(
    novel_id: str,
    index: int = Query(0, ge=0),
    _token: str = Depends(verify_panel_token),
):
    """Query plot_updates for a given import task directly from MySQL."""
    try:
        adapter = await get_storage_adapter()

        if adapter.get_backend_type() != "mysql":
            return JSONResponse(
                content={"detail": "This feature requires MySQL backend"},
                status_code=503,
            )

        pool = adapter._backend._pool
        if pool is None:
            return JSONResponse(
                content={"detail": "MySQL connection pool not available"},
                status_code=503,
            )

        async with pool.acquire() as conn:
            async with conn.cursor() as cur:
                # Get total count
                await cur.execute(
                    "SELECT COUNT(*) FROM plot_updates WHERE novel_id = %s",
                    (novel_id,),
                )
                total = (await cur.fetchone())[0]

                # Get record at the requested index
                item = None
                if total > 0:
                    await cur.execute(
                        "SELECT updates_json, plot_text, plot_info_json, main_plot_json "
                        "FROM plot_updates WHERE novel_id = %s AND plot_index = %s",
                        (novel_id, index),
                    )
                    rec = await cur.fetchone()
                    if rec:
                        updates_json = rec[0]
                        plot_text = rec[1]
                        plot_info_json = rec[2]
                        main_plot_json = rec[3]

                        # Parse JSON strings
                        try:
                            updates_data = json.loads(updates_json) if updates_json else None
                        except (json.JSONDecodeError, TypeError):
                            updates_data = updates_json

                        try:
                            plot_info_data = json.loads(plot_info_json) if plot_info_json else None
                        except (json.JSONDecodeError, TypeError):
                            plot_info_data = plot_info_json

                        try:
                            main_plot_data = json.loads(main_plot_json) if main_plot_json else None
                        except (json.JSONDecodeError, TypeError):
                            main_plot_data = main_plot_json

                        item = {
                            "updates_json": updates_data,
                            "plot_text": plot_text,
                            "plot_info_json": plot_info_data,
                            "main_plot_json": main_plot_data,
                        }

        return JSONResponse(content={
            "total": total,
            "index": index,
            "item": item,
        })

    except Exception as e:
        log.error(f"Failed to query plot updates: {e}")
        return JSONResponse(
            content={"detail": f"Failed to query plot updates: {e}"},
            status_code=500,
        )


@router.delete("/imports/{novel_id}")
async def delete_import(
    novel_id: str,
    _token: str = Depends(verify_panel_token),
):
    """Delete a novel and all its related data from the database."""
    try:
        adapter = await get_storage_adapter()
        if adapter.get_backend_type() != "mysql":
            return JSONResponse(
                content={"detail": "This feature requires MySQL backend"},
                status_code=503,
            )

        pool = adapter._backend._pool
        if pool is None:
            return JSONResponse(
                content={"detail": "MySQL connection pool not available"},
                status_code=503,
            )

        async with pool.acquire() as conn:
            async with conn.cursor() as cur:
                # 先通过 games 表删间接关联
                await cur.execute(
                    "DELETE FROM messages WHERE game_id IN (SELECT id FROM games WHERE novel_id = %s)", (novel_id,))
                await cur.execute(
                    "DELETE FROM game_plot_updates WHERE game_id IN (SELECT id FROM games WHERE novel_id = %s)", (novel_id,))
                await cur.execute("DELETE FROM games WHERE novel_id = %s", (novel_id,))
                # 直接关联表
                await cur.execute("DELETE FROM plot_updates WHERE novel_id = %s", (novel_id,))
                await cur.execute("DELETE FROM chapters WHERE novel_id = %s", (novel_id,))
                await cur.execute("DELETE FROM comments WHERE novel_id = %s", (novel_id,))
                await cur.execute("DELETE FROM favorites WHERE novel_id = %s", (novel_id,))
                await cur.execute("DELETE FROM reading_progress WHERE novel_id = %s", (novel_id,))
                # 最后删导入记录和小说本体
                await cur.execute("DELETE FROM import_novels WHERE novel_id = %s", (novel_id,))
                await cur.execute("DELETE FROM novels WHERE id = %s", (novel_id,))

        log.info(f"Deleted novel {novel_id} and all related data")
        return JSONResponse(content={"message": "删除成功"})

    except Exception as e:
        log.error(f"Failed to delete novel {novel_id}: {e}")
        return JSONResponse(
            content={"detail": f"删除失败: {e}"},
            status_code=500,
        )


@router.post("/imports/{novel_id}/migrate-subscriptions")
async def migrate_subscriptions(
    novel_id: str,
    request: Request,
    _token: str = Depends(verify_panel_token),
):
    """Migrate favorites and comments from related novels to the target novel.

    Reimplements migrate_novel_subscriptions.py logic using async MySQL pool.
    Accepts optional JSON body: {"keyword": "...", "dry_run": true/false, "source_ids": [...]}
    If keyword is omitted, uses the target novel's title.
    If source_ids is provided, only migrate from those specific novels.
    """
    try:
        body = {}
        try:
            body = await request.json()
        except Exception:
            pass

        keyword = body.get("keyword")
        dry_run = body.get("dry_run", False)
        explicit_source_ids = body.get("source_ids")  # optional: user-selected sources

        adapter = await get_storage_adapter()
        if adapter.get_backend_type() != "mysql":
            return JSONResponse(
                content={"detail": "This feature requires MySQL backend"},
                status_code=503,
            )

        pool = adapter._backend._pool
        if pool is None:
            return JSONResponse(
                content={"detail": "MySQL connection pool not available"},
                status_code=503,
            )

        async with pool.acquire() as conn:
            async with conn.cursor() as cur:
                # Get target novel title if keyword not provided
                if not keyword:
                    await cur.execute(
                        "SELECT title FROM novels WHERE id = %s", (novel_id,)
                    )
                    row = await cur.fetchone()
                    if not row:
                        return JSONResponse(
                            content={"detail": "目标小说不存在"},
                            status_code=404,
                        )
                    # Use full title as keyword
                    keyword = row[0]

                # Find all novels matching keyword
                await cur.execute(
                    "SELECT id, title, created_at, popularity FROM novels WHERE title LIKE %s ORDER BY created_at",
                    (f"%{keyword}%",),
                )
                novels = await cur.fetchall()  # (id, title, created_at, popularity)

                if len(novels) < 2:
                    return JSONResponse(content={
                        "message": f"未找到其他包含 '{keyword}' 的小说，无需迁移",
                        "keyword": keyword,
                        "novels_found": len(novels),
                        "favorites_migrated": 0,
                        "comments_migrated": 0,
                    })

                # Source = all matching novels except target, or user-specified list
                all_source_ids = [n[0] for n in novels if n[0] != novel_id]
                novel_list = [{"id": n[0], "title": n[1], "is_target": n[0] == novel_id, "popularity": n[3]} for n in novels]

                if explicit_source_ids:
                    # Filter to only user-selected sources (must be in the matched set)
                    valid_set = set(all_source_ids)
                    source_ids = [sid for sid in explicit_source_ids if sid in valid_set]
                else:
                    source_ids = all_source_ids

                if not source_ids:
                    return JSONResponse(content={
                        "message": "没有源小说可迁移",
                        "keyword": keyword,
                        "novels_found": len(novels),
                        "favorites_migrated": 0,
                        "comments_migrated": 0,
                    })

                placeholders = ",".join(["%s"] * len(source_ids))

                # --- Migrate favorites ---
                await cur.execute(
                    f"SELECT user_id, contribution_keys, max_branch_count, created_at "
                    f"FROM favorites WHERE novel_id IN ({placeholders})",
                    source_ids,
                )
                source_favorites = await cur.fetchall()

                await cur.execute(
                    "SELECT user_id FROM favorites WHERE novel_id = %s",
                    (novel_id,),
                )
                existing_fav_users = {r[0] for r in await cur.fetchall()}

                # Deduplicate: keep the one with highest contribution_keys per user
                user_best = {}
                for fav in source_favorites:
                    uid, contrib_keys, max_branch, created = fav
                    if uid in existing_fav_users:
                        continue
                    if uid not in user_best or contrib_keys > user_best[uid][1]:
                        user_best[uid] = fav

                fav_to_insert = list(user_best.values())

                # --- Migrate comments ---
                await cur.execute(
                    f"SELECT user_id, content, like_count, created_at, updated_at "
                    f"FROM comments WHERE novel_id IN ({placeholders})",
                    source_ids,
                )
                source_comments = await cur.fetchall()

                await cur.execute(
                    "SELECT user_id, content FROM comments WHERE novel_id = %s",
                    (novel_id,),
                )
                existing_comments = {(r[0], r[1]) for r in await cur.fetchall()}

                comments_to_insert = [
                    c for c in source_comments
                    if (c[0], c[1]) not in existing_comments
                ]

                # Compute rename preview
                target_info = next(n for n in novels if n[0] == novel_id)
                target_title = target_info[1]
                base_name = re.sub(r'[\d.]+$', '', target_title).strip()

                source_novels_data = [n for n in novels if n[0] in source_ids]
                source_pops = [n[3] for n in source_novels_data if n[3] is not None]
                preview_max_pop = max(source_pops) if source_pops else 0

                # Find the highest existing 0.9x suffix in DB for this base name
                await cur.execute(
                    "SELECT title FROM novels WHERE title LIKE %s",
                    (f"{base_name}0.9%",),
                )
                existing_titles = [r[0] for r in await cur.fetchall()]
                max_suffix = 89  # will start from 0.90
                for t in existing_titles:
                    m = re.search(r'0\.(\d+)$', t)
                    if m:
                        max_suffix = max(max_suffix, int(m.group(1)))
                next_suffix = max_suffix + 1

                preview_renamed = []
                for i, sid in enumerate(source_ids):
                    src = next(n for n in novels if n[0] == sid)
                    # Skip sources that already have a 0.9x suffix
                    if re.search(r'0\.9\d+$', src[1]):
                        continue
                    s = next_suffix + len(preview_renamed)
                    preview_renamed.append({"id": sid, "old_title": src[1], "new_title": f"{base_name}0.{s}"})

                if dry_run:
                    return JSONResponse(content={
                        "message": "预览完成（dry-run）",
                        "keyword": keyword,
                        "dry_run": True,
                        "novels": novel_list,
                        "source_ids": source_ids,
                        "favorites_to_migrate": len(fav_to_insert),
                        "comments_to_migrate": len(comments_to_insert),
                        "target_new_title": preview_target_title,
                        "target_popularity": preview_max_pop,
                        "renamed_sources": preview_renamed,
                    })

                # Execute migration
                fav_inserted = 0
                for fav in fav_to_insert:
                    uid, contrib_keys, max_branch, created = fav
                    new_id = str(uuid.uuid4())
                    await cur.execute(
                        "INSERT INTO favorites (id, user_id, novel_id, contribution_keys, max_branch_count, created_at) "
                        "VALUES (%s, %s, %s, %s, %s, %s)",
                        (new_id, uid, novel_id, contrib_keys, max_branch, created),
                    )
                    fav_inserted += 1

                comments_inserted = 0
                for comment in comments_to_insert:
                    uid, content, like_count, created, updated = comment
                    new_id = str(uuid.uuid4())
                    await cur.execute(
                        "INSERT INTO comments (id, novel_id, user_id, content, like_count, created_at, updated_at) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                        (new_id, novel_id, uid, content, like_count, created, updated),
                    )
                    comments_inserted += 1

                # --- Rename & swap popularity ---
                new_target_title = base_name
                max_pop = preview_max_pop

                # Update target: new title + max popularity
                await cur.execute(
                    "UPDATE novels SET title = %s, popularity = %s WHERE id = %s",
                    (new_target_title, max_pop, novel_id),
                )
                await cur.execute(
                    "UPDATE import_novels SET title = %s WHERE novel_id = %s",
                    (new_target_title, novel_id),
                )

                # Update sources: popularity = -1, rename with 0.9x suffix
                renamed_sources = preview_renamed
                for r in renamed_sources:
                    await cur.execute(
                        "UPDATE novels SET title = %s, popularity = -1 WHERE id = %s",
                        (r["new_title"], r["id"]),
                    )
                    await cur.execute(
                        "UPDATE import_novels SET title = %s WHERE novel_id = %s",
                        (r["new_title"], r["id"]),
                    )
                # Set popularity = -1 for sources that already had 0.9x suffix (skipped in rename)
                renamed_ids = {r["id"] for r in renamed_sources}
                for sid in source_ids:
                    if sid not in renamed_ids:
                        await cur.execute(
                            "UPDATE novels SET popularity = -1 WHERE id = %s",
                            (sid,),
                        )

        log.info(
            f"Migrated subscriptions to novel {novel_id}: "
            f"{fav_inserted} favorites, {comments_inserted} comments, "
            f"renamed target to '{new_target_title}', pop={max_pop}"
        )
        return JSONResponse(content={
            "message": "迁移完成",
            "keyword": keyword,
            "novels": novel_list,
            "source_ids": source_ids,
            "favorites_migrated": fav_inserted,
            "comments_migrated": comments_inserted,
            "target_new_title": new_target_title,
            "target_popularity": max_pop,
            "renamed_sources": renamed_sources,
        })

    except Exception as e:
        log.error(f"Failed to migrate subscriptions for novel {novel_id}: {e}")
        return JSONResponse(
            content={"detail": f"迁移失败: {e}"},
            status_code=500,
        )


@router.put("/imports/{novel_id}/title")
async def update_title(
    novel_id: str,
    request: Request,
    _token: str = Depends(verify_panel_token),
):
    """Update novel title in both novels and import_novels tables."""
    try:
        body = await request.json()
        title = body.get("title", "").strip()
        if not title:
            return JSONResponse(
                content={"detail": "标题不能为空"},
                status_code=400,
            )

        adapter = await get_storage_adapter()
        if adapter.get_backend_type() != "mysql":
            return JSONResponse(
                content={"detail": "This feature requires MySQL backend"},
                status_code=503,
            )

        pool = adapter._backend._pool
        if pool is None:
            return JSONResponse(
                content={"detail": "MySQL connection pool not available"},
                status_code=503,
            )

        async with pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "UPDATE novels SET title = %s WHERE id = %s",
                    (title, novel_id),
                )
                await cur.execute(
                    "UPDATE import_novels SET title = %s WHERE novel_id = %s",
                    (title, novel_id),
                )

        log.info(f"Updated title for novel {novel_id} to '{title}'")
        return JSONResponse(content={"message": "标题更新成功", "title": title})

    except Exception as e:
        log.error(f"Failed to update title for novel {novel_id}: {e}")
        return JSONResponse(
            content={"detail": f"更新标题失败: {e}"},
            status_code=500,
        )


@router.put("/imports/{novel_id}/visibility")
async def update_visibility(
    novel_id: str,
    request: Request,
    _token: str = Depends(verify_panel_token),
):
    """Update novel visibility in the novels table."""
    try:
        body = await request.json()
        visibility = body.get("visibility")
        if visibility is None or not isinstance(visibility, int):
            return JSONResponse(
                content={"detail": "visibility 必须为整数"},
                status_code=400,
            )

        adapter = await get_storage_adapter()
        if adapter.get_backend_type() != "mysql":
            return JSONResponse(
                content={"detail": "This feature requires MySQL backend"},
                status_code=503,
            )

        pool = adapter._backend._pool
        if pool is None:
            return JSONResponse(
                content={"detail": "MySQL connection pool not available"},
                status_code=503,
            )

        async with pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "UPDATE novels SET visibility = %s WHERE id = %s",
                    (visibility, novel_id),
                )
                if cur.rowcount == 0:
                    return JSONResponse(
                        content={"detail": "小说不存在"},
                        status_code=404,
                    )

        log.info(f"Updated visibility for novel {novel_id} to {visibility}")
        return JSONResponse(content={"message": "可见性更新成功", "visibility": visibility})

    except Exception as e:
        log.error(f"Failed to update visibility for novel {novel_id}: {e}")
        return JSONResponse(
            content={"detail": f"更新可见性失败: {e}"},
            status_code=500,
        )


@router.post("/imports/{novel_id}/cover")
async def upload_cover(
    novel_id: str,
    cover_image: UploadFile = File(...),
    _token: str = Depends(verify_panel_token),
):
    """Forward cover image upload to novel_backend admin API"""
    backend_url = await get_novel_backend_url()
    admin_key = await get_novel_admin_api_key()

    url = f"{backend_url}/api/v1/admin/novels/{novel_id}/cover"
    headers = {"X-Admin-Key": admin_key}

    try:
        content = await cover_image.read()
        files = {"cover_image": (cover_image.filename, content, cover_image.content_type)}
        async with http_client.get_client(timeout=60.0) as client:
            resp = await client.post(url, headers=headers, files=files)
        return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except Exception as e:
        log.error(f"Failed to upload cover for novel {novel_id}: {e}")
        return JSONResponse(
            content={"detail": f"封面上传失败: {e}"},
            status_code=502,
        )


DEFAULT_COVER_LABELS = {
    1: "居家盘腿",
    2: "居家坐床",
    3: "中华旗袍",
    4: "暗夜特工",
    5: "华贵中世纪",
    6: "魔法奇幻",
}


@router.get("/default-covers")
async def get_default_covers(
    _token: str = Depends(verify_panel_token),
):
    """Return public URLs for the 6 default cover images"""
    base_url = os.getenv("S3_PUBLIC_BASE_URL", "https://manbo.chat")
    base = f"{base_url}/covers"

    covers = []
    for i in range(1, 7):
        covers.append({
            "order": i,
            "label": DEFAULT_COVER_LABELS[i],
            "url": f"{base}/deafult_cover_{i}.webp",
            "thumb_url": f"{base}/deafult_cover_{i}_thumb.webp",
        })
    return JSONResponse(content={"covers": covers})


@router.put("/default-covers/{order}")
async def replace_default_cover(
    order: int = Path(..., ge=1, le=6),
    cover_image: UploadFile = File(...),
    _token: str = Depends(verify_panel_token),
):
    """Forward default cover replacement to novel_backend admin API"""
    backend_url = await get_novel_backend_url()
    admin_key = await get_novel_admin_api_key()

    url = f"{backend_url}/api/v1/admin/novels/default-covers/{order}"
    headers = {"X-Admin-Key": admin_key}

    try:
        content = await cover_image.read()
        files = {"cover_image": (cover_image.filename, content, cover_image.content_type)}
        async with http_client.get_client(timeout=60.0) as client:
            resp = await client.put(url, headers=headers, files=files)
        return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except Exception as e:
        log.error(f"Failed to replace default cover {order}: {e}")
        return JSONResponse(
            content={"detail": f"默认封面替换失败: {e}"},
            status_code=502,
        )


@router.post("/imports/{novel_id}/reset-cover")
async def reset_novel_cover(
    novel_id: str,
    request: Request,
    _token: str = Depends(verify_panel_token),
):
    """Reset a novel's cover to a specific default cover via novel_backend"""
    backend_url = await get_novel_backend_url()
    admin_key = await get_novel_admin_api_key()

    body = await request.json()
    order = body.get("order")
    if not order or order not in range(1, 7):
        return JSONResponse(
            content={"detail": "order 必须为 1-6"},
            status_code=400,
        )

    url = f"{backend_url}/api/v1/admin/novels/{novel_id}/cover?reset_default=true&default_order={order}"
    headers = {"X-Admin-Key": admin_key}

    try:
        async with http_client.get_client(timeout=30.0) as client:
            resp = await client.post(url, headers=headers)
        return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except Exception as e:
        log.error(f"Failed to reset cover for novel {novel_id}: {e}")
        return JSONResponse(
            content={"detail": f"重置封面失败: {e}"},
            status_code=502,
        )


@router.get("/app-version")
async def get_app_version(
    _token: str = Depends(verify_panel_token),
):
    """Get current app version config from novel_backend"""
    backend_url = await get_novel_backend_url()

    url = f"{backend_url}/api/v1/app/version"

    try:
        resp = await get_async(url)
        return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except Exception as e:
        log.error(f"Failed to get app version: {e}")
        return JSONResponse(
            content={"detail": "Failed to connect to novel backend"},
            status_code=502,
        )


@router.put("/app-version")
async def update_app_version(
    request: Request,
    _token: str = Depends(verify_panel_token),
):
    """Update app version config via novel_backend admin API"""
    backend_url = await get_novel_backend_url()
    admin_key = await get_novel_admin_api_key()

    url = f"{backend_url}/api/v1/admin/app-version"
    headers = {"X-Admin-Key": admin_key}

    try:
        body = await request.json()
        resp = await put_async(url, json=body, headers=headers)
        return JSONResponse(content=resp.json(), status_code=resp.status_code)
    except Exception as e:
        log.error(f"Failed to update app version: {e}")
        return JSONResponse(
            content={"detail": "Failed to connect to novel backend"},
            status_code=502,
        )
