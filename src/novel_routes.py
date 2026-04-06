"""Novel management routes - forwards requests to novel_backend admin API"""

import json
import os

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
    """Forward import list request to novel_backend admin API, enrich with novels data"""
    backend_url = await get_novel_backend_url()
    admin_key = await get_novel_admin_api_key()

    url = f"{backend_url}/api/v1/admin/import?page={page}&page_size={page_size}"
    headers = {"X-Admin-Key": admin_key}

    try:
        resp = await get_async(url, headers=headers)
        result = resp.json()

        # Enrich items with visibility and cover_url from novels table
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
        except Exception as e:
            log.warning(f"Failed to enrich imports with novel data: {e}")

        return JSONResponse(content=result, status_code=resp.status_code)
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
