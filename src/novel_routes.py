"""Novel management routes - forwards requests to novel_backend admin API"""

import json

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from config import get_novel_backend_url, get_novel_admin_api_key
from log import log
from src.httpx_client import get_async, post_async
from src.storage_adapter import get_storage_adapter
from src.utils import verify_panel_token

router = APIRouter(prefix="/novel")


@router.get("/imports")
async def list_imports(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    _token: str = Depends(verify_panel_token),
):
    """Forward import list request to novel_backend admin API"""
    backend_url = await get_novel_backend_url()
    admin_key = await get_novel_admin_api_key()

    url = f"{backend_url}/api/v1/admin/import?page={page}&page_size={page_size}"
    headers = {"X-Admin-Key": admin_key}

    try:
        resp = await get_async(url, headers=headers)
        return JSONResponse(content=resp.json(), status_code=resp.status_code)
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
