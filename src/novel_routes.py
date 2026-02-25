"""Novel management routes - forwards requests to novel_backend admin API"""

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from config import get_novel_backend_url, get_novel_admin_api_key
from log import log
from src.httpx_client import get_async, post_async
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


@router.post("/imports/{import_id}/retry")
async def retry_import(
    import_id: str,
    _token: str = Depends(verify_panel_token),
):
    """Forward import retry request to novel_backend admin API"""
    backend_url = await get_novel_backend_url()
    admin_key = await get_novel_admin_api_key()

    url = f"{backend_url}/api/v1/admin/import/{import_id}/retry"
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
