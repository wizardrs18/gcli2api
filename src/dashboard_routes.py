"""Dashboard routes — novel platform business metrics."""

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from log import log
from src.storage_adapter import get_storage_adapter
from src.utils import verify_panel_token
from src.dashboard_queries import get_all_dashboard_stats

router = APIRouter(prefix="/dashboard")


@router.get("/stats")
async def get_dashboard_stats(_token: str = Depends(verify_panel_token)):
    """Return aggregated business metrics from the MySQL database."""
    try:
        adapter = await get_storage_adapter()

        if adapter.get_backend_type() != "mysql":
            return JSONResponse(
                content={"detail": "Dashboard requires MySQL backend"},
                status_code=503,
            )

        pool = adapter._backend._pool
        if pool is None:
            return JSONResponse(
                content={"detail": "MySQL connection pool not available"},
                status_code=503,
            )

        stats = await get_all_dashboard_stats(pool)
        return JSONResponse(content={"ok": True, "data": stats})

    except Exception as e:
        log.error(f"Dashboard stats error: {e}")
        return JSONResponse(
            content={"detail": f"Failed to fetch dashboard stats: {e}"},
            status_code=500,
        )
