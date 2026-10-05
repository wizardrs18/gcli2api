"""Offline regression: fallback filters the full import set before pagination.

Run with: .venv/Scripts/python scripts/test_import_list_fallback.py
No database or upstream calls are made.
"""

import json
import sys
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src import novel_routes


class ImportFallbackTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.items = [
            {
                "novel_id": str(i),
                "title": f"Novel {i}",
                "status": "error" if i in {102, 154, 202} else "completed",
            }
            for i in range(205)
        ]
        self.requests = []

    async def list_imports(self, **overrides):
        async def get(url, *, params, **kwargs):
            self.requests.append(params.copy())
            page, size = params["page"], params["page_size"]
            start = (page - 1) * size
            return httpx.Response(200, json={
                "code": 200,
                "data": {
                    "items": self.items[start:start + size],
                    "total": len(self.items),
                    "page": page,
                    "pageSize": size,
                },
            })

        @asynccontextmanager
        async def get_client(**kwargs):
            yield SimpleNamespace(get=get)

        args = dict(page=1, page_size=20, fetch_all=False, title="", status="",
                    visibility="", big_vis1=False, _token="test")
        args.update(overrides)
        adapter = SimpleNamespace(get_backend_type=lambda: "mongodb")
        with (
            patch.object(novel_routes, "get_storage_adapter", AsyncMock(return_value=adapter)),
            patch.object(novel_routes, "get_novel_backend_url", AsyncMock(return_value="https://test")),
            patch.object(novel_routes, "get_novel_admin_api_key", AsyncMock(return_value="test")),
            patch.object(novel_routes.http_client, "get_client", get_client),
        ):
            response = await novel_routes.list_imports(**args)
        return response.status_code, json.loads(response.body)

    async def test_status_searches_beyond_first_page_and_then_paginates(self):
        code, body = await self.list_imports(status="error", page=2, page_size=2)
        data = body["data"]
        self.assertEqual(code, 200)
        self.assertEqual([i["novel_id"] for i in data["items"]], ["202"])
        self.assertEqual((data["total"], data["page"], data["pageSize"]), (3, 2, 2))
        self.assertEqual(sorted(p["page"] for p in self.requests), [1, 2, 3])

    async def test_title_and_status_are_combined(self):
        code, body = await self.list_imports(status="error", title="  NOVEL 15  ")
        self.assertEqual(code, 200)
        self.assertEqual(body["data"]["total"], 1)
        self.assertEqual(body["data"]["items"][0]["novel_id"], "154")

    async def test_no_matches_has_zero_total(self):
        _, body = await self.list_imports(status="paused")
        self.assertEqual(body["data"]["total"], 0)
        self.assertEqual(body["data"]["items"], [])

    async def test_fetch_all_still_applies_filters(self):
        _, body = await self.list_imports(status="error", fetch_all=True, page_size=2)
        self.assertEqual(len(body["data"]["items"]), 3)
        self.assertEqual(body["data"]["total"], 3)
        self.assertEqual(body["data"]["page"], 1)

    async def test_unfiltered_navigation_only_fetches_requested_page(self):
        _, body = await self.list_imports(page=2)
        self.assertEqual(body["data"]["items"][0]["novel_id"], "20")
        self.assertEqual(body["data"]["total"], 205)
        self.assertEqual(self.requests, [{"page": 2, "page_size": 20}])

    async def test_visibility_does_not_silently_return_all_or_unset(self):
        for value in ("1", "unset"):
            code, _ = await self.list_imports(visibility=value)
            self.assertEqual(code, 503)
        code, _ = await self.list_imports(big_vis1=True)
        self.assertEqual(code, 503)
        self.assertEqual(self.requests, [])

    async def test_invalid_visibility_is_rejected(self):
        code, _ = await self.list_imports(visibility="invalid")
        self.assertEqual(code, 400)


if __name__ == "__main__":
    unittest.main()
