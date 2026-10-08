from __future__ import annotations

import os
import re
from typing import Any

import requests

from wap.models.schemas import DiscoveredItem, LinkedResource
from wap.sources.base import SourceAdapter
from wap.utils.http import FetchResult


class GithubAdapter(SourceAdapter):
    """Fetch GitHub wiki / repo markdown via public raw URLs or API (token from env only)."""

    adapter_type = "github"

    def _token(self) -> str | None:
        return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

    def discover(self) -> list[DiscoveredItem]:
        entry = self.source_cfg.get("entry_url")
        if not entry:
            raise ValueError("github adapter requires entry_url")
        # If entry is a wiki page or raw md, treat as single item; if API contents URL, list.
        if "api.github.com" in entry and self._token():
            headers = {"Authorization": f"Bearer {self._token()}", "Accept": "application/vnd.github+json"}
            resp = requests.get(entry, headers=headers, timeout=30)
            resp.raise_for_status()
            items = []
            for obj in resp.json():
                if obj.get("type") != "file":
                    continue
                name = obj["name"]
                if not name.endswith((".md", ".txt", ".markdown")):
                    continue
                items.append(
                    DiscoveredItem(
                        source_id=self.source_id,
                        title=name,
                        url=obj.get("download_url") or obj["html_url"],
                        task_name=name,
                        benchmark_name="GITHUB",
                    )
                )
            return items
        return [
            DiscoveredItem(
                source_id=self.source_id,
                title=entry.rsplit("/", 1)[-1],
                url=entry,
                benchmark_name="GITHUB",
            )
        ]

    def parse(
        self, item: DiscoveredItem, page: FetchResult
    ) -> tuple[str, str, list[LinkedResource], dict[str, Any]]:
        text = page.text
        if "<html" in text[:200].lower():
            # let markdownify-ish strip via regex fallback
            text = re.sub(r"<[^>]+>", "\n", text)
        title = item.title
        m = re.search(r"^#\s+(.+)$", text, re.M)
        if m:
            title = m.group(1).strip()
        links = [
            LinkedResource(url=u, kind="page", title=t)
            for t, u in re.findall(r"\[([^\]]+)\]\(([^)]+)\)", text)
        ]
        return title, text, links, {}