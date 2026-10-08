from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from markdownify import markdownify as md

from wap.models.schemas import DiscoveredItem, LinkedResource
from wap.sources.base import SourceAdapter
from wap.utils.http import FetchResult, normalize_url


class GenericWebAdapter(SourceAdapter):
    adapter_type = "web"

    def discover(self) -> list[DiscoveredItem]:
        entry = self.source_cfg.get("entry_url")
        if not entry:
            raise ValueError("web adapter requires entry_url")
        page = self.fetch(entry)
        soup = BeautifulSoup(page.text, "lxml")
        host = urlparse(entry).netloc
        same_host = self.crawl_config.get("follow_same_host_only", True)
        items: list[DiscoveredItem] = []
        seen: set[str] = set()
        for a in soup.select("a[href]"):
            url = normalize_url(page.final_url, a.get("href") or "")
            if not url or url in seen:
                continue
            if same_host and urlparse(url).netloc != host:
                continue
            title = (a.get_text() or "").strip() or url
            seen.add(url)
            items.append(
                DiscoveredItem(
                    source_id=self.source_id,
                    title=title,
                    url=url,
                    benchmark_name=self.source_name,
                )
            )
        return items

    def parse(
        self, item: DiscoveredItem, page: FetchResult
    ) -> tuple[str, str, list[LinkedResource], dict[str, Any]]:
        soup = BeautifulSoup(page.text, "lxml")
        article = soup.select_one("article") or soup.select_one("main") or soup.body
        if article is None:
            raise RuntimeError(f"no body for {item.url}")
        text_md = md(str(article), heading_style="ATX")
        title = item.title
        h1 = soup.select_one("h1")
        if h1:
            title = h1.get_text(strip=True)
        links = [
            LinkedResource(url=u, kind="page")
            for a in soup.select("a[href]")
            if (u := normalize_url(page.final_url, a.get("href") or ""))
        ]
        return title, text_md, links, {}