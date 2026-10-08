from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from markdownify import markdownify as md

from wap.models.schemas import DiscoveredItem, LinkedResource
from wap.sources.base import SourceAdapter
from wap.utils.http import FetchResult, normalize_url


class GoadAdapter(SourceAdapter):
    adapter_type = "goad"

    def discover(self) -> list[DiscoveredItem]:
        entry = self.source_cfg.get("entry_url")
        if not entry:
            raise ValueError("GOAD adapter requires entry_url")
        page = self.fetch(entry)
        soup = BeautifulSoup(page.text, "lxml")
        items: list[DiscoveredItem] = []
        seen: set[str] = set()
        host = urlparse(entry).netloc

        # Category pages typically list posts as <a href="/posts/...">
        for a in soup.select("a[href]"):
            href = a.get("href") or ""
            url = normalize_url(page.final_url, href)
            if not url:
                continue
            if urlparse(url).netloc != host:
                continue
            if "/posts/" not in urlparse(url).path and "/post/" not in urlparse(url).path:
                # also allow category-linked articles under /GOAD/ etc.
                text = (a.get_text() or "").strip()
                if not re.search(r"GOAD|Dracarys|Exchange", text, re.I):
                    continue
            title = (a.get_text() or "").strip()
            if not title or len(title) < 3:
                continue
            if url.rstrip("/") == entry.rstrip("/"):
                continue
            if url in seen:
                continue
            seen.add(url)
            items.append(
                DiscoveredItem(
                    source_id=self.source_id,
                    title=title,
                    url=url,
                    task_name=title,
                    benchmark_name="GOAD",
                    metadata={"discovered_from": entry},
                )
            )

        # Fallback: parse list items under category
        if not items:
            for li in soup.select("li a[href], article a[href], .post-link"):
                href = li.get("href")
                url = normalize_url(page.final_url, href or "")
                if not url or url in seen:
                    continue
                title = (li.get_text() or "").strip()
                if not title:
                    continue
                seen.add(url)
                items.append(
                    DiscoveredItem(
                        source_id=self.source_id,
                        title=title,
                        url=url,
                        task_name=title,
                        benchmark_name="GOAD",
                    )
                )

        if not items:
            raise RuntimeError(
                f"GOAD discover found 0 articles at {entry}; page structure may have changed"
            )
        return items

    def extract_links(self, page: FetchResult) -> list[LinkedResource]:
        soup = BeautifulSoup(page.text, "lxml")
        out: list[LinkedResource] = []
        for a in soup.select("a[href]"):
            url = normalize_url(page.final_url, a.get("href") or "")
            if not url:
                continue
            kind = "attachment" if re.search(r"\.(pdf|zip|png|jpg|gif)$", url, re.I) else "page"
            out.append(LinkedResource(url=url, kind=kind, title=(a.get_text() or "").strip() or None))
        return out

    def parse(
        self, item: DiscoveredItem, page: FetchResult
    ) -> tuple[str, str, list[LinkedResource], dict[str, Any]]:
        soup = BeautifulSoup(page.text, "lxml")
        title_el = soup.select_one("h1, .post-title, title")
        title = (title_el.get_text() if title_el else item.title).strip()
        article = (
            soup.select_one("article")
            or soup.select_one(".post-content")
            or soup.select_one("main")
            or soup.body
        )
        if article is None:
            raise RuntimeError(f"cannot locate article body for {item.url}")
        # drop nav/footer noise
        for sel in ("nav", "footer", "script", "style", ".sidebar"):
            for el in article.select(sel):
                el.decompose()
        text_md = md(str(article), heading_style="ATX")
        if len(text_md.strip()) < 80:
            raise RuntimeError(f"parsed GOAD body too short for {item.url}")
        links = self.extract_links(page)
        published = None
        time_el = soup.select_one("time")
        if time_el:
            published = time_el.get("datetime") or time_el.get_text(strip=True)
        return title, text_md, links, {"published_at": published}