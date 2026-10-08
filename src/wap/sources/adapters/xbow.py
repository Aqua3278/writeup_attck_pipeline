from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from markdownify import markdownify as md

from wap.models.schemas import DiscoveredItem, LinkedResource
from wap.sources.base import SourceAdapter
from wap.utils.http import FetchResult, normalize_url

XBEN_RE = re.compile(r"XBEN-\d{3}-24", re.I)


class XbowAdapter(SourceAdapter):
    """Crawl RedAmon XBOW Validation Benchmark wiki scorecard + linked sessions."""

    adapter_type = "xbow"

    def discover(self) -> list[DiscoveredItem]:
        entry = self.source_cfg.get("entry_url")
        if not entry:
            raise ValueError("XBOW adapter requires entry_url")
        page = self.fetch(entry)
        soup = BeautifulSoup(page.text, "lxml")
        items: list[DiscoveredItem] = []
        seen: set[str] = set()

        # Table rows: task name + walkthrough / raw links
        for tr in soup.select("table tr"):
            cells = tr.find_all(["td", "th"])
            if len(cells) < 2:
                continue
            row_text = " ".join(c.get_text(" ", strip=True) for c in cells)
            m = XBEN_RE.search(row_text)
            if not m:
                continue
            task = m.group(0).upper()
            # Prefer decoded/walkthrough links, also keep raw
            candidates: list[tuple[str, str]] = []
            for a in tr.select("a[href]"):
                href = a.get("href") or ""
                label = (a.get_text() or "").strip().lower()
                url = normalize_url(page.final_url, href)
                if not url:
                    continue
                if "walkthrough" in label or "sess_decoded" in href or "decoded" in label:
                    candidates.append((url, "decoded"))
                elif label == "raw" or "sess" in href or href.endswith(".md"):
                    candidates.append((url, "session"))
            if not candidates:
                # link on task name itself
                for a in tr.select("a[href]"):
                    url = normalize_url(page.final_url, a.get("href") or "")
                    if url and ("wiki" in url or "XBEN" in url):
                        candidates.append((url, "page"))
            for url, kind in candidates:
                if url in seen:
                    continue
                # skip official xbow-engineering challenge tree (not writeup)
                if "xbow-engineering/validation-benchmarks" in url and "/tree/" in url:
                    continue
                seen.add(url)
                title = f"{task} ({kind})"
                items.append(
                    DiscoveredItem(
                        source_id=self.source_id,
                        title=title,
                        url=url,
                        task_name=task,
                        benchmark_name="XBOW",
                        metadata={"resource_kind": kind, "discovered_from": entry},
                    )
                )

        # Also collect any wiki links that look like sess_decoded outside table
        for a in soup.select("a[href]"):
            href = a.get("href") or ""
            url = normalize_url(page.final_url, href)
            if not url or url in seen:
                continue
            if "sess_decoded" in url or re.search(r"XBEN-\d{3}-24_.*sess", url):
                m = XBEN_RE.search(url) or XBEN_RE.search(a.get_text() or "")
                task = m.group(0).upper() if m else "XBEN-UNKNOWN"
                seen.add(url)
                items.append(
                    DiscoveredItem(
                        source_id=self.source_id,
                        title=f"{task} (decoded)",
                        url=url,
                        task_name=task,
                        benchmark_name="XBOW",
                        metadata={"resource_kind": "decoded"},
                    )
                )

        if not items:
            raise RuntimeError(
                f"XBOW discover found 0 writeup links at {entry}; "
                "scorecard markup may have changed — use local adapter to import markdown"
            )
        return items

    def _try_raw_wiki(self, html_url: str) -> FetchResult | None:
        """GitHub wiki pages sometimes available as raw.githubusercontent.com/wiki/..."""
        if not self.crawl_config.get("prefer_raw_wiki", True):
            return None
        # https://github.com/samugit83/redamon/wiki/Page-Name
        # -> https://raw.githubusercontent.com/wiki/samugit83/redamon/Page-Name.md
        parsed = urlparse(html_url)
        parts = parsed.path.strip("/").split("/")
        if len(parts) < 3 or parts[2] != "wiki":
            return None
        owner, repo = parts[0], parts[1]
        page_name = parts[3] if len(parts) > 3 else "Home"
        # strip .md if present
        page_name = page_name.replace(".md", "")
        # relative wiki links like xbench_sessions/FOO.md
        if "xbench_sessions" in html_url or page_name.startswith("xbench"):
            # keep path after wiki/
            wiki_suffix = "/".join(parts[3:])
            raw_url = f"https://raw.githubusercontent.com/wiki/{owner}/{repo}/{wiki_suffix}"
            if not raw_url.endswith(".md"):
                raw_url += ".md"
        else:
            raw_url = f"https://raw.githubusercontent.com/wiki/{owner}/{repo}/{page_name}.md"
        try:
            return self.fetch(raw_url)
        except Exception:
            return None

    def extract_links(self, page: FetchResult) -> list[LinkedResource]:
        out: list[LinkedResource] = []
        if "text/markdown" in page.content_type or page.url.endswith(".md"):
            for m in re.finditer(r"\[([^\]]+)\]\(([^)]+)\)", page.text):
                url = normalize_url(page.final_url, m.group(2))
                if url:
                    out.append(LinkedResource(url=url, kind="page", title=m.group(1)))
            return out
        soup = BeautifulSoup(page.text, "lxml")
        for a in soup.select("a[href]"):
            url = normalize_url(page.final_url, a.get("href") or "")
            if not url:
                continue
            label = (a.get_text() or "").strip().lower()
            kind = "page"
            if "decoded" in label or "walkthrough" in label:
                kind = "decoded"
            elif label == "raw" or "sess" in (a.get("href") or ""):
                kind = "session"
            out.append(LinkedResource(url=url, kind=kind, title=(a.get_text() or "").strip() or None))
        return out

    def parse(
        self, item: DiscoveredItem, page: FetchResult
    ) -> tuple[str, str, list[LinkedResource], dict[str, Any]]:
        raw = self._try_raw_wiki(item.url)
        if raw and len(raw.text.strip()) > 80:
            page = raw
            text_md = page.text
            title = item.title
            links = self.extract_links(page)
            return title, text_md, links, {"fetched_as": "raw_wiki", "final_url": page.final_url}

        soup = BeautifulSoup(page.text, "lxml")
        # GitHub wiki markdown body
        article = (
            soup.select_one("div.markdown-body")
            or soup.select_one("#wiki-body")
            or soup.select_one("article")
            or soup.select_one("main")
        )
        if article is None:
            raise RuntimeError(f"cannot parse XBOW wiki body: {item.url}")
        for sel in ("nav", "script", "style"):
            for el in article.select(sel):
                el.decompose()
        title_el = soup.select_one("h1")
        title = (title_el.get_text() if title_el else item.title).strip()
        text_md = md(str(article), heading_style="ATX")
        if len(text_md.strip()) < 80:
            raise RuntimeError(f"XBOW body too short: {item.url}")
        links = self.extract_links(page)
        return title, text_md, links, {"fetched_as": "html_wiki", "final_url": page.final_url}