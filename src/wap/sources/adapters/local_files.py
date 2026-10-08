from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from wap.models.schemas import DiscoveredItem, LinkedResource
from wap.sources.base import SourceAdapter
from wap.utils.config import ROOT
from wap.utils.http import FetchResult


def _path_from_file_url(url: str) -> Path:
    if url.startswith("file:"):
        parsed = urlparse(url)
        path = unquote(parsed.path)
        # Windows: /E:/foo -> E:/foo
        if path.startswith("/") and len(path) > 2 and path[2] == ":":
            path = path[1:]
        return Path(path)
    return Path(url)


class LocalFileAdapter(SourceAdapter):
    adapter_type = "local"

    def _root(self) -> Path:
        root = Path(self.crawl_config.get("root_dir", "data/local_import"))
        if not root.is_absolute():
            root = ROOT / root
        return root

    def discover(self) -> list[DiscoveredItem]:
        root = self._root()
        root.mkdir(parents=True, exist_ok=True)
        patterns = self.crawl_config.get("patterns") or ["**/*.md"]
        items: list[DiscoveredItem] = []
        for pat in patterns:
            for path in sorted(root.glob(pat)):
                if not path.is_file():
                    continue
                items.append(
                    DiscoveredItem(
                        source_id=self.source_id,
                        title=path.stem,
                        url=path.resolve().as_uri(),
                        task_name=path.stem,
                        benchmark_name="LOCAL",
                        metadata={"path": str(path.resolve())},
                    )
                )
        return items

    def fetch(self, url: str) -> FetchResult:
        path = _path_from_file_url(url)
        data = path.read_bytes()
        text = data.decode("utf-8", errors="replace")
        return FetchResult(
            url=url,
            final_url=url,
            status_code=200,
            content=data,
            text=text,
            content_type="text/markdown",
            fetched_at=0.0,
        )

    def parse(
        self, item: DiscoveredItem, page: FetchResult
    ) -> tuple[str, str, list[LinkedResource], dict[str, Any]]:
        return item.title, page.text, [], {"local": True}