from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional

from wap.models.schemas import DiscoveredItem, LinkedResource
from wap.utils.http import FetchResult, HttpClient


class SourceAdapter(ABC):
    """Pluggable crawl adapter. Core analyze/map must not depend on source HTML."""

    adapter_type: str = "base"

    def __init__(self, source_cfg: dict[str, Any], http: HttpClient):
        self.source_cfg = source_cfg
        self.http = http
        self.crawl_config: dict[str, Any] = source_cfg.get("crawl_config") or {}

    @property
    def source_id(self) -> str:
        return self.source_cfg["source_id"]

    @property
    def source_name(self) -> str:
        return self.source_cfg.get("source_name", self.source_id)

    @abstractmethod
    def discover(self) -> list[DiscoveredItem]:
        """Discover article/task entry points from entry_url or local root."""

    def fetch(self, url: str) -> FetchResult:
        return self.http.fetch(url)

    def extract_links(self, page: FetchResult) -> list[LinkedResource]:
        return []

    @abstractmethod
    def parse(
        self, item: DiscoveredItem, page: FetchResult
    ) -> tuple[str, str, list[LinkedResource], dict[str, Any]]:
        """
        Returns:
          title, parsed_markdown_or_text, linked_resources, extra_metadata
        """