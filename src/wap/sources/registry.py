from __future__ import annotations

from typing import Any, Type

from wap.sources.adapters.goad import GoadAdapter
from wap.sources.adapters.github_md import GithubAdapter
from wap.sources.adapters.local_files import LocalFileAdapter
from wap.sources.adapters.web_generic import GenericWebAdapter
from wap.sources.adapters.xbow import XbowAdapter
from wap.sources.base import SourceAdapter
from wap.utils.config import load_yaml
from wap.utils.http import HttpClient

ADAPTERS: dict[str, Type[SourceAdapter]] = {
    "goad": GoadAdapter,
    "xbow": XbowAdapter,
    "web": GenericWebAdapter,
    "github": GithubAdapter,
    "local": LocalFileAdapter,
}


class SourceRegistry:
    def __init__(self, sources_yaml: str = "configs/sources.yaml"):
        raw = load_yaml(sources_yaml)
        self.sources: list[dict[str, Any]] = list(raw.get("sources") or [])

    def list(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        if enabled_only:
            return [s for s in self.sources if s.get("enabled", True)]
        return list(self.sources)

    def get(self, source_id: str) -> dict[str, Any]:
        for s in self.sources:
            if s["source_id"] == source_id:
                return s
        raise KeyError(f"unknown source_id: {source_id}")

    def build_adapter(self, source_id: str, respect_robots: bool = True) -> SourceAdapter:
        cfg = self.get(source_id)
        adapter_type = cfg["adapter_type"]
        if adapter_type not in ADAPTERS:
            raise KeyError(
                f"adapter_type={adapter_type} not registered; known={list(ADAPTERS)}"
            )
        cc = cfg.get("crawl_config") or {}
        http = HttpClient(
            user_agent=cc.get("user_agent", "writeup-attck-pipeline/0.1"),
            timeout_sec=float(cc.get("timeout_sec", 30)),
            retries=int(cc.get("retries", 3)),
            interval_sec=float(cc.get("request_interval_sec", 1.0)),
            respect_robots=respect_robots,
        )
        return ADAPTERS[adapter_type](cfg, http)

    def add(self, source: dict[str, Any]) -> None:
        if any(s["source_id"] == source["source_id"] for s in self.sources):
            raise ValueError(f"source_id already exists: {source['source_id']}")
        self.sources.append(source)