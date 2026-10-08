from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from wap.db.store import Store
from wap.models.schemas import CrawlStatus, ParseStatus, WriteupRecord
from wap.sources.registry import SourceRegistry
from wap.utils.config import ROOT, ensure_dirs, load_yaml, resolve_path
from wap.utils.http import content_hash
from wap.utils.ids import make_writeup_id_unique


class CrawlService:
    def __init__(self, pipeline_cfg: Optional[dict] = None):
        self.cfg = pipeline_cfg or load_yaml("configs/pipeline.yaml")
        ensure_dirs(self.cfg)
        self.store = Store(self.cfg["db_path"])
        self.registry = SourceRegistry("configs/sources.yaml")
        for s in self.registry.list():
            self.store.upsert_source(s)

    def crawl(
        self,
        source_id: Optional[str] = None,
        mode: str = "incremental",
        limit: Optional[int] = None,
    ) -> dict:
        sources = (
            [self.registry.get(source_id)]
            if source_id
            else self.registry.list(enabled_only=True)
        )
        stats = {"discovered": 0, "saved": 0, "skipped": 0, "failed": 0, "errors": []}
        respect = bool(self.cfg.get("respect_robots", True))
        raw_root = resolve_path(self.cfg["raw_dir"])
        parsed_root = resolve_path(self.cfg["parsed_dir"])

        for src in sources:
            sid = src["source_id"]
            adapter = self.registry.build_adapter(sid, respect_robots=respect)
            try:
                items = adapter.discover()
            except Exception as e:
                stats["failed"] += 1
                stats["errors"].append({"source_id": sid, "stage": "discover", "error": str(e)})
                self.store.record_failure(sid, src.get("entry_url") or sid, f"discover: {e}")
                continue

            if limit:
                items = items[:limit]
            stats["discovered"] += len(items)

            for item in items:
                try:
                    existing = self.store.get_writeup_by_url(sid, item.url)
                    if mode == "incremental" and existing and existing["crawl_status"] == "success":
                        # still fetch to detect change via hash
                        pass

                    page = adapter.fetch(item.url)
                    title, body, links, meta = adapter.parse(item, page)
                    h = content_hash(body)
                    if (
                        mode == "incremental"
                        and existing
                        and existing["content_hash"] == h
                        and existing["crawl_status"] == "success"
                    ):
                        stats["skipped"] += 1
                        continue

                    if existing:
                        wid = existing["writeup_id"]
                    else:
                        existing_ids = {
                            r["writeup_id"] for r in self.store.list_writeups(sid)
                        }
                        wid = make_writeup_id_unique(
                            sid,
                            title=title,
                            task_name=item.task_name or meta.get("task_name"),
                            resource_kind=(item.metadata or {}).get("resource_kind"),
                            url=page.final_url or item.url,
                            existing=existing_ids,
                        )
                    rel_raw = Path(sid) / f"{wid}.raw.html"
                    rel_parsed = Path(sid) / f"{wid}.md"
                    raw_path = raw_root / rel_raw
                    parsed_path = parsed_root / rel_parsed
                    raw_path.parent.mkdir(parents=True, exist_ok=True)
                    parsed_path.parent.mkdir(parents=True, exist_ok=True)
                    raw_path.write_bytes(page.content)
                    parsed_path.write_text(body, encoding="utf-8")

                    rec = WriteupRecord(
                        writeup_id=wid,
                        source_id=sid,
                        source_name=adapter.source_name,
                        title=title,
                        canonical_url=page.final_url or item.url,
                        task_name=item.task_name or meta.get("task_name"),
                        benchmark_name=item.benchmark_name,
                        published_at=meta.get("published_at") or item.published_at,
                        crawled_at=datetime.now(timezone.utc),
                        content_format="markdown",
                        raw_content_path=str(raw_path.relative_to(ROOT)),
                        parsed_content_path=str(parsed_path.relative_to(ROOT)),
                        content_hash=h,
                        linked_resources=links,
                        crawl_status=CrawlStatus.success,
                        parse_status=ParseStatus.success,
                    )
                    self.store.save_writeup(rec)
                    stats["saved"] += 1
                except Exception as e:
                    stats["failed"] += 1
                    stats["errors"].append(
                        {"source_id": sid, "url": item.url, "error": str(e)}
                    )
                    self.store.record_failure(sid, item.url, str(e))
                    # keep raw if we have it? skip
            self.store.set_source_crawl_time(sid)
        return stats

    def retry_failures(self, source_id: Optional[str] = None) -> dict:
        fails = self.store.list_unresolved_failures(source_id)
        # Re-run crawl in retry mode for failed URLs only would need finer API;
        # for v0.1, re-crawl source incremental after clearing is enough.
        return self.crawl(source_id=source_id, mode="full")