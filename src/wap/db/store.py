from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

from wap.models.schemas import (
    AttackStep,
    PathEdge,
    TechniqueMapping,
    TechniqueRef,
    ValidationIssue,
    WriteupRecord,
)
from wap.utils.config import ROOT


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path)
        if not self.db_path.is_absolute():
            self.db_path = ROOT / self.db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    @contextmanager
    def conn(self) -> Iterator[sqlite3.Connection]:
        c = self._connect()
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()

    def _init_schema(self) -> None:
        schema = (Path(__file__).parent / "schema.sql").read_text(encoding="utf-8")
        with self.conn() as c:
            c.executescript(schema)
            self._migrate(c)

    @staticmethod
    def _migrate(c: sqlite3.Connection) -> None:
        """Add columns on existing DBs (CREATE TABLE IF NOT EXISTS won't alter)."""
        step_cols = {r[1] for r in c.execute("PRAGMA table_info(attack_steps)")}
        for col, decl in (
            ("step_type", "TEXT DEFAULT 'other'"),
            ("phase", "TEXT DEFAULT '其他'"),
            ("chain_status", "TEXT DEFAULT 'pending'"),
            ("chain_reason", "TEXT DEFAULT ''"),
            ("path_id", "TEXT DEFAULT ''"),
            ("depends_on_json", "TEXT DEFAULT '[]'"),
        ):
            if col not in step_cols:
                c.execute(f"ALTER TABLE attack_steps ADD COLUMN {col} {decl}")

        wu_cols = {r[1] for r in c.execute("PRAGMA table_info(writeups)")}
        for col, decl in (
            ("attack_chain_source", "TEXT"),
            ("coverage_status", "TEXT DEFAULT 'pending'"),
            ("chain_paths_json", "TEXT"),
            ("chain_notes", "TEXT"),
        ):
            if col not in wu_cols:
                c.execute(f"ALTER TABLE writeups ADD COLUMN {col} {decl}")

        map_cols = {r[1] for r in c.execute("PRAGMA table_info(technique_mappings)")}
        if "mapping_role" not in map_cols:
            c.execute(
                "ALTER TABLE technique_mappings ADD COLUMN mapping_role TEXT DEFAULT 'sole'"
            )
        if "supporting_behavior" not in map_cols:
            c.execute(
                "ALTER TABLE technique_mappings ADD COLUMN supporting_behavior TEXT DEFAULT ''"
            )
        for col, decl in (
            ("behavior_observed", "TEXT DEFAULT ''"),
            ("definition_match", "INTEGER DEFAULT 0"),
            ("required_conditions_met", "INTEGER DEFAULT 0"),
            ("evidence_directness", "TEXT DEFAULT 'direct'"),
            ("mapping_evidence", "TEXT DEFAULT ''"),
            ("counterevidence", "TEXT DEFAULT ''"),
        ):
            if col not in map_cols:
                c.execute(f"ALTER TABLE technique_mappings ADD COLUMN {col} {decl}")

    def upsert_source(self, src: dict[str, Any]) -> None:
        with self.conn() as c:
            c.execute(
                """
                INSERT INTO sources(source_id, source_name, source_type, entry_url, adapter_type,
                  enabled, crawl_config_json, last_crawl_time, status)
                VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(source_id) DO UPDATE SET
                  source_name=excluded.source_name,
                  source_type=excluded.source_type,
                  entry_url=excluded.entry_url,
                  adapter_type=excluded.adapter_type,
                  enabled=excluded.enabled,
                  crawl_config_json=excluded.crawl_config_json,
                  status=excluded.status
                """,
                (
                    src["source_id"],
                    src.get("source_name"),
                    src.get("source_type"),
                    src.get("entry_url"),
                    src["adapter_type"],
                    1 if src.get("enabled", True) else 0,
                    json.dumps(src.get("crawl_config") or {}, ensure_ascii=False),
                    src.get("last_crawl_time"),
                    src.get("status", "idle"),
                ),
            )

    def set_source_crawl_time(self, source_id: str, when: Optional[str] = None) -> None:
        with self.conn() as c:
            c.execute(
                "UPDATE sources SET last_crawl_time=?, status=? WHERE source_id=?",
                (when or utcnow(), "ok", source_id),
            )

    def get_writeup_by_url(self, source_id: str, url: str) -> Optional[sqlite3.Row]:
        with self.conn() as c:
            return c.execute(
                "SELECT * FROM writeups WHERE source_id=? AND canonical_url=? ORDER BY version DESC LIMIT 1",
                (source_id, url),
            ).fetchone()

    def save_writeup(self, w: WriteupRecord) -> None:
        with self.conn() as c:
            existing = c.execute(
                "SELECT writeup_id, version, content_hash FROM writeups WHERE source_id=? AND canonical_url=?",
                (w.source_id, w.canonical_url),
            ).fetchone()
            if existing and existing["content_hash"] == w.content_hash:
                return
            version = 1
            if existing:
                # archive old
                c.execute(
                    """INSERT OR REPLACE INTO writeup_versions(writeup_id, version, content_hash, raw_content_path, crawled_at)
                       SELECT writeup_id, version, content_hash, raw_content_path, crawled_at FROM writeups WHERE writeup_id=?""",
                    (existing["writeup_id"],),
                )
                version = int(existing["version"]) + 1
                w.writeup_id = existing["writeup_id"]
                w.version = version
            c.execute(
                """
                INSERT INTO writeups(
                  writeup_id, source_id, source_name, title, canonical_url, task_name, benchmark_name,
                  published_at, crawled_at, content_format, raw_content_path, parsed_content_path,
                  content_hash, linked_resources_json, crawl_status, parse_status, version, error
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(writeup_id) DO UPDATE SET
                  title=excluded.title,
                  crawled_at=excluded.crawled_at,
                  raw_content_path=excluded.raw_content_path,
                  parsed_content_path=excluded.parsed_content_path,
                  content_hash=excluded.content_hash,
                  linked_resources_json=excluded.linked_resources_json,
                  crawl_status=excluded.crawl_status,
                  parse_status=excluded.parse_status,
                  version=excluded.version,
                  error=excluded.error,
                  task_name=excluded.task_name,
                  benchmark_name=excluded.benchmark_name
                """,
                (
                    w.writeup_id,
                    w.source_id,
                    w.source_name,
                    w.title,
                    w.canonical_url,
                    w.task_name,
                    w.benchmark_name,
                    w.published_at,
                    w.crawled_at.isoformat(),
                    w.content_format,
                    w.raw_content_path,
                    w.parsed_content_path,
                    w.content_hash,
                    json.dumps([r.model_dump() for r in w.linked_resources], ensure_ascii=False),
                    w.crawl_status.value,
                    w.parse_status.value,
                    w.version,
                    w.error,
                ),
            )

    def record_failure(self, source_id: str, url: str, error: str) -> None:
        with self.conn() as c:
            row = c.execute(
                "SELECT id, attempts FROM crawl_failures WHERE source_id=? AND url=? AND resolved=0",
                (source_id, url),
            ).fetchone()
            if row:
                c.execute(
                    "UPDATE crawl_failures SET attempts=?, error=?, last_attempt_at=? WHERE id=?",
                    (row["attempts"] + 1, error, utcnow(), row["id"]),
                )
            else:
                c.execute(
                    "INSERT INTO crawl_failures(source_id, url, error, attempts, last_attempt_at) VALUES(?,?,?,?,?)",
                    (source_id, url, error, 1, utcnow()),
                )

    def list_writeups(self, source_id: Optional[str] = None) -> list[sqlite3.Row]:
        with self.conn() as c:
            if source_id:
                return list(
                    c.execute(
                        "SELECT * FROM writeups WHERE source_id=? ORDER BY crawled_at",
                        (source_id,),
                    )
                )
            return list(c.execute("SELECT * FROM writeups ORDER BY source_id, crawled_at"))

    def replace_steps(self, writeup_id: str, steps: list[AttackStep], edges: list[PathEdge]) -> None:
        with self.conn() as c:
            c.execute("DELETE FROM attack_steps WHERE writeup_id=?", (writeup_id,))
            c.execute("DELETE FROM path_edges WHERE writeup_id=?", (writeup_id,))
            for s in steps:
                c.execute(
                    """INSERT INTO attack_steps(
                        step_id, writeup_id, sequence, action, target, input, output,
                        purpose, prerequisite, evidence, evidence_location, evidence_type,
                        inference, confidence, chunk_id, created_at, step_type, phase,
                        chain_status, chain_reason, path_id, depends_on_json
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        s.step_id,
                        s.writeup_id,
                        s.sequence,
                        s.action,
                        s.target,
                        s.input,
                        s.output,
                        s.purpose,
                        s.prerequisite,
                        s.evidence,
                        s.evidence_location,
                        s.evidence_type.value,
                        1 if s.inference else 0,
                        s.confidence,
                        s.chunk_id,
                        utcnow(),
                        s.step_type or "other",
                        s.phase or "其他",
                        getattr(s, "chain_status", None) or "pending",
                        getattr(s, "chain_reason", None) or "",
                        getattr(s, "path_id", None) or "",
                        getattr(s, "depends_on_json", None) or "[]",
                    ),
                )
            for e in edges:
                c.execute(
                    "INSERT INTO path_edges(writeup_id, from_step_id, to_step_id, relation) VALUES(?,?,?,?)",
                    (writeup_id, e.from_step_id, e.to_step_id, e.relation),
                )

    def replace_mappings(self, writeup_id: str, mappings: list[TechniqueMapping]) -> None:
        with self.conn() as c:
            c.execute("DELETE FROM technique_mappings WHERE writeup_id=?", (writeup_id,))
            for m in mappings:
                c.execute(
                    """INSERT INTO technique_mappings(
                        mapping_id, step_id, writeup_id, technique_id, technique_name,
                        tactic, mapping_status, mapping_type, mapping_reason, evidence,
                        evidence_location, confidence, review_status, created_at,
                        mapping_role, supporting_behavior,
                        behavior_observed, definition_match, required_conditions_met,
                        evidence_directness, mapping_evidence, counterevidence
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        m.mapping_id,
                        m.step_id,
                        m.writeup_id,
                        m.technique_id,
                        m.technique_name,
                        m.tactic,
                        m.mapping_status.value,
                        m.mapping_type,
                        m.mapping_reason,
                        m.evidence,
                        m.evidence_location,
                        m.confidence,
                        m.review_status,
                        utcnow(),
                        m.mapping_role or "sole",
                        m.supporting_behavior or "",
                        m.behavior_observed or "",
                        1 if m.definition_match else 0,
                        1 if m.required_conditions_met else 0,
                        m.evidence_directness or "direct",
                        m.mapping_evidence or "",
                        m.counterevidence or "",
                    ),
                )

    def replace_catalog(self, techniques: list[TechniqueRef], workbook: str) -> None:
        with self.conn() as c:
            c.execute("DELETE FROM technique_catalog")
            for t in techniques:
                c.execute(
                    "INSERT INTO technique_catalog VALUES(?,?,?,?,?,?,?)",
                    (
                        t.technique_id,
                        t.technique_name,
                        t.tactic or "",
                        t.description,
                        1 if t.retained else 0,
                        workbook,
                        utcnow(),
                    ),
                )

    def get_catalog(self) -> list[TechniqueRef]:
        """Return catalog rows; same technique_id may appear under multiple tactics."""
        with self.conn() as c:
            rows = c.execute("SELECT * FROM technique_catalog").fetchall()
        from wap.mapping.attck_meta import enrich_ref

        return [
            enrich_ref(
                TechniqueRef(
                    technique_id=r["technique_id"],
                    technique_name=r["technique_name"],
                    tactic=r["tactic"],
                    description=r["description"] or "",
                    retained=bool(r["retained"]),
                )
            )
            for r in rows
        ]

    def get_catalog_by_id(self) -> dict[str, TechniqueRef]:
        """Collapse by technique_id; retained=True wins if any row is retained."""
        by_id: dict[str, TechniqueRef] = {}
        for t in self.get_catalog():
            prev = by_id.get(t.technique_id)
            if prev is None:
                by_id[t.technique_id] = t
            elif t.retained and not prev.retained:
                by_id[t.technique_id] = t
        return by_id

    def get_steps(self, writeup_id: str) -> list[sqlite3.Row]:
        with self.conn() as c:
            return list(
                c.execute(
                    "SELECT * FROM attack_steps WHERE writeup_id=? ORDER BY sequence",
                    (writeup_id,),
                )
            )

    def get_selected_steps(self, writeup_id: str) -> list[sqlite3.Row]:
        """Steps on the successful attack chain (chain_status=selected)."""
        with self.conn() as c:
            return list(
                c.execute(
                    """SELECT * FROM attack_steps
                       WHERE writeup_id=? AND chain_status='selected'
                       ORDER BY sequence""",
                    (writeup_id,),
                )
            )

    def update_writeup_chain(
        self,
        writeup_id: str,
        *,
        attack_chain_source: str,
        coverage_status: str,
        chain_paths_json: Optional[str] = None,
        chain_notes: Optional[str] = None,
    ) -> None:
        with self.conn() as c:
            c.execute(
                """UPDATE writeups SET
                     attack_chain_source=?,
                     coverage_status=?,
                     chain_paths_json=COALESCE(?, chain_paths_json),
                     chain_notes=COALESCE(?, chain_notes)
                   WHERE writeup_id=?""",
                (
                    attack_chain_source,
                    coverage_status,
                    chain_paths_json,
                    chain_notes,
                    writeup_id,
                ),
            )

    def update_step_chain(
        self,
        step_id: str,
        *,
        chain_status: str,
        chain_reason: str = "",
        path_id: str = "",
        depends_on_json: str = "[]",
    ) -> None:
        with self.conn() as c:
            c.execute(
                """UPDATE attack_steps SET
                     chain_status=?, chain_reason=?, path_id=?, depends_on_json=?
                   WHERE step_id=?""",
                (chain_status, chain_reason, path_id, depends_on_json, step_id),
            )

    def list_sibling_writeups(self, writeup_id: str) -> list[sqlite3.Row]:
        """Same source + task_name resources (for corpus merge / evidence)."""
        with self.conn() as c:
            row = c.execute(
                "SELECT * FROM writeups WHERE writeup_id=?", (writeup_id,)
            ).fetchone()
            if not row:
                return []
            task = (row["task_name"] or "").strip()
            if not task:
                return []
            return list(
                c.execute(
                    """SELECT * FROM writeups
                       WHERE source_id=? AND task_name=? AND writeup_id!=?
                       ORDER BY crawled_at""",
                    (row["source_id"], task, writeup_id),
                )
            )

    def get_mappings(self, writeup_id: Optional[str] = None) -> list[sqlite3.Row]:
        with self.conn() as c:
            if writeup_id:
                return list(
                    c.execute(
                        "SELECT * FROM technique_mappings WHERE writeup_id=?",
                        (writeup_id,),
                    )
                )
            return list(c.execute("SELECT * FROM technique_mappings"))

    def save_issues(self, issues: list[ValidationIssue]) -> None:
        with self.conn() as c:
            for i in issues:
                c.execute(
                    "INSERT OR REPLACE INTO validation_issues VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        i.issue_id,
                        i.writeup_id,
                        i.step_id,
                        i.mapping_id,
                        i.severity,
                        i.code,
                        i.message,
                        json.dumps(i.details, ensure_ascii=False),
                        utcnow(),
                    ),
                )

    def list_unresolved_failures(self, source_id: Optional[str] = None) -> list[sqlite3.Row]:
        with self.conn() as c:
            if source_id:
                return list(
                    c.execute(
                        "SELECT * FROM crawl_failures WHERE resolved=0 AND source_id=?",
                        (source_id,),
                    )
                )
            return list(c.execute("SELECT * FROM crawl_failures WHERE resolved=0"))

    def rename_writeup_id(self, old_id: str, new_id: str) -> None:
        if old_id == new_id:
            return
        with self.conn() as c:
            exists = c.execute(
                "SELECT 1 FROM writeups WHERE writeup_id=?", (new_id,)
            ).fetchone()
            if exists:
                raise ValueError(f"target writeup_id already exists: {new_id}")
            row = c.execute(
                "SELECT 1 FROM writeups WHERE writeup_id=?", (old_id,)
            ).fetchone()
            if not row:
                raise KeyError(old_id)
            # child tables first
            for table in (
                "attack_steps",
                "path_edges",
                "technique_mappings",
                "validation_issues",
                "writeup_versions",
            ):
                c.execute(
                    f"UPDATE {table} SET writeup_id=? WHERE writeup_id=?",
                    (new_id, old_id),
                )
            # rewrite step_id prefixes that started with old id
            c.execute(
                "UPDATE attack_steps SET step_id = REPLACE(step_id, ?, ?) WHERE writeup_id=?",
                (old_id + "_", new_id + "_", new_id),
            )
            # in-place rename avoids UNIQUE(source_id, url, hash) collision
            c.execute(
                "UPDATE writeups SET writeup_id=? WHERE writeup_id=?",
                (new_id, old_id),
            )

    def resolve_writeup_id(self, ref: str) -> str:
        """Accept full id, or unique substring / title / task_name."""
        rows = self.list_writeups()
        exact = [r for r in rows if r["writeup_id"] == ref]
        if exact:
            return exact[0]["writeup_id"]
        partial = [r for r in rows if ref in r["writeup_id"]]
        if len(partial) == 1:
            return partial[0]["writeup_id"]
        by_title = [
            r
            for r in rows
            if ref.lower() in (r["title"] or "").lower()
            or ref.lower() in (r["task_name"] or "").lower()
        ]
        if len(by_title) == 1:
            return by_title[0]["writeup_id"]
        if not partial and not by_title:
            raise KeyError(f"writeup not found: {ref}")
        raise KeyError(
            f"ambiguous writeup ref {ref!r}; matches: "
            + ", ".join(
                (r["writeup_id"] for r in (partial or by_title)[:8])
            )
        )