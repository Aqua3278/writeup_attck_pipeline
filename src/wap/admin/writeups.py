from __future__ import annotations

import shutil
from pathlib import Path
from typing import Optional

from wap.db.store import Store
from wap.utils.config import ROOT, load_yaml, resolve_path
from wap.utils.ids import display_label, make_writeup_id_unique


class WriteupAdminService:
    def __init__(self, pipeline_cfg: Optional[dict] = None):
        self.cfg = pipeline_cfg or load_yaml("configs/pipeline.yaml")
        self.store = Store(self.cfg["db_path"])

    def list_rows(self, source_id: Optional[str] = None) -> list[dict]:
        out = []
        for r in self.store.list_writeups(source_id):
            out.append(
                {
                    "writeup_id": r["writeup_id"],
                    "label": display_label(
                        r["source_id"], r["title"] or "", r["task_name"]
                    ),
                    "source_id": r["source_id"],
                    "title": r["title"],
                    "task_name": r["task_name"],
                    "steps": len(self.store.get_steps(r["writeup_id"])),
                    "mappings": len(self.store.get_mappings(r["writeup_id"])),
                }
            )
        return out

    def rename_all_to_readable(self) -> list[dict]:
        """Rename opaque wu_xxx ids to goad__/xbow__/local__ slugs; keep analyses."""
        results = []
        used: set[str] = set()
        for r in list(self.store.list_writeups()):
            old = r["writeup_id"]
            url = r["canonical_url"] or ""
            title = r["title"] or ""
            kind = self._infer_kind(title, url)
            # reserve already-readable ids so we don't collide mid-batch
            new = make_writeup_id_unique(
                r["source_id"],
                title=title,
                task_name=r["task_name"],
                resource_kind=kind,
                url=url,
                existing=used | (set(self._all_ids()) - {old}),
            )
            used.add(new)
            if old == new:
                results.append({"old": old, "new": new, "changed": False})
                continue
            self.store.rename_writeup_id(old, new)
            self._rename_files(r, old, new)
            results.append({"old": old, "new": new, "changed": True})
        return results

    def _all_ids(self) -> list[str]:
        return [r["writeup_id"] for r in self.store.list_writeups()]

    def _id_exists(self, writeup_id: str) -> bool:
        with self.store.conn() as c:
            return (
                c.execute(
                    "SELECT 1 FROM writeups WHERE writeup_id=?", (writeup_id,)
                ).fetchone()
                is not None
            )

    @staticmethod
    def _infer_kind(title: str, url: str) -> str | None:
        """Classify xbow resources from filename; ignore misleading title tags."""
        u = (url or "").lower()
        fname = u.rsplit("/", 1)[-1]
        # RedAmon wiki: Foo.md = writeup; Foo_sess*.md / Foo_sess_decoded.md = session log
        if "_sess" in fname:
            return "session"
        if fname.endswith(".md"):
            return "decoded"
        t = (title or "").lower()
        if "(session)" in t or "(raw)" in t:
            return "session"
        if "decoded" in t:
            return "decoded"
        return None

    def _rename_files(self, row, old_id: str, new_id: str) -> None:
        for key in ("raw_content_path", "parsed_content_path"):
            rel = row[key]
            if not rel:
                continue
            old_path = resolve_path(rel)
            if not old_path.exists():
                continue
            new_name = old_path.name.replace(old_id, new_id, 1)
            new_path = old_path.with_name(new_name)
            if new_path != old_path:
                new_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(old_path), str(new_path))
                with self.store.conn() as c:
                    rel_new = str(new_path.relative_to(ROOT)).replace("\\", "/")
                    c.execute(
                        f"UPDATE writeups SET {key}=? WHERE writeup_id=?",
                        (rel_new, new_id),
                    )
        exp = resolve_path(self.cfg["exports_dir"]) / "writeups" / old_id
        if exp.exists():
            dest = exp.parent / new_id
            if dest.exists():
                shutil.rmtree(dest)
            shutil.move(str(exp), str(dest))
