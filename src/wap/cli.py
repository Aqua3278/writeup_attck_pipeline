from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich import print as rprint

# Allow `python -m wap.cli` from src/
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from wap.analyze.path_extract import PathExtractService
from wap.chain.service import ChainService
from wap.crawl.service import CrawlService
from wap.mapping.service import MappingService
from wap.report.service import ReportService
from wap.sources.registry import SourceRegistry
from wap.validate.service import ValidateService


@click.group()
def main() -> None:
    """Writeup → attack path → ATT&CK mapping pipeline."""


@main.group()
def sources() -> None:
    """Manage data sources."""


@sources.command("list")
@click.option("--enabled-only", is_flag=True)
def sources_list(enabled_only: bool) -> None:
    reg = SourceRegistry()
    for s in reg.list(enabled_only=enabled_only):
        flag = "ON" if s.get("enabled", True) else "OFF"
        rprint(
            f"[bold]{s['source_id']}[/bold] ({flag}) "
            f"adapter={s['adapter_type']} entry={s.get('entry_url')}"
        )


@main.command()
@click.option("--source", "source_id", default=None, help="source_id or omit for all enabled")
@click.option("--mode", type=click.Choice(["full", "incremental", "retry"]), default="incremental")
@click.option("--limit", type=int, default=None, help="max items (debug)")
def crawl(source_id: str | None, mode: str, limit: int | None) -> None:
    svc = CrawlService()
    if mode == "retry":
        stats = svc.retry_failures(source_id)
    else:
        stats = svc.crawl(source_id=source_id, mode=mode, limit=limit)
    rprint(json.dumps(stats, ensure_ascii=False, indent=2))


@main.group()
def writeups() -> None:
    """List / rename writeups with readable ids."""


@writeups.command("list")
@click.option("--source", "source_id", default=None)
def writeups_list(source_id: str | None) -> None:
    from wap.admin.writeups import WriteupAdminService

    for row in WriteupAdminService().list_rows(source_id):
        rprint(
            f"{row['writeup_id']}\n"
            f"  {row['label']}  | steps={row['steps']} maps={row['mappings']}"
        )


@writeups.command("rename-readable")
def writeups_rename() -> None:
    """Rename wu_xxxxxxxx ids to goad__/xbow__/local__ readable ids."""
    from wap.admin.writeups import WriteupAdminService

    results = WriteupAdminService().rename_all_to_readable()
    changed = [r for r in results if r["changed"]]
    rprint(f"renamed {len(changed)} / {len(results)}")
    for r in changed:
        rprint(f"  {r['old']}  ->  {r['new']}")


@main.command("load-attck")
def load_attck() -> None:
    svc = MappingService()
    rprint(svc.load_catalog())


@main.command()
@click.option("--source", "source_id", default=None)
@click.option("--writeup-id", default=None)
@click.option("--offline", is_flag=True, help="regex heuristic when LLM unavailable")
def analyze(source_id: str | None, writeup_id: str | None, offline: bool) -> None:
    from wap.db.store import Store
    from wap.utils.config import load_yaml

    store = Store(load_yaml("configs/pipeline.yaml")["db_path"])
    if writeup_id:
        writeup_id = store.resolve_writeup_id(writeup_id)
    if offline:
        from wap.analyze.offline_extract import OfflinePathExtractService

        svc = OfflinePathExtractService()
        if writeup_id:
            rprint(svc.analyze_writeup(writeup_id))
        else:
            out = []
            for w in store.list_writeups(source_id):
                out.append(svc.analyze_writeup(w["writeup_id"]))
            rprint(out)
        return
    svc = PathExtractService()
    if writeup_id:
        rprint(svc.analyze_writeup(writeup_id))
    else:
        rprint(svc.analyze_all(source_id))


@main.command("chain")
@click.option("--source", "source_id", default=None)
@click.option("--writeup-id", default=None)
@click.option("--offline", is_flag=True, help="heuristic chain resolve without LLM")
def chain_cmd(source_id: str | None, writeup_id: str | None, offline: bool) -> None:
    """Resolve successful attack chain (before ATT&CK map)."""
    from wap.db.store import Store
    from wap.utils.config import load_yaml

    store = Store(load_yaml("configs/pipeline.yaml")["db_path"])
    if writeup_id:
        writeup_id = store.resolve_writeup_id(writeup_id)
    svc = ChainService(offline=offline)
    if writeup_id:
        rprint(svc.resolve_writeup(writeup_id))
    else:
        rprint(svc.resolve_all(source_id))


@main.command("map")
@click.option("--source", "source_id", default=None)
@click.option("--writeup-id", default=None)
@click.option("--offline", is_flag=True, help="keyword heuristic when LLM unavailable")
def map_cmd(source_id: str | None, writeup_id: str | None, offline: bool) -> None:
    from wap.db.store import Store
    from wap.utils.config import load_yaml

    store = Store(load_yaml("configs/pipeline.yaml")["db_path"])
    if writeup_id:
        writeup_id = store.resolve_writeup_id(writeup_id)
    if offline:
        from wap.mapping.offline_map import OfflineMappingService
        from wap.mapping.service import MappingService as MS

        MS().load_catalog()
        svc = OfflineMappingService()
        if writeup_id:
            rprint(svc.map_writeup(writeup_id))
        else:
            out = [svc.map_writeup(w["writeup_id"]) for w in store.list_writeups(source_id)]
            rprint(out)
        return
    svc = MappingService()
    svc.load_catalog()
    if writeup_id:
        rprint(svc.map_writeup(writeup_id))
    else:
        rprint(svc.map_all(source_id))


@main.command()
@click.option("--source", "source_id", default=None)
@click.option("--writeup-id", default=None)
def validate(source_id: str | None, writeup_id: str | None) -> None:
    from wap.db.store import Store
    from wap.utils.config import load_yaml

    store = Store(load_yaml("configs/pipeline.yaml")["db_path"])
    if writeup_id:
        writeup_id = store.resolve_writeup_id(writeup_id)
    svc = ValidateService()
    if writeup_id:
        issues = svc.validate_writeup(writeup_id)
    else:
        issues = svc.validate_all(source_id)
    rprint(f"issues={len(issues)}")
    for i in issues[:50]:
        rprint(f"[{i.severity}] {i.code}: {i.message}")


@main.command("eval-candidates")
@click.option("--max-candidates", type=int, default=10)
@click.option(
    "--top-k",
    "top_ks",
    multiple=True,
    type=int,
    default=(10, 20, 30),
    show_default=True,
    help="Top-K grid for vector recall evaluation.",
)
@click.option(
    "--out",
    "out_path",
    default="data/exports/candidate_eval/compare_vector.json",
    show_default=True,
)
@click.option("--with-full-catalog", is_flag=True, help="Index full retained workbook")
def eval_candidates_cmd(
    max_candidates: int,
    top_ks: tuple[int, ...],
    out_path: str,
    with_full_catalog: bool,
) -> None:
    """Evaluate Stage-1 vector candidates on confirmed mapping_cases gold."""
    from pathlib import Path

    from wap.mapping.candidate.evaluate import compare_strategies, write_report
    from wap.mapping.candidate.types import config_from_pipeline
    from wap.utils.config import load_yaml, resolve_path

    pipeline_cfg = load_yaml("configs/pipeline.yaml")
    base_config = config_from_pipeline(pipeline_cfg)
    catalog_refs = None
    if with_full_catalog:
        from wap.mapping.attck_catalog import load_attck_workbook
        from wap.mapping.attck_meta import enrich_ref
        from wap.mapping.candidate.catalog_docs import merge_technique_refs

        techs = load_attck_workbook(
            resolve_path(pipeline_cfg["attck_workbook"]),
            sheet=pipeline_cfg.get("attck_sheet", "Sheet1"),
            excluded_rgb_suffix=pipeline_cfg.get(
                "attck_excluded_fill_rgb_suffix", "FFFF00"
            ),
        )
        for t in techs:
            enrich_ref(t)
        catalog_refs = merge_technique_refs(techs)

    payload = compare_strategies(
        max_candidates=max_candidates,
        top_k_grid=list(top_ks) or [10, 20, 30],
        catalog_refs=catalog_refs,
        base_config=base_config,
    )
    path = write_report(payload, Path(out_path))
    rprint(f"wrote {path}")
    for rep in payload["reports"]:
        rprint(
            f"[cyan]{rep['strategy']}[/cyan] {rep['select_label']} "
            f"recall={rep['recall']} avg_cands={rep['avg_candidates']} "
            f"exclude_prec={rep['exclude_precision']}"
        )
    for cid, rows in (payload.get("focus_cases") or {}).items():
        rprint(f"[yellow]focus {cid}[/yellow]")
        for row in rows:
            rprint(
                f"  {row['strategy']} {row['select_label']} "
                f"rank={row.get('gold_rank')} score={row.get('gold_score')} "
                f"ok={row.get('contains_ok')}"
            )


@main.command()
@click.option("--writeup-id", default=None)
@click.option("--format", "fmt", type=click.Choice(["markdown", "all"]), default="all")
def report(writeup_id: str | None, fmt: str) -> None:
    from wap.db.store import Store
    from wap.utils.config import load_yaml

    if writeup_id:
        store = Store(load_yaml("configs/pipeline.yaml")["db_path"])
        writeup_id = store.resolve_writeup_id(writeup_id)
    svc = ReportService()
    if writeup_id:
        path = svc.export_writeup(writeup_id)
        rprint(f"wrote {path}")
    out = svc.global_report()
    rprint(f"global report -> {out}")


@main.command()
@click.option("--source", "source_id", default=None)
@click.option("--all", "run_all", is_flag=True)
@click.option("--limit", type=int, default=None, help="crawl limit for smoke tests")
@click.option("--skip-llm", is_flag=True, help="crawl + load ATT&CK only")
def run(source_id: str | None, run_all: bool, limit: int | None, skip_llm: bool) -> None:
    if not source_id and not run_all:
        raise click.UsageError("provide --source <id> or --all")
    crawl_svc = CrawlService()
    sid = None if run_all else source_id
    stats = crawl_svc.crawl(source_id=sid, mode="incremental", limit=limit)
    rprint("[cyan]crawl[/cyan]", stats)
    map_svc = MappingService()
    rprint("[cyan]attck[/cyan]", map_svc.load_catalog())
    if skip_llm:
        ReportService().global_report()
        return
    PathExtractService().analyze_all(sid)
    ChainService().resolve_all(sid)
    map_svc.map_all(sid)
    ValidateService().validate_all(sid)
    ReportService().global_report()
    rprint("[green]pipeline complete[/green]")


@main.command()
@click.option("--source", "source_id", default=None)
def retry(source_id: str | None) -> None:
    rprint(CrawlService().retry_failures(source_id))


if __name__ == "__main__":
    main()