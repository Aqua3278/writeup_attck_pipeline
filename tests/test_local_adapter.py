from wap.crawl.service import CrawlService
from wap.mapping.service import MappingService
from wap.report.service import ReportService


def test_local_crawl_and_catalog():
    svc = CrawlService()
    stats = svc.crawl(source_id="local_samples", mode="full")
    assert stats["discovered"] >= 1
    assert stats["saved"] + stats["skipped"] >= 1
    summary = MappingService().load_catalog()
    assert summary["retained"] > 0
    out = ReportService().global_report()
    assert (out / "source_summary.json").exists()
    assert (out / "report.md").exists()