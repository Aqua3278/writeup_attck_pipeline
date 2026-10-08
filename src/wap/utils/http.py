from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

import requests
from tenacity import retry, stop_after_attempt, wait_exponential


@dataclass
class FetchResult:
    url: str
    final_url: str
    status_code: int
    content: bytes
    text: str
    content_type: str
    fetched_at: float


class HttpClient:
    def __init__(
        self,
        user_agent: str,
        timeout_sec: float = 30,
        retries: int = 3,
        interval_sec: float = 1.0,
        respect_robots: bool = True,
    ):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        self.timeout = timeout_sec
        self.retries = retries
        self.interval = interval_sec
        self.respect_robots = respect_robots
        self._last_request = 0.0
        self._robots: dict[str, RobotFileParser] = {}

    def _throttle(self) -> None:
        elapsed = time.time() - self._last_request
        if elapsed < self.interval:
            time.sleep(self.interval - elapsed)

    def allowed(self, url: str) -> bool:
        if not self.respect_robots:
            return True
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in self._robots:
            rp = RobotFileParser()
            rp.set_url(urljoin(base, "/robots.txt"))
            try:
                rp.read()
            except Exception:
                # If robots unreachable, be conservative but allow public docs we target.
                self._robots[base] = rp
                return True
            self._robots[base] = rp
        ua = self.session.headers.get("User-Agent", "*")
        try:
            return self._robots[base].can_fetch(ua, url)
        except Exception:
            return True

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=8), reraise=True)
    def _get(self, url: str) -> requests.Response:
        self._throttle()
        self._last_request = time.time()
        resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        resp.raise_for_status()
        return resp

    def fetch(self, url: str) -> FetchResult:
        if not self.allowed(url):
            raise PermissionError(f"robots.txt disallows: {url}")
        resp = self._get(url)
        ctype = resp.headers.get("Content-Type", "")
        # decode carefully
        text = resp.content.decode(resp.encoding or "utf-8", errors="replace")
        return FetchResult(
            url=url,
            final_url=str(resp.url),
            status_code=resp.status_code,
            content=resp.content,
            text=text,
            content_type=ctype,
            fetched_at=time.time(),
        )


def content_hash(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def normalize_url(base: str, href: str) -> Optional[str]:
    if not href or href.startswith("#") or href.startswith("mailto:"):
        return None
    return urljoin(base, href)