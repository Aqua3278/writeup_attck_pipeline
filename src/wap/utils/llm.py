from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Optional

import httpx
from dotenv import load_dotenv

from wap.utils.config import ROOT, load_yaml

# Ensure .env is loaded even if caller forgot
load_dotenv(ROOT / ".env")


class LLMClient:
    def __init__(self, model_cfg: Optional[dict] = None):
        self.cfg = model_cfg or load_yaml("configs/model.yaml")
        self.base_url = (self.cfg.get("base_url") or "").rstrip("/")
        key_env = self.cfg.get("api_key_env", "LLM_API_KEY")
        self.api_key = (os.environ.get(key_env) or "").strip()
        self.model = self.cfg.get("model", "deepseek-chat")
        self.temperature = float(self.cfg.get("temperature", 0.1))
        self.max_tokens = int(self.cfg.get("max_tokens", 4096))
        self.timeout = float(self.cfg.get("timeout_sec", 120))

    @property
    def available(self) -> bool:
        return bool(self.api_key and self.base_url)

    def chat_json(self, system: str, user: str, retries: int = 3) -> dict[str, Any]:
        if not self.available:
            raise RuntimeError(
                f"LLM not configured: set {self.cfg.get('api_key_env')} and base_url"
            )
        url = self.base_url
        if not url.endswith("/v1") and "/chat/completions" not in url:
            url = url + "/v1/chat/completions"
        elif not url.endswith("/chat/completions"):
            url = url + "/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        last_err: Exception | None = None
        for attempt in range(retries):
            payload = {
                "model": self.model,
                "temperature": self.temperature,
                "max_tokens": self.max_tokens,
                "messages": [
                    {"role": "system", "content": system},
                    {
                        "role": "user",
                        "content": user
                        + "\n\nRespond with a single JSON object only. No markdown fences.",
                    },
                ],
                "response_format": {"type": "json_object"},
            }
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.post(url, headers=headers, json=payload)
                    # Some models reject response_format; retry without it
                    if resp.status_code == 400 and "response_format" in resp.text:
                        payload.pop("response_format", None)
                        resp = client.post(url, headers=headers, json=payload)
                    resp.raise_for_status()
                    data = resp.json()
                msg = data["choices"][0]["message"]
                content = msg.get("content")
                if content is None:
                    content = ""
                if isinstance(content, list):
                    # multimodal-style content parts
                    content = "".join(
                        p.get("text", "") if isinstance(p, dict) else str(p) for p in content
                    )
                content = str(content).strip()
                finish = data["choices"][0].get("finish_reason")
                if not content:
                    raise ValueError(
                        f"LLM returned empty content (attempt {attempt+1}/{retries}); "
                        f"finish_reason={finish}. "
                        "Usually max_tokens too small or prompt too large for this model."
                    )
                try:
                    return _extract_json(content)
                except Exception as parse_err:
                    # Truncated JSON (finish_reason=length): retry with stricter instruction
                    if finish == "length" and attempt + 1 < retries:
                        last_err = parse_err
                        user = (
                            user
                            + "\n\nIMPORTANT: previous reply was truncated. "
                            "Return fewer items and shorter strings. JSON only."
                        )
                        time.sleep(1.0)
                        continue
                    raise
            except Exception as e:
                last_err = e
                time.sleep(1.5 * (attempt + 1))
        raise RuntimeError(f"LLM JSON chat failed after {retries} attempts: {last_err}")


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    if not text:
        raise ValueError("empty LLM content, cannot parse JSON")
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
        if isinstance(obj, list):
            return {"mappings": obj} if obj and "technique_id" in str(obj[0]) else {"steps": obj}
        raise ValueError(f"JSON root must be object, got {type(obj)}")
    except json.JSONDecodeError:
        m = re.search(r"\{[\s\S]*\}", text)
        if not m:
            preview = text[:300].replace("\n", "\\n")
            raise ValueError(f"no JSON object in LLM output; preview={preview!r}") from None
        return json.loads(m.group(0))


def chunk_text(text: str, max_chars: int, overlap: int, max_chunks: int) -> list[tuple[str, str]]:
    """Return list of (chunk_id, chunk_text). Never one giant context."""
    text = text.strip()
    if not text:
        return []
    chunks: list[tuple[str, str]] = []
    start = 0
    idx = 0
    n = len(text)
    while start < n and idx < max_chunks:
        end = min(start + max_chars, n)
        if end < n:
            br = text.rfind("\n\n", start, end)
            if br > start + max_chars // 2:
                end = br
        piece = text[start:end].strip()
        if piece:
            chunks.append((f"chunk_{idx:03d}", piece))
            idx += 1
        if end >= n:
            break
        start = max(end - overlap, start + 1)
    return chunks
