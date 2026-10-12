from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Optional

import httpx
from dotenv import load_dotenv

from wap.utils.config import ROOT, load_yaml

# Ensure .env is loaded even if caller forgot
load_dotenv(ROOT / ".env")


def _resolve_chat_url(base_url: str) -> str:
    """Normalize OpenAI-compatible chat completions URL across providers."""
    url = (base_url or "").rstrip("/")
    if not url:
        return url
    if url.endswith("/chat/completions"):
        return url
    # DeepSeek: .../v1 ; Moonshot: .../v1 ; Zhipu: .../paas/v4
    if url.endswith("/v1") or url.endswith("/v4"):
        return url + "/chat/completions"
    return url + "/v1/chat/completions"


class LLMClient:
    def __init__(
        self,
        model_cfg: Optional[dict] = None,
        *,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        timeout_sec: Optional[float] = None,
        role: Optional[str] = None,
        base_url: Optional[str] = None,
        api_key_env: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        self.cfg = model_cfg or load_yaml("configs/model.yaml")
        self.base_url = (base_url or self.cfg.get("base_url") or "").rstrip("/")
        key_env = api_key_env or self.cfg.get("api_key_env", "LLM_API_KEY")
        self.api_key_env = key_env
        self.api_key = (api_key if api_key is not None else os.environ.get(key_env) or "").strip()
        self.model = model or self.cfg.get("model", "deepseek-chat")
        self.temperature = float(
            temperature if temperature is not None else self.cfg.get("temperature", 0.1)
        )
        self.max_tokens = int(
            max_tokens if max_tokens is not None else self.cfg.get("max_tokens", 4096)
        )
        self.timeout = float(
            timeout_sec
            if timeout_sec is not None
            else self.cfg.get("timeout_sec", 120)
        )
        self.role = role  # optional label: model_a / model_b / model_c
        # Extra request body fields (e.g. Moonshot thinking disable)
        self.extra_body: dict[str, Any] = {}

    @classmethod
    def for_ensemble_role(cls, model_cfg: Optional[dict], role: str) -> "LLMClient":
        """Build a client for ensemble role (model_a|model_b|model_c).

        Each role may override model / base_url / api_key_env (different providers).
        Falls back to top-level model/base_url/api_key_env when role fields are empty.
        """
        cfg = model_cfg or load_yaml("configs/model.yaml")
        ens = cfg.get("ensemble") or {}
        role_cfg = ens.get(role) or {}
        model = role_cfg.get("model") or cfg.get("model", "deepseek-chat")
        if isinstance(model, str) and (not model.strip() or "${" in model):
            model = cfg.get("model", "deepseek-chat")
        base_url = (role_cfg.get("base_url") or "").strip() or None
        if base_url and "${" in base_url:
            base_url = None
        api_key_env = (role_cfg.get("api_key_env") or "").strip() or None
        if api_key_env and "${" in api_key_env:
            api_key_env = None
        client = cls(
            cfg,
            model=str(model),
            temperature=role_cfg.get("temperature"),
            max_tokens=role_cfg.get("max_tokens"),
            timeout_sec=role_cfg.get("timeout_sec"),
            role=role,
            base_url=base_url,
            api_key_env=api_key_env,
        )
        # kimi-k2.6 defaults to thinking; empty content breaks JSON parse — disable for map.
        if role_cfg.get("disable_thinking") or str(model).lower().startswith("kimi-k2"):
            client.extra_body["thinking"] = {"type": "disabled"}
        return client

    @property
    def available(self) -> bool:
        return bool(self.api_key and self.base_url)

    def chat_json(self, system: str, user: str, retries: int = 3) -> dict[str, Any]:
        if not self.available:
            raise RuntimeError(
                f"LLM not configured: set {self.api_key_env} and base_url"
                + (f" (role={self.role})" if self.role else "")
            )
        url = _resolve_chat_url(self.base_url)
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
            if self.extra_body:
                payload.update(self.extra_body)
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.post(url, headers=headers, json=payload)
                    # kimi-k2.6: allowed temperature depends on thinking mode
                    # e.g. "only 1 is allowed" / "only 0.6 is allowed"
                    if resp.status_code == 400 and "temperature" in resp.text.lower():
                        m_temp = re.search(
                            r"only\s+([0-9]*\.?[0-9]+)\s+is allowed",
                            resp.text,
                            re.I,
                        )
                        if m_temp:
                            payload["temperature"] = float(m_temp.group(1))
                            resp = client.post(url, headers=headers, json=payload)
                    # Some models reject response_format; retry without it
                    if resp.status_code == 400 and "response_format" in resp.text:
                        payload.pop("response_format", None)
                        resp = client.post(url, headers=headers, json=payload)
                    # Rate limit: respect Retry-After / org RPM (Moonshot often RPM=3)
                    if resp.status_code == 429:
                        wait = 2.0 * (attempt + 1)
                        ra = resp.headers.get("retry-after")
                        if ra:
                            try:
                                wait = max(wait, float(ra))
                            except ValueError:
                                pass
                        last_err = httpx.HTTPStatusError(
                            f"429 Too Many Requests: {resp.text[:200]}",
                            request=resp.request,
                            response=resp,
                        )
                        time.sleep(wait)
                        continue
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
                # Thinking models may put final answer after reasoning; also try reasoning_content
                finish = data["choices"][0].get("finish_reason")
                if not content and isinstance(msg, dict):
                    content = str(msg.get("reasoning_content") or "").strip()
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
