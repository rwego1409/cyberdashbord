import json
import os
import re
from typing import Any

import requests


class GeminiRiskAdvisor:
    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        timeout_seconds: int = 45,
    ) -> None:
        self.api_key = (api_key or os.getenv("GEMINI_API_KEY", "")).strip()
        self.model = (model or os.getenv("GEMINI_MODEL", "gemini-2.0-flash")).strip()
        self.timeout_seconds = timeout_seconds

    def enabled(self) -> bool:
        return bool(self.api_key)

    def analyze(self, risk_overview: dict[str, Any]) -> dict[str, Any]:
        if not self.enabled():
            return {
                "enabled": False,
                "model": self.model,
                "summary": "Gemini disabled (missing GEMINI_API_KEY).",
                "regional_adjustments": {},
                "regional_reasons": {},
            }

        prompt = self._build_prompt(risk_overview)
        try:
            raw_text = self._generate_text(prompt)
            payload = self._parse_json(raw_text)
            adjustments, reasons = self._extract_adjustments(payload)
            summary = str(payload.get("summary", "")).strip() or "Gemini analysis returned no summary."
            return {
                "enabled": True,
                "model": self.model,
                "summary": summary,
                "regional_adjustments": adjustments,
                "regional_reasons": reasons,
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "enabled": True,
                "model": self.model,
                "summary": f"Gemini analysis failed; baseline scoring used. Error: {exc}",
                "regional_adjustments": {},
                "regional_reasons": {},
            }

    def _build_prompt(self, risk_overview: dict[str, Any]) -> str:
        regional = risk_overview.get("regional_comparison", [])
        top_vectors = risk_overview.get("top_attack_vectors", [])
        national_risk_index = risk_overview.get("national_risk_index", 0)

        compact_input = {
            "national_risk_index": national_risk_index,
            "top_attack_vectors": top_vectors[:8],
            "regional_comparison": regional[:25],
        }

        return (
            "You are a cybersecurity risk analyst for a national SOC.\n"
            "Given the JSON input, produce strict JSON with this schema:\n"
            "{\n"
            '  "summary": "short actionable summary",\n'
            '  "regional_adjustments": [\n'
            '    {"region": "string", "delta": number, "reason": "short reason"}\n'
            "  ]\n"
            "}\n"
            "Rules:\n"
            "- delta must be between -20 and 20.\n"
            "- Include only regions present in regional_comparison.\n"
            "- Keep adjustments conservative.\n"
            "- Return JSON only.\n\n"
            f"INPUT_JSON:\n{json.dumps(compact_input, separators=(',', ':'))}"
        )

    def _generate_text(self, prompt: str) -> str:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        body = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 900},
        }

        response = requests.post(url, json=body, timeout=self.timeout_seconds)
        response.raise_for_status()
        payload = response.json()

        candidates = payload.get("candidates", [])
        if not candidates:
            raise ValueError("Gemini response did not include candidates")

        parts = candidates[0].get("content", {}).get("parts", [])
        text = "\n".join(str(part.get("text", "")) for part in parts if isinstance(part, dict))
        if not text.strip():
            raise ValueError("Gemini returned empty text")
        return text

    def _parse_json(self, text: str) -> dict[str, Any]:
        cleaned = text.strip()
        fence_match = re.search(r"```(?:json)?\s*(.*?)```", cleaned, flags=re.DOTALL | re.IGNORECASE)
        if fence_match:
            cleaned = fence_match.group(1).strip()

        return json.loads(cleaned)

    def _extract_adjustments(self, payload: dict[str, Any]) -> tuple[dict[str, float], dict[str, str]]:
        rows = payload.get("regional_adjustments", [])
        adjustments: dict[str, float] = {}
        reasons: dict[str, str] = {}

        if not isinstance(rows, list):
            return adjustments, reasons

        for row in rows:
            if not isinstance(row, dict):
                continue
            region = str(row.get("region", "")).strip()
            if not region:
                continue

            try:
                delta = float(row.get("delta", 0.0))
            except (TypeError, ValueError):
                delta = 0.0

            # Keep model output bounded to avoid unstable scoring shifts.
            bounded_delta = max(-20.0, min(20.0, delta))
            adjustments[region] = bounded_delta
            reasons[region] = str(row.get("reason", "")).strip()

        return adjustments, reasons
