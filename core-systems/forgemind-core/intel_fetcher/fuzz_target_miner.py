import re
import json
import logging
import hashlib
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin

import aiohttp
from bs4 import BeautifulSoup

from intel_fetcher.utils.retry import resilient_fetch
from intel_fetcher.utils.normalizer import extract_cpe, extract_cve_ids
from intel_fetcher.models.fuzz_target import FuzzTarget

logger = logging.getLogger("FuzzTargetMiner")
logging.basicConfig(level=logging.INFO)

NVD_API = "https://services.nvd.nist.gov/rest/json/cve/1.0/"

FUZZ_CANDIDATE_KEYWORDS = [
    "parse", "decode", "decompress", "read", "handle", "open", "image", "stream", "convert",
    "packet", "protocol", "deserialization", "file format", "memory corruption", "heap buffer",
    "off-by-one", "overflow", "format string", "type confusion"
]


class FuzzTargetMiner:
    def __init__(self, nvd_api_key: Optional[str] = None):
        self.api_key = nvd_api_key
        self.checked_cves = set()

    async def mine_fuzz_targets(self, cve_ids: List[str]) -> List[FuzzTarget]:
        targets: List[FuzzTarget] = []
        async with aiohttp.ClientSession() as session:
            for cve_id in cve_ids:
                if cve_id in self.checked_cves:
                    continue
                self.checked_cves.add(cve_id)
                try:
                    data = await self._fetch_cve_metadata(session, cve_id)
                    if not data:
                        continue
                    target = self._extract_fuzz_target(cve_id, data)
                    if target:
                        targets.append(target)
                except Exception as e:
                    logger.warning(f"Failed to analyze CVE {cve_id}: {e}")
                    continue
        return targets

    async def _fetch_cve_metadata(self, session: aiohttp.ClientSession, cve_id: str) -> Optional[Dict]:
        url = f"{NVD_API}{cve_id}"
        headers = {"apiKey": self.api_key} if self.api_key else {}
        logger.debug(f"Fetching CVE metadata from {url}")
        json_data = await resilient_fetch(session, url, headers=headers, is_json=True)
        return json_data.get("result", {}).get("CVE_Items", [])[0] if json_data else None

    def _extract_fuzz_target(self, cve_id: str, cve_data: Dict) -> Optional[FuzzTarget]:
        desc = cve_data.get("cve", {}).get("description", {}).get("description_data", [{}])[0].get("value", "")
        configs = cve_data.get("configurations", {}).get("nodes", [])
        impact = cve_data.get("impact", {})

        if not any(keyword in desc.lower() for keyword in FUZZ_CANDIDATE_KEYWORDS):
            return None

        cpes = extract_cpe(configs)
        score = self._calculate_priority_score(desc, impact)

        return FuzzTarget(
            cve_id=cve_id,
            description=desc,
            cpes=cpes,
            fuzz_vector=self._infer_vector(desc),
            priority_score=score,
            sha256=hashlib.sha256(desc.encode()).hexdigest()
        )

    def _infer_vector(self, description: str) -> List[str]:
        desc_lower = description.lower()
        vector = []
        if "image" in desc_lower:
            vector.append("image parser")
        if "packet" in desc_lower or "network" in desc_lower:
            vector.append("network decoder")
        if "xml" in desc_lower:
            vector.append("xml deserialization")
        if "pdf" in desc_lower:
            vector.append("pdf reader")
        if "decompress" in desc_lower or "compression" in desc_lower:
            vector.append("archive unpacker")
        if "font" in desc_lower:
            vector.append("font renderer")
        if not vector:
            vector.append("generic parser")
        return vector

    def _calculate_priority_score(self, desc: str, impact: Dict) -> float:
        base_score = impact.get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore", 5.0)
        keyword_hits = sum(1 for k in FUZZ_CANDIDATE_KEYWORDS if k in desc.lower())
        return min(10.0, base_score + keyword_hits * 0.5)

