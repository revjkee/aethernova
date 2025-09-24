import json
import re
import logging
from typing import Dict, List, Optional, Tuple, Union

from intel_fetcher.utils.cpe_normalizer import normalize_cpe
from intel_fetcher.utils.nlp_extractors import extract_vuln_points, extract_keywords, detect_exploit_phrases
from intel_fetcher.models.vuln_context import VulnContext

logger = logging.getLogger("CVEContextParser")
logging.basicConfig(level=logging.INFO)

class CVEContextParser:
    def __init__(self):
        self.contextual_keywords = [
            "buffer overflow", "use-after-free", "race condition", "privilege escalation",
            "remote code execution", "heap corruption", "directory traversal", "unauthenticated access"
        ]

    def parse_cve_record(self, record: Dict) -> Optional[VulnContext]:
        try:
            cve_id = record.get("cve", {}).get("CVE_data_meta", {}).get("ID")
            description = record.get("cve", {}).get("description", {}).get("description_data", [{}])[0].get("value", "")
            references = [ref.get("url") for ref in record.get("cve", {}).get("references", {}).get("reference_data", [])]
            configs = record.get("configurations", {}).get("nodes", [])
            impact = record.get("impact", {})
            published = record.get("publishedDate", "")
            modified = record.get("lastModifiedDate", "")

            if not cve_id or not description:
                logger.warning(f"Skipping incomplete record")
                return None

            vuln_points = extract_vuln_points(description)
            keywords = extract_keywords(description, self.contextual_keywords)
            exploit_likelihood = detect_exploit_phrases(description)

            cvss_score, vector = self._parse_cvss(impact)
            affected_products = self._extract_cpes(configs)

            return VulnContext(
                cve_id=cve_id,
                description=description,
                keywords=keywords,
                vuln_points=vuln_points,
                exploit_likelihood=exploit_likelihood,
                cvss_score=cvss_score,
                cvss_vector=vector,
                affected_products=affected_products,
                references=references,
                published=published,
                modified=modified
            )

        except Exception as ex:
            logger.exception(f"Failed to parse CVE record: {ex}")
            return None

    def _parse_cvss(self, impact: Dict) -> Tuple[float, str]:
        try:
            base = impact.get("baseMetricV3", {})
            score = base.get("cvssV3", {}).get("baseScore", 0.0)
            vector = base.get("cvssV3", {}).get("vectorString", "")
            return score, vector
        except Exception:
            return 0.0, ""

    def _extract_cpes(self, nodes: List[Dict]) -> List[str]:
        cpes = []
        for node in nodes:
            for cpe_entry in node.get("cpe_match", []):
                cpe_uri = cpe_entry.get("cpe23Uri")
                if cpe_uri:
                    cpes.append(normalize_cpe(cpe_uri))
        return cpes

