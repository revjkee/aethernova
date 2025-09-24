# forgemind-core/payload_lab/av_evasion_test.py

import os
import json
import base64
import hashlib
import tempfile
import subprocess
import logging
from typing import Dict, List, Optional

logger = logging.getLogger("av_evasion_test")
logger.setLevel(logging.DEBUG)

class AVTestResult:
    def __init__(self, engine: str, detected: bool, verdict: Optional[str], error: Optional[str]):
        self.engine = engine
        self.detected = detected
        self.verdict = verdict
        self.error = error

    def to_dict(self) -> Dict:
        return {
            "engine": self.engine,
            "detected": self.detected,
            "verdict": self.verdict,
            "error": self.error
        }

class AVEvasionTester:
    def __init__(self, engines: Optional[List[str]] = None):
        self.engines = engines or ["clamscan", "windows-defender", "vt-api"]
        self.temp_dir = tempfile.mkdtemp(prefix="avtest_")

    def _save_payload(self, payload: bytes, filename: str = "payload.bin") -> str:
        path = os.path.join(self.temp_dir, filename)
        with open(path, "wb") as f:
            f.write(payload)
        return path

    def _hash_file(self, filepath: str) -> str:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def _run_clamscan(self, filepath: str) -> AVTestResult:
        try:
            result = subprocess.run(["clamscan", filepath], capture_output=True, text=True)
            output = result.stdout
            detected = "FOUND" in output
            return AVTestResult("clamscan", detected, output.strip(), None)
        except Exception as e:
            return AVTestResult("clamscan", False, None, str(e))

    def _run_windows_defender(self, filepath: str) -> AVTestResult:
        try:
            cmd = ["powershell.exe", "-Command", f"Start-MpScan -ScanPath '{filepath}' -ScanType CustomScan"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            output = result.stdout + result.stderr
            detected = "Threat" in output or "Malware" in output
            return AVTestResult("windows-defender", detected, output.strip(), None)
        except Exception as e:
            return AVTestResult("windows-defender", False, None, str(e))

    def _run_vt_api(self, file_hash: str) -> AVTestResult:
        # Только отправка хэша (поддержка VT API v3)
        try:
            import requests
            api_key = os.getenv("VT_API_KEY", "")
            headers = {"x-apikey": api_key}
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                malicious = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
                verdict = json.dumps(data.get("data", {}).get("attributes", {}).get("last_analysis_results", {}))
                return AVTestResult("vt-api", malicious > 0, verdict, None)
            else:
                return AVTestResult("vt-api", False, None, f"HTTP {response.status_code}")
        except Exception as e:
            return AVTestResult("vt-api", False, None, str(e))

    def test_payload(self, payload: bytes) -> List[AVTestResult]:
        filepath = self._save_payload(payload)
        file_hash = self._hash_file(filepath)
        results = []

        if "clamscan" in self.engines:
            results.append(self._run_clamscan(filepath))
        if "windows-defender" in self.engines and os.name == "nt":
            results.append(self._run_windows_defender(filepath))
        if "vt-api" in self.engines:
            results.append(self._run_vt_api(file_hash))

        return results

    def summarize_results(self, results: List[AVTestResult]) -> Dict[str, Dict]:
        summary = {}
        for result in results:
            summary[result.engine] = result.to_dict()
        return summary

    def cleanup(self):
        try:
            for file in os.listdir(self.temp_dir):
                os.remove(os.path.join(self.temp_dir, file))
            os.rmdir(self.temp_dir)
        except Exception as e:
            logger.warning(f"[AV-EVASION] Cleanup error: {str(e)}")
