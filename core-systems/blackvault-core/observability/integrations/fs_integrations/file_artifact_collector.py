import os
import hashlib
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

from blackvault_core.observability.pipeline import TelemetryEmitter
from blackvault_core.security.detectors.signature_engine import SignatureEngine
from blackvault_core.utils.tracing import trace_event
from blackvault_core.utils.file_utils import is_suspicious_filetype, extract_metadata

LOG = logging.getLogger("FileArtifactCollector")

MONITORED_EXTENSIONS = {'.exe', '.dll', '.zip', '.rar', '.docx', '.vbs', '.js', '.ps1', '.bat', '.msi'}

DEFAULT_PATHS = [
    "C:\\Windows\\Temp",
    "C:\\Users\\Public\\Downloads",
    "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
]

class FileArtifactCollector:
    def __init__(self, emitter: TelemetryEmitter, engine: SignatureEngine, paths: Optional[List[str]] = None):
        self.emitter = emitter
        self.engine = engine
        self.paths = paths if paths else DEFAULT_PATHS
        LOG.info(f"Initialized FileArtifactCollector with paths: {self.paths}")

    def run(self):
        for raw_path in self.paths:
            path = os.path.expandvars(raw_path)
            if os.path.exists(path):
                self._scan_directory(Path(path))

    def _scan_directory(self, path: Path):
        for root, _, files in os.walk(path):
            for file in files:
                filepath = Path(root) / file
                if filepath.suffix.lower() in MONITORED_EXTENSIONS:
                    try:
                        self._analyze_file(filepath)
                    except Exception as e:
                        LOG.warning(f"Failed to process {filepath}: {e}")

    def _analyze_file(self, filepath: Path):
        file_stat = filepath.stat()
        file_hash = self._calculate_sha256(filepath)

        metadata = extract_metadata(filepath)
        is_suspicious = is_suspicious_filetype(filepath.suffix, metadata)

        detection_result = self.engine.match_signature("file_artifact", {
            "hash": file_hash,
            "metadata": metadata,
            "name": filepath.name,
            "size": file_stat.st_size
        })

        risk_score = self._compute_risk(is_suspicious, detection_result)
        classification = self._classify(risk_score)

        artifact_info = {
            "timestamp": datetime.utcnow().isoformat(),
            "path": str(filepath),
            "filename": filepath.name,
            "size_bytes": file_stat.st_size,
            "created_at": datetime.utcfromtimestamp(file_stat.st_ctime).isoformat(),
            "hash": file_hash,
            "suspicious": is_suspicious,
            "signature_hit": detection_result,
            "risk_score": risk_score,
            "classification": classification,
        }

        self.emitter.emit(artifact_info)
        trace_event("fs_artifact_collected", artifact_info)

    def _calculate_sha256(self, filepath: Path) -> str:
        hash_sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def _compute_risk(self, suspicious: bool, signature_hit: bool) -> int:
        score = 0
        if suspicious:
            score += 30
        if signature_hit:
            score += 50
        return score

    def _classify(self, score: int) -> str:
        if score >= 70:
            return "critical"
        elif score >= 40:
            return "suspicious"
        return "informational"
