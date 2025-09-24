import subprocess
import logging
import json
from typing import Optional, Dict, Literal, Union
from pydantic import BaseModel, Field, validator
from enum import Enum
from datetime import datetime

logger = logging.getLogger("blackvault.handlers.isolate_container")

# --- CONFIGURATION ---

class ContainerRuntime(str, Enum):
    docker = "docker"
    kubernetes = "kubernetes"

class IsolationMode(str, Enum):
    pause = "pause"
    stop = "stop"
    network_block = "network_block"

class IsolationRequest(BaseModel):
    container_id: str = Field(..., min_length=4)
    runtime: ContainerRuntime
    mode: IsolationMode = IsolationMode.network_block
    namespace: Optional[str] = None
    dry_run: bool = False
    operator: str = Field(..., min_length=3)
    reason: Optional[str] = Field(None, max_length=256)

    @validator("container_id")
    def validate_id(cls, v):
        if not v.isalnum() and ":" not in v and "_" not in v:
            raise ValueError("Invalid container ID format")
        return v


class IsolationResult(BaseModel):
    success: bool
    message: str
    timestamp: datetime
    runtime: ContainerRuntime
    container_id: str
    operator: str
    dry_run: bool
    details: Optional[Dict] = None


# --- INTERNAL EXECUTION WRAPPER ---

class ContainerIsolator:
    def __init__(self, request: IsolationRequest):
        self.req = request
        self.cmd = []
        self._generate_cmd()

    def _generate_cmd(self):
        if self.req.runtime == ContainerRuntime.docker:
            if self.req.mode == IsolationMode.pause:
                self.cmd = ["docker", "pause", self.req.container_id]
            elif self.req.mode == IsolationMode.stop:
                self.cmd = ["docker", "stop", self.req.container_id]
            elif self.req.mode == IsolationMode.network_block:
                self.cmd = [
                    "docker", "network", "disconnect", "bridge", self.req.container_id
                ]
        elif self.req.runtime == ContainerRuntime.kubernetes:
            if not self.req.namespace:
                raise ValueError("Namespace is required for Kubernetes isolation")
            if self.req.mode == IsolationMode.pause:
                # Kubernetes doesn't support pause; simulate with 'scale'
                self.cmd = [
                    "kubectl", "scale", "deployment", self.req.container_id,
                    "--replicas=0", "-n", self.req.namespace
                ]
            elif self.req.mode == IsolationMode.stop:
                self.cmd = [
                    "kubectl", "delete", "pod", self.req.container_id,
                    "-n", self.req.namespace
                ]
            elif self.req.mode == IsolationMode.network_block:
                self.cmd = [
                    "kubectl", "annotate", "pod", self.req.container_id,
                    "k8s.v1.cni.cncf.io/networks-attachment=",
                    "-n", self.req.namespace, "--overwrite"
                ]

    def execute(self) -> IsolationResult:
        logger.info(f"Isolation request received: {self.req.json()}")
        if self.req.dry_run:
            return IsolationResult(
                success=True,
                message="Dry-run: no changes applied",
                timestamp=datetime.utcnow(),
                runtime=self.req.runtime,
                container_id=self.req.container_id,
                operator=self.req.operator,
                dry_run=True,
                details={"cmd": self.cmd}
            )

        try:
            result = subprocess.run(self.cmd, check=True, capture_output=True, text=True)
            logger.info(f"Isolation executed: {self.cmd}")
            return IsolationResult(
                success=True,
                message="Container isolated successfully",
                timestamp=datetime.utcnow(),
                runtime=self.req.runtime,
                container_id=self.req.container_id,
                operator=self.req.operator,
                dry_run=False,
                details={
                    "stdout": result.stdout.strip(),
                    "stderr": result.stderr.strip(),
                    "cmd": self.cmd
                }
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"Isolation failed: {e}")
            return IsolationResult(
                success=False,
                message="Isolation command failed",
                timestamp=datetime.utcnow(),
                runtime=self.req.runtime,
                container_id=self.req.container_id,
                operator=self.req.operator,
                dry_run=False,
                details={
                    "error": str(e),
                    "stdout": e.stdout,
                    "stderr": e.stderr,
                    "cmd": self.cmd
                }
            )


# --- MAIN HANDLER FUNCTION ---

def isolate_container(request_data: Dict[str, Union[str, bool]]) -> Dict:
    try:
        req = IsolationRequest(**request_data)
        isolator = ContainerIsolator(req)
        result = isolator.execute()
        log_entry = {
            "event": "container_isolation",
            "result": result.dict(),
            "logged_at": datetime.utcnow().isoformat()
        }
        logger.info(json.dumps(log_entry, indent=2))
        return result.dict()
    except Exception as ex:
        logger.exception(f"Unhandled exception during isolation: {ex}")
        return {
            "success": False,
            "message": "Unhandled error",
            "error": str(ex),
            "timestamp": datetime.utcnow().isoformat()
        }
