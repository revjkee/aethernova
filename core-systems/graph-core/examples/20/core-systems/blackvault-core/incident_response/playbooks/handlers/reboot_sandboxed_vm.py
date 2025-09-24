import logging
import json
import subprocess
from datetime import datetime
from typing import Dict, Optional, Literal, Union
from pydantic import BaseModel, Field, validator
from enum import Enum

logger = logging.getLogger("blackvault.handlers.reboot_sandboxed_vm")

# --- VM PROVIDERS ---

class VMProvider(str, Enum):
    KVM = "kvm"
    LIBVIRT = "libvirt"
    PROXMOX = "proxmox"
    VMWARE = "vmware"
    CLOUD_API = "cloud_api"  # Stub, e.g. AWS, Azure, etc.

class RebootMode(str, Enum):
    SOFT = "soft"
    HARD = "hard"
    FORCE = "force"

# --- REQUEST MODEL ---

class RebootRequest(BaseModel):
    vm_id: str = Field(..., min_length=2)
    provider: VMProvider
    mode: RebootMode = RebootMode.SOFT
    operator: str = Field(..., min_length=3)
    reason: Optional[str] = None
    context: Optional[str] = None
    dry_run: bool = False
    snapshot_before: bool = True

    @validator("vm_id")
    def validate_vm_id(cls, v):
        if " " in v or len(v.strip()) < 2:
            raise ValueError("Invalid VM identifier")
        return v.strip()

# --- RESULT MODEL ---

class RebootResult(BaseModel):
    success: bool
    message: str
    timestamp: datetime
    vm_id: str
    provider: VMProvider
    operator: str
    dry_run: bool
    mode: RebootMode
    snapshot_before: bool
    command: Optional[str] = None
    details: Optional[Dict] = None

# --- PROVIDER LOGIC ---

class VMRebooter:
    def __init__(self, request: RebootRequest):
        self.req = request
        self.cmd: Optional[str] = None
        self.details: Dict = {}

    def _generate_cmd(self):
        if self.req.provider == VMProvider.KVM:
            self.cmd = f"virsh reboot {self.req.vm_id}"
            if self.req.mode == RebootMode.FORCE:
                self.cmd = f"virsh destroy {self.req.vm_id} && virsh start {self.req.vm_id}"
        elif self.req.provider == VMProvider.LIBVIRT:
            self.cmd = f"virsh reboot {self.req.vm_id}"
        elif self.req.provider == VMProvider.PROXMOX:
            if self.req.mode == RebootMode.HARD:
                self.cmd = f"qm stop {self.req.vm_id} && qm start {self.req.vm_id}"
            else:
                self.cmd = f"qm reboot {self.req.vm_id}"
        elif self.req.provider == VMProvider.VMWARE:
            self.cmd = f"vim-cmd vmsvc/reboot {self.req.vm_id}"
        elif self.req.provider == VMProvider.CLOUD_API:
            self.cmd = f"curl -X POST https://cloud.api/reboot -d '{{\"vm_id\": \"{self.req.vm_id}\"}}'"
        else:
            raise ValueError("Unsupported provider")

    def _snapshot_vm(self):
        try:
            if self.req.provider in [VMProvider.KVM, VMProvider.LIBVIRT]:
                snapshot_cmd = f"virsh snapshot-create-as {self.req.vm_id} snapshot_before_reboot --disk-only --atomic"
                subprocess.run(snapshot_cmd, check=True, shell=True)
                self.details["snapshot"] = "created"
            elif self.req.provider == VMProvider.PROXMOX:
                snapshot_cmd = f"qm snapshot {self.req.vm_id} snapshot_before_reboot"
                subprocess.run(snapshot_cmd, check=True, shell=True)
                self.details["snapshot"] = "created"
            else:
                self.details["snapshot"] = "not_supported"
        except Exception as ex:
            logger.warning(f"Snapshot creation failed: {ex}")
            self.details["snapshot"] = f"failed: {ex}"

    def execute(self) -> RebootResult:
        logger.info(f"Reboot request received: {self.req.dict()}")
        self._generate_cmd()

        if self.req.snapshot_before:
            self._snapshot_vm()

        if self.req.dry_run:
            return RebootResult(
                success=True,
                message="Dry-run executed. VM not rebooted.",
                timestamp=datetime.utcnow(),
                vm_id=self.req.vm_id,
                provider=self.req.provider,
                operator=self.req.operator,
                dry_run=True,
                mode=self.req.mode,
                snapshot_before=self.req.snapshot_before,
                command=self.cmd,
                details={"note": "dry-run simulation"}
            )

        try:
            result = subprocess.run(self.cmd, check=True, shell=True, capture_output=True, text=True)
            logger.info(f"Reboot executed: {self.cmd}")
            return RebootResult(
                success=True,
                message="VM rebooted successfully",
                timestamp=datetime.utcnow(),
                vm_id=self.req.vm_id,
                provider=self.req.provider,
                operator=self.req.operator,
                dry_run=False,
                mode=self.req.mode,
                snapshot_before=self.req.snapshot_before,
                command=self.cmd,
                details={
                    "stdout": result.stdout.strip(),
                    "stderr": result.stderr.strip()
                }
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"VM reboot failed: {e}")
            return RebootResult(
                success=False,
                message="VM reboot failed",
                timestamp=datetime.utcnow(),
                vm_id=self.req.vm_id,
                provider=self.req.provider,
                operator=self.req.operator,
                dry_run=False,
                mode=self.req.mode,
                snapshot_before=self.req.snapshot_before,
                command=self.cmd,
                details={
                    "error": str(e),
                    "stdout": e.stdout,
                    "stderr": e.stderr
                }
            )


# --- MAIN HANDLER FUNCTION ---

def reboot_sandboxed_vm(request_data: Dict[str, Union[str, bool, Dict]]) -> Dict:
    try:
        req = RebootRequest(**request_data)
        rebooter = VMRebooter(req)
        result = rebooter.execute()

        audit_log = {
            "event": "vm_reboot_triggered",
            "result": result.dict(),
            "context": req.context or "global",
            "logged_at": datetime.utcnow().isoformat()
        }
        logger.info(json.dumps(audit_log, indent=2))
        return result.dict()
    except Exception as ex:
        logger.exception(f"Unhandled VM reboot exception: {ex}")
        return {
            "success": False,
            "message": "Unhandled exception during VM reboot",
            "error": str(ex),
            "timestamp": datetime.utcnow().isoformat()
        }
