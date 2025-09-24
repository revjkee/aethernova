import subprocess
import logging
from typing import Literal, Union, Dict, Optional, List
from datetime import datetime
from pydantic import BaseModel, Field, IPvAnyAddress, validator
import json

logger = logging.getLogger("blackvault.handlers.block_ip")

# --- SUPPORTED FIREWALLS / ENGINES ---

class BlockEngine(str):
    IPTABLES = "iptables"
    NFTABLES = "nftables"
    SDN_OVS = "sdn_ovs"
    EBPF = "ebpf"

class BlockMode(str):
    DROP = "drop"
    REJECT = "reject"

# --- INPUT MODEL ---

class BlockIPRequest(BaseModel):
    ip: IPvAnyAddress
    engine: BlockEngine
    mode: BlockMode = BlockMode.DROP
    dry_run: bool = False
    operator: str = Field(..., min_length=2)
    reason: Optional[str] = Field(default=None, max_length=255)
    interface: Optional[str] = None  # used for SDN
    context: Optional[str] = None

    @validator("engine")
    def validate_engine(cls, v):
        if v not in BlockEngine.__members__.values():
            raise ValueError(f"Unsupported engine: {v}")
        return v

# --- OUTPUT MODEL ---

class BlockIPResult(BaseModel):
    success: bool
    message: str
    timestamp: datetime
    engine: BlockEngine
    ip: str
    operator: str
    dry_run: bool
    cmd: List[str]
    details: Optional[Dict] = None


# --- FIREWALL EXECUTOR ---

class IPBlocker:
    def __init__(self, request: BlockIPRequest):
        self.req = request
        self.cmd: List[str] = []
        self._build_command()

    def _build_command(self):
        ip = str(self.req.ip)

        if self.req.engine == BlockEngine.IPTABLES:
            action = "DROP" if self.req.mode == BlockMode.DROP else "REJECT"
            self.cmd = [
                "iptables", "-A", "INPUT", "-s", ip, "-j", action
            ]
        elif self.req.engine == BlockEngine.NFTABLES:
            self.cmd = [
                "nft", "add", "rule", "ip", "filter", "input", "ip", "saddr", ip, self.req.mode
            ]
        elif self.req.engine == BlockEngine.SDN_OVS:
            if not self.req.interface:
                raise ValueError("Interface required for SDN blocking")
            self.cmd = [
                "ovs-ofctl", "add-flow", self.req.interface,
                f"priority=1000,ip,nw_src={ip},actions=drop"
            ]
        elif self.req.engine == BlockEngine.EBPF:
            self.cmd = [
                "bpftool", "map", "update", "pinned", "/sys/fs/bpf/ip_blocklist",
                "key", ip, "value", "1"
            ]

    def execute(self) -> BlockIPResult:
        logger.info(f"Executing IP block: {self.req.dict()}")
        if self.req.dry_run:
            return BlockIPResult(
                success=True,
                message="Dry-run: no rule applied",
                timestamp=datetime.utcnow(),
                engine=self.req.engine,
                ip=str(self.req.ip),
                operator=self.req.operator,
                dry_run=True,
                cmd=self.cmd,
                details={"note": "dry-run simulated"}
            )
        try:
            result = subprocess.run(self.cmd, check=True, capture_output=True, text=True)
            logger.info(f"Firewall rule applied: {' '.join(self.cmd)}")
            return BlockIPResult(
                success=True,
                message="IP successfully blocked",
                timestamp=datetime.utcnow(),
                engine=self.req.engine,
                ip=str(self.req.ip),
                operator=self.req.operator,
                dry_run=False,
                cmd=self.cmd,
                details={
                    "stdout": result.stdout.strip(),
                    "stderr": result.stderr.strip()
                }
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block IP {self.req.ip}: {e}")
            return BlockIPResult(
                success=False,
                message="Failed to block IP",
                timestamp=datetime.utcnow(),
                engine=self.req.engine,
                ip=str(self.req.ip),
                operator=self.req.operator,
                dry_run=False,
                cmd=self.cmd,
                details={
                    "stdout": e.stdout,
                    "stderr": e.stderr,
                    "returncode": e.returncode
                }
            )


# --- MAIN INTERFACE FUNCTION ---

def block_ip(request_data: Dict[str, Union[str, bool]]) -> Dict:
    try:
        req = BlockIPRequest(**request_data)
        blocker = IPBlocker(req)
        result = blocker.execute()
        log_entry = {
            "event": "ip_block",
            "result": result.dict(),
            "logged_at": datetime.utcnow().isoformat(),
            "context": req.context or "global"
        }
        logger.info(json.dumps(log_entry, indent=2))
        return result.dict()
    except Exception as ex:
        logger.exception(f"Unhandled error during IP block: {ex}")
        return {
            "success": False,
            "message": "Unhandled exception",
            "error": str(ex),
            "timestamp": datetime.utcnow().isoformat()
        }
