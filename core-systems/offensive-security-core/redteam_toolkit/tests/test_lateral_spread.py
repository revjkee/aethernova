import unittest
import os
import platform
from unittest.mock import patch
from redteam_toolkit.core.lateral import (
    SmbLateralMover,
    WinRMLateralMover,
    PsExecLateralMover
)
from redteam_toolkit.utils.auth import check_admin_privileges
from redteam_toolkit.utils.network import simulate_network_map, is_host_alive

class TestLateralMovement(unittest.TestCase):

    def setUp(self):
        self.target_ip = "192.168.56.101"
        self.username = "testuser"
        self.password = "testpass"
        self.local_admin = check_admin_privileges()
        self.assertTrue(platform.system().lower() in ["windows", "linux", "darwin"])
        self.simulated_hosts = simulate_network_map(subnet="192.168.56.0/24", count=3)

    def test_host_availability(self):
        self.assertTrue(is_host_alive(self.target_ip), f"{self.target_ip} is unreachable")

    def test_smb_lateral_success(self):
        mover = SmbLateralMover(
            ip=self.target_ip,
            username=self.username,
            password=self.password
        )
        result = mover.execute(payload="whoami")
        self.assertTrue(result.success)
        self.assertIn("testuser", result.output)

    def test_winrm_lateral_execution(self):
        mover = WinRMLateralMover(
            ip=self.target_ip,
            username=self.username,
            password=self.password
        )
        result = mover.execute(payload="hostname")
        self.assertTrue(result.success)
        self.assertRegex(result.output.lower(), r"host")

    def test_psexec_fallback_chain(self):
        mover = PsExecLateralMover(
            ip=self.target_ip,
            username=self.username,
            password=self.password
        )
        try:
            result = mover.execute(payload="echo injected")
            self.assertTrue(result.success)
        except RuntimeError as e:
            self.assertIn("access denied", str(e).lower())

    def test_missing_privilege_raises(self):
        with patch("redteam_toolkit.utils.auth.check_admin_privileges", return_value=False):
            with self.assertRaises(PermissionError):
                SmbLateralMover(
                    ip=self.target_ip,
                    username=self.username,
                    password=self.password
                ).execute(payload="cmd.exe")

    def test_multiple_targets_spread(self):
        reachable = [host for host in self.simulated_hosts if is_host_alive(host)]
        self.assertGreaterEqual(len(reachable), 2)
        results = []
        for host in reachable:
            mover = SmbLateralMover(ip=host, username=self.username, password=self.password)
            try:
                results.append(mover.execute(payload="hostname"))
            except Exception:
                continue
        self.assertTrue(any(r.success for r in results), "No spread was successful")

    def test_payload_trace_logging(self):
        mover = WinRMLateralMover(ip=self.target_ip, username=self.username, password=self.password)
        result = mover.execute(payload="echo marker")
        self.assertTrue("marker" in result.output)
        self.assertTrue(os.path.exists("logs/lateral_movement_trace.log"))

if __name__ == "__main__":
    unittest.main()
