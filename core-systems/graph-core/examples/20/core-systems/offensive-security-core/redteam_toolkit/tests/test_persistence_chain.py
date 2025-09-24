import unittest
import os
import platform
import time
from redteam_toolkit.persistence.scheduled_task import ScheduledTaskPersist
from redteam_toolkit.persistence.registry_run import RegistryRunPersist
from redteam_toolkit.persistence.wmi_event import WmiEventPersist
from redteam_toolkit.persistence.dll_hijack import DllHijackPersist
from redteam_toolkit.utils.system import is_reboot_required, simulate_reboot

class TestPersistenceChain(unittest.TestCase):

    def setUp(self):
        self.payload = os.path.abspath("tests/fixtures/payload_stub.exe")
        self.assertTrue(os.path.exists(self.payload), "Payload binary missing")
        self.test_tag = "RedTeamPersistenceTest"
        self.is_windows = platform.system().lower() == "windows"
        if not self.is_windows:
            self.skipTest("Persistence techniques require Windows OS")

    def test_1_registry_run_key_persistence(self):
        persist = RegistryRunPersist(name=self.test_tag, path=self.payload)
        result = persist.deploy()
        self.assertTrue(result.success)
        self.assertIn("registry", result.details.lower())
        self.assertTrue(persist.validate())

    def test_2_scheduled_task_persistence(self):
        persist = ScheduledTaskPersist(name=self.test_tag, path=self.payload, interval="PT1M")
        result = persist.deploy()
        self.assertTrue(result.success)
        self.assertIn("task", result.details.lower())
        self.assertTrue(persist.validate())

    def test_3_wmi_event_subscription_persistence(self):
        persist = WmiEventPersist(name=self.test_tag, path=self.payload, trigger="Win32_LocalTime")
        result = persist.deploy()
        self.assertTrue(result.success)
        self.assertIn("wmi", result.details.lower())
        self.assertTrue(persist.validate())

    def test_4_dll_hijacking_simulation(self):
        hijacker = DllHijackPersist(target="explorer.exe", malicious_dll=self.payload)
        result = hijacker.deploy()
        self.assertTrue(result.success)
        self.assertIn(".dll", result.details.lower())

    def test_5_full_chain_validation_and_reboot(self):
        self.assertTrue(is_reboot_required(), "Persistence did not trigger reboot condition")
        simulate_reboot()
        post_reboot_validators = [
            RegistryRunPersist(name=self.test_tag, path=self.payload),
            ScheduledTaskPersist(name=self.test_tag, path=self.payload, interval="PT1M"),
            WmiEventPersist(name=self.test_tag, path=self.payload, trigger="Win32_LocalTime")
        ]
        for validator in post_reboot_validators:
            self.assertTrue(validator.validate(), f"{validator.__class__.__name__} validation failed")

    def test_6_cleanup_chain(self):
        RegistryRunPersist(name=self.test_tag, path=self.payload).remove()
        ScheduledTaskPersist(name=self.test_tag, path=self.payload).remove()
        WmiEventPersist(name=self.test_tag, path=self.payload).remove()
        # DLL Hijack cleanup assumed to be manual (test environment)
        self.assertFalse(RegistryRunPersist(name=self.test_tag, path=self.payload).validate())
        self.assertFalse(ScheduledTaskPersist(name=self.test_tag, path=self.payload).validate())

if __name__ == "__main__":
    unittest.main()
