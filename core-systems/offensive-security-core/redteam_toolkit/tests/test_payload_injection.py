import unittest
import ctypes
import threading
import time
import os
import platform
from redteam_toolkit.core.injectors import (
    ShellcodeInjector,
    RemoteThreadInjector,
    ReflectiveDllInjector
)
from redteam_toolkit.utils.memory import validate_memory_permissions, get_process_handle

class TestPayloadInjection(unittest.TestCase):

    def setUp(self):
        self.dummy_pid = os.getpid()
        self.shellcode = b"\x90" * 100 + b"\xC3"
        self.dll_path = os.path.abspath("tests/fixtures/test.dll")
        self.assertTrue(os.path.exists(self.dll_path), "DLL path not found")

    def test_shellcode_injection_success(self):
        injector = ShellcodeInjector(self.dummy_pid, self.shellcode)
        result = injector.inject()
        self.assertTrue(result, "Shellcode injection failed")

    def test_remote_thread_injection_behavior(self):
        injector = RemoteThreadInjector(self.dummy_pid, self.shellcode)
        result = injector.inject()
        self.assertTrue(result, "Remote thread injection failed")
        time.sleep(0.3)  # allow thread to run
        self.assertTrue(validate_memory_permissions(self.dummy_pid), "Memory protection mismatch")

    def test_reflective_dll_injection_simulation(self):
        injector = ReflectiveDllInjector(self.dummy_pid, self.dll_path)
        result = injector.inject()
        self.assertTrue(result, "Reflective DLL injection failed")

    def test_injection_on_invalid_pid(self):
        with self.assertRaises(Exception):
            ShellcodeInjector(999999, self.shellcode).inject()

    def test_cross_platform_skipped(self):
        if platform.system().lower() != "windows":
            self.skipTest("Injection only supported on Windows targets")

    def test_memory_write_integrity(self):
        handle = get_process_handle(self.dummy_pid)
        self.assertIsNotNone(handle, "Failed to get process handle for test")
        # Simulate write and verify buffer length
        buf = ctypes.create_string_buffer(self.shellcode)
        self.assertEqual(len(buf.raw), len(self.shellcode), "Buffer mismatch during write")

    def test_multiple_concurrent_injections(self):
        injectors = [
            ShellcodeInjector(self.dummy_pid, self.shellcode),
            RemoteThreadInjector(self.dummy_pid, self.shellcode)
        ]
        threads = [threading.Thread(target=i.inject) for i in injectors]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertTrue(all(t.is_alive() is False for t in threads), "Threads did not complete")

    def test_payload_format_validation(self):
        malformed_payload = b"this_is_not_shellcode"
        injector = ShellcodeInjector(self.dummy_pid, malformed_payload)
        with self.assertRaises(ValueError):
            injector.inject(strict=True)

if __name__ == "__main__":
    unittest.main()
