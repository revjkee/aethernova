import logging
import time
import threading
import hashlib
from scapy.all import sniff, ARP, DNS, TCP, IP, Raw
from blackvault_core.security.alerts import raise_alert
from blackvault_core.observability.pipeline import TelemetryEmitter
from blackvault_core.utils.crypto import hash_ip, secure_log
from blackvault_core.utils.tracing import trace_event

LOG = logging.getLogger("MITMActivityLogger")

class MITMActivityLogger:
    def __init__(self, iface="eth0", telemetry_emitter: TelemetryEmitter = None):
        self.iface = iface
        self.emitter = telemetry_emitter or TelemetryEmitter()
        self.arp_table = {}
        self.running = False

    def start(self):
        self.running = True
        threading.Thread(target=self._start_sniffing, daemon=True).start()
        LOG.info("MITMActivityLogger started on interface: %s", self.iface)

    def stop(self):
        self.running = False
        LOG.info("MITMActivityLogger stopped.")

    def _start_sniffing(self):
        sniff(prn=self._process_packet, iface=self.iface, store=False, stop_filter=lambda _: not self.running)

    def _process_packet(self, packet):
        if packet.haslayer(ARP):
            self._detect_arp_spoof(packet)
        elif packet.haslayer(DNS):
            self._detect_dns_spoof(packet)
        elif packet.haslayer(TCP) and packet.haslayer(Raw):
            self._detect_ssl_strip(packet)

    def _detect_arp_spoof(self, packet):
        ip = packet.psrc
        mac = packet.hwsrc
        if ip in self.arp_table:
            if self.arp_table[ip] != mac:
                self._log_event("arp_spoof", ip, self.arp_table[ip], mac)
        else:
            self.arp_table[ip] = mac

    def _detect_dns_spoof(self, packet):
        qname = packet[DNS].qd.qname.decode(errors="ignore")
        spoof_indicators = ["malware", "sinkhole", "phish"]
        if any(ind in qname for ind in spoof_indicators):
            self._log_event("dns_spoof", qname)

    def _detect_ssl_strip(self, packet):
        payload = packet[Raw].load
        if b"HTTP/" in payload and b"Location: http://" in payload:
            host = packet[IP].dst
            self._log_event("ssl_strip_detected", host)

    def _log_event(self, event_type, *details):
        timestamp = time.time()
        event_hash = hash_
