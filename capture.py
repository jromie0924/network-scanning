from dataclasses import asdict, dataclass
from datetime import datetime

import json
import logging
import re
import subprocess
import time

from threading import Thread, Lock
from typing import Iterator

from arp_scan import ArpScan
import config
from runtime import Runtime


logger = logging.getLogger(config.APP_NAME)

TSHARK = "/usr/bin/tshark"
GEOIP_DIR = "/home/jackson/GeoIP/"
# TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"
# GEOIP_DIR = "/Users/jacksonromie/GeoIP/GeoLite2-Country_20260901"

LOCAL_REG = r'(192).+|(172).+|(127).+|(10).+'

FIELDS = {
    "number": ("frame.number",),
    "time": ("frame.time_epoch",),
    "src": ("ip.src", "ipv6.src"),
    "dst": ("ip.dst", "ipv6.dst"),
    "src_country": ("ip.geoip.src_country", "ipv6.geoip.src_country"),
    "dst_country": ("ip.geoip.dst_country", "ipv6.geoip.dst_country"),
    "src_iso": ("ip.geoip.src_country_iso", "ipv6.geoip.src_country_iso"),
    "dst_iso": ("ip.geoip.dst_country_iso", "ipv6.geoip.dst_country_iso"),
    "src_mac": ("eth.src",),
    "dst_mac": ("eth.dst",),
}

COLUMNS = [field for fields in FIELDS.values() for field in fields]

GEO_ONLY = "ip.geoip.country or ipv6.geoip.country"

# TODO - probably could delete this.
PUBLIC_ONLY = (
    "not net 10.0.0.0/8 "
    "and not net 172.16.0.0/12 "
    "and not net 192.168.0.0/16 "
    "and not net 127.0.0.0/8 "
    "and not net fe80::/10 "  # IPv6 link-local
    "and not net fc00::/7"  # IPv6 unique-local
)

class TsharkError(RuntimeError):
    """tshark exited non-zero; the message carries its stderr."""

@dataclass(frozen=True)
class GeoPacket:
    number: int
    time: float
    src: str
    dst: str
    src_country: str
    dst_country: str
    src_iso: str
    dst_iso: str
    src_mac: str
    dst_mac: str

class Capture:
    def __init__(self, interface=None):
        self._interface = interface or config.SCANNING_INTERFACE
        self._runtime = Runtime()
        self._lock = Lock()
        self.run_arp_scan()
            
    def run_arp_scan(self):
        logger.info("Running ARP scan...")
        with self._lock:
            now = time.time()
            self._last_arp_scan = now
            local_device_list = ArpScan().mac_to_ip()
            self._runtime.local_device_list = local_device_list
            logger.debug(f"arp scan result: {self._runtime.local_device_list}")
    
    @staticmethod
    def _parse(line: str) -> GeoPacket:
        cols = line.split("\t")
        # Trailing empty fields can be dropped; pad so unpacking is safe.
        cols += [""] * (len(COLUMNS) - len(cols))
        it = iter(cols[: len(COLUMNS)])
        values = {}
        for attr, fields in FIELDS.items():
            # Consume every column this attribute owns before picking, or the v4/v6
            # pairs would desync the moment one of them is empty.
            chunk = [next(it) for _ in fields]
            values[attr] = next((v for v in chunk if v), "")
        number = values.pop("number")
        time = values.pop("time")
        return GeoPacket(
            number=int(number),
            time=float(time) if time else 0.0,
            **values,
        )
    
    @staticmethod
    def _geoip_opt() -> list[str]:
        return ["-o", f'uat:maxmind_db_paths:"{GEOIP_DIR}"', "-N", "g"]
    
    @staticmethod
    def _field_args() -> list[str]:
        args = []
        for field in COLUMNS:
            args += ["-e", field]
        return args + [
            "-T", "fields",
            "-E", "separator=/t",
            # A frame can carry more than one IP header (tunnels, ICMP quotes).
            # Without this, those rows grow extra values and the columns shift.
            "-E", "occurrence=f",
        ]
    
    @staticmethod
    def _stream(args: list[str]) -> Iterator[GeoPacket]:
        proc = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        # A live capture we stop ourselves exits non-zero by design. Tracking who
        # ended it separates that from tshark dying on its own (bad interface, no
        # capture permission, malformed filter), which must still raise.
        terminated = False
        try:
            # readline() rather than `for line in proc.stdout`, which keeps its own
            # read-ahead buffer and would hold packets back on a live capture.
            for line in iter(proc.stdout.readline, ""):
                line = line.rstrip("\n")
                if line:
                    yield Capture._parse(line)
        except (KeyboardInterrupt, GeneratorExit):
            terminated = True
            proc.terminate() # lets tshark flush and close cleanly
            raise
        finally:
            if proc.poll() is None:
                terminated = True
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
            proc.stdout.close()
            stderr = proc.stderr.read()
            proc.stderr.close()
            rc = proc.wait()
            if rc != 0 and not terminated:
                raise TsharkError(stderr.strip() or f"tshark exited {rc}")
    
    @staticmethod
    def iter_live(
        interface: str,
        display_filter: str = GEO_ONLY,
        capture_filter: str | None = None, # was PUBLIC_ONLY
        duration: int | None = None,
        packet_count: int | None = None,
    ) -> Iterator[GeoPacket]:
        args = [TSHARK, "-i", interface]
        if capture_filter:
            args += ["-f", capture_filter]
        if display_filter:
            args += ["-Y", display_filter]
        if duration:
            args += ["-a", f"duration:{duration}"]
        if packet_count:
            args += ["-c", str(packet_count)]
        args += ["-l"]  # flush stdout per packet, or output sits in a 4KB buffer
        yield from Capture._stream(args + Capture._geoip_opt() + Capture._field_args())
    
    def scan(self):
        country_blacklist = self._runtime.country_mapping
        device_mapping = self._runtime.system_mapping
        
        packets = Capture.iter_live(interface=self._interface)
        
        total = 0
        try:
            for pkt in packets:
                total += 1
                src_iso = pkt.src_iso
                dst_iso = pkt.src_iso
                
                now = time.time()
                if (now - self._last_arp_scan) / 60 >= 15:
                    self.run_arp_scan()
                
                if src_iso in country_blacklist.keys() or dst_iso in country_blacklist.keys():
                    logger.info(f"ALERT: Packet captured communicating to/from {pkt.src_country or pkt.dst_country}.")
                    timestamp = datetime.now().isoformat()
                    with self._lock:
                        local_device_list = self._runtime.local_device_list
                    if local_device_list.get(pkt.src_mac.upper()):
                        device_name = device_mapping.get(pkt.src_mac.upper())
                    else:
                        device_name = device_mapping.get(pkt.dst_mac.upper())
                    if device_name:
                        logger.info(f"Device identified: {device_name}.")
                    else:
                        logger.warning(f"Device unrecognized. Source MAC Address: {pkt.src_mac} || Destination MAC Address: {pkt.dst_mac}")
                    logger.debug(f"Full packet metadata:\n{pkt}")
                    try:
                        file = open(config.NAUGHTY_LIST, 'r')
                        naughty_list = json.load(file)
                    except Exception:
                        naughty_list = {}
                    if not device_name:
                        if re.match(LOCAL_REG, pkt.src):
                            device_name = pkt.src_mac
                        elif re.match(LOCAL_REG, pkt.dst):
                            device_name = pkt.dst_mac
                        else:
                            device_name = "UNKNOWN"
                    packet_json = asdict(pkt)
                    packet_json["timestamp"] = timestamp
                    if device_name in naughty_list.keys():
                        naughty_list[device_name].append(packet_json)
                    else:
                        naughty_list[device_name] = [packet_json]
                    
                    with open(config.NAUGHTY_LIST, 'w') as f:
                        json.dump(naughty_list, f)
                        
                        
                    
        except KeyboardInterrupt:
            logger.info(f"Scan stopped. Intercepted {total} packets.")
        

                
