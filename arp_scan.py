from dataclasses import dataclass
import json
import re
import subprocess
import logging

import config


logger = logging.getLogger(config.APP_NAME)

ARP_SCAN = "arp-scan"

# arp-scan writes a banner, a blank line, then "<ip>\t<mac>\t<vendor>" rows, then a
# summary footer. Anchoring on the IP/MAC pair skips both without counting lines.
HOST_LINE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\t"
    r"(?P<mac>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})"
    r"(?:\t(?P<vendor>.*))?$"
)


class ArpScanError(RuntimeError):
    """arp-scan exited non-zero; the message carries its stderr."""


@dataclass(frozen=True)
class ArpHost:
    ip: str
    mac: str
    vendor: str


class ArpScan:
    def __init__(self, interface=None):
        self._interface = interface or config.SCANNING_INTERFACE

    @staticmethod
    def _parse(line: str) -> ArpHost | None:
        match = HOST_LINE.match(line)
        if not match:
            return None
        return ArpHost(
            ip=match["ip"],
            # device_mapping keys are uppercase; arp-scan reports lowercase.
            mac=match["mac"].upper(),
            vendor=(match["vendor"] or "").strip(),
        )

    def hosts(self, sudo: bool | None = None) -> list[ArpHost]:
        sudo = config.ARP_SCAN_SUDO if sudo is None else sudo
        args = [ARP_SCAN, "-I", self._interface, "--localnet"]
        if sudo:
            args.insert(0, "sudo")
        proc = subprocess.run(args, capture_output=True, text=True)
        if proc.returncode != 0:
            raise ArpScanError(proc.stderr.strip() or f"arp-scan exited {proc.returncode}")

        hosts = []
        seen = set()
        for line in proc.stdout.splitlines():
            host = ArpScan._parse(line)
            # A host answering twice (arp-scan flags these "DUP") would otherwise
            # land in the list once per reply.
            if host and host.mac not in seen:
                seen.add(host.mac)
                hosts.append(host)
        return hosts

    def mac_to_ip(self, sudo: bool | None = None) -> dict[str, str]:
        if config.BYPASS_ARP_SCAN:
            try:
                with open("arp_scan.json", 'r') as file:
                    return json.load(file)
            except FileNotFoundError:
                logger.critical("arp_scan.json not found. Exiting.")
                exit(1)
        return {host.mac: host.ip for host in self.hosts(sudo=sudo)}
