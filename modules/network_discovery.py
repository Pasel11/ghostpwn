#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Network Discovery Module
اكتشاف الشبكة الداخلية - بدون nmap
"""
import sys
import os
import socket
import struct
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class NetworkDiscovery:
    """اكتشاف الشبكة الداخلية"""

    def __init__(self, timeout: float = 1.0, max_threads: int = 100):
        self.timeout = timeout
        self.max_threads = max_threads

    def log(self, msg, level="info"):
        icons = {"info": "[*]", "success": "[✓]", "warn": "[!]", "error": "[✗]"}
        print(f"    {icons.get(level, '[*]')} {msg}")

    # ============================ Host Discovery ============================
    def ping_host(self, host: str) -> bool:
        """فحص إذا كان host حي (TCP connect على port 80)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, 80))
            sock.close()
            return result == 0
        except Exception:
            return False

    def scan_host_alive(self, host: str) -> Optional[Dict]:
        """فحص إذا كان host alive عبر طرق متعددة"""
        # TCP connect على بورتات شائعة
        common_ports = [80, 443, 22, 21, 25, 3389, 445]
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    return {
                        "host": host,
                        "port": port,
                        "alive": True,
                    }
            except Exception:
                continue
        return None

    def scan_subnet(self, subnet: str = "192.168.1.0/24") -> List[Dict]:
        """فحص subnet كاملة لاكتشاف الـ hosts"""
        self.log(f"Scanning subnet: {subnet}")
        hosts = self._parse_subnet(subnet)

        if not hosts:
            self.log("Invalid subnet format", "error")
            return []

        self.log(f"Testing {len(hosts)} hosts...")

        alive_hosts = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.scan_host_alive, host): host for host in hosts}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    alive_hosts.append(result)
                    self.log(f"  [+] {result['host']} alive (port {result['port']})", "success")

        self.log(f"Found {len(alive_hosts)} alive hosts", "success")
        return alive_hosts

    def _parse_subnet(self, subnet: str) -> List[str]:
        """تحليل subnet CIDR لقائمة IPs"""
        if "/" not in subnet:
            return [subnet]

        try:
            base, cidr = subnet.split("/")
            cidr = int(cidr)

            # تحويل base IP لـ integer
            base_int = struct.unpack("!I", socket.inet_aton(base))[0]

            # حساب mask
            mask = (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF

            # network address
            network = base_int & mask

            # عدد الـ hosts
            num_hosts = 2 ** (32 - cidr) - 2  # -2 لـ network و broadcast

            hosts = []
            for i in range(1, num_hosts + 1):
                ip_int = network + i
                ip = socket.inet_ntoa(struct.pack("!I", ip_int))
                hosts.append(ip)

            return hosts[:254]  # حد أقصى 254 hosts
        except Exception:
            return []

    # ============================ Port Scan ============================
    def scan_target_ports(self, host: str, ports: List[int] = None) -> List[Dict]:
        """فحص بورتات host معين"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                    993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443]

        self.log(f"Scanning {len(ports)} ports on {host}...")

        open_ports = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._scan_port, host, port): port for port in ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    self.log(f"  [+] {host}:{result['port']} open ({result['service']})", "success")

        open_ports.sort(key=lambda x: x["port"])
        return open_ports

    def _scan_port(self, host: str, port: int) -> Optional[Dict]:
        """فحص بورت واحد"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))

            if result == 0:
                # البورت مفتوح - حاول نتعرف على الخدمة
                service = self._detect_service(sock, port)
                sock.close()
                return {
                    "host": host,
                    "port": port,
                    "state": "open",
                    "service": service,
                }
            sock.close()
            return None
        except Exception:
            return None

    def _detect_service(self, sock: socket.socket, port: int) -> str:
        """التعرف على الخدمة"""
        SERVICES = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
        }
        if port in SERVICES:
            return SERVICES[port]

        # محاولة قراءة banner
        try:
            sock.settimeout(1.0)
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            if banner:
                return f"Unknown ({banner[:50]})"
        except Exception:
            pass
        return "Unknown"

    # ============================ ARP Table ============================
    def get_local_network_info(self) -> Dict:
        """معلومات الشبكة المحلية"""
        self.log("Getting local network info...")

        info = {}

        # اسم الـ hostname
        try:
            hostname = socket.gethostname()
            info["hostname"] = hostname
            self.log(f"  Hostname: {hostname}")
        except Exception:
            pass

        # الـ IP المحلي
        try:
            # طريقة للحصول على IP المحلي
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            info["local_ip"] = local_ip
            self.log(f"  Local IP: {local_ip}")

            # استنتاج الـ subnet
            parts = local_ip.split(".")
            if len(parts) == 4:
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                info["subnet"] = subnet
                self.log(f"  Subnet: {subnet}")
        except Exception:
            pass

        return info

    # ============================ Service Detection ============================
    def detect_services(self, host: str, ports: List[Dict]) -> List[Dict]:
        """كشف تفاصيل الخدمات على البورتات المفتوحة"""
        self.log(f"Detecting services on {host}...")

        for port_info in ports:
            port = port_info["port"]
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                sock.connect((host, port))

                # HTTP detection
                if port in (80, 8080, 8000, 8888):
                    sock.send(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                    banner = sock.recv(4096).decode("utf-8", errors="ignore")
                    if "HTTP/" in banner:
                        port_info["service"] = "HTTP"
                        # استخراج Server header
                        server_match = re.search(r"Server:\s*(.+)", banner, re.IGNORECASE)
                        if server_match:
                            port_info["banner"] = server_match.group(1).strip()

                # SSH detection
                elif port == 22:
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                    if "SSH" in banner:
                        port_info["service"] = "SSH"
                        port_info["banner"] = banner

                # FTP detection
                elif port == 21:
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                    if "FTP" in banner or "220" in banner:
                        port_info["service"] = "FTP"
                        port_info["banner"] = banner

                # SMTP detection
                elif port == 25:
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                    if "SMTP" in banner or "220" in banner:
                        port_info["service"] = "SMTP"
                        port_info["banner"] = banner

                sock.close()
            except Exception:
                pass

        return ports

    # ============================ Full Network Scan ============================
    def full_scan(self, subnet: str = None) -> Dict:
        """فحص شبكة كامل"""
        if not subnet:
            local_info = self.get_local_network_info()
            subnet = local_info.get("subnet", "192.168.1.0/24")

        self.log(f"\nStarting full network scan on {subnet}")

        result = {
            "subnet": subnet,
            "local_info": self.get_local_network_info(),
            "alive_hosts": [],
            "host_details": {},
        }

        # 1) اكتشاف الـ hosts
        alive_hosts = self.scan_subnet(subnet)
        result["alive_hosts"] = alive_hosts

        # 2) فحص البورتات لكل host
        for host_info in alive_hosts:
            host = host_info["host"]
            self.log(f"\nScanning ports on {host}...")
            open_ports = self.scan_target_ports(host)
            if open_ports:
                # كشف تفاصيل الخدمات
                open_ports = self.detect_services(host, open_ports)
                result["host_details"][host] = open_ports

        return result


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Network Discovery")
    parser.add_argument("--subnet", default="192.168.1.0/24", help="Subnet to scan (CIDR)")
    parser.add_argument("--host", help="Single host to scan")
    parser.add_argument("--ports", help="Custom ports (comma-separated)")
    parser.add_argument("--local", action="store_true", help="Auto-detect local subnet")
    args = parser.parse_args()

    discovery = NetworkDiscovery()

    if args.local:
        result = discovery.full_scan()
    elif args.host:
        ports = [int(p) for p in args.ports.split(",")] if args.ports else None
        result = discovery.scan_target_ports(args.host, ports)
        result = discovery.detect_services(args.host, result)
        for p in result:
            print(f"  {p['port']}/tcp  {p['state']}  {p['service']}  {p.get('banner', '')}")
    else:
        result = discovery.full_scan(args.subnet)

    import json
    print(f"\n{json.dumps(result, indent=2)}")
