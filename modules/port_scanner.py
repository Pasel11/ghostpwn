#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Port Scanner (Zero-Dependency)
يستخدم فقط socket - بدون nmap
"""
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional


class PortScanner:
    """Port scanner يعتمد فقط على socket"""

    # البورتات الشائعة + خدماتها
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
        135: "MS-RPC", 139: "NetBIOS", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9000: "PHP-FPM",
        27017: "MongoDB", 11211: "Memcached",
    }

    def __init__(self, timeout: float = 2.0, max_threads: int = 100):
        self.timeout = timeout
        self.max_threads = max_threads

    def scan_port(self, host: str, port: int) -> Optional[Dict]:
        """فحص بورت واحد"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                # البورت مفتوح - نحاول نتعرف على الخدمة
                service = self._detect_service(sock, port)
                sock.close()
                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                }
            else:
                sock.close()
                return None
        except socket.gaierror:
            return None
        except socket.timeout:
            return None
        except Exception:
            return None

    def _detect_service(self, sock: socket.socket, port: int) -> str:
        """محاولة التعرف على الخدمة"""
        # البورتات المعروفة
        if port in self.COMMON_PORTS:
            return self.COMMON_PORTS[port]

        # محاولة قراءة banner
        try:
            sock.settimeout(1.0)
            # إرسال HTTP request للبورتات الـ web
            if port in (80, 8080, 8000, 8888, 9000):
                sock.send(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            if banner:
                # أخذ أول سطر فقط
                first_line = banner.split("\n")[0].strip()
                return f"Unknown ({first_line[:50]})"
        except Exception:
            pass
        return "Unknown"

    def scan(self, host: str, ports: str = "1-1000", max_threads: Optional[int] = None) -> List[Dict]:
        """فحص مجموعة بورتات"""
        # تحليل ports string (مثل "1-1000" أو "80,443,8080" أو "top100")
        port_list = self._parse_ports(ports)
        if not port_list:
            return []

        threads = max_threads or self.max_threads
        open_ports = []

        print(f"  [*] Scanning {len(port_list)} ports on {host}...")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self.scan_port, host, port): port for port in port_list}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    print(f"  [+] Port {result['port']:5d}/tcp  open  {result['service']}")

        # ترتيب النتائج
        open_ports.sort(key=lambda x: x["port"])
        return open_ports

    def _parse_ports(self, ports: str) -> List[int]:
        """تحليل string البورتات لأنواع مختلفة"""
        port_list = []

        if ports == "top100":
            # أهم 100 بورت
            port_list = sorted(self.COMMON_PORTS.keys())[:30] + list(range(1, 100))
            port_list = sorted(set(port_list))
        elif ports == "top1000":
            port_list = list(range(1, 1001))
        elif ports == "full":
            port_list = list(range(1, 65536))
        elif "-" in ports:
            # range مثل "1-1000"
            try:
                start, end = ports.split("-")
                port_list = list(range(int(start), int(end) + 1))
            except ValueError:
                pass
        elif "," in ports:
            # list مثل "80,443,8080"
            for p in ports.split(","):
                try:
                    port_list.append(int(p.strip()))
                except ValueError:
                    continue
        else:
            try:
                port_list = [int(ports)]
            except ValueError:
                pass

        return port_list

    def quick_scan(self, host: str) -> List[Dict]:
        """فحص سريع للبورتات الشائعة"""
        ports = ",".join(str(p) for p in sorted(self.COMMON_PORTS.keys()))
        return self.scan(host, ports)


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    scanner = PortScanner(timeout=2.0)
    results = scanner.quick_scan(target)
    print(f"\n[✓] Found {len(results)} open ports")
