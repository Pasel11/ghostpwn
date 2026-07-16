#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Full Automatic Mode
الوضع الأوتوماتيكي الكامل - من الاستطلاع لما بعد الاختراق

كل ما يحتاجه اليوزر: URL
والأداة تعمل كل شيء:
1. استطلاع
2. بحث
3. تخفي
4. هجمات
5. استغلال
6. ما بعد الاستغلال
"""
import os
import sys
import time
import json
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display
from modules.live_reporter import LiveReporter
from modules.proxy_manager import ProxyManager
from modules.masquerade import MasqueradeEngine
from modules.smart_waf import SmartWAFDetector
from modules.ai_reasoner import AIReasoner
from modules.component_analyzer import ComponentAnalyzer
from modules.adaptive_scanner import AdaptiveScanner
from modules.zero_day_detector import ZeroDayDetector
from modules.vuln_notifier import SmartNotifier
from modules.exploit_chain import ExploitChainEngine
from modules.attack_planner import AttackPlanner, AttackGoal
from modules.target_takeover import TargetTakeoverEngine
from modules.post_exploit_menu import PostExploitMenu
from modules.report_generator import generate_full_report


class FullAutoScanner:
    """الماسح الأوتوماتيكي الكامل"""

    def __init__(self, url: str, options: Dict = None):
        self.url = url
        self.options = options or {}

        # إعداد HTTP client
        self.client = HttpClient(
            timeout=self.options.get("timeout", 15),
            user_agent=self.options.get("user_agent", "ghostpwn/1.0"),
            proxy=self.options.get("proxy"),
            cookie=self.options.get("cookie"),
            delay=self.options.get("delay", 0),
        )

        # الـ modules
        self.reporter = LiveReporter()
        self.proxy_manager = ProxyManager()
        self.masquerade = MasqueradeEngine(self.client)
        self.waf_detector = SmartWAFDetector(self.client)
        self.notifier = SmartNotifier()

        # النتائج
        self.all_vulns = []
        self.all_findings = []
        self.extra_data = {}
        self.shell_obtained = False
        self.shell_url = None

    def _log(self, msg, level="info"):
        getattr(self.reporter.logger, level, self.reporter.logger.info)(msg)

    def run(self) -> Dict:
        """تشغيل الفحص الشامل الأوتوماتيكي"""
        start_time = time.time()

        # Banner
        self._print_banner()
        self._print_legal_warning()

        # Phase 1: Setup & Reconnaissance
        self.reporter.start_phase("1. الاستطلاع والإعداد (Reconnaissance)")
        self._phase_recon()
        self.reporter.end_phase()
        self._print_phase_summary("الاستطلاع", self.extra_data.get("recon", {}))

        # Phase 2: Stealth & WAF Evasion
        self.reporter.start_phase("2. التخفي وتجاوز WAF (Stealth & Evasion)")
        self._phase_stealth()
        self.reporter.end_phase()
        self._print_phase_summary("التخفي", {"masquerade": self.masquerade.get_stats()})

        # Phase 3: AI Analysis
        self.reporter.start_phase("3. التحليل الذكي (AI Analysis)")
        self._phase_ai_analysis()
        self.reporter.end_phase()
        self._print_phase_summary("التحليل الذكي", self.extra_data.get("ai", {}))

        # Phase 4: Component Analysis
        self.reporter.start_phase("4. تحليل المكونات (Component Analysis)")
        self._phase_component_analysis()
        self.reporter.end_phase()
        self._print_phase_summary("تحليل المكونات", self.extra_data.get("components_summary", {}))

        # Phase 5: Vulnerability Scanning
        self.reporter.start_phase("5. فحص الثغرات (Vulnerability Scanning)")
        self._phase_vuln_scan()
        self.reporter.end_phase()
        self._print_phase_summary("فحص الثغرات", {"vulns_found": len(self.all_vulns)})

        # Phase 6: Zero-Day Detection
        self.reporter.start_phase("6. كشف الثغرات غير المعروفة (Zero-Day)")
        self._phase_zero_day()
        self.reporter.end_phase()
        self._print_phase_summary("Zero-Day", {"findings": len(self.all_vulns)})

        # Phase 7: Exploit Chain Analysis
        self.reporter.start_phase("7. تحليل سلاسل الاستغلال (Exploit Chains)")
        self._phase_exploit_chains()
        self.reporter.end_phase()

        # Phase 8: Auto Exploitation
        self.reporter.start_phase("8. الاستغلال الأوتوماتيكي (Auto Exploitation)")
        self._phase_exploitation()
        self.reporter.end_phase()
        self._print_phase_summary("الاستغلال", {"shell_obtained": self.shell_obtained})

        # Phase 9: Post-Exploitation
        if self.shell_obtained:
            self.reporter.start_phase("9. ما بعد الاختراق (Post-Exploitation)")
            self._phase_post_exploit()
            self.reporter.end_phase()

        # Phase 10: Report Generation
        self.reporter.start_phase("10. توليد التقرير (Report Generation)")
        report_paths = self._phase_report(start_time)
        self.reporter.end_phase()

        # Final Report
        self.reporter.print_final_report()

        # لو حصلنا على shell، نعرض قائمة ما بعد الاختراق
        if self.shell_obtained and self.shell_url:
            print(f"\n{Colors.GREEN + Colors.BOLD}✅ تم اختراق الموقع!{Colors.NC}")
            print(f"{Colors.CYAN}فتح قائمة ما بعد الاختراق...{Colors.NC}")

            time.sleep(2)

            menu = PostExploitMenu(self.client)
            menu.set_shell(self.shell_url)
            menu.show_menu()

        return {
            "url": self.url,
            "duration": time.time() - start_time,
            "vulns_count": len(self.all_vulns),
            "shell_obtained": self.shell_obtained,
            "reports": report_paths,
        }

    def _print_banner(self):
        """عرض banner"""
        print(f"\n{Colors.RED}")
        print(f"  ██████   ██  █████  ██   ██ ███████ ██      ██████   ██████")
        print(f"  ██   ██  ██ ██   ██  ██ ██  ██      ██      ██   ██ ██    ██")
        print(f"  ███████  ██ ███████   ███   █████   ██      ██████  ██    ██")
        print(f"  ██   ██  ██ ██   ██  ██ ██  ██      ██      ██   ██ ██    ██")
        print(f"  ██   ██  ██ ██   ██  ██   ██ ███████ ███████ ██████   ██████")
        print(f"{Colors.NC}")
        print(f"{Colors.CYAN}  Full Automatic Web Pentest - Recon to Post-Exploit{Colors.NC}")
        print(f"{Colors.GRAY}  استطلاع → تخفي → هجوم → استغلال → ما بعد الاختراق{Colors.NC}")
        print(f"\n  {Colors.BOLD}الهدف:{Colors.NC} {self.url}")
        print(f"  {Colors.BOLD}الوضع:{Colors.NC} أوتوماتيكي كامل\n")

    def _print_legal_warning(self):
        """تحذير قانوني"""
        print(f"{Colors.YELLOW}  ⚠️  تنبيه قانوني:{Colors.NC}")
        print(f"     استخدم الأداة فقط على مواقع تملكها أو لديك إذن صريح بفحصها.")
        print(f"     الاستخدام غير المصرح به جريمة يعاقب عليها القانون.\n")

    def _print_phase_summary(self, phase_name: str, results: Dict):
        """طباعة ملخص كل phase"""
        print(f"\n  {Colors.MAGENTA}── ملخص {fix_display(phase_name)} ──{Colors.NC}")

        if not results:
            print(f"    {Colors.GRAY}لا توجد نتائج{Colors.NC}")
            return

        # عرض أهم النتائج
        for key, value in results.items():
            if isinstance(value, (str, int, float, bool)):
                print(f"    {Colors.BOLD}{key}:{Colors.NC} {value}")
            elif isinstance(value, list):
                print(f"    {Colors.BOLD}{key}:{Colors.NC} {len(value)} عنصر")
                for item in value[:3]:
                    if isinstance(item, dict):
                        # عرض أهم حقل
                        for k in ["name", "type", "title", "severity"]:
                            if k in item:
                                print(f"      {Colors.CYAN}- {item[k]}{Colors.NC}")
                                break
                    elif isinstance(item, str):
                        print(f"      {Colors.CYAN}- {item[:60]}{Colors.NC}")
            elif isinstance(value, dict):
                print(f"    {Colors.BOLD}{key}:{Colors.NC} {len(value)} عناصر")

        # عرض درجة الخطورة
        if "vulns_found" in results or "findings" in results:
            count = results.get("vulns_found", results.get("findings", 0))
            if count > 0:
                print(f"\n    {Colors.RED}🚨 درجة الخطورة: {count} ثغرة{Colors.NC}")

        print()

    # ============================ Phases ============================
    def _phase_recon(self):
        """Phase 1: الاستطلاع"""
        self._log("جمع معلومات أساسية...", "info")

        resp = self.client.get(self.url)
        if resp["status"] == 0:
            self._log("فشل الاتصال بالموقع", "error")
            return

        # معلومات أساسية
        recon = {
            "status": resp["status"],
            "headers_count": len(resp["headers"]),
            "body_size": len(resp["body"]),
            "server": resp["headers"].get("Server", "Unknown"),
            "content_type": resp["headers"].get("Content-Type", "Unknown"),
        }

        # فحص robots.txt
        robots_url = self.url.rstrip("/") + "/robots.txt"
        robots_resp = self.client.get(robots_url)
        if robots_resp["status"] == 200:
            recon["robots_txt"] = "موجود"
            self._log("robots.txt موجود", "success")

        # فحص sitemap.xml
        sitemap_url = self.url.rstrip("/") + "/sitemap.xml"
        sitemap_resp = self.client.get(sitemap_url)
        if sitemap_resp["status"] == 200:
            recon["sitemap_xml"] = "موجود"
            self._log("sitemap.xml موجود", "success")

        self.extra_data["recon"] = recon
        self._log(f"Status: {recon['status']} | Server: {recon['server']}", "success")

    def _phase_stealth(self):
        """Phase 2: التخفي"""
        self._log("تفعيل وضع التخفي...", "info")

        # اختيار profile
        self.masquerade.select_profile()
        self._log(f"تم التنكر: {self.masquerade.current_profile['name']}", "success")

        # كشف WAF
        waf_result = self.waf_detector.detect_waf(self.url)
        self.extra_data["waf"] = waf_result

        if waf_result["detected"]:
            self._log(f"WAF مكتشف: {waf_result['name']}", "warn")
            self.reporter.report_finding({
                "type": "waf_detected",
                "severity": "info",
                "title": f"WAF: {waf_result['name']}",
                "description": "الموقع محمي بـ WAF",
                "url": self.url,
            })

            # تفعيل evasion
            self._log("تفعيل evasion...", "info")
            self.masquerade.set_behavior_mode("stealth")
        else:
            self._log("لا يوجد WAF", "success")
            self.masquerade.set_behavior_mode("human")

    def _phase_ai_analysis(self):
        """Phase 3: التحليل الذكي"""
        self._log("تحليل ذكي للموقع...", "info")

        reasoner = AIReasoner(self.client)
        result = reasoner.analyze(self.url)

        # إضافة hypotheses
        for vuln_type, confidence in result.get("sorted", [])[:5]:
            if confidence > 0.4:
                self.reporter.report_finding({
                    "type": "ai_hypothesis",
                    "severity": "info",
                    "title": f"فرضية: {vuln_type}",
                    "description": f"درجة الثقة: {confidence*100:.0f}%",
                    "url": self.url,
                })

        self.extra_data["ai"] = result.get("behavior", {})

    def _phase_component_analysis(self):
        """Phase 4: تحليل المكونات"""
        self._log("تحليل المكونات والقوالب والإضافات...", "info")

        analyzer = ComponentAnalyzer(self.client)
        result = analyzer.analyze(self.url)

        components = result.get("components", {})

        # عرض المكونات
        for plugin in components.get("wordpress_plugins", []):
            self.reporter.report_component(plugin)

        for theme in components.get("wordpress_themes", []):
            self.reporter.report_component(theme)

        for path in components.get("paths", []):
            self.reporter.report_component({
                "name": path["path"],
                "type": "path",
                "is_outdated": path.get("vulnerable", False),
                "vulnerabilities": [path.get("info", {})] if path.get("info") else [],
            })

        for tech in components.get("tech_stack", []):
            self.reporter.report_component({
                "name": tech,
                "type": "tech",
            })

        # إضافة الثغرات
        for vuln in result.get("vulnerabilities", []):
            self.all_vulns.append(vuln)
            self.reporter.report_finding(vuln)

        self.extra_data["components"] = components
        self.extra_data["components_summary"] = result.get("summary", {})

    def _phase_vuln_scan(self):
        """Phase 5: فحص الثغرات"""
        self._log("الفحص التكيّفي للثغرات...", "info")

        if self.waf_detector.should_terminate:
            self._log("تم إنهاء الفحص بسبب WAF", "warn")
            return

        scanner = AdaptiveScanner(self.client, self.waf_detector, self.notifier)
        vulns = scanner.run_adaptive_scan(self.url)

        for vuln in vulns:
            self.all_vulns.append(vuln)
            self.reporter.report_finding(vuln)

    def _phase_zero_day(self):
        """Phase 6: كشف Zero-Day"""
        self._log("كشف الثغرات غير المعروفة...", "info")

        if self.waf_detector.should_terminate:
            return

        detector = ZeroDayDetector(self.client)
        result = detector.scan(self.url)

        for category, findings in result.items():
            for finding in findings:
                finding["category"] = category
                self.all_vulns.append(finding)
                self.reporter.report_finding(finding)

    def _phase_exploit_chains(self):
        """Phase 7: تحليل سلاسل الاستغلال"""
        self._log("تحليل سلاسل الاستغلال...", "info")

        chain_engine = ExploitChainEngine()

        for vuln in self.all_vulns:
            chain_engine.add_vuln(vuln)

        chains = chain_engine.find_chains()

        if chains:
            self._log(f"تم اكتشاف {len(chains)} chain محتمل", "success")
            chain_engine.print_chains()

        self.extra_data["chains"] = chains

    def _phase_exploitation(self):
        """Phase 8: الاستغلال"""
        self._log("الاستغلال الأوتوماتيكي...", "info")

        # تخطيط الهجوم
        planner = AttackPlanner()
        planner.set_goal(AttackGoal.FULL_COMPROMISE)
        plan = planner.analyze_vulns(self.all_vulns)

        self._log("خطة الهجوم:", "info")
        planner.print_attack_plan(plan)

        # محاولة الاستغلال
        listener_ip = self.options.get("listener_ip")
        listener_port = self.options.get("listener_port", 4444)

        if listener_ip and self.all_vulns:
            takeover = TargetTakeoverEngine(
                self.client,
                listener_ip=listener_ip,
                listener_port=listener_port,
            )

            result = takeover.execute_takeover(self.all_vulns)

            if result.get("shell_obtained"):
                self.shell_obtained = True
                self.shell_url = result.get("web_shell_url")
                self._log("تم الحصول على shell!", "success")

    def _phase_post_exploit(self):
        """Phase 9: ما بعد الاختراق"""
        self._log("مرحلة ما بعد الاختراق...", "info")

        if not self.shell_url:
            return

        # تنفيذ post-exploitation تلقائي
        from modules.post_exploit import PostExploit
        pe = PostExploit(self.client)
        pe.set_shell(self.shell_url)
        result = pe.run_full()

        self.extra_data["post_exploit"] = result

        # عرض ملخص
        if "stats" in result:
            stats = result["stats"]
            self._log(f"ملفات مستخرجة: {stats.get('exfil_files', 0)}", "info")
            self._log(f"فرص رفع صلاحيات: {stats.get('privesc_findings', 0)}", "info")

    def _phase_report(self, start_time: float) -> Dict:
        """Phase 10: توليد التقرير"""
        self._log("توليد التقرير الشامل...", "info")

        duration = time.time() - start_time

        reports = generate_full_report(
            self.url,
            self.all_vulns,
            self.extra_data,
            duration,
            "full",
            self.options.get("output", "reports")
        )

        self._log(f"JSON: {reports['json']}", "success")
        self._log(f"HTML: {reports['html']}", "success")
        self._log(f"CSV:  {reports['csv']}", "success")

        return reports


# ============================ Convenience Function ============================
def full_auto_scan(url: str, options: Dict = None) -> Dict:
    """فحص أوتوماتيكي كامل"""
    if not url.startswith("http"):
        url = "http://" + url

    scanner = FullAutoScanner(url, options or {})
    return scanner.run()


# ============================ Main ============================
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="ghostpwn - Full Automatic Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
أمثلة:
  python3 full_auto.py https://target.com
  python3 full_auto.py https://target.com --listener-ip 10.0.0.1
  python3 full_auto.py https://target.com --proxy http://127.0.0.1:8080
"""
    )
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--listener-ip", help="Listener IP for reverse shell")
    parser.add_argument("--listener-port", type=int, default=4444)
    parser.add_argument("--proxy", help="HTTP proxy")
    parser.add_argument("--cookie", help="Cookie string")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--delay", type=float, default=0)
    parser.add_argument("--output", default="reports")
    args = parser.parse_args()

    options = {
        "listener_ip": args.listener_ip,
        "listener_port": args.listener_port,
        "proxy": args.proxy,
        "cookie": args.cookie,
        "timeout": args.timeout,
        "delay": args.delay,
        "output": args.output,
    }

    result = full_auto_scan(args.url, options)

    print(f"\n{Colors.GREEN}[✓] اكتمل الفحص!{Colors.NC}")
    print(f"  المدة: {result['duration']:.1f}s")
    print(f"  الثغرات: {result['vulns_count']}")
    print(f"  Shell: {'نعم' if result['shell_obtained'] else 'لا'}")
