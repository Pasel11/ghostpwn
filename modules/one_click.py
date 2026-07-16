#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - One-Click Mode
وضع النقرة الواحدة - يدخل URL فقط والأداة تعمل كل شيء بذكاء

الـ user بيحتاج بس:
  python3 ghostpwn.py URL

والأداة تعمل:
  1. تحليل ذكي للموقع
  2. فحص المكونات (plugins, themes, paths)
  3. مقارنة بقاعدة بيانات الثغرات
  4. فحص الثغرات التكيفي
  5. كشف zero-day
  6. عرض النتائج live
  7. توليد تقرير شامل
"""
import sys
import os
import time
import json
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display
from modules.live_reporter import LiveReporter
from modules.ai_reasoner import AIReasoner
from modules.component_analyzer import ComponentAnalyzer
from modules.adaptive_scanner import AdaptiveScanner
from modules.smart_waf import SmartWAFDetector
from modules.zero_day_detector import ZeroDayDetector
from modules.vuln_notifier import SmartNotifier
from modules.report_generator import generate_full_report


class OneClickScanner:
    """الماسح الأوتوماتيكي الكامل - نقرة واحدة"""

    def __init__(self, url: str, options: Dict = None):
        self.url = url
        self.options = options or {}

        # إعداد الـ HTTP client
        self.client = HttpClient(
            timeout=self.options.get("timeout", 15),
            user_agent=self.options.get("user_agent", "ghostpwn/1.0"),
            proxy=self.options.get("proxy"),
            cookie=self.options.get("cookie"),
            delay=self.options.get("delay", 0),
        )

        # الـ modules
        self.reporter = LiveReporter()
        self.waf_detector = SmartWAFDetector(self.client)
        self.ai_reasoner = AIReasoner(self.client)
        self.component_analyzer = ComponentAnalyzer(self.client)
        self.adaptive_scanner = AdaptiveScanner(self.client, self.waf_detector, self.reporter.notifier if hasattr(self.reporter, 'notifier') else None)
        self.zero_day_detector = ZeroDayDetector(self.client)

        # النتائج
        self.all_vulns = []
        self.all_findings = []
        self.extra_data = {}

    def _log(self, msg, level="info"):
        getattr(self.reporter.logger, level, self.reporter.logger.info)(msg)

    def run(self) -> Dict:
        """تشغيل الفحص الشامل"""
        start_time = time.time()

        # Banner
        self._print_banner()

        # تأكيد قانوني
        self._print_legal_warning()

        # Phase 1: WAF Detection
        self.reporter.start_phase("1. كشف WAF والحماية")
        waf_result = self._phase_waf_detection()
        self.reporter.end_phase()

        # Phase 2: AI Analysis
        self.reporter.start_phase("2. تحليل ذكي للموقع (AI)")
        ai_result = self._phase_ai_analysis()
        self.reporter.end_phase()

        # Phase 3: Component Analysis
        self.reporter.start_phase("3. تحليل المكونات والقوالب والإضافات")
        component_result = self._phase_component_analysis()
        self.reporter.end_phase()

        # Phase 4: Adaptive Vulnerability Scanning
        self.reporter.start_phase("4. الفحص التكيّفي للثغرات")
        vuln_result = self._phase_adaptive_scanning()
        self.reporter.end_phase()

        # Phase 5: Zero-Day Detection
        self.reporter.start_phase("5. كشف الثغرات غير المعروفة (Zero-Day)")
        zeroday_result = self._phase_zero_day_detection()
        self.reporter.end_phase()

        # Phase 6: Summary & Report
        self.reporter.start_phase("6. توليد التقرير الشامل")
        report_paths = self._phase_generate_report(start_time)
        self.reporter.end_phase()

        # Final Report
        self.reporter.print_final_report()

        return {
            "url": self.url,
            "duration": time.time() - start_time,
            "vulns_count": len(self.all_vulns),
            "components_count": self.reporter.stats["components_found"],
            "reports": report_paths,
        }

    def _print_banner(self):
        """عرض الـ banner"""
        print(f"\n{Colors.RED}")
        print(f"  ██████   ██  █████  ██   ██ ███████ ██      ██████   ██████")
        print(f"  ██   ██  ██ ██   ██  ██ ██  ██      ██      ██   ██ ██    ██")
        print(f"  ███████  ██ ███████   ███   █████   ██      ██████  ██    ██")
        print(f"  ██   ██  ██ ██   ██  ██ ██  ██      ██      ██   ██ ██    ██")
        print(f"  ██   ██  ██ ██   ██  ██   ██ ███████ ███████ ██████   ██████")
        print(f"{Colors.NC}")
        print(f"{Colors.CYAN}  One-Click Automatic Web Pentest Toolkit{Colors.NC}")
        print(f"{Colors.GRAY}  URL → Full Analysis → Live Results → Report{Colors.NC}")
        print(f"\n  {Colors.BOLD}Target:{Colors.NC} {self.url}")
        print(f"  {Colors.BOLD}Mode:{Colors.NC} Full Automatic (One-Click)")
        print()

    def _print_legal_warning(self):
        """تحذير قانوني"""
        print(f"{Colors.YELLOW}  ⚠️  تنبيه قانوني:{Colors.NC}")
        print(f"     استخدم الأداة فقط على مواقع تملكها أو لديك إذن صريح بفحصها.")
        print(f"     الاستخدام غير المصرح به جريمة يعاقب عليها القانون.")
        print()

    def _phase_waf_detection(self) -> Dict:
        """Phase 1: كشف WAF"""
        self._log("فحص وجود WAF...", "info")
        result = self.waf_detector.detect_waf(self.url)

        if result["detected"]:
            self.reporter.report_finding({
                "type": "waf_detected",
                "severity": "info",
                "title": f"WAF مكتشف: {result['name']}",
                "description": "الموقع محمي بـ WAF - قد يصعب الفحص",
                "url": self.url,
            })
        else:
            self.reporter.report_finding({
                "type": "no_waf",
                "severity": "medium",
                "title": "بدون حماية WAF",
                "description": "الموقع بدون WAF - عرضة للهجمات",
                "url": self.url,
            })

        return result

    def _phase_ai_analysis(self) -> Dict:
        """Phase 2: تحليل AI"""
        self._log("تحليل ذكي للموقع...", "info")
        result = self.ai_reasoner.analyze(self.url)

        # إضافة hypotheses كـ findings
        for vuln_type, confidence in result.get("sorted", [])[:5]:
            if confidence > 0.4:
                self.reporter.report_finding({
                    "type": "ai_hypothesis",
                    "severity": "info",
                    "title": f"فرضية AI: {vuln_type}",
                    "description": f"درجة الثقة: {confidence*100:.0f}%",
                    "url": self.url,
                })

        self.extra_data["ai_analysis"] = result.get("behavior", {})
        return result

    def _phase_component_analysis(self) -> Dict:
        """Phase 3: تحليل المكونات"""
        self._log("تحليل المكونات والقوالب والإضافات...", "info")
        result = self.component_analyzer.analyze(self.url)

        # عرض المكونات live
        components = result.get("components", {})

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

        # إضافة الثغرات المكتشفة
        for vuln in result.get("vulnerabilities", []):
            self.all_vulns.append(vuln)
            self.reporter.report_finding(vuln)

        self.extra_data["components"] = components
        return result

    def _phase_adaptive_scanning(self) -> Dict:
        """Phase 4: الفحص التكيّفي"""
        self._log("الفحص التكيّفي للثغرات...", "info")

        # فحص لو الـ WAF قال ننهي
        if self.waf_detector.should_terminate:
            self._log("تم إنهاء الفحص بسبب WAF", "warn")
            return {"terminated": True}

        # تشغيل الفحص التكيّفي
        vulns = self.adaptive_scanner.run_adaptive_scan(self.url)

        # إضافة النتائج
        for vuln in vulns:
            self.all_vulns.append(vuln)
            self.reporter.report_finding(vuln)

        return {"vulns": vulns}

    def _phase_zero_day_detection(self) -> Dict:
        """Phase 5: كشف Zero-Day"""
        self._log("كشف الثغرات غير المعروفة...", "info")

        # فحص لو الـ WAF قال ننهي
        if self.waf_detector.should_terminate:
            self._log("تخطي zero-day بسبب WAF", "warn")
            return {"terminated": True}

        result = self.zero_day_detector.scan(self.url)

        # إضافة النتائج
        for category, findings in result.items():
            for finding in findings:
                finding["category"] = category
                self.all_vulns.append(finding)
                self.reporter.report_finding(finding)

        return result

    def _phase_generate_report(self, start_time: float) -> Dict:
        """Phase 6: توليد التقرير"""
        self._log("توليد التقرير الشامل...", "info")

        duration = time.time() - start_time

        # تجميع كل النتائج
        reports = generate_full_report(
            self.url,
            self.all_vulns,
            self.extra_data,
            duration,
            self.options.get("depth", "full"),
            self.options.get("output", "reports")
        )

        self._log(f"JSON: {reports['json']}", "success")
        self._log(f"HTML: {reports['html']}", "success")
        self._log(f"CSV:  {reports['csv']}", "success")

        return reports


# ============================ Convenience Function ============================
def one_click_scan(url: str, options: Dict = None) -> Dict:
    """دالة مساعدة - فحص بنقرة واحدة"""
    if not url.startswith("http"):
        url = "http://" + url

    scanner = OneClickScanner(url, options or {})
    return scanner.run()


# ============================ Main ============================
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="ghostpwn - One-Click Automatic Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
أمثلة:
  python3 one_click.py https://target.com
  python3 one_click.py https://target.com --proxy http://127.0.0.1:8080
  python3 one_click.py https://target.com --cookie "session=abc123"
"""
    )
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--proxy", help="HTTP proxy")
    parser.add_argument("--cookie", help="Cookie string")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests")
    parser.add_argument("--output", default="reports", help="Reports directory")
    args = parser.parse_args()

    options = {
        "proxy": args.proxy,
        "cookie": args.cookie,
        "timeout": args.timeout,
        "delay": args.delay,
        "output": args.output,
    }

    result = one_click_scan(args.url, options)

    print(f"\n{Colors.GREEN}[✓] اكتمل الفحص!{Colors.NC}")
    print(f"  المدة: {result['duration']:.1f}s")
    print(f"  الثغرات: {result['vulns_count']}")
    print(f"  المكونات: {result['components_count']}")
    print(f"  التقارير: {result['reports']['html']}")
