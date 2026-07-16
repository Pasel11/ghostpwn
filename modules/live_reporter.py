#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Live Reporter
عرض النتائج live أثناء العملية - بدون انتظار النهاية
"""
import sys
import os
import time
import threading
from typing import Dict, List, Optional
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.arabic_display import SmartLogger, Colors, fix_display


class LiveReporter:
    """عرض النتائج live"""

    def __init__(self, audit_logger=None):
        self.audit = audit_logger
        self.logger = SmartLogger()

        self.start_time = time.time()
        self.current_phase = ""
        self.phase_start_time = None

        self.stats = {
            "requests_made": 0,
            "vulns_found": 0,
            "components_found": 0,
            "errors": 0,
            "warnings": 0,
        }

        self.vulns_by_severity = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        self.recent_findings = []  # آخر 10 findings
        self.all_findings = []

        # thread لعرض stats دورياً
        self._stop_display = False
        self._display_thread = None

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)

    # ============================ Phase Tracking ============================
    def start_phase(self, phase_name: str):
        """بدء phase جديدة"""
        self.current_phase = phase_name
        self.phase_start_time = time.time()

        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")
        print(f"{Colors.MAGENTA}  ▶ {fix_display(phase_name)}{Colors.NC}")
        print(f"{Colors.MAGENTA}{'═'*60}{Colors.NC}")

        if self.audit:
            self.audit.log_event(f"PHASE START: {phase_name}", "phase")

    def end_phase(self):
        """إنهاء phase"""
        if self.phase_start_time:
            duration = time.time() - self.phase_start_time
            print(f"\n  {Colors.GRAY}[{duration:.1f}s]{Colors.NC}")
            if self.audit:
                self.audit.log_event(
                    f"PHASE END: {self.current_phase} ({duration:.1f}s)",
                    "phase"
                )

        self.current_phase = ""
        self.phase_start_time = None

    # ============================ Live Findings ============================
    def report_finding(self, finding: Dict):
        """عرض finding فوراً"""
        self.all_findings.append(finding)

        # إضافة للـ recent
        self.recent_findings.insert(0, finding)
        if len(self.recent_findings) > 10:
            self.recent_findings.pop()

        # تحديث الإحصائيات
        self.stats["vulns_found"] += 1

        severity = finding.get("severity", "info")
        if severity in self.vulns_by_severity:
            self.vulns_by_severity[severity] += 1

        # عرض فوري
        self._print_finding(finding)

        if self.audit:
            self.audit.log_vuln(finding)

    def _print_finding(self, finding: Dict):
        """عرض finding واحد"""
        severity = finding.get("severity", "info")
        finding_type = finding.get("type", "unknown")

        colors = {
            "critical": Colors.RED + Colors.BOLD,
            "high": Colors.RED,
            "medium": Colors.YELLOW,
            "low": Colors.BLUE,
            "info": Colors.GRAY,
        }

        labels = {
            "critical": "CRITICAL",
            "high": "HIGH",
            "medium": "MEDIUM",
            "low": "LOW",
            "info": "INFO",
        }

        color = colors.get(severity, Colors.NC)
        label = labels.get(severity, "INFO")

        print(f"\n  {color}┌─ [{label}] {finding_type}{Colors.NC}")

        if finding.get("title"):
            print(f"  {color}│{Colors.NC} {fix_display(finding['title'])}")

        if finding.get("url"):
            print(f"  {color}│{Colors.NC} URL: {finding['url'][:80]}")

        if finding.get("component"):
            version = f" v{finding['version']}" if finding.get("version") else ""
            print(f"  {color}│{Colors.NC} Component: {finding['component']}{version}")

        if finding.get("path"):
            print(f"  {color}│{Colors.NC} Path: {finding['path']}")

        if finding.get("param"):
            print(f"  {color}│{Colors.NC} Param: {finding['param']}")

        if finding.get("payload"):
            print(f"  {color}│{Colors.NC} Payload: {finding['payload'][:80]}")

        if finding.get("evidence"):
            print(f"  {color}│{Colors.NC} Evidence: {fix_display(str(finding['evidence'])[:100])}")

        if finding.get("description"):
            print(f"  {color}│{Colors.NC} {fix_display(finding['description'][:150])}")

        if finding.get("fix"):
            print(f"  {color}│{Colors.NC} Fix: {fix_display(finding['fix'][:150])}")

        if finding.get("cve"):
            print(f"  {color}│{Colors.NC} CVE: {finding['cve']}")

        print(f"  {color}└─{Colors.NC}")

    # ============================ Progress ============================
    def update_progress(self, message: str, current: int = None, total: int = None):
        """عرض progress"""
        if current is not None and total is not None:
            percent = (current / total * 100) if total > 0 else 0
            bar_length = 30
            filled = int(bar_length * current / total) if total > 0 else 0
            bar = "█" * filled + "░" * (bar_length - filled)

            sys.stdout.write(
                f"\r  {Colors.CYAN}[{bar}]{Colors.NC} {percent:.0f}% - {fix_display(message)}"
            )
            sys.stdout.flush()

            if current >= total:
                sys.stdout.write("\n")
                sys.stdout.flush()
        else:
            self._log(message, "info")

    # ============================ Component Found ============================
    def report_component(self, component: Dict):
        """عرض component مكتشف"""
        self.stats["components_found"] += 1

        name = component.get("name", "unknown")
        version = component.get("version", "")
        comp_type = component.get("type", "unknown")
        is_outdated = component.get("is_outdated", False)
        vuln_count = len(component.get("vulnerabilities", []))

        version_str = f" v{version}" if version else ""
        outdated_str = f" {Colors.RED}⚠️ OUTDATED{Colors.NC}" if is_outdated else ""
        vuln_str = f" {Colors.YELLOW}({vuln_count} vulns){Colors.NC}" if vuln_count > 0 else f" {Colors.GREEN}✓{Colors.NC}"

        type_icon = {
            "wordpress_plugin": "🔌",
            "wordpress_theme": "🎨",
            "tech": "🛠️",
            "path": "📂",
        }.get(comp_type, "•")

        print(f"  {type_icon} {name}{version_str}{outdated_str}{vuln_str}")

    # ============================ Stats ============================
    def increment_requests(self, count: int = 1):
        """زيادة عداد الطلبات"""
        self.stats["requests_made"] += count

    def increment_errors(self):
        """زيادة عداد الأخطاء"""
        self.stats["errors"] += 1

    def increment_warnings(self):
        """زيادة عداد التحذيرات"""
        self.stats["warnings"] += 1

    def print_live_stats(self):
        """عرض إحصائيات live"""
        elapsed = time.time() - self.start_time
        req_per_sec = self.stats["requests_made"] / elapsed if elapsed > 0 else 0

        print(f"\n{Colors.CYAN}{'─'*60}{Colors.NC}")
        print(f"  {Colors.BOLD}📊 Live Stats:{Colors.NC}")
        print(f"    المدة: {elapsed:.1f}s")
        print(f"    الطلبات: {self.stats['requests_made']} ({req_per_sec:.1f}/s)")
        print(f"    المكونات: {self.stats['components_found']}")
        print(f"    الثغرات: {self.stats['vulns_found']}")
        print(f"    الأخطاء: {self.stats['errors']}")

        if self.stats["vulns_found"] > 0:
            print(f"\n    {Colors.BOLD}الثغرات حسب الخطورة:{Colors.NC}")
            for sev, count in self.vulns_by_severity.items():
                if count > 0:
                    color = {
                        "critical": Colors.RED + Colors.BOLD,
                        "high": Colors.RED,
                        "medium": Colors.YELLOW,
                        "low": Colors.BLUE,
                        "info": Colors.GRAY,
                    }.get(sev, Colors.NC)
                    bar = "█" * count
                    print(f"      {color}{sev:10s}: {count} {bar}{Colors.NC}")

        if self.current_phase:
            print(f"\n    {Colors.BOLD}المرحلة الحالية:{Colors.NC} {fix_display(self.current_phase)}")

        print(f"{Colors.CYAN}{'─'*60}{Colors.NC}")

    def print_final_report(self):
        """عرض التقرير النهائي"""
        elapsed = time.time() - self.start_time

        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")
        print(f"{Colors.MAGENTA}  📋 Final Report{Colors.NC}")
        print(f"{Colors.MAGENTA}{'═'*60}{Colors.NC}")

        print(f"\n  {Colors.BOLD}⏱️  المدة الإجمالية:{Colors.NC} {elapsed:.1f}s")
        print(f"  {Colors.BOLD}📊 الطلبات:{Colors.NC} {self.stats['requests_made']}")
        print(f"  {Colors.BOLD}🔌 المكونات:{Colors.NC} {self.stats['components_found']}")
        print(f"  {Colors.BOLD}🚨 الثغرات:{Colors.NC} {self.stats['vulns_found']}")

        if self.stats["vulns_found"] > 0:
            print(f"\n  {Colors.BOLD}📈 الثغرات حسب الخطورة:{Colors.NC}")
            for sev, count in self.vulns_by_severity.items():
                if count > 0:
                    color = {
                        "critical": Colors.RED + Colors.BOLD,
                        "high": Colors.RED,
                        "medium": Colors.YELLOW,
                        "low": Colors.BLUE,
                        "info": Colors.GRAY,
                    }.get(sev, Colors.NC)
                    label = {
                        "critical": "حرج",
                        "high": "عالي",
                        "medium": "متوسط",
                        "low": "منخفض",
                        "info": "معلومة",
                    }.get(sev, sev)
                    bar = "█" * count
                    print(f"    {color}{label:8s}: {count} {bar}{Colors.NC}")

        # حساب مستوى الخطر
        risk_score = (
            self.vulns_by_severity["critical"] * 10 +
            self.vulns_by_severity["high"] * 7 +
            self.vulns_by_severity["medium"] * 4 +
            self.vulns_by_severity["low"] * 1
        )

        if risk_score >= 20:
            risk_level = "حرج 🔴"
            risk_color = Colors.RED + Colors.BOLD
        elif risk_score >= 10:
            risk_level = "عالي 🟠"
            risk_color = Colors.RED
        elif risk_score >= 5:
            risk_level = "متوسط 🟡"
            risk_color = Colors.YELLOW
        elif risk_score > 0:
            risk_level = "منخفض 🔵"
            risk_color = Colors.BLUE
        else:
            risk_level = "آمن 🟢"
            risk_color = Colors.GREEN

        print(f"\n  {Colors.BOLD}مستوى الخطر:{Colors.NC} {risk_color}{fix_display(risk_level)}{Colors.NC} (score: {risk_score})")

        # آخر النتائج
        if self.recent_findings:
            print(f"\n  {Colors.BOLD}آخر النتائج:{Colors.NC}")
            for finding in self.recent_findings[:5]:
                severity = finding.get("severity", "info")
                color = {
                    "critical": Colors.RED + Colors.BOLD,
                    "high": Colors.RED,
                    "medium": Colors.YELLOW,
                    "low": Colors.BLUE,
                    "info": Colors.GRAY,
                }.get(severity, Colors.NC)
                title = finding.get("title", finding.get("type", "unknown"))
                print(f"    {color}[{severity}]{Colors.NC} {fix_display(str(title)[:50])}")

        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")

    def get_findings(self) -> List[Dict]:
        """الحصول على كل النتائج"""
        return self.all_findings

    def get_stats(self) -> Dict:
        """الحصول على الإحصائيات"""
        return {
            **self.stats,
            "vulns_by_severity": self.vulns_by_severity,
            "elapsed": time.time() - self.start_time,
        }
