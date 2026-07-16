#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Help System
نظام مساعدة سياقي
"""
import sys
import os


class HelpSystem:
    """نظام مساعدة"""

    HELP_TOPICS = {
        "getting_started": {
            "title": "🚀 البداية السريعة",
            "content": """
كيف تبدأ مع ghostpwn:

1. الوضع التفاعلي (موصى به للمبتدئين):
   python3 ghostpwn.py --interactive

2. فحص سريع:
   python3 ghostpwn.py https://target.com --depth=fast

3. فحص كامل:
   python3 ghostpwn.py https://target.com --depth=deep

4. فحص أوتوماتيكي كامل:
   python3 ghostpwn.py https://target.com --auto
""",
        },
        "profiles": {
            "title": "📋 أنواع الفحص (Profiles)",
            "content": """
الـ profiles المتاحة:

1. quick      - فحص سريع (2-5 دقائق)
2. standard   - فحص قياسي (10-20 دقيقة)
3. deep       - فحص عميق (30-60 دقيقة)
4. stealth    - فحص صامت (لتجنب WAF)
5. vuln_only  - فحص ثغرات فقط
6. recon      - استطلاع فقط
7. full_attack - فحص + استغلال + brute + dump
8. wordpress  - فحص WordPress مخصص
9. api        - فحص API مخصص

استخدام:
  python3 ghostpwn.py https://target.com --profile standard
""",
        },
        "modules": {
            "title": "📦 الـ Modules",
            "content": """
الـ modules في ghostpwn (20 module):

الفحص:
  - http_client: HTTP client
  - port_scanner: فحص البورتات
  - vuln_detector: كشف 13+ نوع ثغرة
  - advanced_vuln: فحوصات متقدمة
  - crawler: زاحف ويب
  - cms_scanner: كشف CMS

الاستغلال:
  - exploit: استغلال SQLi/LFI/RCE
  - brute_force: SSH/FTP/HTTP/SMTP
  - db_dump: استخراج قواعد البيانات
  - revshell_deployer: نشر reverse shell

الأدوات:
  - payload_generator: 18 reverse shell + 7 web shell
  - payload_encoder: تشفير payloads
  - wizard: مرشد تفاعلي
  - profiles: إعدادات مسبقة
  - config: نظام إعدادات
""",
        },
        "reports": {
            "title": "📊 التقارير",
            "content": """
أنواع التقارير:

1. HTML    - تقرير تفاعلي (افتحه في المتصفح)
2. JSON    - للمعالجة البرمجية
3. CSV     - للتحليل في Excel
4. Audit   - سجل تدقيق شامل

التقارير تُحفظ في:
  reports/<hostname>_<timestamp>/

لفتح التقرير HTML:
  - على الموبايل: انسخه لمجلد Download وافتحه في المتصفح
  - على الكمبيوتر: افتحه مباشرة في المتصفح
""",
        },
        "stealth": {
            "title": "🥷 وضع التخفي",
            "content": """
وضع التخفي يقلل كشف WAF/IDS:

المستويات:
  - low:    0.5s delay بين الطلبات
  - medium: 1-3s delay + UA عشوائي
  - high:   3-7s delay + UA عشوائي + بطيء

استخدام:
  python3 ghostpwn.py https://target.com --stealth high

ملاحظات:
  - الفحص الصامت أبطأ لكن أكثر أماناً
  - مناسب للمواقع المحمية بـ WAF قوي
  - يقلل من احتمالية الحظر
""",
        },
        "legal": {
            "title": "⚠️  التنبيه القانوني",
            "content": """
استخدم الأداة فقط على:

✅ مسموح:
  - مواقع تملكها شخصياً
  - مواقع لديك إذن كتابي بفحصها
  - بيئات اختبار (DVWA, WebGoat, HackTheBox)
  - Bug Bounty programs المعلنة

❌ ممنوع:
  - فحص مواقع بدون إذن
  - فحص مواقع حكومية أو مؤسسية
  - اختراق مواقع وسرقة بيانات
  - تدمير logs أو آثار

العواقب القانونية:
  - غرامات كبيرة
  - السجن
  - سجل جنائي

أنت مسؤول عن استخدامك للأداة.
""",
        },
        "troubleshooting": {
            "title": "🔧 استكشاف الأخطاء",
            "content": """
مشاكل شائعة وحلولها:

1. "Connection refused":
   - تأكد من اتصالك بالإنترنت
   - تأكد من صحة الـ URL

2. "Timeout":
   - زد الـ timeout: --timeout=30
   - استخدم --depth=fast

3. "Module not found":
   - تأكد إنك في مجلد ghostpwn
   - تأكد إن Python 3.6+ مثبت

4. لا يتم كشف ثغرات:
   - استخدم --depth=deep
   - تأكد إن الموقع يعمل

5. الفحص بطيء جداً:
   - استخدم --depth=fast
   - زد الـ threads: --threads=20

6. ملفات التقارير غير موجودة:
   - تأكد من صلاحيات الكتابة
   - راجع مجلد reports/
""",
        },
        "cli": {
            "title": "💻 خيارات سطر الأوامر",
            "content": """
الخيارات الرئيسية:

  python3 ghostpwn.py [URL] [OPTIONS]

الخيارات:
  --interactive, -i    القائمة التفاعلية
  --auto               فحص أوتوماتيكي كامل
  --full               هجوم كامل (exploit + brute + dump)
  --depth LEVEL        fast/medium/deep (default: medium)
  --threads N          عدد الـ threads (default: 10)
  --timeout N          مهلة الطلب (default: 15)
  --proxy URL          HTTP proxy
  --cookie STR         Cookie للجلسة
  --stealth LEVEL      low/medium/high
  --brute              تفعيل brute force
  --dump-db            DB dump لو SQLi
  --deploy-shell       reverse shell deploy
  --listener-ip IP     listener IP
  --skip-port          تخطي فحص البورتات
  --skip-crawl         تخطي الزحف
  --skip-vuln          تخطي فحص الثغرات
  --cleanup            تنظيف الملفات المؤقتة
  --help, -h           عرض المساعدة

أمثلة:
  python3 ghostpwn.py -i
  python3 ghostpwn.py https://target.com --auto
  python3 ghostpwn.py https://target.com --full --listener-ip 10.0.0.1
""",
        },
    }

    def __init__(self):
        pass

    def show_help(self, topic: str = None):
        """عرض المساعدة"""
        if topic and topic in self.HELP_TOPICS:
            help_data = self.HELP_TOPICS[topic]
            print(f"\n{help_data['title']}")
            print("=" * 60)
            print(help_data["content"])
            print("=" * 60)
        else:
            self._show_main_help()

    def _show_main_help(self):
        """عرض القائمة الرئيسية للمساعدة"""
        print("\n❓ نظام المساعدة - ghostpwn")
        print("=" * 60)
        print("\nالمواضيع المتاحة:")

        topics = list(self.HELP_TOPICS.keys())
        for i, key in enumerate(topics, 1):
            print(f"  {i}. {self.HELP_TOPICS[key]['title']}")

        print(f"\nاستخدام:")
        print(f"  python3 ghostpwn.py --help [topic]")
        print(f"\nأمثلة:")
        print(f"  python3 ghostpwn.py --help getting_started")
        print(f"  python3 ghostpwn.py --help profiles")

    def interactive_help(self):
        """مساعدة تفاعلية"""
        while True:
            print("\n" + "=" * 60)
            print("❓ نظام المساعدة")
            print("=" * 60)
            print("\nالمواضيع:")

            topics = list(self.HELP_TOPICS.keys())
            for i, key in enumerate(topics, 1):
                print(f"  {i}. {self.HELP_TOPICS[key]['title']}")
            print(f"  0. خروج")

            try:
                choice = input("\nاختر موضوع (0-{}): ".format(len(topics))).strip()
                if choice == "0":
                    break
                idx = int(choice) - 1
                if 0 <= idx < len(topics):
                    self.show_help(topics[idx])
                    input("\nاضغط Enter للمتابعة...")
            except (ValueError, KeyboardInterrupt, EOFError):
                break


if __name__ == "__main__":
    help_sys = HelpSystem()
    if len(sys.argv) > 1:
        help_sys.show_help(sys.argv[1])
    else:
        help_sys.interactive_help()
