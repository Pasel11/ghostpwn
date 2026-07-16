#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Interactive Wizard
مرشد تفاعلي خطوة بخطوة لليوزر الجديد
"""
import sys
import os
from typing import Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.profiles import PROFILES, profile_menu, get_profile, list_profiles
from modules.config import Config


class Wizard:
    """مرشد تفاعلي"""

    def __init__(self):
        self.config = Config()
        self.colors = self._get_colors()

    def _get_colors(self):
        if sys.stdout.isatty():
            return {
                "RED": "\033[1;31m", "GREEN": "\033[1;32m", "YELLOW": "\033[1;33m",
                "BLUE": "\033[1;34m", "MAGENTA": "\033[1;35m", "CYAN": "\033[1;36m",
                "BOLD": "\033[1m", "GRAY": "\033[0;90m", "NC": "\033[0m",
            }
        return {k: "" for k in ["RED", "GREEN", "YELLOW", "BLUE", "MAGENTA", "CYAN", "BOLD", "GRAY", "NC"]}

    def c(self, color: str, text: str) -> str:
        """تلوين نص"""
        return f"{self.colors.get(color, '')}{text}{self.colors['NC']}"

    def clear(self):
        """تنظيف الشاشة"""
        os.system("clear" if os.name != "nt" else "cls")

    def pause(self, msg: str = "اضغط Enter للمتابعة..."):
        """إيقاف مؤقت"""
        try:
            input(f"\n{msg}")
        except (KeyboardInterrupt, EOFError):
            sys.exit(0)

    def header(self, title: str):
        """عرض header"""
        self.clear()
        print(self.c("RED", """
  ██████   ██  █████  ██   ██ ███████ ██      ██████   ██████
  ██   ██  ██ ██   ██  ██ ██  ██      ██      ██   ██ ██    ██
  ███████  ██ ███████   ███   █████   ██      ██████  ██    ██
  ██   ██  ██ ██   ██  ██ ██  ██      ██      ██   ██ ██    ██
  ██   ██  ██ ██   ██  ██   ██ ███████ ███████ ██████   ██████
"""))
        print(self.c("CYAN", f"  {title}"))
        print(self.c("GRAY", "  " + "─" * 60))
        print()

    def ask(self, question: str, default: str = "") -> str:
        """سؤال مفتوح"""
        try:
            prompt = f"{self.c('BOLD', '?')} {question}"
            if default:
                default_str = f"[{default}]"
                prompt += f" {self.c('GRAY', default_str)}"
            prompt += ": " + self.colors.get("BOLD", "")
            answer = input(prompt).strip() or default
            print(self.colors.get("NC", ""), end="")
            return answer
        except (KeyboardInterrupt, EOFError):
            print("\nbye!")
            sys.exit(0)

    def ask_yes_no(self, question: str, default: bool = False) -> bool:
        """سؤال نعم/لا"""
        default_str = "Y/n" if default else "y/N"
        try:
            prompt = f"{self.c('BOLD', '?')} {question} {self.c('GRAY', default_str)}: "
            answer = input(prompt).strip().lower()
            print(self.colors.get("NC", ""), end="")
            if not answer:
                return default
            return answer in ("y", "yes", "نعم", "ا")
        except (KeyboardInterrupt, EOFError):
            return False

    def ask_choice(self, question: str, choices: list, default: int = 0) -> int:
        """اختيار من قائمة"""
        print(f"{self.c('BOLD', '?')} {question}")
        for i, choice in enumerate(choices, 1):
            marker = "→" if i == default + 1 else " "
            print(f"  {marker} {i}. {choice}")
        try:
            answer = input(f"\nاختر (1-{len(choices)}) [{default + 1}]: ").strip()
            if not answer:
                return default
            idx = int(answer) - 1
            if 0 <= idx < len(choices):
                return idx
            return default
        except (ValueError, KeyboardInterrupt, EOFError):
            return default

    # ============================ Main Menu ============================
    def main_menu(self):
        """القائمة الرئيسية"""
        while True:
            self.header("🎯 القائمة الرئيسية")

            options = [
                "🚀 فحص سريع (Quick Scan)",
                "🎯 فحص قياسي (Standard Scan)",
                "🔍 فحص عميق (Deep Scan)",
                "🥷 فحص صامت (Stealth Scan)",
                "⚙️  فحص مخصص (Custom Scan)",
                "📋 فحص متعدد الأهداف (Batch Scan)",
                "🛠  توليد Payloads",
                "💾 إدارة الأهداف المحفوظة",
                "⚙️  الإعدادات",
                "❓ المساعدة",
                "🚪 خروج",
            ]

            choice = self.ask_choice("اختر من القائمة:", options)

            if choice == 0:
                self._run_profile("quick")
            elif choice == 1:
                self._run_profile("standard")
            elif choice == 2:
                self._run_profile("deep")
            elif choice == 3:
                self._run_profile("stealth")
            elif choice == 4:
                self._custom_scan()
            elif choice == 5:
                self._batch_scan()
            elif choice == 6:
                self._payload_menu()
            elif choice == 7:
                self._manage_targets()
            elif choice == 8:
                self._settings_menu()
            elif choice == 9:
                self._help()
            elif choice == 10:
                print(f"\n{self.c('GREEN', 'bye! 👋')}")
                sys.exit(0)

    # ============================ Run Profile ============================
    def _run_profile(self, profile_name: str):
        """تشغيل profile"""
        profile = PROFILES.get(profile_name)
        if not profile:
            print(f"{self.c('RED', '[!]')} Profile غير معروف")
            self.pause()
            return

        self.header(f"{profile['icon']} {profile['name']}")

        print(f"{self.c('BOLD', 'الوصف:')} {profile['description']}")
        print(f"\n{self.c('BOLD', 'الإعدادات:')}")
        for k, v in profile["options"].items():
            print(f"  {k}: {v}")

        url = self.ask("أدخل URL الموقع")
        if not url:
            return
        if not url.startswith("http"):
            url = "http://" + url

        # خيارات إضافية
        if self.ask_yes_no("هل لديك cookie للجلسة؟", False):
            cookie = self.ask("Cookie")
            profile["options"]["cookie"] = cookie

        if self.ask_yes_no("هل تريد استخدام proxy؟", False):
            proxy = self.ask("Proxy URL (مثل http://127.0.0.1:8080)")
            profile["options"]["proxy"] = proxy

        # تأكيد
        print(f"\n{self.c('YELLOW', '⚠️  تنبيه قانوني:')}")
        print(f"  استخدم فقط على مواقع لديك إذن بفحصها!")

        if not self.ask_yes_no("\nمتابعة الفحص؟", True):
            return

        # تشغيل الفحص
        self._execute_scan(url, profile["options"])

    # ============================ Custom Scan ============================
    def _custom_scan(self):
        """فحص مخصص"""
        self.header("⚙️  فحص مخصص")

        url = self.ask("أدخل URL الموقع")
        if not url:
            return
        if not url.startswith("http"):
            url = "http://" + url

        options = {}

        # العمق
        depth_choices = ["fast (سريع)", "medium (متوسط)", "deep (عميق)"]
        depth_idx = self.ask_choice("اختر عمق الفحص:", depth_choices, 1)
        options["depth"] = ["fast", "medium", "deep"][depth_idx]

        # الـ threads
        threads = self.ask("عدد الـ threads", "10")
        try:
            options["threads"] = int(threads)
        except ValueError:
            options["threads"] = 10

        # timeout
        timeout = self.ask("مهلة كل طلب (ثانية)", "15")
        try:
            options["timeout"] = int(timeout)
        except ValueError:
            options["timeout"] = 15

        # المراحل للتخطي
        print(f"\n{self.c('BOLD', 'اختر المراحل للتخطي:')}")
        skip_options = [
            ("skip_port", "تخطي فحص البورتات"),
            ("skip_crawl", "تخطي الزحف"),
            ("skip_dir", "تخطي directory brute"),
            ("skip_vuln", "تخطي فحص الثغرات"),
            ("skip_subdomain", "تخطي subdomain brute"),
            ("skip_tech", "تخطي كشف التكنولوجيا"),
        ]

        for key, label in skip_options:
            options[key] = self.ask_yes_no(label, False)

        # خيارات متقدمة
        if self.ask_yes_no("\nتفعيل الاستغلال الأوتوماتيكي؟", False):
            options["auto_exploit"] = True

            if self.ask_yes_no("تفعيل brute force؟", False):
                options["auto_brute"] = True

            if self.ask_yes_no("تفعيل DB dump (لو SQLi)؟", False):
                options["dump_db"] = True

            if self.ask_yes_no("تفعيل reverse shell deploy (لو RCE)؟", False):
                options["deploy_shell"] = True
                listener_ip = self.ask("Listener IP")
                listener_port = self.ask("Listener port", "4444")
                options["listener_ip"] = listener_ip
                try:
                    options["listener_port"] = int(listener_port)
                except ValueError:
                    options["listener_port"] = 4444

        # stealth mode
        if self.ask_yes_no("\nتفعيل وضع التخفي؟", False):
            stealth_choices = ["low (0.5s delay)", "medium (2s delay)", "high (5s delay)"]
            stealth_idx = self.ask_choice("اختر مستوى التخفي:", stealth_choices, 1)
            options["stealth"] = ["low", "medium", "high"][stealth_idx]
            options["delay"] = [0.5, 2.0, 5.0][stealth_idx]

        # proxy/cookie
        if self.ask_yes_no("\nاستخدام proxy؟", False):
            options["proxy"] = self.ask("Proxy URL")

        if self.ask_yes_no("استخدام cookie؟", False):
            options["cookie"] = self.ask("Cookie")

        # تأكيد
        print(f"\n{self.c('BOLD', 'الإعدادات النهائية:')}")
        for k, v in options.items():
            print(f"  {k}: {v}")

        if not self.ask_yes_no("\nمتابعة الفحص؟", True):
            return

        self._execute_scan(url, options)

    # ============================ Batch Scan ============================
    def _batch_scan(self):
        """فحص متعدد الأهداف"""
        self.header("📋 فحص متعدد الأهداف")

        print("أدخل URLs (واحد في كل سطر، سطر فارغ للإنهاء):")
        targets = []
        while True:
            try:
                url = input(f"  [{len(targets) + 1}] ").strip()
                if not url:
                    break
                if not url.startswith("http"):
                    url = "http://" + url
                targets.append(url)
            except (KeyboardInterrupt, EOFError):
                break

        if not targets:
            print(f"{self.c('RED', '[!]')} لا توجد أهداف")
            self.pause()
            return

        print(f"\n{self.c('GREEN', '[✓]')} تم إدخال {len(targets)} هدف")

        # اختيار profile
        profile_name = profile_menu()
        if not profile_name:
            return

        options = get_profile(profile_name)

        # concurrent scans
        concurrent = self.ask("عدد الفحوصات المتزامنة", "2")
        try:
            concurrent = int(concurrent)
        except ValueError:
            concurrent = 2

        # تأكيد
        if not self.ask_yes_no(f"\nبدء فحص {len(targets)} هدف؟", True):
            return

        # تشغيل
        from modules.batch_scanner import BatchScanner
        scanner = BatchScanner(options, max_concurrent=concurrent)
        summary = scanner.scan_batch(targets)

        # حفظ التقارير
        import time
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        json_file = f"batch_report_{timestamp}.json"
        html_file = f"batch_report_{timestamp}.html"

        scanner.save_summary(summary, json_file)
        scanner.save_html_summary(summary, html_file)

        print(f"\n{self.c('GREEN', '[✓]')} التقارير:")
        print(f"  JSON: {json_file}")
        print(f"  HTML: {html_file}")

        self.pause()

    # ============================ Payload Menu ============================
    def _payload_menu(self):
        """menu توليد payloads"""
        while True:
            self.header("🛠  توليد Payloads")

            options = [
                "🔄 Reverse Shell (18 نوع)",
                "🌐 Web Shell (7 أنواع)",
                "📝 SQLi Payloads (مشفرة)",
                "⚡ XSS Payloads (مشفرة)",
                "💥 Command Injection Payloads",
                "🥷 WAF Bypass Payloads",
                "📋 عرض كل Reverse Shells",
                "📋 عرض كل Web Shells",
                "← رجوع",
            ]

            choice = self.ask_choice("اختر:", options)

            if choice == 0:
                self._gen_reverse_shell()
            elif choice == 1:
                self._gen_web_shell()
            elif choice == 2:
                self._gen_sqli_payloads()
            elif choice == 3:
                self._gen_xss_payloads()
            elif choice == 4:
                self._gen_cmd_payloads()
            elif choice == 5:
                self._gen_waf_payloads()
            elif choice == 6:
                from modules.payload_generator import list_reverse_shells
                list_reverse_shells()
                self.pause()
            elif choice == 7:
                from modules.payload_generator import list_web_shells
                list_web_shells()
                self.pause()
            elif choice == 8:
                return

    def _gen_reverse_shell(self):
        """توليد reverse shell"""
        self.header("🔄 Reverse Shell Generator")

        ip = self.ask("Listener IP")
        if not ip:
            return

        port = self.ask("Listener Port", "4444")
        try:
            port = int(port)
        except ValueError:
            port = 4444

        from modules.payload_generator import REVERSE_SHELLS, generate_reverse_shell

        print(f"\n{self.c('BOLD', 'الأنواع المتاحة:')}")
        types = list(REVERSE_SHELLS.keys())
        for i, t in enumerate(types, 1):
            print(f"  {i}. {t} - {REVERSE_SHELLS[t][0]}")

        choice = self.ask_choice("\nاختر نوع", [t for t in types], 0)
        shell_type = types[choice]

        shell = generate_reverse_shell(shell_type, ip, port)
        if shell:
            print(f"\n{self.c('GREEN', 'Payload:')}")
            print(f"{self.c('CYAN', shell)}")
            print(f"\n{self.c('YELLOW', '[*]')} شغّل listener: nc -lvnp {port}")

            if self.ask_yes_no("\nحفظ في ملف؟", False):
                filename = self.ask("اسم الملف", f"shell_{shell_type}.txt")
                with open(filename, "w") as f:
                    f.write(shell)
                print(f"{self.c('GREEN', '[✓]')} تم الحفظ: {filename}")

        self.pause()

    def _gen_web_shell(self):
        """توليد web shell"""
        self.header("🌐 Web Shell Generator")

        from modules.payload_generator import WEB_SHELLS, generate_web_shell

        print(f"\n{self.c('BOLD', 'الأنواع المتاحة:')}")
        types = list(WEB_SHELLS.keys())
        for i, t in enumerate(types, 1):
            print(f"  {i}. {t} - {WEB_SHELLS[t][0]}")

        choice = self.ask_choice("\nاختر نوع", [t for t in types], 0)
        shell_type = types[choice]

        password = self.ask("Password", "ghost")

        ext = "php" if shell_type.startswith("php") else shell_type.split("-")[0]
        filename = self.ask("اسم الملف", f"shell.{ext}")

        shell = generate_web_shell(shell_type, password)
        if shell:
            with open(filename, "w") as f:
                f.write(shell)
            print(f"\n{self.c('GREEN', '[✓]')} Shell saved: {filename}")
            print(f"{self.c('YELLOW', '[!]')} ارفع الملف للموقع يدوياً")

        self.pause()

    def _gen_sqli_payloads(self):
        """توليد SQLi payloads"""
        from modules.payload_encoder import PayloadEncoder
        encoder = PayloadEncoder()
        payloads = encoder.generate_sqli_payloads()

        print(f"\n{self.c('GREEN', '[✓]')} Generated {len(payloads)} payloads")
        print(f"\n{self.c('BOLD', 'أول 15 payload:')}")
        for p in payloads[:15]:
            print(f"  [{p['encoder']:15s}] {p['encoded']}")

        if self.ask_yes_no("\nحفظ الكل في ملف؟", False):
            with open("sqli_payloads.txt", "w") as f:
                for p in payloads:
                    f.write(f"[{p['encoder']}] {p['original']} -> {p['encoded']}\n")
            print(f"{self.c('GREEN', '[✓]')} Saved: sqli_payloads.txt")

        self.pause()

    def _gen_xss_payloads(self):
        """توليد XSS payloads"""
        from modules.payload_encoder import PayloadEncoder
        encoder = PayloadEncoder()
        payloads = encoder.generate_xss_payloads()

        print(f"\n{self.c('GREEN', '[✓]')} Generated {len(payloads)} payloads")
        for p in payloads[:15]:
            print(f"  [{p['encoder']:15s}] {p['encoded']}")

        if self.ask_yes_no("\nحفظ الكل؟", False):
            with open("xss_payloads.txt", "w") as f:
                for p in payloads:
                    f.write(f"[{p['encoder']}] {p['original']} -> {p['encoded']}\n")
            print(f"{self.c('GREEN', '[✓]')} Saved: xss_payloads.txt")

        self.pause()

    def _gen_cmd_payloads(self):
        """توليد cmd payloads"""
        cmd = self.ask("الأمر", "id")
        from modules.payload_encoder import PayloadEncoder
        encoder = PayloadEncoder()
        payloads = encoder.generate_cmd_payloads(cmd)

        print(f"\n{self.c('GREEN', '[✓]')} Generated {len(payloads)} payloads")
        for p in payloads[:15]:
            print(f"  [{p['encoder']:15s}] {p['encoded']}")

        self.pause()

    def _gen_waf_payloads(self):
        """توليد WAF bypass payloads"""
        from modules.payload_encoder import PayloadEncoder
        encoder = PayloadEncoder()
        waf = encoder.generate_waf_bypass_payloads()

        for category, payloads in waf.items():
            print(f"\n{self.c('BOLD', category)}:")
            for p in payloads:
                print(f"  {p}")

        self.pause()

    # ============================ Target Manager ============================
    def _manage_targets(self):
        """إدارة الأهداف المحفوظة"""
        while True:
            self.header("💾 إدارة الأهداف المحفوظة")

            targets = self.config.get_targets()
            print(f"{self.c('BOLD', 'الأهداف المحفوظة:')} {len(targets)}")

            if targets:
                for i, t in enumerate(targets, 1):
                    print(f"  {i}. {t.get('name', 'غير مسمى')} - {t['url']}")

            options = ["➕ إضافة هدف", "🗑  حذف هدف", "📂 فحص هدف محفوظ", "← رجوع"]
            choice = self.ask_choice("\nاختر:", options)

            if choice == 0:
                url = self.ask("URL")
                name = self.ask("الاسم (اختياري)", url)
                if url:
                    self.config.add_target(url, name)
                    print(f"{self.c('GREEN', '[✓]')} تم الإضافة")
            elif choice == 1:
                if not targets:
                    print(f"{self.c('RED', '[!]')} لا توجد أهداف")
                else:
                    idx = self.ask_choice("اختر هدف للحذف:",
                                        [t["url"] for t in targets])
                    if 0 <= idx < len(targets):
                        self.config.remove_target(targets[idx]["url"])
                        print(f"{self.c('GREEN', '[✓]')} تم الحذف")
            elif choice == 2:
                if not targets:
                    print(f"{self.c('RED', '[!]')} لا توجد أهداف")
                else:
                    idx = self.ask_choice("اختر هدف للفحص:",
                                        [t["url"] for t in targets])
                    if 0 <= idx < len(targets):
                        self._run_profile("standard")
                        # تخطي URL لأن الـ _run_profile بيسأل
            elif choice == 3:
                return

            self.pause()

    # ============================ Settings ============================
    def _settings_menu(self):
        """menu الإعدادات"""
        while True:
            self.header("⚙️  الإعدادات")

            options = [
                "📋 عرض الإعدادات",
                "🔄 إعادة التعيين",
                "📝 تعديل عمق الفحص الافتراضي",
                "📝 تعديل عدد الـ threads",
                "🌐 تعديل الـ proxy",
                "🎨 تفعيل/إيقاف الألوان",
                "← رجوع",
            ]

            choice = self.ask_choice("اختر:", options)

            if choice == 0:
                self.config.print_config()
                self.pause()
            elif choice == 1:
                if self.ask_yes_no("متأكد من إعادة التعيين؟", False):
                    self.config.reset()
                    print(f"{self.c('GREEN', '[✓]')} تم إعادة التعيين")
                    self.pause()
            elif choice == 2:
                depth = self.ask("العمق", self.config.get("general", "default_depth"))
                if depth in ("fast", "medium", "deep"):
                    self.config.set("general", "default_depth", depth)
                    print(f"{self.c('GREEN', '[✓]')} تم التحديث")
                self.pause()
            elif choice == 3:
                threads = self.ask("Threads", str(self.config.get("general", "default_threads")))
                try:
                    self.config.set("general", "default_threads", int(threads))
                    print(f"{self.c('GREEN', '[✓]')} تم التحديث")
                except ValueError:
                    pass
                self.pause()
            elif choice == 4:
                proxy = self.ask("Proxy URL", self.config.get("network", "proxy"))
                self.config.set("network", "proxy", proxy)
                print(f"{self.c('GREEN', '[✓]')} تم التحديث")
                self.pause()
            elif choice == 5:
                current = self.config.get("ui", "colors", True)
                self.config.set("ui", "colors", not current)
                print(f"{self.c('GREEN', '[✓]')} الألوان: {'ON' if not current else 'OFF'}")
                self.pause()
            elif choice == 6:
                return

    # ============================ Help ============================
    def _help(self):
        """menu المساعدة"""
        self.header("❓ المساعدة")

        print(f"""{self.c('BOLD', '👻 ghostpwn - دليل الاستخدام')}

{self.c('CYAN', '🎯 البداية السريعة:')}
  1. اختر "فحص سريع" من القائمة الرئيسية
  2. أدخل URL الموقع (مثل: https://example.com)
  3. انتظر حتى ينتهي الفحص
  4. افتح التقرير HTML في المتصفح

{self.c('CYAN', '📋 أنواع الفحص:')}
  - {self.c('BOLD', 'سريع')}: فحص أساسي (2-5 دقائق)
  - {self.c('BOLD', 'قياسي')}: فحص متوازن (10-20 دقيقة)
  - {self.c('BOLD', 'عميق')}: فحص شامل (30-60 دقيقة)
  - {self.c('BOLD', 'صامت')}: فحص بطيء لتجنب WAF

{self.c('CYAN', '🛠 توليد Payloads:')}
  - Reverse Shells: 18 نوع
  - Web Shells: 7 أنواع
  - SQLi/XSS/CMD payloads مشفرة
  - WAF bypass payloads

{self.c('CYAN', '📊 التقارير:')}
  - HTML: تقرير تفاعلي
  - JSON: للمعالجة البرمجية
  - CSV: للتحليل في Excel
  - Audit log: سجل تدقيق

{self.c('CYAN', '⚠️  تنبيه قانوني:')}
  استخدم الأداة فقط على مواقع تملكها أو لديك إذن بفحصها.

{self.c('CYAN', '💡 نصائح:')}
  - استخدم "فحص سريع" للبدء
  - لو فيه WAF، استخدم "فحص صامت"
  - احفظ الأهداف المتكررة في "إدارة الأهداف"
  - فعّل الألوان من الإعدادات للتمييز
""")
        self.pause()

    # ============================ Execute Scan ============================
    def _execute_scan(self, url: str, options: dict):
        """تنفيذ الفحص"""
        self.clear()
        print(f"\n{self.c('GREEN', '🚀 بدء الفحص...')}")
        print(f"{self.c('BOLD', 'الهدف:')} {url}")
        print(f"{self.c('BOLD', 'الإعدادات:')} {options}")
        print()

        # دمج مع الإعدادات المحفوظة
        options["output"] = self.config.get("general", "output_dir")
        options.setdefault("user_agent", self.config.get("general", "default_user_agent"))

        try:
            from modules.auto_pentest import AutoPentest
            auto = AutoPentest(url, options)
            result = auto.run()

            print(f"\n{self.c('GREEN', '[✓]')} اكتمل الفحص!")
            print(f"  المدة: {result['duration']}s")
            print(f"  الثغرات: {result['vulns_count']}")
            print(f"  الاستغلال: {result['exploits_count']}")

            # حفظ في التاريخ
            self.config.add_history({
                "url": url,
                "timestamp": __import__("time").strftime("%Y-%m-%d %H:%M:%S"),
                "vulns": result["vulns_count"],
                "exploits": result["exploits_count"],
                "duration": result["duration"],
            })

        except Exception as e:
            print(f"\n{self.c('RED', '[✗]')} خطأ: {e}")
            import traceback
            traceback.print_exc()

        self.pause()


if __name__ == "__main__":
    wizard = Wizard()
    wizard.main_menu()
