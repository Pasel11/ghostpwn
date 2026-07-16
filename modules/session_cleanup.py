#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Session Cleanup
ينظّف ملفات الأداة المؤقتة على جهازك أنت فقط (لا يمسح أي شيء على الهدف)

⚠️  ملاحظة مهمة:
  - هذا ينظّف ملفاتك المحلية فقط (التقارير المؤقتة، cache، إلخ)
  - لا يمسح logs على الأنظمة المستهدفة
  - الـ audit logs يتم الاحتفاظ بها (لأنها أدلة مهمة)
"""
import os
import sys
import shutil
import glob
import time
from typing import List


class SessionCleanup:
    """تنظيف محلي آمن"""

    def __init__(self, base_dir: str = "."):
        self.base_dir = base_dir
        self.cleaned_files: List[str] = []
        self.cleaned_dirs: List[str] = []

    def clean_temp_files(self) -> List[str]:
        """تنظيف ملفات temp"""
        temp_patterns = [
            "*.tmp",
            "*.bak",
            "*.swp",
            "*~",
            "*.pyc",
            "*.pyo",
        ]

        cleaned = []
        for pattern in temp_patterns:
            for filepath in glob.glob(os.path.join(self.base_dir, "**", pattern), recursive=True):
                try:
                    os.remove(filepath)
                    cleaned.append(filepath)
                    self.cleaned_files.append(filepath)
                except Exception:
                    pass

        # __pycache__ directories
        for pycache in glob.glob(os.path.join(self.base_dir, "**", "__pycache__"), recursive=True):
            try:
                shutil.rmtree(pycache)
                cleaned.append(pycache)
                self.cleaned_dirs.append(pycache)
            except Exception:
                pass

        return cleaned

    def clean_reports_older_than(self, days: int = 30) -> List[str]:
        """تنظيف التقارير الأقدم من X يوم"""
        reports_dir = os.path.join(self.base_dir, "reports")
        if not os.path.isdir(reports_dir):
            return []

        cleaned = []
        cutoff_time = time.time() - (days * 24 * 60 * 60)

        for entry in os.listdir(reports_dir):
            entry_path = os.path.join(reports_dir, entry)
            try:
                mtime = os.path.getmtime(entry_path)
                if mtime < cutoff_time:
                    if os.path.isdir(entry_path):
                        shutil.rmtree(entry_path)
                    else:
                        os.remove(entry_path)
                    cleaned.append(entry_path)
                    self.cleaned_files.append(entry_path)
            except Exception:
                pass

        return cleaned

    def clean_generated_shells(self) -> List[str]:
        """تنظيف الـ shells المولّدة (لو موجودة محلياً)"""
        shell_patterns = [
            "shell.php",
            "shell.asp",
            "shell.aspx",
            "shell.jsp",
            "shells_*.txt",
            "all_shells.txt",
        ]

        cleaned = []
        for pattern in shell_patterns:
            for filepath in glob.glob(os.path.join(self.base_dir, pattern)):
                try:
                    os.remove(filepath)
                    cleaned.append(filepath)
                    self.cleaned_files.append(filepath)
                except Exception:
                    pass

        return cleaned

    def keep_only_audit_logs(self) -> List[str]:
        """حذف كل شيء من reports ما عدا audit logs (الأدلة المهمة)"""
        reports_dir = os.path.join(self.base_dir, "reports")
        if not os.path.isdir(reports_dir):
            return []

        cleaned = []
        audit_dir = os.path.join(reports_dir, "audit")

        for entry in os.listdir(reports_dir):
            entry_path = os.path.join(reports_dir, entry)
            if entry == "audit":
                continue  # الحفاظ على audit logs

            try:
                if os.path.isdir(entry_path):
                    shutil.rmtree(entry_path)
                else:
                    os.remove(entry_path)
                cleaned.append(entry_path)
                self.cleaned_files.append(entry_path)
            except Exception:
                pass

        return cleaned

    def full_local_cleanup(self, keep_audit: bool = True) -> dict:
        """تنظيف محلي شامل"""
        results = {
            "temp_files": self.clean_temp_files(),
            "old_reports": self.clean_reports_older_than(days=30),
            "generated_shells": self.clean_generated_shells(),
        }

        if not keep_audit:
            results["audit_logs"] = self.keep_only_audit_logs()
        else:
            results["audit_logs"] = "KEPT (important evidence)"

        return results

    def print_summary(self):
        """عرض ملخص التنظيف"""
        print(f"\n🧹 Session Cleanup Summary")
        print(f"{'='*60}")
        print(f"Files cleaned: {len(self.cleaned_files)}")
        print(f"Directories cleaned: {len(self.cleaned_dirs)}")

        if self.cleaned_files:
            print(f"\nFiles:")
            for f in self.cleaned_files[:20]:
                print(f"  - {f}")
            if len(self.cleaned_files) > 20:
                print(f"  ... and {len(self.cleaned_files) - 20} more")

        if self.cleaned_dirs:
            print(f"\nDirectories:")
            for d in self.cleaned_dirs[:10]:
                print(f"  - {d}")

        print(f"\n✓ Audit logs preserved (important for reporting)")
        print(f"{'='*60}\n")


# CLI
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Session Cleanup")
    parser.add_argument("--dir", default=".", help="Base directory")
    parser.add_argument("--temp", action="store_true", help="Clean temp files only")
    parser.add_argument("--old-reports", type=int, metavar="DAYS",
                       help="Clean reports older than X days")
    parser.add_argument("--shells", action="store_true", help="Clean generated shells")
    parser.add_argument("--full", action="store_true", help="Full local cleanup")
    parser.add_argument("--no-audit", action="store_true",
                       help="Also delete audit logs (NOT RECOMMENDED)")
    args = parser.parse_args()

    cleanup = SessionCleanup(args.dir)

    if args.temp:
        result = cleanup.clean_temp_files()
        print(f"Cleaned {len(result)} temp files")
    elif args.old_reports:
        result = cleanup.clean_reports_older_than(args.old_reports)
        print(f"Cleaned {len(result)} old reports")
    elif args.shells:
        result = cleanup.clean_generated_shells()
        print(f"Cleaned {len(result)} shells")
    elif args.full:
        result = cleanup.full_local_cleanup(keep_audit=not args.no_audit)
        cleanup.print_summary()
        print("Details:")
        for category, items in result.items():
            if isinstance(items, list):
                print(f"  {category}: {len(items)} items")
            else:
                print(f"  {category}: {items}")
    else:
        parser.print_help()
