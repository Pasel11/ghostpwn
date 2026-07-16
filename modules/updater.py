#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Auto Updater
فحص وتحديث تلقائي من GitHub
"""
import os
import sys
import json
import time
import urllib.request
import urllib.error
from typing import Dict, Optional


GITHUB_API = "https://api.github.com/repos/Pasel11/ghostpwn/releases/latest"
GITHUB_LATEST = "https://api.github.com/repos/Pasel11/ghostpwn/commits/main"
CURRENT_VERSION = "1.0.0"


class Updater:
    """تحديث تلقائي"""

    def __init__(self):
        self.current_version = CURRENT_VERSION

    def check_for_updates(self) -> Dict:
        """فحص وجود تحديثات"""
        try:
            req = urllib.request.Request(GITHUB_LATEST, headers={
                "User-Agent": "ghostpwn-updater",
                "Accept": "application/vnd.github.v3+json",
            })
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            latest_commit = data.get("sha", "")[:8]
            commit_date = data.get("commit", {}).get("author", {}).get("date", "")
            commit_msg = data.get("commit", {}).get("message", "").split("\n")[0]

            return {
                "has_update": True,  # نفترض إن فيه تحديث لو الـ commit مختلف
                "latest_commit": latest_commit,
                "commit_date": commit_date,
                "commit_message": commit_msg,
                "current_version": self.current_version,
            }
        except urllib.error.URLError as e:
            return {
                "has_update": False,
                "error": f"Network error: {e}",
            }
        except Exception as e:
            return {
                "has_update": False,
                "error": str(e),
            }

    def get_local_commit(self) -> Optional[str]:
        """الحصول على الـ commit المحلي"""
        try:
            import subprocess
            result = subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None

    def update(self) -> Dict:
        """تنفيذ التحديث"""
        try:
            import subprocess

            # التأكد إننا في git repo
            if not os.path.isdir(".git"):
                return {
                    "success": False,
                    "error": "Not a git repository. Clone from GitHub first.",
                }

            # git fetch
            print("  [*] Fetching updates...")
            result = subprocess.run(
                ["git", "fetch", "origin"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"git fetch failed: {result.stderr}",
                }

            # git pull
            print("  [*] Pulling updates...")
            result = subprocess.run(
                ["git", "pull", "origin", "main"],
                capture_output=True, text=True, timeout=60
            )

            if result.returncode == 0:
                return {
                    "success": True,
                    "output": result.stdout,
                }
            else:
                return {
                    "success": False,
                    "error": f"git pull failed: {result.stderr}",
                }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Update timed out",
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
            }

    def check_and_update(self, auto: bool = False) -> bool:
        """فحص وتحديث"""
        print(f"\n🔄 فحص التحديثات...")
        print(f"  الإصدار الحالي: {self.current_version}")

        updates = self.check_for_updates()
        if updates.get("error"):
            print(f"  [!] {updates['error']}")
            return False

        if not updates.get("has_update"):
            print(f"  [✓] أنت على أحدث إصدار")
            return True

        local_commit = self.get_local_commit()
        latest_commit = updates.get("latest_commit", "")

        print(f"  [!] تحديث متاح!")
        print(f"      المحلي: {local_commit or 'unknown'}")
        print(f"      الأحدث: {latest_commit}")
        print(f"      التاريخ: {updates.get('commit_date', '')}")
        print(f"      الرسالة: {updates.get('commit_message', '')}")

        if local_commit == latest_commit:
            print(f"  [✓] أنت على أحدث commit")
            return True

        if auto:
            should_update = True
        else:
            try:
                answer = input("\n  تحديث الآن؟ (y/N): ").strip().lower()
                should_update = answer in ("y", "yes", "نعم")
            except (KeyboardInterrupt, EOFError):
                should_update = False

        if should_update:
            print("\n  بدء التحديث...")
            result = self.update()
            if result.get("success"):
                print(f"  [✓] تم التحديث بنجاح!")
                print(f"      {result.get('output', '')[:200]}")
                return True
            else:
                print(f"  [✗] فشل التحديث: {result.get('error')}")
                return False

        return False


if __name__ == "__main__":
    updater = Updater()
    updater.check_and_update(auto="--auto" in sys.argv)
