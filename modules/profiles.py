#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Scan Profiles
إعدادات مسبقة جاهزة لأنواع الفحص المختلفة
"""
import sys
import os
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ============================ Profiles Definition ============================
PROFILES = {
    "quick": {
        "name": "فحص سريع",
        "description": "فحص سريع للثغرات الأساسية (2-5 دقائق)",
        "icon": "⚡",
        "options": {
            "depth": "fast",
            "threads": 20,
            "timeout": 10,
            "skip_port": True,
            "skip_crawl": True,
            "skip_dir": True,
            "skip_subdomain": True,
            "auto_exploit": False,
        },
    },
    "standard": {
        "name": "فحص قياسي",
        "description": "فحص متوازن شامل (10-20 دقيقة)",
        "icon": "🎯",
        "options": {
            "depth": "medium",
            "threads": 10,
            "timeout": 15,
            "skip_port": False,
            "skip_crawl": False,
            "skip_dir": False,
            "skip_subdomain": False,
            "auto_exploit": False,
        },
    },
    "deep": {
        "name": "فحص عميق",
        "description": "فحص شامل وعميق (30-60 دقيقة)",
        "icon": "🔍",
        "options": {
            "depth": "deep",
            "threads": 5,
            "timeout": 30,
            "skip_port": False,
            "skip_crawl": False,
            "skip_dir": False,
            "skip_subdomain": False,
            "auto_exploit": False,
        },
    },
    "stealth": {
        "name": "فحص صامت",
        "description": "فحص بطيء وصامت لتجنب WAF/IDS",
        "icon": "🥷",
        "options": {
            "depth": "medium",
            "threads": 1,
            "timeout": 20,
            "skip_port": False,
            "skip_crawl": False,
            "skip_dir": False,
            "skip_subdomain": False,
            "auto_exploit": False,
            "stealth": "high",
            "delay": 5.0,
        },
    },
    "vuln_only": {
        "name": "فحص الثغرات فقط",
        "description": "فحص الثغرات بدون port/crawl/dir",
        "icon": "🐛",
        "options": {
            "depth": "medium",
            "threads": 10,
            "timeout": 15,
            "skip_port": True,
            "skip_crawl": True,
            "skip_dir": True,
            "skip_subdomain": True,
            "skip_tech": True,
            "auto_exploit": False,
        },
    },
    "recon": {
        "name": "استطلاع فقط",
        "description": "جمع معلومات بدون فحص ثغرات",
        "icon": "📡",
        "options": {
            "depth": "medium",
            "threads": 10,
            "timeout": 15,
            "skip_port": False,
            "skip_crawl": False,
            "skip_dir": False,
            "skip_subdomain": False,
            "skip_vuln": True,
            "auto_exploit": False,
        },
    },
    "full_attack": {
        "name": "هجوم كامل",
        "description": "فحص + استغلال + brute + dump (خطير!)",
        "icon": "⚔️",
        "options": {
            "depth": "deep",
            "threads": 10,
            "timeout": 30,
            "skip_port": False,
            "skip_crawl": False,
            "skip_dir": False,
            "skip_subdomain": False,
            "auto_exploit": True,
            "auto_brute": True,
            "dump_db": True,
            "deploy_shell": False,  # يحتاج listener_ip
        },
    },
    "wordpress": {
        "name": "فحص WordPress",
        "description": "فحص مخصص لمواقع WordPress",
        "icon": "📝",
        "options": {
            "depth": "medium",
            "threads": 5,
            "timeout": 15,
            "skip_port": True,
            "skip_crawl": False,
            "skip_dir": False,
            "skip_subdomain": True,
            "auto_exploit": False,
        },
    },
    "api": {
        "name": "فحص API",
        "description": "فحص مخصص لـ REST/GraphQL APIs",
        "icon": "🔌",
        "options": {
            "depth": "medium",
            "threads": 5,
            "timeout": 15,
            "skip_port": True,
            "skip_crawl": False,
            "skip_dir": True,
            "skip_subdomain": True,
            "auto_exploit": False,
        },
    },
}


def list_profiles():
    """عرض كل الـ profiles"""
    print("\n📋 Profiles المتاحة:")
    print("=" * 70)
    for key, profile in PROFILES.items():
        print(f"  {profile['icon']} {key:15s} - {profile['name']}")
        print(f"  {'':18s}  {profile['description']}")
        print()
    print("=" * 70)


def get_profile(name: str) -> Dict:
    """الحصول على profile بالاسم"""
    return PROFILES.get(name, {}).get("options", {})


def profile_menu() -> str:
    """عرض menu لاختيار profile"""
    print("\n📋 اختر نوع الفحص:")
    print("-" * 60)

    items = list(PROFILES.items())
    for i, (key, profile) in enumerate(items, 1):
        print(f"  {i}. {profile['icon']} {profile['name']}")
        print(f"     {profile['description']}")

    print(f"  0. خروج")
    print("-" * 60)

    while True:
        try:
            choice = input(f"\nاختر رقم (1-{len(items)}): ").strip()
            if choice == "0":
                return None
            idx = int(choice) - 1
            if 0 <= idx < len(items):
                return items[idx][0]
            print(f"[!] اختر رقم من 1 إلى {len(items)}")
        except ValueError:
            print("[!] أدخل رقم صحيح")
        except (KeyboardInterrupt, EOFError):
            return None


if __name__ == "__main__":
    list_profiles()
    selected = profile_menu()
    if selected:
        print(f"\n[✓] Selected: {selected}")
        print(f"Options: {get_profile(selected)}")
