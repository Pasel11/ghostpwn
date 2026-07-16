#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Configuration System
حفظ وتحميل الإعدادات
"""
import os
import json
from typing import Dict, Optional


class Config:
    """نظام الإعدادات"""

    DEFAULT_CONFIG = {
        "general": {
            "default_depth": "medium",
            "default_threads": 10,
            "default_timeout": 15,
            "default_user_agent": "ghostpwn/1.0",
            "output_dir": "reports",
        },
        "scanning": {
            "skip_port": False,
            "skip_crawl": False,
            "skip_dir": False,
            "skip_vuln": False,
            "skip_subdomain": False,
            "skip_tech": False,
            "auto_exploit": False,
            "auto_brute": False,
            "dump_db": False,
            "deploy_shell": False,
        },
        "stealth": {
            "enabled": False,
            "level": "medium",
            "delay": 0,
        },
        "reports": {
            "html": True,
            "json": True,
            "csv": False,
            "sarif": False,
            "pdf": False,
        },
        "network": {
            "proxy": "",
            "cookie": "",
            "auth_header": "",
        },
        "ui": {
            "language": "ar",
            "colors": True,
            "progress_bar": True,
        },
        "targets": [],  # قائمة الأهداف المحفوظة
        "history": [],  # تاريخ الفحوصات
    }

    def __init__(self, config_file: str = None):
        if config_file is None:
            home = os.path.expanduser("~")
            self.config_file = os.path.join(home, ".ghostpwn_config.json")
        else:
            self.config_file = config_file

        self.config = self.DEFAULT_CONFIG.copy()
        self.load()

    def load(self):
        """تحميل الإعدادات من الملف"""
        try:
            if os.path.isfile(self.config_file):
                with open(self.config_file, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                    # دمج الإعدادات المحفوظة مع الافتراضية
                    for section, values in saved.items():
                        if section in self.config:
                            if isinstance(self.config[section], dict):
                                self.config[section].update(values)
                            else:
                                self.config[section] = values
                        else:
                            self.config[section] = values
        except Exception:
            pass

    def save(self):
        """حفظ الإعدادات"""
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(self.config, f, ensure_ascii=False, indent=2)
            return True
        except Exception:
            return False

    def get(self, section: str, key: str = None, default=None):
        """الحصول على قيمة"""
        if section not in self.config:
            return default
        if key is None:
            return self.config[section]
        return self.config[section].get(key, default)

    def set(self, section: str, key: str, value):
        """تعيين قيمة"""
        if section not in self.config:
            self.config[section] = {}
        if isinstance(self.config[section], dict):
            self.config[section][key] = value
        else:
            self.config[section] = value
        self.save()

    def add_target(self, target: str, name: str = ""):
        """إضافة هدف محفوظ"""
        target_entry = {"url": target, "name": name or target}
        if target_entry not in self.config["targets"]:
            self.config["targets"].append(target_entry)
            self.save()

    def remove_target(self, target: str):
        """حذف هدف"""
        self.config["targets"] = [t for t in self.config["targets"] if t["url"] != target]
        self.save()

    def get_targets(self) -> list:
        """الحصول على كل الأهداف"""
        return self.config.get("targets", [])

    def add_history(self, entry: dict):
        """إضافة لتاريخ الفحوصات"""
        self.config["history"].append(entry)
        # الاحتفاظ بآخر 50 فحص فقط
        if len(self.config["history"]) > 50:
            self.config["history"] = self.config["history"][-50:]
        self.save()

    def get_history(self) -> list:
        """الحصول على تاريخ الفحوصات"""
        return self.config.get("history", [])

    def reset(self):
        """إعادة التعيين للإعدادات الافتراضية"""
        self.config = self.DEFAULT_CONFIG.copy()
        self.save()

    def print_config(self):
        """عرض الإعدادات"""
        print("\n⚙️  إعدادات ghostpwn:")
        print("=" * 60)
        for section, values in self.config.items():
            if isinstance(values, dict):
                print(f"\n  [{section}]")
                for k, v in values.items():
                    print(f"    {k}: {v}")
            elif isinstance(values, list):
                print(f"\n  [{section}] ({len(values)} items)")
                for item in values[:5]:
                    print(f"    - {item}")
                if len(values) > 5:
                    print(f"    ... and {len(values) - 5} more")
        print("\n" + "=" * 60)
