#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Plugin System
نظام Plugins يتيح للمستخدم كتابة modules خاصة

كل plugin لازم يحتوي على:
- class Plugin inherits from BasePlugin
- def run(self, url) -> List[Dict]  # يرجع الثغرات
- def info(self) -> Dict  # معلومات الـ plugin

مثال plugin:
    class MyPlugin(BasePlugin):
        def info(self):
            return {"name": "My Plugin", "version": "1.0"}
        
        def run(self, url):
            # فحص مخصص
            return [{"type": "custom", "severity": "info"}]
"""
import os
import sys
import importlib
import inspect
import json
from typing import Dict, List, Optional, Type

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.arabic_display import SmartLogger, Colors, fix_display


class BasePlugin:
    """الـ base class لكل الـ plugins"""

    name = "Base Plugin"
    version = "1.0"
    description = "Base plugin class"
    author = "Unknown"

    def __init__(self, http_client=None, audit_logger=None):
        self.client = http_client
        self.audit = audit_logger
        self.logger = SmartLogger()

    def info(self) -> Dict:
        """معلومات الـ plugin"""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
        }

    def run(self, url: str) -> List[Dict]:
        """تنفيذ الـ plugin - يجب override"""
        raise NotImplementedError("Plugin must implement run()")

    def log(self, msg, level="info"):
        """logging"""
        getattr(self.logger, level, self.logger.info)(f"[{self.name}] {msg}")


class PluginManager:
    """مدير الـ plugins"""

    def __init__(self, plugins_dir: str = None, audit_logger=None):
        if plugins_dir is None:
            plugins_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "plugins"
            )

        self.plugins_dir = plugins_dir
        self.audit = audit_logger
        self.logger = SmartLogger()

        self.loaded_plugins: Dict[str, BasePlugin] = {}
        self.plugin_info: List[Dict] = []

        # إنشاء مجلد plugins لو مش موجود
        os.makedirs(self.plugins_dir, exist_ok=True)

        # إنشاء __init__.py لو مش موجود
        init_file = os.path.join(self.plugins_dir, "__init__.py")
        if not os.path.exists(init_file):
            with open(init_file, "w") as f:
                f.write("")

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[PLUGIN] {msg}", level)

    def load_plugins(self) -> int:
        """تحميل كل الـ plugins"""
        self._log(f"تحميل plugins من: {self.plugins_dir}", "info")

        count = 0
        for filename in os.listdir(self.plugins_dir):
            if not filename.endswith(".py") or filename.startswith("_"):
                continue

            module_name = filename[:-3]
            try:
                # إضافة plugins dir للـ path
                if self.plugins_dir not in sys.path:
                    sys.path.insert(0, self.plugins_dir)

                # استيراد الـ module
                module = importlib.import_module(module_name)

                # البحث عن class يورث BasePlugin
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, BasePlugin) and obj != BasePlugin:
                        # إنشاء instance
                        plugin = obj()
                        self.loaded_plugins[module_name] = plugin
                        self.plugin_info.append(plugin.info())
                        count += 1
                        self._log(f"  ✓ تم تحميل: {plugin.name} v{plugin.version}", "success")
                        break

            except Exception as e:
                self._log(f"  ✗ فشل تحميل {module_name}: {e}", "error")

        self._log(f"تم تحميل {count} plugin", "info")
        return count

    def run_plugin(self, plugin_name: str, url: str, http_client=None) -> List[Dict]:
        """تشغيل plugin معين"""
        if plugin_name not in self.loaded_plugins:
            self._log(f"Plugin غير موجود: {plugin_name}", "error")
            return []

        plugin = self.loaded_plugins[plugin_name]
        
        # تمرير http_client لو مش موجود
        if http_client and not plugin.client:
            plugin.client = http_client

        self._log(f"تشغيل plugin: {plugin.name}", "info")
        
        try:
            results = plugin.run(url)
            self._log(f"  ✓ {len(results)} نتيجة", "success")
            return results
        except Exception as e:
            self._log(f"  ✗ خطأ: {e}", "error")
            return []

    def run_all(self, url: str, http_client=None) -> Dict[str, List[Dict]]:
        """تشغيل كل الـ plugins"""
        self._log(f"تشغيل كل plugins ({len(self.loaded_plugins)})...", "phase")

        all_results = {}
        all_vulns = []

        for name, plugin in self.loaded_plugins.items():
            results = self.run_plugin(name, url, http_client)
            all_results[name] = results
            all_vulns.extend(results)

        self._log(f"إجمالي النتائج: {len(all_vulns)}", "info")
        return all_results

    def list_plugins(self) -> List[Dict]:
        """عرض كل الـ plugins"""
        return self.plugin_info

    def print_plugins(self):
        """عرض قائمة الـ plugins"""
        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")
        print(f"{Colors.MAGENTA}  🔌 Loaded Plugins{Colors.NC}")
        print(f"{Colors.MAGENTA}{'═'*60}{Colors.NC}")

        if not self.plugin_info:
            print(f"\n  {Colors.YELLOW}لا توجد plugins محملة{Colors.NC}")
            print(f"  {Colors.GRAY}ضع plugins في: {self.plugins_dir}/{Colors.NC}")
            return

        for i, info in enumerate(self.plugin_info, 1):
            print(f"\n  {i}. {Colors.GREEN}{info['name']}{Colors.NC} v{info['version']}")
            print(f"     {fix_display(info.get('description', ''))}")
            print(f"     Author: {info.get('author', 'Unknown')}")

        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")


# ============================ Example Plugin ============================
class ExamplePlugin(BasePlugin):
    """مثال plugin - يمكن للمستخدم نسخه وتعديله"""

    name = "Example Plugin"
    version = "1.0"
    description = "مثال لـ plugin يفحص header معين"
    author = "ghostpwn"

    def run(self, url: str) -> List[Dict]:
        """فحص مخصص"""
        results = []

        if not self.client:
            return results

        resp = self.client.get(url)
        headers = resp.get("headers", {})

        # فحص custom header
        if "X-Custom-Header" in headers:
            results.append({
                "type": "custom_header_found",
                "severity": "info",
                "url": url,
                "title": "Custom header detected",
                "evidence": f"X-Custom-Header: {headers['X-Custom-Header']}",
            })

        return results


# ============================ Plugin Template Generator ============================
PLUGIN_TEMPLATE = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Plugin: {plugin_name}
Description: {description}
Author: {author}
Version: {version}
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from plugin_base import BasePlugin
except ImportError:
    # fallback لو plugin_base مش متاح
    class BasePlugin:
        def __init__(self, http_client=None, audit_logger=None):
            self.client = http_client
            self.audit = audit_logger
        def run(self, url):
            return []


class {class_name}(BasePlugin):
    """Plugin: {plugin_name}"""

    name = "{plugin_name}"
    version = "{version}"
    description = "{description}"
    author = "{author}"

    def run(self, url: str) -> list:
        """
        تنفيذ الفحص
        url: الهدف URL
        يرجع: قائمة من الثغرات
        """
        results = []

        # TODO: اكتب الفحص الخاص بك هنا
        # مثال:
        # if self.client:
        #     resp = self.client.get(url)
        #     if "vulnerable" in resp["body"]:
        #         results.append({{
        #             "type": "custom_vuln",
        #             "severity": "high",
        #             "url": url,
        #             "title": "Custom vulnerability",
        #             "evidence": "Found 'vulnerable' in response",
        #         }})

        return results
'''


def create_plugin(name: str, description: str = "", author: str = "Anonymous",
                  version: str = "1.0", output_dir: str = None) -> str:
    """إنشاء plugin جديد من template"""
    if output_dir is None:
        output_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "plugins"
        )

    os.makedirs(output_dir, exist_ok=True)

    # تحويل name لـ class name
    class_name = "".join(word.capitalize() for word in name.split("_"))

    content = PLUGIN_TEMPLATE.format(
        plugin_name=name,
        class_name=class_name,
        description=description,
        author=author,
        version=version,
    )

    filepath = os.path.join(output_dir, f"{name}.py")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)

    return filepath


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Plugin Manager")
    parser.add_argument("--list", action="store_true", help="List loaded plugins")
    parser.add_argument("--run", help="Run specific plugin")
    parser.add_argument("--run-all", action="store_true", help="Run all plugins")
    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--create", help="Create new plugin")
    parser.add_argument("--desc", default="My custom plugin", help="Plugin description")
    args = parser.parse_args()

    pm = PluginManager()

    if args.create:
        filepath = create_plugin(args.create, args.desc)
        print(f"[✓] Plugin created: {filepath}")
        print(f"    عدّل الملف وأضف الفحص الخاص بك")
    elif args.list:
        pm.load_plugins()
        pm.print_plugins()
    elif args.run_all and args.url:
        pm.load_plugins()
        results = pm.run_all(args.url)
        print(f"\nResults: {json.dumps(results, indent=2, ensure_ascii=False)}")
    elif args.run and args.url:
        pm.load_plugins()
        results = pm.run_plugin(args.run, args.url)
        print(f"\nResults: {json.dumps(results, indent=2, ensure_ascii=False)}")
    else:
        parser.print_help()
