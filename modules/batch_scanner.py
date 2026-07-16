#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Batch Scanner
فحص أهداف متعددة في نفس الوقت
"""
import sys
import os
import time
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient
from modules.auto_pentest import AutoPentest


class BatchScanner:
    """فحص أهداف متعددة"""

    def __init__(self, options: Dict = None, max_concurrent: int = 3):
        self.options = options or {}
        self.max_concurrent = max_concurrent
        self.results = []
        self.lock = threading.Lock()

    def log(self, msg, level="info"):
        icons = {"info": "[*]", "success": "[✓]", "warn": "[!]", "error": "[✗]"}
        colors = {"info": "\033[1;36m", "success": "\033[1;32m",
                 "warn": "\033[1;33m", "error": "\033[1;31m"}
        nc = "\033[0m"
        icon = icons.get(level, "[*]")
        color = colors.get(level, "")
        with self.lock:
            print(f"{color}{icon}{nc} {msg}")

    def scan_single(self, url: str) -> Dict:
        """فحص هدف واحد"""
        self.log(f"Starting scan: {url}")
        start_time = time.time()

        try:
            # تعديل الـ options للـ target ده
            target_options = self.options.copy()
            auto = AutoPentest(url, target_options)
            result = auto.run()

            result["scan_duration"] = time.time() - start_time
            self.log(f"Completed: {url} ({result['vulns_count']} vulns, "
                    f"{result['exploits_count']} exploits)", "success")

            with self.lock:
                self.results.append(result)

            return result

        except Exception as e:
            self.log(f"Failed: {url} - {e}", "error")
            return {
                "target": url,
                "error": str(e),
                "vulns_count": 0,
                "exploits_count": 0,
                "scan_duration": time.time() - start_time,
            }

    def scan_batch(self, targets: List[str]) -> List[Dict]:
        """فحص مجموعة أهداف"""
        self.log(f"Starting batch scan of {len(targets)} targets")
        self.log(f"Max concurrent scans: {self.max_concurrent}")
        self.log(f"Total estimated time: ~{len(targets) * 60 / self.max_concurrent:.0f}s")

        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            futures = {executor.submit(self.scan_single, target): target for target in targets}

            completed = 0
            for future in as_completed(futures):
                completed += 1
                target = futures[future]
                self.log(f"Progress: {completed}/{len(targets)}")

        total_duration = time.time() - start_time

        # توليد تقرير شامل
        summary = self._generate_summary(total_duration)
        return summary

    def _generate_summary(self, total_duration: float) -> Dict:
        """توليد ملخص شامل"""
        total_vulns = sum(r.get("vulns_count", 0) for r in self.results)
        total_exploits = sum(r.get("exploits_count", 0) for r in self.results)
        successful_scans = sum(1 for r in self.results if "error" not in r)
        failed_scans = sum(1 for r in self.results if "error" in r)

        # تصنيف الثغرات
        vuln_types = {}
        for result in self.results:
            for vuln in result.get("vulns", []):
                vtype = vuln.get("type", "unknown")
                if vtype not in vuln_types:
                    vuln_types[vtype] = 0
                vuln_types[vtype] += 1

        # أكثر الأهداف تعرضاً للثغرات
        targets_by_vulns = sorted(
            self.results,
            key=lambda x: x.get("vulns_count", 0),
            reverse=True
        )

        summary = {
            "metadata": {
                "total_targets": len(self.results),
                "successful_scans": successful_scans,
                "failed_scans": failed_scans,
                "total_duration": round(total_duration, 2),
                "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            },
            "statistics": {
                "total_vulns": total_vulns,
                "total_exploits": total_exploits,
                "avg_vulns_per_target": round(total_vulns / max(successful_scans, 1), 1),
                "vuln_types": vuln_types,
            },
            "top_vulnerable_targets": [
                {
                    "target": r.get("target", ""),
                    "vulns": r.get("vulns_count", 0),
                    "exploits": r.get("exploits_count", 0),
                }
                for r in targets_by_vulns[:10]
            ],
            "results": self.results,
        }

        return summary

    def save_summary(self, summary: Dict, output_file: str):
        """حفظ الملخص"""
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)

    def save_html_summary(self, summary: Dict, output_file: str):
        """حفظ ملخص HTML"""
        meta = summary["metadata"]
        stats = summary["statistics"]

        # بناء جدول الأهداف
        targets_rows = ""
        for result in summary["results"]:
            target = result.get("target", "unknown")
            vulns = result.get("vulns_count", 0)
            exploits = result.get("exploits_count", 0)
            duration = result.get("scan_duration", 0)
            status = "✓" if "error" not in result else "✗"
            status_color = "#3fb950" if "error" not in result else "#dc3545"

            targets_rows += f"""
            <tr>
                <td><span style="color:{status_color}">{status}</span></td>
                <td>{target}</td>
                <td>{vulns}</td>
                <td>{exploits}</td>
                <td>{duration:.1f}s</td>
            </tr>
            """

        # بناء أنواع الثغرات
        vuln_types_html = ""
        for vtype, count in sorted(stats["vuln_types"].items(),
                                   key=lambda x: x[1], reverse=True):
            vuln_types_html += f"<tr><td>{vtype}</td><td>{count}</td></tr>"

        # بناء top vulnerable
        top_html = ""
        for t in summary["top_vulnerable_targets"]:
            top_html += f"""
            <tr>
                <td>{t['target']}</td>
                <td>{t['vulns']}</td>
                <td>{t['exploits']}</td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>ghostpwn - Batch Scan Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial; background: #0f1419; color: #c9d1d9; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #ff6b6b; }}
        h2 {{ color: #58a6ff; margin-top: 30px; }}
        .stats {{ display: flex; flex-wrap: wrap; gap: 12px; margin: 20px 0; }}
        .stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
                padding: 15px; flex: 1; min-width: 150px; text-align: center; }}
        .stat-num {{ font-size: 32px; font-weight: bold; color: #58a6ff; }}
        .stat-label {{ color: #8b949e; font-size: 13px; margin-top: 4px; }}
        table {{ width: 100%; border-collapse: collapse; background: #161b22;
                border-radius: 8px; overflow: hidden; }}
        th {{ background: #21262d; padding: 12px; text-align: right; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #21262d; }}
        tr:hover {{ background: #1c2128; }}
        a {{ color: #58a6ff; text-decoration: none; }}
    </style>
</head>
<body>
<div class="container">
    <h1>🔴 ghostpwn - Batch Scan Report</h1>
    <p style="color: #8b949e;">{meta['scan_date']}</p>

    <div class="stats">
        <div class="stat">
            <div class="stat-num">{meta['total_targets']}</div>
            <div class="stat-label">Total Targets</div>
        </div>
        <div class="stat">
            <div class="stat-num" style="color: #3fb950">{meta['successful_scans']}</div>
            <div class="stat-label">Successful</div>
        </div>
        <div class="stat">
            <div class="stat-num" style="color: #dc3545">{meta['failed_scans']}</div>
            <div class="stat-label">Failed</div>
        </div>
        <div class="stat">
            <div class="stat-num" style="color: #ffc107">{stats['total_vulns']}</div>
            <div class="stat-label">Total Vulns</div>
        </div>
        <div class="stat">
            <div class="stat-num" style="color: #fd7e14">{stats['total_exploits']}</div>
            <div class="stat-label">Exploits</div>
        </div>
        <div class="stat">
            <div class="stat-num">{meta['total_duration']}s</div>
            <div class="stat-label">Duration</div>
        </div>
    </div>

    <h2>📊 Targets Summary</h2>
    <table>
        <thead>
            <tr>
                <th>Status</th>
                <th>Target</th>
                <th>Vulns</th>
                <th>Exploits</th>
                <th>Duration</th>
            </tr>
        </thead>
        <tbody>
            {targets_rows}
        </tbody>
    </table>

    <h2>🏆 Top Vulnerable Targets</h2>
    <table>
        <thead>
            <tr>
                <th>Target</th>
                <th>Vulns</th>
                <th>Exploits</th>
            </tr>
        </thead>
        <tbody>
            {top_html}
        </tbody>
    </table>

    <h2>📋 Vulnerability Types</h2>
    <table>
        <thead>
            <tr>
                <th>Type</th>
                <th>Count</th>
            </tr>
        </thead>
        <tbody>
            {vuln_types_html}
        </tbody>
    </table>
</div>
</body>
</html>
"""
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)


def load_targets_from_file(file_path: str) -> List[str]:
    """تحميل الأهداف من ملف"""
    targets = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                # تخطي الـ comments والأسطر الفارغة
                if line and not line.startswith("#"):
                    if not line.startswith("http"):
                        line = "http://" + line
                    targets.append(line)
    except Exception as e:
        print(f"[!] Error reading file: {e}")
    return targets


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Batch Scanner")
    parser.add_argument("--file", required=True, help="File with targets (one per line)")
    parser.add_argument("--concurrent", type=int, default=3, help="Max concurrent scans")
    parser.add_argument("--depth", default="medium", choices=["fast", "medium", "deep"])
    parser.add_argument("--output", default="batch_report", help="Output prefix")
    parser.add_argument("--exploit", action="store_true", help="Auto exploit")
    args = parser.parse_args()

    targets = load_targets_from_file(args.file)
    if not targets:
        print("[!] No valid targets found")
        sys.exit(1)

    print(f"\n[+] Loaded {len(targets)} targets")
    for t in targets:
        print(f"    - {t}")

    options = {
        "depth": args.depth,
        "auto_exploit": args.exploit,
        "skip_port": True,
        "skip_subdomain": True,
    }

    scanner = BatchScanner(options, max_concurrent=args.concurrent)
    summary = scanner.scan_batch(targets)

    # حفظ التقارير
    json_file = f"{args.output}.json"
    html_file = f"{args.output}.html"

    scanner.save_summary(summary, json_file)
    scanner.save_html_summary(summary, html_file)

    print(f"\n[✓] Reports saved:")
    print(f"    JSON: {json_file}")
    print(f"    HTML: {html_file}")
