#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Report Generator (Zero-Dependency)
يولّد تقارير HTML/JSON/CSV بدون مكتبات خارجية
"""
import json
import csv
import os
import html
import time
from typing import List, Dict


# ----------------------------- التصنيفات -----------------------------
SEVERITY_COLORS = {
    "critical": "#dc3545",
    "high":     "#fd7e14",
    "medium":   "#ffc107",
    "low":      "#0dcaf0",
    "info":     "#6c757d",
}

SEVERITY_LABELS_AR = {
    "critical": "حرج",
    "high":     "عالي",
    "medium":   "متوسط",
    "low":      "منخفض",
    "info":     "معلومة",
}

VULN_TYPE_AR = {
    "sql_injection_error":       "SQL Injection (Error-based)",
    "sql_injection_boolean":     "SQL Injection (Boolean-based)",
    "sql_injection_time":        "SQL Injection (Time-based)",
    "xss_reflected":             "XSS (Reflected)",
    "xss_reflected_partial":     "XSS (Reflected Partial)",
    "lfi":                       "Local File Inclusion",
    "lfi_windows":               "LFI (Windows)",
    "lfi_php_filter":            "LFI (php://filter)",
    "lfi_log_file":              "LFI (Log File)",
    "command_injection":         "Command Injection",
    "ssti":                      "Server-Side Template Injection",
    "open_redirect":             "Open Redirect",
    "cors_wildcard_credentials": "CORS Wildcard + Credentials",
    "cors_reflected_credentials":"CORS Reflected + Credentials",
    "cors_reflected":            "CORS Reflected Origin",
    "dangerous_http_methods":    "HTTP Methods خطرة",
    "trace_enabled":             "TRACE Method مفعّل",
    "clickjacking":              "Clickjacking",
    "missing_security_header":   "Header أمني مفقود",
    "waf_detected":              "WAF مكتشف",
    "no_waf":                    "بدون حماية WAF",
    "xxe":                       "XML External Entity (XXE)",
    "xxe_error":                 "XXE (XML Error)",
    "ssrf":                      "Server-Side Request Forgery",
    "default":                   "غير مصنف",
}

RECOMMENDATIONS = {
    "sql_injection_error":       "استخدم Prepared Statements في كل الاستعلامات. لا تثق بمدخلات المستخدم.",
    "sql_injection_boolean":     "استخدم Parameterized Queries. فعّl أقل صلاحيات لحساب DB.",
    "sql_injection_time":        "استخدم Prepared Statements. راجع كل الاستعلامات الديناميكية.",
    "xss_reflected":             "استخدم Context-Aware Output Encoding. فعّل CSP و HttpOnly cookies.",
    "xss_reflected_partial":     "راجع كل مخرجات الـ user input. استخدم encoding صحيح.",
    "lfi":                       "لا تمرر مدخلات المستخدم لدوال include. استخدم whitelist.",
    "lfi_windows":               "لا تمرر مدخلات المستخدم لدوال include. استخدم whitelist.",
    "lfi_php_filter":            "عطّل php://filter wrapper. استخدم whitelist صارمة.",
    "lfi_log_file":              "احمِ ملفات الـ logs. عطّل allow_url_include.",
    "command_injection":         "لا تستخدم system() مع مدخلات المستخدم. استخدم escapeshellarg().",
    "ssti":                      "لا تمرر مدخلات المستخدم لـ template engines. استخدم sandbox.",
    "open_redirect":             "لا توجّه لـ URLs من مدخلات بدون تحقق. استخدم whitelist.",
    "cors_wildcard_credentials": "لا تستخدم ACAO: * مع credentials. حدد origins مسموح بها.",
    "cors_reflected_credentials":"لا تعكس Origin بدون تحقق. استخدم whitelist.",
    "cors_reflected":            "لا تعكس Origin بدون تحقق. استخدم whitelist.",
    "dangerous_http_methods":    "عطّل PUT/DELETE/TRACE على مستوى الـ server.",
    "trace_enabled":             "عطّل TRACE في إعدادات الـ web server.",
    "clickjacking":              "أضف X-Frame-Options: DENY أو CSP frame-ancestors.",
    "missing_security_header":   "أضف الـ security headers المفقودة في إعدادات الـ server.",
    "waf_detected":              "حسناً - يوجد WAF. تأكد من إعداداته محدّثة.",
    "no_waf":                    "ركّب WAF (Cloudflare, ModSecurity) للحماية.",
    "xxe":                       "عطّل DTD processing في XML parser. استخدم defusedxml.",
    "xxe_error":                 "عطّل DTD processing. راجع إعدادات الـ parser.",
    "ssrf":                      "تحقق من URLs من المستخدم. عطّل الوصول لـ metadata/localhost.",
    "default":                   "راجع التفاصيل وأصلح الثغرة.",
}


def calculate_risk_score(vulns: List[Dict]) -> Dict:
    """حساب مستوى الخطر"""
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        sev = v.get("severity", "info")
        if sev in sev_counts:
            sev_counts[sev] += 1

    score = (sev_counts["critical"] * 10 +
             sev_counts["high"] * 7 +
             sev_counts["medium"] * 4 +
             sev_counts["low"] * 1)

    if score >= 20:
        level, color = "حرج", "#dc3545"
    elif score >= 10:
        level, color = "عالي", "#fd7e14"
    elif score >= 5:
        level, color = "متوسط", "#ffc107"
    elif score > 0:
        level, color = "منخفض", "#0dcaf0"
    else:
        level, color = "آمن", "#198754"

    return {
        "score": score,
        "level": level,
        "color": color,
        "counts": sev_counts,
    }


def write_json_report(scan_data: Dict, output_path: str) -> str:
    """كتابة تقرير JSON"""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(scan_data, f, ensure_ascii=False, indent=2)
    return output_path


def write_csv_report(vulns: List[Dict], output_path: str) -> str:
    """كتابة تقرير CSV"""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["#", "Severity", "Type", "URL", "Evidence", "Recommendation"])
        for i, v in enumerate(vulns, 1):
            vtype = v.get("type", "unknown")
            writer.writerow([
                i,
                v.get("severity", "info"),
                VULN_TYPE_AR.get(vtype, vtype),
                v.get("url", ""),
                v.get("evidence", "")[:200],
                RECOMMENDATIONS.get(vtype, RECOMMENDATIONS["default"]),
            ])
    return output_path


def write_html_report(scan_data: Dict, output_path: str) -> str:
    """كتابة تقرير HTML تفاعلي"""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    meta = scan_data.get("meta", {})
    vulns = scan_data.get("vulnerabilities", [])
    risk = calculate_risk_score(vulns)

    # بناء جدول الثغرات
    vuln_rows = []
    for i, v in enumerate(vulns, 1):
        sev = v.get("severity", "info")
        color = SEVERITY_COLORS.get(sev, "#6c757d")
        vtype = v.get("type", "unknown")
        vtype_ar = VULN_TYPE_AR.get(vtype, vtype)
        url = html.escape(v.get("url", ""))[:150]
        evidence = html.escape(v.get("evidence", ""))[:300]
        recommendation = html.escape(RECOMMENDATIONS.get(vtype, RECOMMENDATIONS["default"]))
        vuln_rows.append(f"""
        <tr data-severity="{sev}">
            <td>{i}</td>
            <td><span class="badge" style="background:{color}">{SEVERITY_LABELS_AR.get(sev, sev)}</span></td>
            <td><strong>{html.escape(vtype_ar)}</strong></td>
            <td class="url-cell">{url}</td>
            <td>{evidence}</td>
            <td class="rec-cell">{recommendation}</td>
        </tr>
        """)

    vulns_table = "\n".join(vuln_rows) if vuln_rows else '<tr><td colspan="6" class="no-vulns">✓ لم يتم اكتشاف ثغرات</td></tr>'

    # بناء الـ stats cards
    stats_cards = []
    for sev, count in risk["counts"].items():
        if count > 0:
            color = SEVERITY_COLORS[sev]
            stats_cards.append(f"""
            <div class="stat-card" style="border-color:{color}">
                <div class="stat-num" style="color:{color}">{count}</div>
                <div class="stat-label">{SEVERITY_LABELS_AR[sev]}</div>
            </div>
            """)

    stats_html = "\n".join(stats_cards) if stats_cards else '<div class="stat-card"><div class="stat-num" style="color:#198754">0</div><div class="stat-label">ثغرات</div></div>'

    # معلومات إضافية
    subdomains = scan_data.get("subdomains", [])
    directories = scan_data.get("directories", [])
    tech_stack = scan_data.get("tech_stack", [])
    open_ports = scan_data.get("open_ports", [])

    html_content = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>تقرير ghostpwn - {html.escape(meta.get('target', ''))}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
            background: #0f1419; color: #c9d1d9; line-height: 1.6; padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            background: linear-gradient(135deg, #1a1f2e 0%, #2d1a1a 100%);
            border: 1px solid #30363d; border-radius: 12px; padding: 30px; margin-bottom: 20px;
        }}
        header h1 {{ color: #ff6b6b; font-size: 28px; margin-bottom: 8px; }}
        header .subtitle {{ color: #8b949e; font-size: 14px; }}
        .meta-grid {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px; margin-top: 20px;
        }}
        .meta-item {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px; }}
        .meta-item .label {{ color: #8b949e; font-size: 12px; margin-bottom: 4px; }}
        .meta-item .value {{ color: #58a6ff; font-weight: 600; word-break: break-all; }}
        .risk-banner {{
            background: {risk['color']}; color: #fff; border-radius: 10px;
            padding: 20px; text-align: center; margin: 20px 0;
            font-weight: bold; font-size: 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }}
        .stats {{ display: flex; flex-wrap: wrap; gap: 12px; margin: 20px 0; }}
        .stat-card {{
            flex: 1; min-width: 120px; background: #161b22; border: 2px solid #30363d;
            border-radius: 8px; padding: 15px; text-align: center;
        }}
        .stat-num {{ font-size: 32px; font-weight: bold; }}
        .stat-label {{ color: #8b949e; font-size: 13px; margin-top: 4px; }}
        .card {{
            background: #161b22; border: 1px solid #30363d; border-radius: 10px;
            padding: 20px; margin-bottom: 20px;
        }}
        .card h3 {{
            color: #58a6ff; margin-bottom: 15px; padding-bottom: 8px;
            border-bottom: 1px solid #30363d;
        }}
        .vulns-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        .vulns-table th {{
            background: #21262d; color: #c9d1d9; padding: 12px;
            text-align: right; border-bottom: 2px solid #30363d;
        }}
        .vulns-table td {{
            padding: 10px 12px; border-bottom: 1px solid #21262d; vertical-align: top;
        }}
        .vulns-table tr[data-severity="critical"] {{ border-right: 4px solid #dc3545; }}
        .vulns-table tr[data-severity="high"] {{ border-right: 4px solid #fd7e14; }}
        .vulns-table tr[data-severity="medium"] {{ border-right: 4px solid #ffc107; }}
        .vulns-table tr:hover {{ background: #1c2128; }}
        .url-cell {{ font-family: 'Courier New', monospace; font-size: 12px; color: #f0883e; word-break: break-all; }}
        .rec-cell {{ font-size: 12px; color: #3fb950; background: rgba(63,185,80,0.05); padding: 8px; border-radius: 4px; }}
        .badge {{ color: #fff; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }}
        .no-vulns {{ text-align: center; padding: 30px; color: #3fb950; }}
        .filter-bar {{
            background: #161b22; border: 1px solid #30363d; border-radius: 8px;
            padding: 10px; margin-bottom: 15px; display: flex; gap: 8px; flex-wrap: wrap;
        }}
        .filter-btn {{
            background: #21262d; color: #c9d1d9; border: 1px solid #30363d;
            padding: 5px 12px; border-radius: 4px; cursor: pointer; font-size: 12px;
        }}
        .filter-btn:hover {{ background: #30363d; }}
        .filter-btn.active {{ background: #58a6ff; color: #fff; border-color: #58a6ff; }}
        .info-list {{ list-style: none; }}
        .info-list li {{ padding: 6px 0; border-bottom: 1px solid #21262d; font-family: 'Courier New', monospace; font-size: 13px; }}
        .info-list li:last-child {{ border-bottom: none; }}
        footer {{ text-align: center; color: #484f58; font-size: 12px; margin-top: 30px; padding-top: 20px; border-top: 1px solid #21262d; }}
        @media (max-width: 600px) {{
            body {{ padding: 10px; }} header {{ padding: 20px; }}
            .vulns-table {{ font-size: 11px; }} .vulns-table th, .vulns-table td {{ padding: 6px; }}
        }}
    </style>
</head>
<body>
<div class="container">
    <header>
        <h1>🔴 تقرير ghostpwn</h1>
        <div class="subtitle">ghostpwn v1.0 - Zero-Dependency Web Pentesting | {html.escape(meta.get('timestamp', ''))}</div>
        <div class="meta-grid">
            <div class="meta-item">
                <div class="label">الهدف</div>
                <div class="value">{html.escape(meta.get('target', ''))}</div>
            </div>
            <div class="meta-item">
                <div class="label">المدة</div>
                <div class="value">{meta.get('duration_sec', 0)} ثانية</div>
            </div>
            <div class="meta-item">
                <div class="label">عمق الفحص</div>
                <div class="value">{html.escape(meta.get('depth', ''))}</div>
            </div>
            <div class="meta-item">
                <div class="label">عدد الفحوصات</div>
                <div class="value">{meta.get('checks_count', 0)}</div>
            </div>
        </div>
    </header>

    <div class="risk-banner">
        مستوى الخطر: {risk['level']} (الدرجة: {risk['score']})
    </div>

    <div class="stats">
        <div class="stat-card" style="border-color:#58a6ff">
            <div class="stat-num" style="color:#58a6ff">{len(vulns)}</div>
            <div class="stat-label">إجمالي النتائج</div>
        </div>
        {stats_html}
    </div>

    <div class="card">
        <h3>📋 الثغرات المكتشفة</h3>
        <div class="filter-bar">
            <span style="color:#8b949e;font-size:12px">تصفية:</span>
            <button class="filter-btn active" onclick="filterVulns('all')">الكل</button>
            <button class="filter-btn" onclick="filterVulns('critical')" style="border-color:#dc3545">حرج</button>
            <button class="filter-btn" onclick="filterVulns('high')" style="border-color:#fd7e14">عالي</button>
            <button class="filter-btn" onclick="filterVulns('medium')" style="border-color:#ffc107">متوسط</button>
            <button class="filter-btn" onclick="filterVulns('low')" style="border-color:#0dcaf0">منخفض</button>
            <button class="filter-btn" onclick="filterVulns('info')" style="border-color:#6c757d">معلومة</button>
        </div>
        <table class="vulns-table">
            <thead>
                <tr>
                    <th>#</th><th>الخطورة</th><th>النوع</th>
                    <th>URL</th><th>التفاصيل</th><th>التوصية</th>
                </tr>
            </thead>
            <tbody>
                {vulns_table}
            </tbody>
        </table>
    </div>

    {f'''<div class="card">
        <h3>🔌 البورتات المفتوحة ({len(open_ports)})</h3>
        <ul class="info-list">
            {''.join(f'<li>{p["port"]}/tcp - {p["service"]}</li>' for p in open_ports)}
        </ul>
    </div>''' if open_ports else ''}

    {f'''<div class="card">
        <h3>🌐 Subdomains ({len(subdomains)})</h3>
        <ul class="info-list">
            {''.join(f'<li>{s["subdomain"]} -> {", ".join(s["ips"])}</li>' for s in subdomains)}
        </ul>
    </div>''' if subdomains else ''}

    {f'''<div class="card">
        <h3>📂 Directories Found ({len(directories)})</h3>
        <ul class="info-list">
            {''.join(f'<li>[{d["status"]}] {d["path"]}</li>' for d in directories[:50])}
        </ul>
    </div>''' if directories else ''}

    {f'''<div class="card">
        <h3>🛠️ Tech Stack ({len(tech_stack)})</h3>
        <ul class="info-list">
            {''.join(f'<li>{t}</li>' for t in tech_stack)}
        </ul>
    </div>''' if tech_stack else ''}

    <footer>
        <p>⚠️ تقرير منتج بواسطة ghostpwn v1.0 (Zero-Dependency)</p>
        <p>الأداة لا تعتمد على أي أدوات خارجية - فقط Python standard library</p>
    </footer>
</div>
<script>
function filterVulns(severity) {{
    const rows = document.querySelectorAll('.vulns-table tbody tr');
    rows.forEach(row => {{
        if (severity === 'all' || row.dataset.severity === severity) {{
            row.style.display = '';
        }} else {{
            row.style.display = 'none';
        }}
    }});
    document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
}}
</script>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return output_path


def generate_full_report(target_url: str, vulns: List[Dict], extra_data: Dict,
                         duration: float, depth: str, output_dir: str) -> Dict:
    """توليد كل التقارير"""
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    hostname = target_url.split("//")[-1].split("/")[0].split(":")[0]
    report_dir = os.path.join(output_dir, f"{hostname}_{timestamp}")
    os.makedirs(report_dir, exist_ok=True)

    scan_data = {
        "meta": {
            "tool": "ghostpwn",
            "version": "1.0",
            "target": target_url,
            "hostname": hostname,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration_sec": round(duration, 2),
            "depth": depth,
            "checks_count": len(vulns),
        },
        "vulnerabilities": vulns,
        "open_ports": extra_data.get("open_ports", []),
        "subdomains": extra_data.get("subdomains", []),
        "directories": extra_data.get("directories", []),
        "tech_stack": extra_data.get("tech_stack", []),
        "crawler_data": extra_data.get("crawler_data", {}),
    }

    # JSON
    json_path = os.path.join(report_dir, "report.json")
    write_json_report(scan_data, json_path)

    # HTML
    html_path = os.path.join(report_dir, "report.html")
    write_html_report(scan_data, html_path)

    # CSV
    csv_path = os.path.join(report_dir, "report.csv")
    write_csv_report(vulns, csv_path)

    return {
        "dir": report_dir,
        "json": json_path,
        "html": html_path,
        "csv": csv_path,
    }
