#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Progress Tracking
أشرطة تقدم وعرض إحصائيات
"""
import sys
import time
from typing import Optional


class ProgressBar:
    """شريط تقدم"""

    def __init__(self, total: int, prefix: str = "", width: int = 40):
        self.total = total
        self.prefix = prefix
        self.width = width
        self.current = 0
        self.start_time = time.time()

    def update(self, current: int, suffix: str = ""):
        """تحديث التقدم"""
        self.current = current
        percent = (current / self.total) * 100 if self.total > 0 else 0
        filled = int(self.width * current / self.total) if self.total > 0 else 0
        bar = "█" * filled + "░" * (self.width - filled)

        elapsed = time.time() - self.start_time
        if current > 0 and current < self.total:
            eta = (elapsed / current) * (self.total - current)
            eta_str = f"ETA: {eta:.0f}s"
        elif current >= self.total:
            eta_str = "Done"
        else:
            eta_str = "..."

        # ANSI colors
        if percent < 33:
            color = "\033[1;31m"  # red
        elif percent < 66:
            color = "\033[1;33m"  # yellow
        else:
            color = "\033[1;32m"  # green
        nc = "\033[0m"

        sys.stdout.write(f"\r{self.prefix} {color}{bar}{nc} {percent:.0f}% ({current}/{self.total}) {eta_str} {suffix}")
        sys.stdout.flush()

        if current >= self.total:
            print()  # newline

    def finish(self):
        """إنهاء الشريط"""
        self.update(self.total)


class PhaseTracker:
    """تتبع phases الفحص"""

    def __init__(self):
        self.phases = []
        self.current_phase = None
        self.start_time = time.time()

    def start_phase(self, name: str, total_steps: int = 0):
        """بدء phase"""
        self.current_phase = {
            "name": name,
            "start": time.time(),
            "end": None,
            "duration": None,
            "total_steps": total_steps,
            "current_step": 0,
        }
        self.phases.append(self.current_phase)

    def update_step(self, step: int = None):
        """تحديث الخطوة الحالية"""
        if self.current_phase:
            if step is not None:
                self.current_phase["current_step"] = step
            else:
                self.current_phase["current_step"] += 1

    def end_phase(self):
        """إنهاء phase"""
        if self.current_phase:
            self.current_phase["end"] = time.time()
            self.current_phase["duration"] = (
                self.current_phase["end"] - self.current_phase["start"]
            )
            self.current_phase = None

    def print_summary(self):
        """عرض ملخص الـ phases"""
        total_duration = time.time() - self.start_time

        print(f"\n📊 ملخص الفحص:")
        print("=" * 60)
        print(f"  المدة الإجمالية: {total_duration:.1f}s")
        print(f"  عدد الـ phases: {len(self.phases)}")
        print()
        print(f"  {'Phase':<30} {'Duration':<12} {'Status'}")
        print(f"  {'-'*30} {'-'*12} {'-'*10}")

        for phase in self.phases:
            name = phase["name"][:30]
            duration = phase.get("duration", 0)
            status = "✓" if phase.get("end") else "..."

            # bar visual
            bar_len = min(int(duration * 2), 20)
            bar = "█" * bar_len

            print(f"  {name:<30} {duration:>8.1f}s   {status} {bar}")

        print("=" * 60)


class StatsDisplay:
    """عرض إحصائيات حية"""

    def __init__(self):
        self.stats = {
            "requests_made": 0,
            "vulns_found": 0,
            "errors": 0,
            "warnings": 0,
            "bytes_received": 0,
            "start_time": time.time(),
        }

    def request_made(self, bytes_received: int = 0):
        """تسجيل طلب"""
        self.stats["requests_made"] += 1
        self.stats["bytes_received"] += bytes_received

    def vuln_found(self):
        """تسجيل ثغرة"""
        self.stats["vulns_found"] += 1

    def error(self):
        """تسجيل خطأ"""
        self.stats["errors"] += 1

    def warning(self):
        """تسجيل تحذير"""
        self.stats["warnings"] += 1

    def print_stats(self):
        """عرض الإحصائيات"""
        elapsed = time.time() - self.stats["start_time"]
        req_per_sec = self.stats["requests_made"] / elapsed if elapsed > 0 else 0
        kb_received = self.stats["bytes_received"] / 1024

        print(f"\n📈 إحصائيات:")
        print(f"  الطلبات: {self.stats['requests_made']} ({req_per_sec:.1f}/s)")
        print(f"  الثغرات: {self.stats['vulns_found']}")
        print(f"  الأخطاء: {self.stats['errors']}")
        print(f"  التحذيرات: {self.stats['warnings']}")
        print(f"  البيانات: {kb_received:.1f} KB")
        print(f"  المدة: {elapsed:.1f}s")


# Global instances
_phase_tracker = None
_stats_display = None


def get_phase_tracker() -> PhaseTracker:
    global _phase_tracker
    if _phase_tracker is None:
        _phase_tracker = PhaseTracker()
    return _phase_tracker


def get_stats_display() -> StatsDisplay:
    global _stats_display
    if _stats_display is None:
        _stats_display = StatsDisplay()
    return _stats_display
