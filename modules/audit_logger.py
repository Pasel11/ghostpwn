#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Audit Logger
بديل أخلاقي لـ anti-forensics:
- بدل ما نمسح الأثر، نسجّله بشكل شفاف
- الـ audit log ده دليل احترافي على عملك
- مهم جداً للتقارير والإثبات القانوني
"""
import os
import sys
import json
import time
import hashlib
from typing import Dict, List, Optional


class AuditLogger:
    """سجل تدقيق شامل - بديل أخلاقي لـ anti-forensics"""

    def __init__(self, target: str, log_dir: str = "reports/audit"):
        self.target = target
        self.log_dir = log_dir
        self.events: List[Dict] = []
        self.phases: Dict[str, Dict] = {}
        self.current_phase: Optional[str] = None
        self.session_id = self._generate_session_id()

        os.makedirs(log_dir, exist_ok=True)

    def _generate_session_id(self) -> str:
        """توليد session ID فريد"""
        timestamp = str(time.time())
        target_hash = hashlib.md5(self.target.encode()).hexdigest()[:8]
        return f"{int(time.time())}_{target_hash}"

    def log_event(self, message: str, level: str = "info"):
        """تسجيل حدث"""
        event = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "epoch": time.time(),
            "level": level,
            "message": message,
            "phase": self.current_phase,
        }
        self.events.append(event)

    def start_phase(self, phase_name: str):
        """بدء phase جديدة"""
        self.current_phase = phase_name
        self.phases[phase_name] = {
            "start": time.time(),
            "end": None,
            "duration": None,
            "events_count": 0,
        }
        self.log_event(f"Started phase: {phase_name}", "phase")

    def end_phase(self, phase_name: str):
        """إنهاء phase"""
        if phase_name in self.phases:
            self.phases[phase_name]["end"] = time.time()
            self.phases[phase_name]["duration"] = (
                self.phases[phase_name]["end"] - self.phases[phase_name]["start"]
            )
            self.log_event(
                f"Ended phase: {phase_name} "
                f"(duration: {self.phases[phase_name]['duration']:.2f}s)",
                "phase"
            )
        self.current_phase = None

    def log_request(self, method: str, url: str, status: int,
                    response_size: int, elapsed: float):
        """تسجيل HTTP request"""
        event = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "epoch": time.time(),
            "level": "request",
            "method": method,
            "url": url,
            "status": status,
            "response_size": response_size,
            "elapsed": round(elapsed, 3),
            "phase": self.current_phase,
        }
        self.events.append(event)

    def log_vuln(self, vuln: Dict):
        """تسجيل ثغرة مكتشفة"""
        event = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "epoch": time.time(),
            "level": "vuln",
            "vuln": vuln,
            "phase": self.current_phase,
        }
        self.events.append(event)

    def log_exploit(self, exploit_type: str, target: str, result: Dict):
        """تسجيل استغلال"""
        event = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "epoch": time.time(),
            "level": "exploit",
            "type": exploit_type,
            "target": target,
            "result": result,
            "phase": self.current_phase,
        }
        self.events.append(event)

    def save(self) -> str:
        """حفظ الـ audit log"""
        # إحصائيات
        stats = {
            "session_id": self.session_id,
            "target": self.target,
            "start_time": self.events[0]["timestamp"] if self.events else None,
            "end_time": self.events[-1]["timestamp"] if self.events else None,
            "total_events": len(self.events),
            "total_phases": len(self.phases),
            "phases": self.phases,
        }

        # تصنيف الأحداث
        events_by_level = {}
        for event in self.events:
            level = event.get("level", "info")
            if level not in events_by_level:
                events_by_level[level] = 0
            events_by_level[level] += 1

        stats["events_by_level"] = events_by_level

        # حفظ JSON
        log_data = {
            "metadata": stats,
            "events": self.events,
        }

        log_file = os.path.join(self.log_dir, f"audit_{self.session_id}.json")
        with open(log_file, "w", encoding="utf-8") as f:
            json.dump(log_data, f, ensure_ascii=False, indent=2)

        # حفظ human-readable log
        text_log = os.path.join(self.log_dir, f"audit_{self.session_id}.log")
        with open(text_log, "w", encoding="utf-8") as f:
            f.write(f"ghostpwn Audit Log\n")
            f.write(f"{'='*60}\n")
            f.write(f"Session ID: {self.session_id}\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Start: {stats['start_time']}\n")
            f.write(f"End: {stats['end_time']}\n")
            f.write(f"Total Events: {stats['total_events']}\n")
            f.write(f"{'='*60}\n\n")

            f.write("Phases Summary:\n")
            f.write("-" * 60 + "\n")
            for phase, info in self.phases.items():
                duration = info.get("duration", 0)
                f.write(f"  {phase:20s} - {duration:.2f}s\n")
            f.write("\n")

            f.write("Events:\n")
            f.write("-" * 60 + "\n")
            for event in self.events:
                timestamp = event.get("timestamp", "")
                level = event.get("level", "info").upper()
                message = event.get("message", "")
                phase = event.get("phase", "")

                if level == "REQUEST":
                    f.write(f"  [{timestamp}] {level:8s} "
                           f"{event.get('method', ''):6s} "
                           f"{event.get('url', '')[:80]} "
                           f"-> {event.get('status', '')}\n")
                elif level == "VULN":
                    vuln = event.get("vuln", {})
                    f.write(f"  [{timestamp}] VULN     "
                           f"{vuln.get('type', '')} "
                           f"({vuln.get('severity', '')})\n")
                elif level == "EXPLOIT":
                    f.write(f"  [{timestamp}] EXPLOIT  "
                           f"{event.get('type', '')} "
                           f"-> {event.get('target', '')[:50]}\n")
                else:
                    phase_str = f"[{phase}] " if phase else ""
                    f.write(f"  [{timestamp}] {level:8s} {phase_str}{message}\n")

        return log_file

    def print_summary(self):
        """عرض ملخص الـ audit log"""
        print(f"\n📋 Audit Log Summary")
        print(f"{'='*60}")
        print(f"Session ID: {self.session_id}")
        print(f"Target: {self.target}")
        print(f"Total Events: {len(self.events)}")
        print(f"Phases: {len(self.phases)}")
        print(f"\nPhases Duration:")
        for phase, info in self.phases.items():
            duration = info.get("duration", 0)
            print(f"  {phase:20s} - {duration:.2f}s")
        print(f"{'='*60}\n")
