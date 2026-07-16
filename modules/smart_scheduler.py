#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Smart Scheduler
جدولة ذكية للمهام - تحدد ترتيب الفحص الأمثل

الذكاء:
1. ترتيب المهام حسب الأولوية
2. dependency resolution
3. resource management
4. adaptive scheduling
5. parallel task detection
"""
import os
import sys
import time
import threading
from enum import Enum, auto
from typing import Dict, List, Optional, Callable, Set, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.arabic_display import SmartLogger, Colors, fix_display


class TaskPriority(Enum):
    """أولوية المهام"""
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    INFO = 4


class TaskStatus(Enum):
    """حالة المهام"""
    PENDING = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    SKIPPED = auto()


@dataclass
class Task:
    """مهمة"""
    id: str
    name: str
    func: Callable
    args: tuple = ()
    kwargs: dict = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.MEDIUM
    dependencies: Set[str] = field(default_factory=set)
    status: TaskStatus = TaskStatus.PENDING
    result: Any = None
    error: Optional[str] = None
    start_time: float = 0
    end_time: float = 0
    duration: float = 0


class SmartScheduler:
    """جدول ذكي للمهام"""

    def __init__(self, max_workers: int = 10, audit_logger=None):
        self.max_workers = max_workers
        self.audit = audit_logger
        self.logger = SmartLogger()

        self.tasks: Dict[str, Task] = {}
        self.completed_tasks: Dict[str, Task] = {}
        self.results: Dict[str, Any] = {}

        self.lock = threading.Lock()

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[SCHEDULER] {msg}", level)

    def add_task(self, task_id: str, name: str, func: Callable,
                 args: tuple = (), kwargs: dict = None,
                 priority: TaskPriority = TaskPriority.MEDIUM,
                 dependencies: Set[str] = None) -> Task:
        """إضافة مهمة"""
        task = Task(
            id=task_id,
            name=name,
            func=func,
            args=args,
            kwargs=kwargs or {},
            priority=priority,
            dependencies=dependencies or set(),
        )

        with self.lock:
            self.tasks[task_id] = task

        return task

    def run(self) -> Dict[str, Any]:
        """تشغيل كل المهام بالترتيب الأمثل"""
        self._log(f"بدء جدولة {len(self.tasks)} مهمة...", "phase")

        start_time = time.time()

        # ترتيب المهام حسب الأولوية والـ dependencies
        sorted_tasks = self._topological_sort()

        # تنفيذ المهام
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}

            for task in sorted_tasks:
                # انتظار الـ dependencies
                self._wait_for_dependencies(task)

                # تنفيذ المهمة
                future = executor.submit(self._execute_task, task)
                futures[future] = task

            # انتظار كل النتائج
            for future in as_completed(futures):
                task = futures[future]
                try:
                    result = future.result()
                    self.results[task.id] = result
                except Exception as e:
                    self._log(f"مهمة فشلت: {task.name} - {e}", "error")

        total_duration = time.time() - start_time
        self._log(f"اكتملت {len(self.completed_tasks)} مهمة في {total_duration:.1f}s", "success")

        return self.results

    def _topological_sort(self) -> List[Task]:
        """ترتيب طوبولوجي (dependency-aware)"""
        # ترتيب حسب الأولوية أولاً
        sorted_by_priority = sorted(
            self.tasks.values(),
            key=lambda t: (t.priority.value, len(t.dependencies))
        )

        # التأكد من أن الـ dependencies تتنفذ أولاً
        result = []
        added = set()

        while len(result) < len(sorted_by_priority):
            for task in sorted_by_priority:
                if task.id in added:
                    continue

                # فحص لو الـ dependencies كلها أُضيفت
                if all(dep in added for dep in task.dependencies):
                    result.append(task)
                    added.add(task.id)

        return result

    def _wait_for_dependencies(self, task: Task):
        """انتظار الـ dependencies"""
        for dep_id in task.dependencies:
            while dep_id not in self.completed_tasks:
                time.sleep(0.1)

    def _execute_task(self, task: Task) -> Any:
        """تنفيذ مهمة واحدة"""
        task.status = TaskStatus.RUNNING
        task.start_time = time.time()

        self._log(f"  ▶ {task.name}", "info")

        try:
            result = task.func(*task.args, **task.kwargs)
            task.result = result
            task.status = TaskStatus.COMPLETED
            self._log(f"  ✓ {task.name}", "success")
        except Exception as e:
            task.error = str(e)
            task.status = TaskStatus.FAILED
            self._log(f"  ✗ {task.name}: {e}", "error")

        task.end_time = time.time()
        task.duration = task.end_time - task.start_time

        with self.lock:
            self.completed_tasks[task.id] = task

        return task.result

    def get_stats(self) -> Dict:
        """إحصائيات"""
        total = len(self.tasks)
        completed = sum(1 for t in self.tasks.values() if t.status == TaskStatus.COMPLETED)
        failed = sum(1 for t in self.tasks.values() if t.status == TaskStatus.FAILED)

        total_duration = sum(t.duration for t in self.completed_tasks.values())

        return {
            "total_tasks": total,
            "completed": completed,
            "failed": failed,
            "success_rate": (completed / total * 100) if total > 0 else 0,
            "total_duration": total_duration,
        }

    def print_stats(self):
        """عرض الإحصائيات"""
        stats = self.get_stats()
        print(f"\n  {Colors.CYAN}📊 Scheduler Stats:{Colors.NC}")
        print(f"    Tasks: {stats['total_tasks']}")
        print(f"    Completed: {stats['completed']}")
        print(f"    Failed: {stats['failed']}")
        print(f"    Success Rate: {stats['success_rate']:.1f}%")

        # عرض تفاصيل كل مهمة
        print(f"\n    {'Task':<30} {'Status':<12} {'Duration':<10}")
        print(f"    {'-'*30} {'-'*12} {'-'*10}")

        for task in self.completed_tasks.values():
            status_color = Colors.GREEN if task.status == TaskStatus.COMPLETED else Colors.RED
            status_str = task.status.name
            print(f"    {task.name[:30]:<30} {status_color}{status_str:<12}{Colors.NC} {task.duration:.2f}s")
