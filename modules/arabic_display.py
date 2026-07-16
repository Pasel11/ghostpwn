#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Arabic Display Handler
يحل مشكلة النص العربي المعكوس في Termux

الحل:
1. لو النص فيه عربي فقط → نعكسه ونشكّله (RTL)
2. لو النص mixed (عربي + إنجليزي) → نفصل كل جزء ونعرضه صح
3. لو فيه ANSI colors → نحافظ عليها
4. لو في رموز وأرقام → نحافظ على ترتيبها

ميزات إضافية:
- كشف تلقائي للـ terminal (Termux/Linux/Windows)
- fallback لو arabic_reshaper مش متاح
- تصحيح اتجاه النص Mixed
"""
import sys
import os
import re
from typing import Optional


# فحص توفر مكتبات الـ RTL
try:
    import arabic_reshaper
    from bidi.algorithm import get_display
    HAS_RTL_LIBS = True
except ImportError:
    HAS_RTL_LIBS = False


# كشف نوع الـ terminal
def detect_terminal() -> str:
    """كشف نوع الـ terminal"""
    term = os.environ.get("TERM", "").lower()
    termux = os.environ.get("TERMUX_VERSION", "") or os.environ.get("PREFIX", "")

    if termux or "/data/data/com.termux" in (os.environ.get("PREFIX", "")):
        return "termux"
    elif "tmux" in term:
        return "tmux"
    elif "screen" in term:
        return "screen"
    elif sys.platform == "win32":
        return "windows"
    elif sys.platform == "darwin":
        return "macos"
    else:
        return "linux"


TERMINAL_TYPE = detect_terminal()


# أحرف عربية للكشف
ARABIC_PATTERN = re.compile(r'[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]')


def has_arabic(text: str) -> bool:
    """فحص إذا كان النص فيه عربي"""
    return bool(ARABIC_PATTERN.search(text))


def is_arabic_char(char: str) -> bool:
    """فحص إذا كان الحرف عربي"""
    return bool(ARABIC_PATTERN.match(char))


def split_by_direction(text: str) -> list:
    """تقسيم النص حسب الاتجاه (عربي/لاتيني)"""
    if not text:
        return []

    segments = []
    current_segment = ""
    current_is_arabic = is_arabic_char(text[0])

    for char in text:
        char_is_arabic = is_arabic_char(char)

        # الأرقام والرموز بتتبع الـ segment الحالي
        if char.isalpha():
            if char_is_arabic != current_is_arabic:
                # تغيير الاتجاه
                if current_segment:
                    segments.append((current_segment, current_is_arabic))
                current_segment = char
                current_is_arabic = char_is_arabic
            else:
                current_segment += char
        else:
            # رمز أو رقم - نضيفه للـ segment الحالي
            current_segment += char

    if current_segment:
        segments.append((current_segment, current_is_arabic))

    return segments


def reshape_arabic(text: str) -> str:
    """تشكيل النص العربي (لوصل الحروف)"""
    if not HAS_RTL_LIBS or not has_arabic(text):
        return text

    try:
        reshaped = arabic_reshaper.reshape(text)
        return reshaped
    except Exception:
        return text


def reverse_for_rtl(text: str) -> str:
    """عكس النص للعرض RTL في terminal"""
    if not text:
        return text
    return text[::-1]


def process_mixed_text(text: str) -> str:
    """معالجة النص المختلط (عربي + إنجليزي)"""
    if not text or not has_arabic(text):
        return text

    if not HAS_RTL_LIBS:
        return text

    segments = split_by_direction(text)
    result = ""

    for segment_text, is_arabic in segments:
        if is_arabic:
            # نشكّل العربي ونعرضه RTL
            reshaped = reshape_arabic(segment_text)
            display = get_display(reshaped)
            result += display
        else:
            # اللاتيني نعرضه كما هو
            result += segment_text

    return result


def fix_display(text: str, force_rtl: bool = None) -> str:
    """الدالة الرئيسية - تصلح عرض أي نص"""
    if not text:
        return text

    # كشف الاتجاه المطلوب
    if force_rtl is None:
        force_rtl = has_arabic(text)

    if not force_rtl:
        return text

    # حفظ ANSI escape codes
    ansi_pattern = re.compile(r'(\x1b\[[0-9;]*m)')
    parts = ansi_pattern.split(text)
    codes = ansi_pattern.findall(text)

    result = ""
    for i, part in enumerate(parts):
        if not part:
            continue
        # لو part هو ANSI code نضيفه كما هو
        if ansi_pattern.match(part):
            result += part
        else:
            # نعالج النص
            result += process_mixed_text(part)

    return result


def smart_print(text: str = "", end: str = "\n", file=None):
    """print ذكي - يصلح النص العربي تلقائياً"""
    if file is None:
        file = sys.stdout

    fixed = fix_display(text)
    print(fixed, end=end, file=file)


# ============================ Colored Output Helper ============================
class Colors:
    """ألوان مع دعم RTL"""

    if sys.stdout.isatty():
        RED = '\033[1;31m'
        GREEN = '\033[1;32m'
        YELLOW = '\033[1;33m'
        BLUE = '\033[1;34m'
        MAGENTA = '\033[1;35m'
        CYAN = '\033[1;36m'
        WHITE = '\033[1;37m'
        BOLD = '\033[1m'
        GRAY = '\033[0;90m'
        NC = '\033[0m'
    else:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = BOLD = GRAY = NC = ''


def color_text(color: str, text: str) -> str:
    """تلوين نص مع إصلاح RTL"""
    if not color:
        return fix_display(text)
    return f"{color}{fix_display(text)}{Colors.NC}"


# ============================ Smart Logger ============================
class SmartLogger:
    """logger ذكي يحل مشكلة العربية"""

    def __init__(self, use_colors: bool = True):
        self.use_colors = use_colors and sys.stdout.isatty()

    def _print(self, icon: str, color: str, msg: str):
        """طباعة رسالة ملونة مع إصلاح RTL"""
        if self.use_colors and color:
            # نطبع الـ icon ملون ثم الرسالة مصلحة
            print(f"{color}{icon}{Colors.NC} ", end="")
            print(fix_display(msg))
        else:
            print(f"{icon} {fix_display(msg)}")

    def info(self, msg: str):
        self._print("[*]", Colors.CYAN, msg)

    def success(self, msg: str):
        self._print("[+]", Colors.GREEN, msg)

    def warn(self, msg: str):
        self._print("[!]", Colors.YELLOW, msg)

    def error(self, msg: str):
        self._print("[-]", Colors.RED, msg)

    def vuln(self, msg: str):
        """رسالة ثغرة - نستخدم أيقونة مميزة"""
        self._print("[!]", Colors.RED + Colors.BOLD, f"VULN: {msg}")

    def phase(self, msg: str):
        """رسالة phase"""
        if self.use_colors:
            print(f"\n{Colors.MAGENTA}{'='*60}{Colors.NC}")
            print(f"{Colors.MAGENTA}  ▶ {fix_display(msg)}{Colors.NC}")
            print(f"{Colors.MAGENTA}{'='*60}{Colors.NC}")
        else:
            print(f"\n{'='*60}")
            print(f"  ▶ {fix_display(msg)}")
            print(f"{'='*60}")


# ============================ Test ============================
if __name__ == "__main__":
    print(f"\nTerminal detected: {TERMINAL_TYPE}")
    print(f"RTL libraries available: {HAS_RTL_LIBS}")
    print(f"\n--- Test Cases ---")

    test_cases = [
        "مرحبا بالعالم",
        "Found ثغرة in this page",
        "[*] بدء فحص الموقع https://example.com",
        "تم اكتشاف 5 ثغرات من نوع SQL Injection",
        "Critical: ثغرة XSS في صفحة login",
        "Testing param 'id' مع payload: ' OR '1'='1",
        "Status: 200 | Headers: 12 | الثغرات: 3",
    ]

    for test in test_cases:
        print(f"\nOriginal: {test}")
        print(f"Fixed:    {fix_display(test)}")

    print(f"\n--- Smart Logger Test ---")
    logger = SmartLogger()
    logger.phase("مرحلة الفحص الرئيسية")
    logger.info("بدء فحص الثغرات")
    logger.success("تم اكتشاف 5 ثغرات")
    logger.warn("WAF مكتشف - تفعيل وضع التخفي")
    logger.error("فشل الاتصال بالموقع")
    logger.vuln("SQL Injection في parameter 'id'")
