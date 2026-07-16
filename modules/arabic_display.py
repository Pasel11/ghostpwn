#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Arabic Display Handler (v2 - Full RTL)
يحل مشكلة النص العربي المعكوس في Termux بالكامل

الحل الجديد:
1. كشف النص العربي
2. تشكيل الحروف (arabic_reshaper)
3. عكس الاتجاه (python-bidi)
4. لو المكتبات مش متاحة: عكس يدوي ذكي
5. دعم النص المختلط (عربي + إنجليزي + أرقام + رموز)
6. الحفاظ على ANSI colors
7. الحفاظ على المسافات والـ newlines
"""
import sys
import os
import re
from typing import Optional, List, Tuple


# محاولة استيراد المكتبات
try:
    import arabic_reshaper
    from bidi.algorithm import get_display
    HAS_RTL_LIBS = True
except ImportError:
    HAS_RTL_LIBS = False
    try:
        # محاولة تثبيت تلقائي
        import subprocess
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "arabic_reshaper", "python-bidi"],
            capture_output=True, timeout=60
        )
        import arabic_reshaper
        from bidi.algorithm import get_display
        HAS_RTL_LIBS = True
    except Exception:
        HAS_RTL_LIBS = False


# ============================ كشف نوع الـ terminal ============================
def detect_terminal() -> str:
    """كشف نوع الـ terminal"""
    termux = (
        os.environ.get("TERMUX_VERSION", "") or
        "/data/data/com.termux" in os.environ.get("PREFIX", "") or
        os.path.exists("/data/data/com.termux")
    )
    if termux:
        return "termux"
    elif "tmux" in os.environ.get("TMUX", ""):
        return "tmux"
    elif sys.platform == "win32":
        return "windows"
    else:
        return "linux"


TERMINAL_TYPE = detect_terminal()


# ============================ كشف الحروف العربية ============================
ARABIC_RANGE = r'[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]'

def has_arabic(text: str) -> bool:
    """فحص إذا كان النص فيه عربي"""
    if not text:
        return False
    return bool(re.search(ARABIC_RANGE, text))


def is_arabic_char(char: str) -> bool:
    """فحص إذا كان الحرف عربي"""
    return bool(re.match(ARABIC_RANGE, char)) if char else False


# ============================ ANSI Colors Handling ============================
ANSI_PATTERN = re.compile(r'(\x1b\[[0-9;]*m)')


def split_ansi(text: str) -> List[Tuple[str, str]]:
    """تقسيم النص إلى (text, ansi_code) pairs"""
    parts = []
    last_end = 0

    for match in ANSI_PATTERN.finditer(text):
        # النص قبل الـ ANSI code
        if match.start() > last_end:
            parts.append((text[last_end:match.start()], ""))
        # الـ ANSI code نفسه
        parts.append(("", match.group()))
        last_end = match.end()

    # النص المتبقي
    if last_end < len(text):
        parts.append((text[last_end:], ""))

    return parts


# ============================ معالجة النص العربي ============================
def reshape_arabic(text: str) -> str:
    """تشكيل الحروف العربية (لوصلها)"""
    if not HAS_RTL_LIBS or not text:
        return text

    try:
        reshaped = arabic_reshaper.reshape(text)
        return reshaped
    except Exception:
        return text


def apply_bidi(text: str) -> str:
    """تطبيق خوارزمية Bidi لعكس الاتجاه"""
    if not HAS_RTL_LIBS or not text:
        return text

    try:
        return get_display(text)
    except Exception:
        return text


def manual_rtl_reverse(text: str) -> str:
    """عكس يدوي ذكي للنص العربي (fallback)"""
    if not text:
        return text

    # تقسيم النص إلى segments حسب نوع الحرف
    segments = []
    current_segment = ""
    current_type = None  # 'arabic', 'latin', 'number', 'space', 'symbol'

    for char in text:
        if is_arabic_char(char):
            char_type = "arabic"
        elif char.isalpha():
            char_type = "latin"
        elif char.isdigit():
            char_type = "number"
        elif char.isspace():
            char_type = "space"
        else:
            char_type = "symbol"

        if current_type is None:
            current_type = char_type
            current_segment = char
        elif char_type == current_type:
            current_segment += char
        elif char_type == "space" and current_type in ("arabic", "latin", "number"):
            # المسافة تتبع الـ segment الحالي
            current_segment += char
        else:
            segments.append((current_segment, current_type))
            current_segment = char
            current_type = char_type

    if current_segment:
        segments.append((current_segment, current_type))

    # معالجة كل segment
    result_parts = []
    for segment_text, seg_type in segments:
        if seg_type == "arabic":
            # نعكس العربي (لأنه RTL)
            result_parts.append(segment_text[::-1])
        elif seg_type == "number":
            # الأرقام تظل LTR
            result_parts.append(segment_text)
        elif seg_type == "latin":
            # اللاتيني يظل LTR
            result_parts.append(segment_text)
        else:
            result_parts.append(segment_text)

    # عكس ترتيب الـ segments كلها (لأن النص RTL)
    result_parts.reverse()

    return "".join(result_parts)


def process_text_segment(text: str) -> str:
    """معالجة جزء نصي واحد (بدون ANSI codes)"""
    if not text:
        return text

    # لو مفيش عربي، نرجع النص كما هو
    if not has_arabic(text):
        return text

    # لو المكتبات متاحة
    if HAS_RTL_LIBS:
        try:
            # تشكيل الحروف العربية
            reshaped = reshape_arabic(text)
            # تطبيق Bidi
            display = apply_bidi(reshaped)
            return display
        except Exception:
            pass

    # fallback: عكس يدوي
    return manual_rtl_reverse(text)


# ============================ الدالة الرئيسية ============================
def fix_display(text: str, force_rtl: bool = None) -> str:
    """الدالة الرئيسية - تصلح عرض أي نص"""
    if not text:
        return text

    # كشف الاتجاه المطلوب
    if force_rtl is None:
        force_rtl = has_arabic(text)

    if not force_rtl:
        return text

    # تقسيم النص حسب الأسطر (للحفاظ على الـ newlines)
    lines = text.split("\n")
    fixed_lines = []

    for line in lines:
        # تقسيم السطر إلى ANSI + text parts
        parts = split_ansi(line)

        # معالجة كل جزء نصي
        fixed_parts = []
        for text_part, ansi_part in parts:
            if text_part:
                fixed_parts.append(process_text_segment(text_part))
            if ansi_part:
                fixed_parts.append(ansi_part)

        fixed_lines.append("".join(fixed_parts))

    return "\n".join(fixed_lines)


# ============================ Smart Print ============================
def smart_print(text: str = "", end: str = "\n", file=None):
    """print ذكي - يصلح النص العربي تلقائياً"""
    if file is None:
        file = sys.stdout

    fixed = fix_display(text)
    print(fixed, end=end, file=file)


# ============================ Colors ============================
class Colors:
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
        DIM = '\033[2m'
        NC = '\033[0m'
    else:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = BOLD = GRAY = DIM = NC = ''


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

    def _format_icon(self, icon: str, msg: str, color: str = "") -> str:
        """تنسيق الرسالة"""
        fixed_msg = fix_display(msg)
        if self.use_colors and color:
            return f"{color}{icon}{Colors.NC} {fixed_msg}"
        return f"{icon} {fixed_msg}"

    def info(self, msg: str):
        print(self._format_icon("[*]", msg, Colors.CYAN))

    def success(self, msg: str):
        print(self._format_icon("[+]", msg, Colors.GREEN))

    def warn(self, msg: str):
        print(self._format_icon("[!]", msg, Colors.YELLOW))

    def error(self, msg: str):
        print(self._format_icon("[-]", msg, Colors.RED))

    def vuln(self, msg: str):
        """رسالة ثغرة"""
        print(self._format_icon("[!]", f"VULN: {msg}", Colors.RED + Colors.BOLD))

    def phase(self, msg: str):
        """رسالة phase"""
        fixed = fix_display(msg)
        if self.use_colors:
            print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")
            print(f"{Colors.MAGENTA}  ▶ {fixed}{Colors.NC}")
            print(f"{Colors.MAGENTA}{'═'*60}{Colors.NC}")
        else:
            print(f"\n{'='*60}")
            print(f"  ▶ {fixed}")
            print(f"{'='*60}")


# ============================ Test ============================
if __name__ == "__main__":
    print(f"\nTerminal: {TERMINAL_TYPE}")
    print(f"RTL libs: {HAS_RTL_LIBS}")

    test_cases = [
        "مرحبا بالعالم",
        "Found ثغرة في الموقع",
        "[*] بدء فحص الموقع https://example.com",
        "تم اكتشاف 5 ثغرات من نوع SQL Injection",
        "Critical: ثغرة XSS في صفحة login",
        "Testing param 'id' مع payload: ' OR '1'='1",
        "Status: 200 | Headers: 12 | الثغرات: 3",
        "السلام عليكم ورحمة الله وبركاته",
        "مرحلة 1: الاستطلاع (Reconnaissance)",
        "تم العثور على plugin قديم: contact-form-7 v5.0.0",
    ]

    print(f"\n{'='*60}")
    print("Test Cases:")
    print(f"{'='*60}\n")

    for test in test_cases:
        print(f"Original: {test}")
        fixed = fix_display(test)
        print(f"Fixed:    {fixed}")
        print()

    # Smart Logger test
    print(f"\n{'='*60}")
    print("Smart Logger Test:")
    print(f"{'='*60}\n")

    logger = SmartLogger()
    logger.phase("مرحلة الفحص الرئيسية")
    logger.info("بدء فحص الثغرات")
    logger.success("تم اكتشاف 5 ثغرات")
    logger.warn("WAF مكتشف - تفعيل وضع التخفي")
    logger.error("فشل الاتصال بالموقع")
    logger.vuln("SQL Injection في parameter id")
