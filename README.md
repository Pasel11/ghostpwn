# 👻 ghostpwn v1.0 - Zero-Dependency Web Pentesting Toolkit

![Version](https://img.shields.io/badge/version-1.0.0-red)
![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)
![Python](https://img.shields.io/badge/python-3.6%2B-blue)
![License](https://img.shields.io/badge/use-ethical%20only-orange)

> **أداة اختبار اختراق مواقع كاملة مكتوبة بـ Python pure - بدون أي أدوات خارجية!**
>
> مفيش nmap, sqlmap, nikto, ffuf, whatweb - كل حاجة مكتوبة من الصفر بـ Python standard library فقط.

---

## ⚠️ تنبيه قانوني

**استخدم الأداة فقط على:**
- ✅ مواقع تملكها شخصياً
- ✅ مواقع لديك إذن صريح بفحصها
- ✅ بيئات اختبار (DVWA, WebGoat, HackTheBox, TryHackMe, httpbin.org)
- ✅ Bug Bounty programs المعلنة

**يُمنع:** فحص أي موقع بدون إذن صريح - هذا جريمة يعاقب عليها القانون.

---

## ✨ المميزات

### 🚀 Zero-Dependency (بدون أي أدوات خارجية)
- ❌ مفيش nmap - عملنا Port Scanner بـ `socket`
- ❌ مفيش sqlmap - عملنا SQLi Detector بـ payloads مكتوبة من الصفر
- ❌ مفيش nikto - عملنا Vulnerability Detector شامل
- ❌ مفيش ffuf/gobuster/dirb - عملنا Directory Brute Forcer
- ❌ مفيش whatweb - عملنا Tech Detector
- ❌ مفيش requests - عملنا HTTP Client بـ `urllib`
- ✅ فقط Python 3.6+ standard library

### 📦 13+ Module لفحص الثغرات
1. **SQL Injection** - Error-based, Boolean-based, Time-based
2. **XSS** - Reflected (10 payloads مختلفة)
3. **LFI** - 15 payload + php://filter + log files
4. **Command Injection** - 15 payload + filter bypass
5. **SSTI** - 8 templates (Jinja2, Twig, FreeMarker, ERB, etc.)
6. **Open Redirect** - 6 payloads
7. **CORS** - Wildcard, Reflected, Credentials
8. **HTTP Methods** - PUT/DELETE/TRACE
9. **Clickjacking** - X-Frame-Options/CSP
10. **Security Headers** - 7 headers
11. **WAF Detection** - 12+ WAF signatures
12. **XXE** - XML External Entity
13. **SSRF** - Server-Side Request Forgery

### 🔍 Discovery Modules
- **Port Scanner** - بدون nmap (socket + threading)
- **Subdomain Brute Forcer** - DNS brute force
- **Directory Brute Forcer** - 200+ wordlist مدمج
- **Crawler** - استخراج URLs, Forms, Emails, HTML comments
- **Tech Detector** - 30+ tech signatures

### ⚔️ Payload Generators
- **18 Reverse Shell types**: Bash, Python, PHP, Perl, Ruby, Netcat, Ncat, PowerShell, PowerShell B64, Node.js, Lua, Awk, Java, Telnet, Xterm
- **7 Web Shell types**: PHP, PHP Tiny, PHP eval, PHP Bypass, ASP, ASPX, JSP

### 📊 Reports
- **HTML** - تفاعلي مع filter bar + recommendations
- **JSON** - للمعالجة البرمجية
- **CSV** - للتحليل في Excel

---

## 🚀 التثبيت (سهل جداً!)

### المتطلبات الوحيدة: Python 3.6+

```bash
# لا تحتاج تثبيت أي شيء!
# فقط انسخ المجلد وابدأ الاستخدام

# على Termux (موبايل):
pkg install python
git clone https://github.com/Pasel11/ghostpwn.git
cd ghostpwn
python3 ghostpwn.py --interactive

# على Kali Linux:
git clone https://github.com/Pasel11/ghostpwn.git
cd ghostpwn
python3 ghostpwn.py --interactive

# على أي نظام فيه Python:
python3 ghostpwn.py --interactive
```

**مش لازم تثبت nmap, sqlmap, nikto, ffuf, etc. - الأداة بتشتغل بدونهم!**

---

## 📖 الاستخدام

### الطريقة الأسهل: Interactive Menu
```bash
python3 ghostpwn.py --interactive
# أو
python3 ghostpwn.py -i
```

### فحص سريع
```bash
python3 ghostpwn.py https://target.com --depth=fast
```

### فحص عميق
```bash
python3 ghostpwn.py https://target.com --depth=deep
```

### فحص ثغرات فقط (سريع جداً)
```bash
python3 ghostpwn.py https://target.com --skip-port --skip-crawl --skip-dir --skip-subdomain
```

### فحص مع proxy
```bash
python3 ghostpwn.py https://target.com --proxy=http://127.0.0.1:8080
```

### فحص مع cookie
```bash
python3 ghostpwn.py https://target.com --cookie="PHPSESSID=abc123"
```

### توليد Reverse Shell
```bash
# عرض كل الأنواع
python3 ghostpwn.py --list-reverse

# توليد bash shell
python3 ghostpwn.py --reverse bash --ip 10.0.0.1 --port 4444

# توليد PowerShell (مع AV bypass)
python3 ghostpwn.py --reverse powershell-b64 --ip 10.0.0.1 --port 4444

# توليد كل الـ shells في ملف
python3 ghostpwn.py --all-reverse --ip 10.0.0.1 --port 4444
```

### توليد Web Shell
```bash
# عرض كل الأنواع
python3 ghostpwn.py --list-web

# توليد PHP shell
python3 ghostpwn.py --webshell php --output shell.php

# توليد ASP shell
python3 ghostpwn.py --webshell asp --output shell.asp
```

### فحص بورتات فقط
```bash
python3 ghostpwn.py --interactive
# اختر 8
# أو استخدم PortScanner مباشرة:
python3 -c "from modules.port_scanner import PortScanner; PortScanner().scan('target.com', 'top1000')"
```

---

## 🎛️ كل الخيارات

### خيارات الفحص
| الخيار | الوصف | الافتراضي |
|-------|-------|----------|
| `--depth` | `fast` / `medium` / `deep` | `medium` |
| `--threads` | عدد الـ threads | `10` |
| `--timeout` | مهلة كل طلب | `15` |
| `--proxy` | HTTP proxy | - |
| `--cookie` | Cookie | - |
| `--user-agent` | User-Agent | `ghostpwn/1.0` |
| `--delay` | تأخير بين الطلبات | `0` |
| `--output` | مجلد التقارير | `reports` |

### تخطي المراحل
| الخيار | الوصف |
|-------|-------|
| `--skip-port` | تخطي فحص البورتات |
| `--skip-crawl` | تخطي الزحف |
| `--skip-dir` | تخطي directory brute |
| `--skip-vuln` | تخطي فحص الثغرات |
| `--skip-subdomain` | تخطي subdomain brute |
| `--skip-tech` | تخطي كشف التكنولوجيا |

### Payload Generators
| الخيار | الوصف |
|-------|-------|
| `--list-reverse` | عرض كل reverse shells |
| `--list-web` | عرض كل web shells |
| `--reverse TYPE` | توليد reverse shell |
| `--webshell TYPE` | توليد web shell |
| `--all-reverse` | توليد كل الـ shells |

---

## 📁 هيكل المشروع

```
ghostpwn/
├── ghostpwn.py              # الـ CLI الرئيسي
├── modules/
│   ├── __init__.py
│   ├── http_client.py       # HTTP client (urllib فقط)
│   ├── port_scanner.py      # Port scanner (socket فقط)
│   ├── vuln_detector.py     # كشف الثغرات (13+ type)
│   ├── crawler.py           # Crawler + Directory/Subdomain brute + Tech detector
│   ├── report_generator.py  # مولّد التقارير HTML/JSON/CSV
│   └── payload_generator.py # مولّد Reverse/Web shells
├── reports/                 # التقارير (تُنشأ تلقائياً)
└── README.md
```

---

## 🧪 اختبار الأداة

### فحص httpbin.org (آمن للاختبار)
```bash
python3 ghostpwn.py https://httpbin.org --depth=fast --skip-port
```

### فحص DVWA
```bash
docker run -d -p 8080:80 vulnerables/web-dvwa
python3 ghostpwn.py http://localhost:8080 --depth=deep
```

### فحص بورتات على scanme.nmap.org (آمن)
```bash
python3 ghostpwn.py --interactive
# اختر 8
# hostname: scanme.nmap.org
# ports: top100
```

---

## 🆚 مقارنة مع أدوات أخرى

| الميزة | ghostpwn | nmap + sqlmap + nikto + ffuf |
|--------|----------|------------------------------|
| التثبيت | Python فقط | تثبيت كل أداة على حدة |
| الحجم | ~50KB | ~500MB+ |
| الـ dependencies | 0 | 50+ |
| يعمل على Termux | ✅ بسهولة | ❌ يحتاج تثبيت معقد |
| يعمل على Windows | ✅ | ❌ مشاكل كثيرة |
| السرعة | ✅ سريع | متوسط |
| التخصيص | ✅ سهل | صعب |

---

## ❓ الأسئلة الشائعة

### س: ليه مش محتاج nmap؟
ج: عملنا Port Scanner من الصفر باستخدام `socket` و `threading`. نفس الفكرة لكن بدون الـ dependency.

### س: هل الـ SQLi detector زي sqlmap؟
ج: مش بالضبط - sqlmap أدق وأشمل. لكن ghostpwn بيكتشف SQLi بـ 17 payload (Error-based, Boolean-based, Time-based) وهو كافي لـ quick assessment.

### س: هل الأداة بتشتغل على الموبايل؟
ج: أيوه! تحتاج بس Termux + Python. مفيش حاجة تانية.

### س: هل تقدر تستخدمها على Windows؟
ج: أيوه - Python standard library متوفر على Windows. بس بعض الـ payloads (زي bash) مش هتشتغل على target Windows.

### س: إيه الفرق بين ghostpwn و webpwn؟
ج: webpwn بتستخدم أدوات خارجية (nmap, sqlmap, etc.). ghostpwn مكتوبة بالكامل بـ Python pure - مفيش أي أدوات خارجية.

---

## 📜 الترخيص

هذا المشروع للاستخدام التعليمي والأخلاقي فقط.
استخدمه بمسؤولية وفقاً لقوانين بلدك.

---

## 🙏 شكر

- شكر لـ Python Software Foundation على standard library الرائع
- شكر لـ OWASP على المرجعية الأمنية
- شكر لـ PayloadsAllTheThings على الـ payloads

---

**تذكر**: With great power comes great responsibility. 🔐

استخدم الأداة بمسؤولية - الهدف هو **تحسين الأمان** وليس استغلال الثغرات.
