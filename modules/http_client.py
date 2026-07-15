#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - HTTP Client (Zero-Dependency)
يستخدم فقط Python standard library (urllib, socket, ssl)
"""
import socket
import ssl
import urllib.request
import urllib.parse
import urllib.error
import http.client
import gzip
import io
import time
import json
from typing import Optional, Dict, Any


class HttpClient:
    """HTTP client يعتمد فقط على standard library"""

    def __init__(self, timeout: int = 15, user_agent: str = "ghostpwn/1.0",
                 proxy: Optional[str] = None, cookie: Optional[str] = None,
                 allow_redirects: bool = True, verify_ssl: bool = False,
                 delay: float = 0):
        self.timeout = timeout
        self.user_agent = user_agent
        self.proxy = proxy
        self.cookie = cookie
        self.allow_redirects = allow_redirects
        self.verify_ssl = verify_ssl
        self.delay = delay
        self.session_cookies = {}
        self.ssl_context = ssl.create_default_context()
        if not verify_ssl:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE

    def _build_request(self, url: str, method: str = "GET",
                       data: Optional[bytes] = None,
                       headers: Optional[Dict] = None) -> urllib.request.Request:
        """بناء كائن Request"""
        final_headers = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
        if self.cookie:
            final_headers["Cookie"] = self.cookie
        if self.session_cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.session_cookies.items())
            final_headers["Cookie"] = cookie_str + ("; " + self.cookie if self.cookie else "")
        if headers:
            final_headers.update(headers)

        return urllib.request.Request(url, data=data, method=method,
                                       headers=final_headers)

    def _decode_response(self, response) -> str:
        """فك تشفير الـ response (gzip, deflate)"""
        body = response.read()
        encoding = response.headers.get("Content-Encoding", "")
        if encoding == "gzip":
            try:
                body = gzip.decompress(body)
            except Exception:
                pass
        elif encoding == "deflate":
            try:
                import zlib
                body = zlib.decompress(body, -zlib.MAX_WBITS)
            except Exception:
                pass

        # محاولة فك التشفير بترميزات مختلفة
        for encoding in ["utf-8", "utf-8-sig", "latin-1", "cp1256", "iso-8859-6"]:
            try:
                return body.decode(encoding)
            except UnicodeDecodeError:
                continue
        return body.decode("utf-8", errors="ignore")

    def _extract_cookies(self, response) -> None:
        """استخراج cookies من response"""
        for header in response.headers.get_all("Set-Cookie") or []:
            try:
                cookie_part = header.split(";")[0]
                if "=" in cookie_part:
                    name, value = cookie_part.split("=", 1)
                    self.session_cookies[name.strip()] = value.strip()
            except Exception:
                continue

    def request(self, url: str, method: str = "GET",
                data: Optional[Any] = None,
                headers: Optional[Dict] = None,
                json_data: Optional[Dict] = None) -> Dict[str, Any]:
        """تنفيذ HTTP request"""
        # delay (anti-DoS)
        if self.delay > 0:
            time.sleep(self.delay)

        # تحضير الـ data
        body = None
        final_headers = dict(headers) if headers else {}
        if json_data is not None:
            body = json.dumps(json_data).encode("utf-8")
            final_headers["Content-Type"] = "application/json"
        elif data is not None:
            if isinstance(data, dict):
                body = urllib.parse.urlencode(data).encode("utf-8")
                final_headers["Content-Type"] = "application/x-www-form-urlencoded"
            elif isinstance(data, str):
                body = data.encode("utf-8")

        # إعداد الـ opener
        handlers = [urllib.request.HTTPSHandler(context=self.ssl_context)]

        if not self.allow_redirects:
            class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None
            handlers.append(NoRedirectHandler())

        if self.proxy:
            handlers.append(urllib.request.ProxyHandler({
                "http": self.proxy,
                "https": self.proxy
            }))

        opener = urllib.request.build_opener(*handlers)

        # تنفيذ الطلب
        start_time = time.time()
        try:
            req = self._build_request(url, method, body, final_headers)
            resp = opener.open(req, timeout=self.timeout)
            elapsed = time.time() - start_time

            result = {
                "status": resp.getcode(),
                "headers": dict(resp.headers),
                "body": self._decode_response(resp),
                "url": resp.url,
                "elapsed": round(elapsed, 3),
                "error": None,
            }
            self._extract_cookies(resp)
            return result

        except urllib.error.HTTPError as e:
            elapsed = time.time() - start_time
            try:
                body_text = e.read().decode("utf-8", errors="ignore")
            except Exception:
                body_text = ""
            return {
                "status": e.code,
                "headers": dict(e.headers or {}),
                "body": body_text,
                "url": url,
                "elapsed": round(elapsed, 3),
                "error": None,
            }
        except urllib.error.URLError as e:
            return {
                "status": 0,
                "headers": {},
                "body": "",
                "url": url,
                "elapsed": round(time.time() - start_time, 3),
                "error": f"URLError: {e.reason}",
            }
        except socket.timeout:
            return {
                "status": 0,
                "headers": {},
                "body": "",
                "url": url,
                "elapsed": self.timeout,
                "error": "Timeout",
            }
        except Exception as e:
            return {
                "status": 0,
                "headers": {},
                "body": "",
                "url": url,
                "elapsed": round(time.time() - start_time, 3),
                "error": f"{type(e).__name__}: {e}",
            }

    def get(self, url: str, headers: Optional[Dict] = None) -> Dict:
        return self.request(url, "GET", headers=headers)

    def post(self, url: str, data=None, headers: Optional[Dict] = None,
             json_data: Optional[Dict] = None) -> Dict:
        return self.request(url, "POST", data=data, headers=headers, json_data=json_data)

    def head(self, url: str, headers: Optional[Dict] = None) -> Dict:
        return self.request(url, "HEAD", headers=headers)

    def put(self, url: str, data=None, headers: Optional[Dict] = None) -> Dict:
        return self.request(url, "PUT", data=data, headers=headers)

    def delete(self, url: str, headers: Optional[Dict] = None) -> Dict:
        return self.request(url, "DELETE", headers=headers)

    def options(self, url: str, headers: Optional[Dict] = None) -> Dict:
        return self.request(url, "OPTIONS", headers=headers)


# اختبار سريع لو اتشغّل مباشرة
if __name__ == "__main__":
    client = HttpClient(timeout=10)
    result = client.get("https://httpbin.org/get")
    print(f"Status: {result['status']}")
    print(f"Elapsed: {result['elapsed']}s")
    print(f"Body (first 200 chars): {result['body'][:200]}")
