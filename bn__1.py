#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BINOLLA — Binolla Candle Fetcher (نسخة مبسّطة)
=====================================================
يتصل بمنصة Binolla (https://binolla.com/ar/) عبر WebSocket
باستخدام بروتوكول Socket.IO v4 / Engine.IO v4:

    wss://ws3.binolla.com/socket.io/?EIO=4&transport=websocket

يدعم:
  - **تسجيل دخول HTTP بالإيميل/كلمة المرور** بنفس بنية qx__1.py:
      * Browser(Session) + CipherSuiteAdapter (TLS fingerprinting يحاكي Chrome)
      * Login(Browser)  : GET /login → استخراج CSRF → POST form data
                          (email, password, remember) → استخراج JWT
      * Settings(Browser) : GET /api/state و /api/dictionaries
  - مصادقة JWT عبر WebSocket (42["authorization",{token,...}]).
  - استلام الرسائل الثنائية (binary events بصيغة 451-[...]).
  - جلب: الأصول، الأرصدة، الإعدادات، الطلبات المفتوحة/المغلقة،
    التنبيهات، الشموع التاريخية، الاقتباسات اللحظية (quotes).
  - تغيير الأصل والفريم عبر asset/list/change.
  - وضع صفقات (binary options) عبر orders/open.
  - حفظ الإيميل/كلمة المرور والتوكن في credentials.json.

البروتوكول باختصار:
  - 0{...}        Engine.IO OPEN  (sid, pingInterval=25s, pingTimeout=20s)
  - 40            Socket.IO CONNECT (من العميل إلى الخادم)
  - 40{...}       Socket.IO CONNECT_ACK (من الخادم)
  - 42[event,data] Socket.IO EVENT (نصّي)
  - 451-[event,{_placeholder:true,num:0}]  Socket.IO BINARY EVENT
                                              (متبوع بإطار ثنائي واحد)
  - 2 / 3         Engine.IO PING / PONG (الخادم يرسل 2، العميل يردّ بـ 3)

حقول نموذج تسجيل الدخول في https://binolla.com/login:
  - input[name="email"]     (type=text,    id ديناميكي مثل :r0:)
  - input[name="password"]  (type=password, id ديناميكي مثل :r1:)
  - input[name="remember"]  (type=checkbox)
  - input[name="cf-turnstile-response"]  (مخفي — Cloudflare CAPTCHA)

ملاحظة: الـ IDs ديناميكية، لذا نعتمد على `name` فقط (كما في qx__1.py).

الاستخدام:
    python bn__1.py
  ثم أدخل الإيميل وكلمة المرور (تُحفظ تلقائياً في credentials.json).

  أو بصيغة non-interactive:
    BINOLLA_EMAIL="you@example.com" BINOLLA_PASSWORD="secret" \\
        python bn__1.py --asset EURUSD_otc --period 1 --days 7 -y
"""

import os
import sys
import ssl
import json
import time
import random
import shutil
import logging
import asyncio
import threading
import traceback
import itertools
import contextlib
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import certifi
import requests
import websocket
from bs4 import BeautifulSoup
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import orjson as _orjson
    HAS_ORJSON = True
except Exception:
    HAS_ORJSON = False

# ==============================================================================
# SECTION 0: CONFIG & CONSTANTS
# ==============================================================================
HOST = "binolla.com"
WS_HOST = "ws3.binolla.com"
ORIGIN_URL = f"https://{HOST}"
WSS_URL = f"wss://{WS_HOST}/socket.io/?EIO=4&transport=websocket"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# إعدادات TLS fingerprinting (تحاكي Chrome) لتجاوز اكتشاف البوتات البسيط
DEFAULT_CIPHER_SUITE = (
    'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:'
    'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:'
    'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:'
    'DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384'
)
DEFAULT_ECDH_CURVE = 'prime256v1'

# استراتيجية إعادة المحاولة لطلبات HTTP
retry_strategy = Retry(
    total=3,
    backoff_factor=0.5,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET", "POST"],
)

CREDENTIALS_FILE = Path("credentials.json")
DATA_DIR = Path("binolla_data")
DATA_DIR.mkdir(exist_ok=True)
LOG_FILE = Path("binolla.log")

# إعدادات الجلب
FETCH_CHUNK_SIZE = 200          # عدد الشموع لكل batch
FETCH_BATCH_DELAY = 0.10        # ثانية بين الـ batches
MAX_FETCH_RETRIES = 5
RETRY_BACKOFF_BASE = 2
RETRY_BACKOFF_MAX = 15
KEEPALIVE_INTERVAL = 5          # ping كل 5 ثوان للحفاظ على الاتصال

_request_counter = itertools.count(int(time.time() * 1000))

# ==============================================================================
# SECTION 1: LOGGING
# ==============================================================================
def logmsg(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"  \033[2m[{ts}]\033[0m {msg}")
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass


def log_exception(context: str, exc: BaseException) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    tb_text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    print(f"  \033[91m[{ts}] FATAL in {context}: {exc}\033[0m")
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] FATAL in {context}: {exc}\n{tb_text}\n")
    except Exception:
        pass


# إعداد سكّت WebSocket
def _prepare_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )
    ws_logger = logging.getLogger("websocket")
    ws_logger.setLevel(logging.WARNING)
    ws_logger.addHandler(logging.NullHandler())


_prepare_logging()
logger = logging.getLogger("binolla")
cacert = certifi.where()
ssl_context = ssl.create_default_context(cafile=cacert)


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


def _thread_excepthook(args):
    log_exception(f"thread '{args.thread.name}'", args.exc_value)
threading.excepthook = _thread_excepthook


def _main_excepthook(exc_type, exc_value, exc_tb):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_tb)
        return
    log_exception("main thread (top level)", exc_value)
sys.excepthook = _main_excepthook


# ==============================================================================
# SECTION 2: ASYNC HELPERS
# ==============================================================================
async def wait_until(predicate: Callable[[], bool], *, timeout: float = 10.0,
                     step: float = 0.05) -> None:
    async def _loop():
        while not predicate():
            await asyncio.sleep(step)
    try:
        await asyncio.wait_for(_loop(), timeout=timeout)
    except asyncio.TimeoutError:
        raise


async def wait_for_first_event(*events: asyncio.Event, timeout: float = 10.0) -> int:
    """يُنتظر أول event يُطلق من القائمة، ويُعيد إنديكسه. يرفع TimeoutError عند انتهاء المهلة."""
    tasks = [asyncio.ensure_future(e.wait()) for e in events]
    try:
        done, pending = await asyncio.wait(tasks, timeout=timeout,
                                           return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        if not done:
            raise asyncio.TimeoutError()
        completed = tasks.index(next(iter(done)))
        return completed
    except asyncio.TimeoutError:
        raise


def _schedule_event_set(event: Optional[asyncio.Event],
                        loop: Optional[asyncio.AbstractEventLoop]) -> None:
    if event is None or loop is None:
        return
    if loop.is_running():
        asyncio.run_coroutine_threadsafe(
            asyncio.wait_for(_set_event_async(event), 0.001), loop)
    else:
        try:
            event.set()
        except Exception:
            pass


async def _set_event_async(event: asyncio.Event) -> None:
    event.set()


# ==============================================================================
# SECTION 2.5: HTTP NAVIGATOR (Browser + CipherSuiteAdapter)
# ==============================================================================
# مطابق لـ qx__1.py — يستخدم ترتيب Cipher Suites يحاكي Chrome،
# مما يساعد على تجاوز اكتشاف البوتات البسيط في Cloudflare/CDN.

class CipherSuiteAdapter(HTTPAdapter):
    """HTTPAdapter مخصّص يضبط TLS cipher suites و ECDH curve لمحاكاة Chrome."""
    __attrs__ = ['ssl_context', 'max_retries', 'config', '_pool_connections',
                 '_pool_maxsize', '_pool_block', 'source_address']

    def __init__(self, *args, **kwargs):
        self.ssl_context = kwargs.pop('ssl_context', None)
        self.cipherSuite = kwargs.pop('cipherSuite', DEFAULT_CIPHER_SUITE)
        self.source_address = kwargs.pop('source_address', None)
        self.server_hostname = kwargs.pop('server_hostname', None)
        self.ecdhCurve = kwargs.pop('ecdhCurve', DEFAULT_ECDH_CURVE)
        if not self.ssl_context:
            self.ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            self.ssl_context.orig_wrap_socket = self.ssl_context.wrap_socket
            self.ssl_context.wrap_socket = self.wrap_socket
        if self.server_hostname:
            self.ssl_context.server_hostname = self.server_hostname
        if self.cipherSuite:
            self.ssl_context.set_ciphers(self.cipherSuite)
            self.ssl_context.set_ecdh_curve(self.ecdhCurve)
            self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
        super().__init__(*args, **kwargs)

    def wrap_socket(self, *args, **kwargs):
        if hasattr(self.ssl_context, 'server_hostname') and self.ssl_context.server_hostname:
            kwargs['server_hostname'] = self.ssl_context.server_hostname
            self.ssl_context.check_hostname = False
        else:
            self.ssl_context.check_hostname = True
        return self.ssl_context.orig_wrap_socket(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = self.ssl_context
        kwargs['source_address'] = self.source_address
        return super().init_poolmanager(*args, **kwargs)


class Browser(Session):
    """جلسة HTTP مع TLS fingerprinting. مطابق لـ qx__1.py Browser."""

    def __init__(self, *args, **kwargs):
        self.response = None
        self.default_headers = None
        self.ecdhCurve = kwargs.pop('ecdhCurve', DEFAULT_ECDH_CURVE)
        self.cipherSuite = kwargs.pop('cipherSuite', DEFAULT_CIPHER_SUITE)
        self.source_address = kwargs.pop('source_address', None)
        self.server_hostname = kwargs.pop('server_hostname', None)
        _proxies = kwargs.pop('proxies', None)
        super().__init__(*args, **kwargs)
        self.proxies = _proxies or {}
        self.headers.update(self.get_headers())
        self.mount('https://', CipherSuiteAdapter(
            ecdhCurve=self.ecdhCurve, cipherSuite=self.cipherSuite,
            server_hostname=self.server_hostname, source_address=self.source_address,
            ssl_context=ssl_context, max_retries=retry_strategy))

    def __enter__(self): return self
    def __exit__(self, exc_type, exc_val, exc_tb): self.close()
    async def __aenter__(self): return self
    async def __aexit__(self, exc_type, exc_val, exc_tb): self.__exit__(exc_type, exc_val, exc_tb)

    def get_headers(self):
        self.default_headers = {"User-Agent": USER_AGENT}
        return self.default_headers

    def set_headers(self, headers=None):
        self.headers.update(self.default_headers)
        if headers: self.headers.update(headers)

    def get_cookies(self):
        return '; '.join(f'{i.name}={i.value}' for i in self.cookies)

    def get_soup(self):
        if self.response and not self.response.ok:
            raise RuntimeError(self.response.reason)
        return BeautifulSoup(self.response.content, "html.parser")

    def send_request(self, method, url, headers=None, **kwargs):
        merged_headers = self.headers.copy()
        if headers: merged_headers.update(headers)
        if self.proxies: kwargs['proxies'] = self.proxies
        self.response = self.request(method, url, headers=merged_headers, **kwargs)
        return self.response


# ==============================================================================
# SECTION 3: STATES & ENUMS
# ==============================================================================
class WebsocketStatus(IntEnum):
    DISCONNECTED = 0
    CONNECTING = 1
    CONNECTED = 2
    ERROR = 3


class AuthStatus(IntEnum):
    NONE = 0
    PENDING = 1
    AUTHENTICATED = 2
    FAILED = 3


class ConnectionState:
    """حالة الاتصال المشتركة بين العميل والـ API."""
    def __init__(self):
        self.SSID: Optional[str] = None
        self.userAccountType: int = 1   # 1 = demo, 0 = real
        self.status: WebsocketStatus = WebsocketStatus.DISCONNECTED
        self.auth_status: AuthStatus = AuthStatus.NONE

        # أحداث async
        self.ws_connected_event: Optional[asyncio.Event] = None
        self.ws_closed_event: Optional[asyncio.Event] = None
        self.ws_error_event: Optional[asyncio.Event] = None
        self.auth_accepted_event: Optional[asyncio.Event] = None
        self.auth_rejected_event: Optional[asyncio.Event] = None

        # أعلام بسيطة
        self.check_websocket_if_connect: Optional[int] = None
        self.check_websocket_if_error: bool = False
        self.websocket_error_reason: Optional[str] = None
        self.check_accepted_connection: bool = False
        self.check_rejected_connection: bool = False

        # قفل داخلي لمنع التضارب
        self.ssl_Mutual_exclusion: bool = False
        self.ssl_Mutual_exclusion_write: bool = False

        # loop خارجي (من العميل async)
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def init_events(self) -> None:
        self.ws_connected_event = asyncio.Event()
        self.ws_closed_event = asyncio.Event()
        self.ws_error_event = asyncio.Event()
        self.auth_accepted_event = asyncio.Event()
        self.auth_rejected_event = asyncio.Event()

    def reset_events(self) -> None:
        for ev in (self.ws_connected_event, self.ws_closed_event,
                   self.ws_error_event, self.auth_accepted_event,
                   self.auth_rejected_event):
            if ev is not None:
                ev.clear()

    def signal_ws_connected(self):
        _schedule_event_set(self.ws_connected_event, self._loop)

    def signal_ws_closed(self):
        _schedule_event_set(self.ws_closed_event, self._loop)

    def signal_auth_accepted(self):
        _schedule_event_set(self.auth_accepted_event, self._loop)

    def signal_auth_rejected(self):
        _schedule_event_set(self.auth_rejected_event, self._loop)

    def signal_ws_error(self):
        _schedule_event_set(self.ws_error_event, self._loop)


# ==============================================================================
# SECTION 4: SOCKET.IO v4 PACKET PARSER
# ==============================================================================
def _detect_packet_type(msg_str: str) -> Tuple[str, Optional[str]]:
    """يُحلّل أول 1-2 محارف من رسالة Engine.IO v4.

    يُعيد (engine_code, payload_or_None).
    مثلاً:
      '0{"sid":...}'     -> ('0', '{"sid":...}')
      '40'               -> ('40', '')
      '42["tick"]'       -> ('42', '["tick"]')
      '451-["s_assets/list",{...}]' -> ('451-', '["s_assets/list",{...}]')
      '2'                -> ('2', None)  # PING from server
      '3'                -> ('3', None)  # PONG from server
    """
    if not msg_str:
        return ('', None)
    # Binary event / binary ack — الصيغة: 4 5 N - <json>
    # حيث N = عدد المُرفقات
    if len(msg_str) >= 4 and msg_str[0] == '4' and msg_str[1] == '5' \
            and msg_str[2].isdigit() and msg_str[3] == '-':
        return ('45' + msg_str[2] + '-', msg_str[4:])
    # 4 + 2 digits socket.io namespace + 1 message (نادر جداً في Binolla)
    if len(msg_str) >= 3 and msg_str[0] == '4' and msg_str[1].isdigit():
        return (msg_str[:2], msg_str[2:])
    # 4 + 1 char (40, 41, 42, 43, 46)  — most common
    if len(msg_str) >= 2 and msg_str[0] == '4':
        return (msg_str[:2], msg_str[2:] if len(msg_str) > 2 else '')
    # Engine.IO codes 0, 1, 2, 3, 6 (noop/no probe upgrade)
    return (msg_str[0], msg_str[1:] if len(msg_str) > 1 else None)


def _safe_json_loads(s: Union[str, bytes]) -> Any:
    """يحاول فك JSON بأمان. يدعم أو حل أو JSON قياسي."""
    if isinstance(s, bytes):
        try:
            s = s.decode("utf-8", errors="ignore")
        except Exception:
            return None
    if not s:
        return None
    if HAS_ORJSON:
        try:
            return _orjson.loads(s)
        except Exception:
            pass
    try:
        return json.loads(s)
    except Exception:
        return None


# ==============================================================================
# SECTION 5: WEBSOCKET CLIENT (EIO=4, Socket.IO v4)
# ==============================================================================
class BinollaWebsocketClient:
    """عميل WebSocket لمنصة Binolla مع دعم الرسائل الثنائية."""

    # ملف تسجيل كل رسائل WebSocket (واردة + صادرة) — يُفتح lazily
    _ws_log_file = None
    _ws_log_path: Optional[Path] = None

    def __init__(self, api: "BinollaAPI"):
        self.api = api
        self.state = api.state
        self.headers = {
            "User-Agent": USER_AGENT,
            "Origin": ORIGIN_URL,
            "Host": WS_HOST,
        }
        self.wss = websocket.WebSocketApp(
            WSS_URL,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close,
            on_open=self.on_open,
            on_ping=self.on_ping,
            on_pong=self.on_pong,
            header=self.headers,
            cookie=self.api.session_data.get("cookies"),
        )

        # ----- حالة استقبال الرسائل الثنائية -----
        self._binary_packet_queue: List[Dict] = []

        # إعدادات heartbeat
        self._ping_interval = 25.0
        self._ping_timeout = 20.0
        self._last_server_ping_at: float = time.time()

        # ----- ملف تسجيل كامل لكل رسائل WebSocket -----
        # اسم الملف يضمّن timestamp البدء حتى لا تُكتب فوقه جلسات سابقة
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        BinollaWebsocketClient._ws_log_path = Path(f"ws_messages_{ts}.log")
        try:
            BinollaWebsocketClient._ws_log_file = open(
                BinollaWebsocketClient._ws_log_path, "a", encoding="utf-8")
            self._ws_log_write(f"# WebSocket session log — started at {datetime.now().isoformat()}\n"
                               f"# WSS URL: {WSS_URL}\n"
                               f"# Origin:  {ORIGIN_URL}\n"
                               f"# Token:   {(self.state.SSID or '')[:40]}...\n"
                               f"# Format:  DIR | LEN | TIME | RAW (or hex for binary)\n"
                               f"# DIR: ← = received from server, → = sent to server\n"
                               f"# ===========================================================\n")
            logmsg(f"{Colors.CYAN}WS message log: {BinollaWebsocketClient._ws_log_path.absolute()}{Colors.RESET}")
        except Exception as e:
            logger.warning("Could not open WS log file: %s", e)

    @classmethod
    def _ws_log_write(cls, line: str) -> None:
        """يكتب سطراً في ملف سجل WebSocket (thread-safe بشكل بسيط)."""
        if cls._ws_log_file is None:
            return
        try:
            cls._ws_log_file.write(line)
            cls._ws_log_file.flush()
        except Exception:
            pass

    def _log_incoming(self, msg) -> None:
        """يسجل رسالة واردة من الخادم (في ملف السجل + على الـ console)."""
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        if isinstance(msg, (bytes, bytearray)):
            data = bytes(msg)
            # جرب JSON decode للـ binary packets
            try:
                decoded = data.decode("utf-8", errors="ignore")
                if decoded and decoded[0] in '[{':
                    self._ws_log_write(f"← BIN {len(data):6d} {ts} {decoded[:5000]}\n")
                    # اطبع على الـ console (مقتطع لمنع الفيض)
                    self._console_msg("←", "BIN", len(data), ts, decoded)
                    return
            except Exception:
                pass
            # وإلا، اعرض الـ hex أول 200 بايت
            hex_preview = data[:200].hex()
            self._ws_log_write(f"← BIN {len(data):6d} {ts} hex={hex_preview}\n")
            try:
                ascii_preview = data[:500].decode("utf-8", errors="replace")
                self._ws_log_write(f"         ascii={ascii_preview}\n")
                self._console_msg("←", "BIN", len(data), ts, ascii_preview)
            except Exception:
                pass
        else:
            text = msg.decode("utf-8", errors="ignore") if isinstance(msg, bytes) else str(msg)
            preview = text if len(text) <= 5000 else text[:5000] + f"... [truncated, total={len(text)}]"
            self._ws_log_write(f"← TXT {len(text):6d} {ts} {preview}\n")
            self._console_msg("←", "TXT", len(text), ts, text)

    def _log_outgoing(self, data) -> None:
        """يسجل رسالة صادرة من العميل (في ملف السجل + على الـ console)."""
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        if isinstance(data, (bytes, bytearray)):
            d = bytes(data)
            try:
                decoded = d.decode("utf-8", errors="ignore")
                if decoded and decoded[0] in '[{012345"':
                    self._ws_log_write(f"→ BIN {len(d):6d} {ts} {decoded[:5000]}\n")
                    self._console_msg("→", "BIN", len(d), ts, decoded)
                    return
            except Exception:
                pass
            hex_preview = d[:200].hex()
            self._ws_log_write(f"→ BIN {len(d):6d} {ts} hex={hex_preview}\n")
            self._console_msg("→", "BIN", len(d), ts, f"hex={hex_preview[:100]}")
        else:
            text = str(data)
            preview = text if len(text) <= 5000 else text[:5000] + f"... [truncated, total={len(text)}]"
            self._ws_log_write(f"→ TXT {len(text):6d} {ts} {preview}\n")
            self._console_msg("→", "TXT", len(text), ts, text)

    def _console_msg(self, direction: str, kind: str, length: int,
                      ts: str, content: str) -> None:
        """يطبع رسالة WS على الـ console بألوان مميّزة (مقتطعة لـ 250 حرف)."""
        # اختصر المحتوى المعروض على الـ console لمنع الفيض
        max_console = 250
        if len(content) > max_console:
            display = content[:max_console] + f" ...[+{len(content) - max_console} chars]"
        else:
            display = content
        # لون: أخضر للوارد، أزرق للصادر
        if direction == "←":
            color = Colors.GREEN
        else:
            color = Colors.BLUE
        print(f"{color}{direction} {kind} {length:6d} {ts} {display}{Colors.RESET}")

    # ---- on_open: يُرسل بعد فتح قناة WebSocket -----
    def on_open(self, wss):
        logger.info("WebSocket connected to %s", WSS_URL)
        logmsg(f"WebSocket channel opened to {WS_HOST}")
        self.state.check_websocket_if_connect = 1
        self.state.status = WebsocketStatus.CONNECTING
        # في EIO=4 ننتظر رسالة 0{...} (Engine.IO OPEN) قبل إرسال 40
        # (يحدث داخل _on_engineio_open). لا نرسل شيئاً هنا.

    # ---- on_message: قلب المعالج -----
    def on_message(self, wss, msg):
        # سجلّ الرسالة الواردة (text أو binary) في ملف السجل
        try:
            self._log_incoming(msg)
        except Exception:
            pass

        self.state.ssl_Mutual_exclusion = True
        try:
            if self.api is not None:
                self.api.last_message_at = time.time()

            # رسالة ثنائية (bytes) — قد تكون مُرفق لـ binary event سابق
            if isinstance(msg, (bytes, bytearray)):
                self._on_binary_frame(bytes(msg))
                self.state.ssl_Mutual_exclusion = False
                return

            msg_str = msg.decode("utf-8", errors="ignore") if isinstance(msg, bytes) else str(msg)

            # 1) PING من الخادم — نردّ بـ PONG فوراً
            if msg_str == "2":
                self._last_server_ping_at = time.time()
                try:
                    self.wss.send("3")
                except Exception:
                    pass
                self.state.ssl_Mutual_exclusion = False
                return

            # 2) PONG من الخادم (ردّ على ping أرسلناه)
            if msg_str == "3":
                self.state.ssl_Mutual_exclusion = False
                return

            # 3) Engine.IO OPEN: 0{"sid":...,"pingInterval":25000,...}
            if msg_str.startswith("0"):
                self._on_engineio_open(msg_str[1:])
                self.state.ssl_Mutual_exclusion = False
                return

            # 4) Socket.IO CONNECT_ACK: 40{"sid":"..."}
            if msg_str.startswith("40"):
                logger.info("Socket.IO namespace connected: %s", msg_str[2:] or "(no sid)")
                self.state.signal_ws_connected()
                self.state.status = WebsocketStatus.CONNECTED
                # أرسل authorization الآن
                self._send_authorization()
                self.state.ssl_Mutual_exclusion = False
                return

            # 5) Socket.IO DISCONNECT: 41
            if msg_str.startswith("41"):
                logger.warning("Socket.IO namespace disconnected by server.")
                self.state.check_websocket_if_connect = 0
                self.state.status = WebsocketStatus.DISCONNECTED
                self.state.signal_ws_closed()
                self.state.ssl_Mutual_exclusion = False
                return

            # 6) Binary event prefix: 45N-<json>
            if msg_str.startswith("45") and len(msg_str) >= 4 and msg_str[3] == '-':
                self._on_binary_event_header(msg_str)
                self.state.ssl_Mutual_exclusion = False
                return

            # 7) Socket.IO text EVENT: 42[event, data]
            if msg_str.startswith("42"):
                self._on_text_event(msg_str[2:])
                self.state.ssl_Mutual_exclusion = False
                return

            # أي شيء آخر (6 noop، إلخ) — نتجاهله
            logger.debug("Unhandled Engine.IO frame: %s", msg_str[:120])
        except Exception as e:
            logger.error("Unhandled error in on_message: %s", e)
            log_exception("on_message", e)
        self.state.ssl_Mutual_exclusion = False

    # ---- 0{...}: تحديث إعدادات heartbeat ----
    def _on_engineio_open(self, payload: str) -> None:
        if not payload:
            return
        data = _safe_json_loads(payload)
        if not isinstance(data, dict):
            return
        # pingInterval / pingTimeout مقدّرة بالمللي ثانية
        pi = data.get("pingInterval")
        pt = data.get("pingTimeout")
        if isinstance(pi, (int, float)):
            self._ping_interval = float(pi) / 1000.0
        if isinstance(pt, (int, float)):
            self._ping_timeout = float(pt) / 1000.0
        sid = data.get("sid", "")
        logger.info("Engine.IO OPEN: sid=%s pingInterval=%.1fs pingTimeout=%.1fs",
                    sid, self._ping_interval, self._ping_timeout)
        logmsg(f"Engine.IO session established (sid={sid[:8]}..., "
               f"ping={self._ping_interval:.0f}s)")
        # مهم في EIO=4: العميل يُرسل '40' (Socket.IO CONNECT) طلباً
        # للانضمام إلى namespace الافتراضي "/".
        # الخادم سيردّ بـ 40{"sid":"..."} (CONNECT_ACK) ثم نكمل المصادقة.
        try:
            self._log_outgoing("40")
            self.wss.send("40")
            logger.info("Sent Socket.IO CONNECT (40).")
        except Exception as e:
            logger.error("Failed to send 40 CONNECT: %s", e)

    # ---- 42[...]: حدث نصّي ----
    def _on_text_event(self, payload: str) -> None:
        arr = _safe_json_loads(payload)
        if not isinstance(arr, list) or not arr:
            return
        event_name = arr[0]
        args = arr[1:] if len(arr) > 1 else []

        # أحداث المصادقة
        if event_name == "authorization" and args:
            # قد يصل ردّ على auth إضافي (نادر)
            self._handle_authorization_response(args[0])
        elif event_name == "s_authorization":
            # تأكيد المصادقة من الخادم (بدون payload)
            logger.info("Authorization ACCEPTED by server.")
            logmsg(f"{Colors.GREEN}Authorization accepted.{Colors.RESET}")
            self.state.check_accepted_connection = True
            self.state.check_rejected_connection = False
            self.state.auth_status = AuthStatus.AUTHENTICATED
            self.state.status = WebsocketStatus.CONNECTED
            self.state.signal_auth_accepted()
            # بعد التأكيد، نُشترك في كل القنوات
            self._send_post_auth_subscriptions()
        elif event_name == "authorization/reject":
            logger.warning("Authorization REJECTED by server.")
            logmsg(f"{Colors.RED}Authorization rejected.{Colors.RESET}")
            self.state.check_rejected_connection = True
            self.state.auth_status = AuthStatus.FAILED
            self.state.signal_auth_rejected()
        else:
            # أي حدث نصّي آخر — مرّره إلى EventRegistry / المعالجات
            self._dispatch_event(event_name, args, binary_payload=None)

    # ---- 45N-<json>: رأس حدث ثنائي ----
    def _on_binary_event_header(self, msg_str: str) -> None:
        """نستقبل رأس 45N-<json>، ثم ننتظر N إطار ثنائي بعد ذلك."""
        try:
            # استخراج العدد N والـ json
            # الصيغة: '4' + '5' + '<digit>' + '-' + <json>
            n_attachments = int(msg_str[2])
            json_text = msg_str[4:]
            arr = _safe_json_loads(json_text)
            if not isinstance(arr, list):
                logger.warning("Malformed binary event header: %s", msg_str[:120])
                return
            if n_attachments <= 0:
                # بدون مُرفقات — عالجه كأنه حدث نصّي
                self._dispatch_event(arr[0], arr[1:], binary_payload=None)
                return
            # ضعه في الطابور وانتظر الإطارات الثنائية
            self._binary_packet_queue.append({
                "parts": arr,
                "expected": n_attachments,
                "received": 0,
                "buffers": [],
            })
        except Exception as e:
            logger.error("Error parsing binary header: %s — %s", e, msg_str[:120])

    # ---- إطار ثنائي يصل بعد رأس 45N-... ----
    def _on_binary_frame(self, data: bytes) -> None:
        if not self._binary_packet_queue:
            logger.debug("Stray binary frame (%d bytes) — no pending header.", len(data))
            return
        # آخر طلب في الطابور (LIFO) — يتوافق مع سلوك Socket.IO v4
        pending = self._binary_packet_queue[-1]
        pending["buffers"].append(data)
        pending["received"] += 1
        if pending["received"] >= pending["expected"]:
            # اكتمل — انزع من الطابور وعالجه
            self._binary_packet_queue.pop()
            self._reassemble_and_dispatch(pending)

    # ---- إعادة تجميع الـ placeholders في الـ JSON ----
    def _reassemble_and_dispatch(self, pending: Dict) -> None:
        """يأخذ الـ JSON الأصلي (مع _placeholder:true,num:N) ويستبدلها بالمُرفقات الثنائية."""
        try:
            parts = pending["parts"]
            buffers = pending["buffers"]

            # الخطاف البطيء: ابحث عن كل _placeholder في الـ JSON واستبدله
            def _walk(obj: Any) -> Any:
                if isinstance(obj, dict):
                    if obj.get("_placeholder") is True and "num" in obj:
                        n = int(obj["num"])
                        if 0 <= n < len(buffers):
                            return buffers[n]
                        return None
                    return {k: _walk(v) for k, v in obj.items()}
                if isinstance(obj, list):
                    return [_walk(x) for x in obj]
                return obj

            parts = [_walk(p) for p in parts]

            event_name = parts[0] if parts else ""
            args = parts[1:] if len(parts) > 1 else []
            self._dispatch_event(event_name, args, binary_payload=None)
        except Exception as e:
            logger.error("Error reassembling binary packet: %s", e)

    # ---- توزيع الحدث على المعالجات / EventRegistry ----
    def _dispatch_event(self, event_name: str, args: List[Any],
                       binary_payload: Optional[bytes]) -> None:
        # حاول فك الـ bytes كـ JSON إن أمكن
        decoded_args = []
        for a in args:
            if isinstance(a, (bytes, bytearray)):
                # جرب JSON أولاً (الأكثر شيوعاً في Binolla)
                as_json = _safe_json_loads(a)
                if as_json is not None:
                    decoded_args.append(as_json)
                else:
                    # إذا فشل JSON، احتفظ بالـ bytes الخام
                    decoded_args.append(bytes(a))
            else:
                decoded_args.append(a)

        # طبّق القناة
        try:
            self.api.event_data[event_name] = decoded_args
        except Exception:
            pass

        # استدعِ المعالج المخصص إن وُجد
        try:
            handler = self.api.event_handlers.get(event_name)
            if handler:
                handler(*decoded_args)
        except Exception as e:
            logger.error("Event handler error for '%s': %s", event_name, e)

        # ارفع الـ async events المقابلة
        try:
            loop = self.api._async_loop
            if loop and loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    self.api.event_registry.set_event(event_name, decoded_args), loop)
        except Exception as e:
            logger.debug("Could not signal event '%s': %s", event_name, e)

        # تسجيل آخر رسالة من نوع quotes (live prices)
        if event_name == "s_quotes/list" and decoded_args:
            try:
                self.api.realtime_quotes = decoded_args[0]
            except Exception:
                pass

        # آخر شمعة لحظية من history/last
        if event_name == "s_history/last" and decoded_args:
            try:
                self.api.history_last = decoded_args[0]
            except Exception:
                pass

        # جلب الشموع التاريخية عبر history/region
        # الـ payload الثنائي يجب أن يحتوي على `index` لمطابقة الطلب.
        if event_name == "s_history/region" and decoded_args:
            try:
                payload = decoded_args[0]
                index = None
                # ابحث عن `index` في بنى متعددة محتملة:
                # - dict: {"index":..., "candles":[...]}
                # - list of dicts: [{"index":..., "candles":[...]}]
                # - dict تحت "data": {"data":{"index":..., "candles":[...]}}
                if isinstance(payload, dict):
                    index = payload.get("index")
                    if index is None and isinstance(payload.get("data"), dict):
                        index = payload["data"].get("index")
                elif isinstance(payload, list) and payload and isinstance(payload[0], dict):
                    index = payload[0].get("index")
                # خزّن الـ payload تحت الـ index المُستخرج
                if index is not None:
                    self.api.history_regions[index] = payload
                    # ارفع الـ event المُطابق
                    loop = self.api._async_loop
                    if loop and loop.is_running():
                        asyncio.run_coroutine_threadsafe(
                            self.api.event_registry.set_event(
                                f's_history/region_{index}', payload),
                            loop)
                    logger.info("s_history/region received (index=%s, payload size=%d bytes)",
                                index, len(str(payload)[:200]))
                else:
                    logger.warning("s_history/region: no index field found in payload")
            except Exception as e:
                logger.error("Error handling s_history/region: %s", e)

        # الأرصدة
        if event_name == "s_balances/list" and decoded_args:
            try:
                self.api.balances = decoded_args[0]
            except Exception:
                pass

        # قائمة الأصول
        if event_name == "s_assets/list" and decoded_args:
            try:
                self.api.assets_list = decoded_args[0]
            except Exception:
                pass

        # الطلبات المفتوحة
        if event_name == "s_orders/opened/list" and decoded_args:
            try:
                self.api.opened_orders = decoded_args[0]
            except Exception:
                pass

        # الطلبات المغلقة
        if event_name == "s_orders/closed/list" and decoded_args:
            try:
                self.api.closed_orders = decoded_args[0]
            except Exception:
                pass

        # الإعدادات
        if event_name == "s_settings/list" and decoded_args:
            try:
                self.api.settings = decoded_args[0]
            except Exception:
                pass

    # ---- إرسال الـ authorization بعد الـ connect ----
    def _send_authorization(self) -> None:
        token = self.state.SSID or self.api.token
        if not token:
            logmsg(f"{Colors.RED}No JWT token available — cannot authorize.{Colors.RESET}")
            self.state.signal_auth_rejected()
            return
        payload = {
            "token": token,
            "uaid": 0,
            "userAccountType": self.state.userAccountType,
        }
        data = '42["authorization",' + json.dumps(payload, separators=(",", ":")) + ']'
        try:
            self._log_outgoing(data)
            self.wss.send(data)
            logger.info("Authorization sent (token=%s...).", token[:24])
            logmsg("Sent authorization frame to Binolla server...")
            self.state.auth_status = AuthStatus.PENDING
        except Exception as e:
            logger.error("Failed to send authorization: %s", e)
            self.state.signal_auth_rejected()

    # ---- اشتراك ما بعد المصادقة ----
    def _send_post_auth_subscriptions(self) -> None:
        """يرسل الطلبات الأولية بعد تأكيد المصادقة (يطابق الترتيب المُلتقط بدقة).

        ملاحظة هامة: بعد `s_authorization`، الخادم يُرسل تلقائياً 3 binary packets:
          - s_assets/list   (قائمة الأصول)
          - s_settings/list (الإعدادات)
          - s_balances/list (الأرصدة)
        ثم العميل يُرسل فقط الـ 8 طلبات التالية:
          1) orders/opened/list
          2) orders/closed/list
          3) assets/list
          4) alert/list
          5) alert/closed/list
          6) indicator/list
          7) drawing/load
          8) asset/list/change  ← هذا الطلب يُفعّل تدفقات s_history/last و s_quotes/list
        الـ server يستجيب لكل طلب بـ binary packet مطابق (s_<name>).
        """
        try:
            subscriptions = [
                '42["orders/opened/list"]',
                '42["orders/closed/list"]',
                '42["assets/list"]',
                '42["alert/list"]',
                '42["alert/closed/list"]',
                '42["indicator/list"]',
                '42["drawing/load"]',
            ]
            for msg in subscriptions:
                self._log_outgoing(msg)
                self.wss.send(msg)
                # مهلة صغيرة جداً بين الطلبات (50ms) لتجنّب الـ rate-limiting
                time.sleep(0.05)

            # 2) تغيير الأصل الافتراضي — يُفعّل s_history/last و s_quotes/list
            asset = self.api.current_asset or "EURUSD_otc"
            period = self.api.current_period or 1
            change_payload = [{"asset": asset, "period": period}]
            data = '42["asset/list/change",' + json.dumps(change_payload,
                                                          separators=(",", ":")) + ']'
            self._log_outgoing(data)
            self.wss.send(data)

            logger.info("Post-auth subscriptions sent (asset=%s, period=%s).", asset, period)
        except Exception as e:
            logger.error("Error sending post-auth subscriptions: %s", e)

    # ---- on_error / on_close ----
    def on_error(self, wss, error):
        logger.error("WebSocket error: %s", error)
        log_exception("websocket.on_error", error if isinstance(error, BaseException)
                      else RuntimeError(str(error)))
        self.state.websocket_error_reason = str(error)
        self.state.check_websocket_if_error = True
        self.state.status = WebsocketStatus.ERROR
        self.state.check_accepted_connection = False
        self.state.signal_ws_error()

    def on_close(self, wss, close_status_code, close_msg):
        logger.info("WebSocket closed: code=%s msg=%s", close_status_code, close_msg)
        logmsg(f"WebSocket closed (code={close_status_code}).")
        self.state.check_websocket_if_connect = 0
        self.state.status = WebsocketStatus.DISCONNECTED
        self.state.check_accepted_connection = False
        self.state.signal_ws_closed()

    def on_ping(self, wss, ping_msg): pass
    def on_pong(self, wss, pong_msg): pass


# ==============================================================================
# SECTION 6: EVENT REGISTRY (async wait-for-event)
# ==============================================================================
class EventRegistry:
    """تسجيل أحداث async — كل event_name له Event + data."""

    def __init__(self):
        self._events: Dict[str, asyncio.Event] = {}
        self._data: Dict[str, Any] = {}
        self._lock = asyncio.Lock()

    async def get_event(self, key: str) -> asyncio.Event:
        async with self._lock:
            if key not in self._events:
                self._events[key] = asyncio.Event()
            return self._events[key]

    async def set_event(self, key: str, data: Any = None):
        async with self._lock:
            if key not in self._events:
                self._events[key] = asyncio.Event()
            self._data[key] = data
            self._events[key].set()

    async def wait_event(self, key: str, timeout: float = 30.0) -> Any:
        event = await self.get_event(key)
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
            return self._data.get(key)
        except asyncio.TimeoutError:
            return None

    async def clear_event(self, key: str):
        async with self._lock:
            if key in self._events:
                self._events[key].clear()
            if key in self._data:
                del self._data[key]


# ==============================================================================
# SECTION 7: BINOLLA API CORE
# ==============================================================================
class BinollaAPI:
    """واجهة برمجية لمنصة Binolla — تتصل، تصادق، وتُرسل الطلبات."""

    def __init__(self, token: str = "", user_data_dir: str = ".",
                 is_demo: bool = True, proxies: Optional[str] = None):
        self.token = token
        self.state = ConnectionState()
        self.state.userAccountType = 1 if is_demo else 0
        self.is_demo = is_demo
        self.user_data_dir = user_data_dir
        self.proxies = proxies
        self.session_data: Dict[str, Any] = {"user_agent": USER_AGENT, "cookies": ""}

        # WebSocket
        self.websocket_thread: Optional[threading.Thread] = None
        self.websocket_client: Optional[BinollaWebsocketClient] = None
        self.last_message_at: float = time.time()

        # الحالة الحالية للأصل/الفريم
        self.current_asset: Optional[str] = None
        self.current_period: Optional[int] = None

        # أحدث بيانات مُلتقطة
        self.assets_list: Any = None
        self.balances: Any = None
        self.settings: Any = None
        self.opened_orders: Any = None
        self.closed_orders: Any = None
        self.history_last: Any = None
        self.history_regions: Dict[int, Any] = {}  # {index: payload} — لجلب الشموع المتوازي
        self.realtime_quotes: Any = None

        # Event Registry
        self.event_registry = EventRegistry()
        self.event_data: Dict[str, Any] = {}
        self.event_handlers: Dict[str, Callable] = {}

        self._async_loop: Optional[asyncio.AbstractEventLoop] = None

    # ---- إعداد التوكن (لو مُرر بعد الإنشا) ----
    def set_token(self, token: str) -> None:
        self.token = token
        self.state.SSID = token

    def register_handler(self, event_name: str, handler: Callable) -> None:
        """يُسجّل معالجاً مخصصاً لحدث نصّي أو ثنائي محدد."""
        self.event_handlers[event_name] = handler

    # ---- إرسال طلب WebSocket عام ----
    def send_websocket_request(self, data: str, no_force_send: bool = True) -> None:
        if no_force_send:
            deadline = time.time() + 5.0
            while (self.state.ssl_Mutual_exclusion or self.state.ssl_Mutual_exclusion_write):
                if time.time() > deadline:
                    break
                time.sleep(0.001)
        self.state.ssl_Mutual_exclusion_write = True
        try:
            if self.websocket_client and self.websocket_client.wss:
                # سجلّ الرسالة الصادرة قبل الإرسال
                try:
                    self.websocket_client._log_outgoing(data)
                except Exception:
                    pass
                self.websocket_client.wss.send(data)
        finally:
            self.state.ssl_Mutual_exclusion_write = False

    # ---- بدء الاتصال WebSocket ----
    async def start_websocket(self, timeout: float = 15.0) -> Tuple[bool, str]:
        self.state.check_websocket_if_connect = None
        self.state.check_websocket_if_error = False
        self.state.websocket_error_reason = None
        self.state.init_events()
        self.state.reset_events()
        try:
            self.state._loop = asyncio.get_running_loop()
            self._async_loop = self.state._loop
        except RuntimeError:
            self.state._loop = None
            self._async_loop = None

        if not self.token:
            return False, "No JWT token provided."

        self.state.SSID = self.token
        self.websocket_client = BinollaWebsocketClient(self)

        payload = {
            "suppress_origin": True,
            # في EIO=4 لا نُفعّل WS-level ping — الخادم يُرسل Engine.IO PING ("2")
            # كل 25 ثانية، ونردّ بـ "3" داخل on_message. لو فعّلنا ping_interval هنا،
            # مكتبة websocket-client ستُرسل WS PING frames (مستوى RFC 6455) وقد
            # تُربك خادم Socket.IO. نُبقي ping_interval=0 (معطّل) و ping_timeout=30
            # (قيمة افتراضية — المكتبة تتطلبها >0 حتى لو كان ping_interval=0).
            "ping_interval": 0,
            "ping_timeout": 30,
            "origin": ORIGIN_URL,
            "host": WS_HOST,
            "sslopt": {
                "check_hostname": True,
                "cert_reqs": ssl.CERT_REQUIRED,
                "ca_certs": cacert,
                "context": ssl_context,
            },
        }
        # دعم البروكسي
        if self.proxies:
            try:
                from urllib.parse import urlparse
                p = urlparse(self.proxies if isinstance(self.proxies, str) else self.proxies.get("http", ""))
                if p.hostname and p.port:
                    payload["http_proxy_host"] = p.hostname
                    payload["http_proxy_port"] = p.port
                    if p.scheme.startswith("socks"):
                        payload["http_proxy_auth_timeout"] = 30
            except Exception:
                pass

        self.websocket_thread = threading.Thread(
            target=self.websocket_client.wss.run_forever, kwargs=payload)
        self.websocket_thread.daemon = True
        self.websocket_thread.start()

        try:
            idx = await wait_for_first_event(
                self.state.ws_connected_event,
                self.state.auth_rejected_event,
                self.state.ws_error_event,
                self.state.ws_closed_event,
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            return False, "Timeout waiting for websocket open / namespace connect"

        if idx == 0:
            return True, "Websocket connected successfully."
        elif idx == 1:
            self.state.SSID = None
            return False, "Websocket token rejected."
        elif idx == 2:
            return False, self.state.websocket_error_reason or "Websocket error"
        elif idx == 3:
            return False, "Websocket connection closed."
        return False, "Unknown websocket state"

    # ---- انتظار تأكيد المصادقة ----
    async def wait_for_authorization(self, timeout: float = 15.0) -> bool:
        if not self.state.auth_accepted_event:
            self.state.init_events()
        self.state.auth_accepted_event.clear()
        self.state.auth_rejected_event.clear()
        try:
            idx = await wait_for_first_event(
                self.state.auth_accepted_event,
                self.state.auth_rejected_event,
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            return False
        return idx == 0

    # ---- الاتصال الكامل (websocket + auth) ----
    async def connect(self) -> Tuple[bool, str]:
        self.state.ssl_Mutual_exclusion = False
        self.state.ssl_Mutual_exclusion_write = False
        check_websocket, websocket_reason = await self.start_websocket()
        if not check_websocket:
            return check_websocket, websocket_reason
        # بعد ws_connected، يُرسل العميل authorization تلقائياً داخل on_message
        check_auth = await self.wait_for_authorization(timeout=15.0)
        if not check_auth:
            return False, "Authorization failed or timed out."
        return True, "Connected and authorized."

    # ---- إغلاق ----
    async def close(self) -> bool:
        if self.websocket_client and self.websocket_client.wss:
            try:
                self.websocket_client.wss.close()
            except Exception:
                pass
            await asyncio.sleep(0.5)
        if self.websocket_thread and self.websocket_thread.is_alive():
            self.websocket_thread.join(timeout=5)
        return True

    # ===================================================================
    # دوال Binolla المُيسّرة (薄 core API)
    # ===================================================================

    def change_asset(self, asset: str, period: int) -> None:
        """يُبدّل الأصل والفريم. مثال: change_asset('EURUSD_otc', 1)"""
        self.current_asset = asset
        self.current_period = period
        payload = [{"asset": asset, "period": period}]
        data = '42["asset/list/change",' + json.dumps(payload, separators=(",", ":")) + ']'
        self.send_websocket_request(data)

    def subscribe_quotes(self) -> None:
        """يشترك في بث الاقتباسات اللحظية (s_quotes/list)."""
        self.send_websocket_request('42["quotes/list"]')

    def fetch_assets(self) -> None:
        self.send_websocket_request('42["assets/list"]')

    def fetch_balances(self) -> None:
        self.send_websocket_request('42["balances/list"]')

    def fetch_settings(self) -> None:
        self.send_websocket_request('42["settings/list"]')

    def fetch_orders_opened(self) -> None:
        self.send_websocket_request('42["orders/opened/list"]')

    def fetch_orders_closed(self) -> None:
        self.send_websocket_request('42["orders/closed/list"]')

    def fetch_history_last(self) -> None:
        self.send_websocket_request('42["history/last"]')

    def fetch_history_region(self, asset: str, time_sec: int, index: Optional[int] = None,
                              offset: int = 1000, period: int = 1) -> int:
        """يرسل طلب جلب شموع تاريخية من منطقة زمنية محددة.

        الـ endpoint: `history/region`
        الـ response: `s_history/region` (binary packet يحتوي على ~offset شمعة JSON)

        المعاملات:
          asset    : اسم الأصل (مثل 'EURUSD_otc')
          time_sec : Unix timestamp (seconds) لبداية المنطقة الزمنية
          index    : مُعرّف فريد للطلب (إن لم يُمرّر، يُولّد تلقائياً)
          offset   : عدد الشموع لكل batch (افتراضي 1000)
          period    : الفريم بالدقائق (1 = M1, 5 = M5, 15 = M15, 30 = M30, 60 = H1)

        يُعيد: الـ `index` المُستخدم (لمطابقة الاستجابة عبر event
        `s_history/region_<index>`).
        """
        if index is None:
            index = next(_request_counter)
        payload = {
            "asset": asset,
            "index": index,
            "time": int(time_sec),
            "offset": int(offset),
            "period": int(period),
        }
        data = '42["history/region",' + json.dumps(payload, separators=(",", ":")) + ']'
        self.send_websocket_request(data)
        logger.info("history/region sent: asset=%s time=%d offset=%d period=%d index=%d",
                    asset, time_sec, offset, period, index)
        return index

    def fetch_alerts(self) -> None:
        self.send_websocket_request('42["alert/list"]')

    def fetch_alerts_closed(self) -> None:
        self.send_websocket_request('42["alert/closed/list"]')

    def fetch_indicators(self) -> None:
        self.send_websocket_request('42["indicator/list"]')

    def load_drawings(self) -> None:
        self.send_websocket_request('42["drawing/load"]')

    # ---- وضع صفقة (binary option) ----
    def place_order(self, asset: str, amount: float, direction: str,
                    expiration: int, account_type: int = 1) -> None:
        """يفتح صفقة على منصة Binolla.

        المعاملات:
          asset        : اسم الأصل، مثلاً 'EURUSD_otc'
          amount       : المبلغ بالدولار (أو عملة الحساب)
          direction    : 'call' (صعود) أو 'put' (هبوط)
          expiration   : مدة الصفقة بالثواني (60, 120, 180, 300, 600)
          account_type : 1 = demo, 0 = real
        """
        direction = direction.lower()
        if direction not in ("call", "put"):
            raise ValueError(f"direction must be 'call' or 'put', got: {direction}")
        payload = {
            "asset": asset,
            "amount": float(amount),
            "direction": direction,
            "expiration": int(expiration),
            "userAccountType": account_type,
        }
        data = '42["orders/open",' + json.dumps(payload, separators=(",", ":")) + ']'
        self.send_websocket_request(data)
        logger.info("Order sent: %s %s %.2f exp=%ds", asset, direction, amount, expiration)

    # ---- جلب قائمة الأصول مع انتظار ----
    async def get_assets_async(self, timeout: float = 10.0) -> Any:
        await self.event_registry.clear_event("s_assets/list")
        self.fetch_assets()
        return await self.event_registry.wait_event("s_assets/list", timeout=timeout)

    async def get_balances_async(self, timeout: float = 10.0) -> Any:
        await self.event_registry.clear_event("s_balances/list")
        self.fetch_balances()
        return await self.event_registry.wait_event("s_balances/list", timeout=timeout)

    async def get_settings_async(self, timeout: float = 10.0) -> Any:
        await self.event_registry.clear_event("s_settings/list")
        self.fetch_settings()
        return await self.event_registry.wait_event("s_settings/list", timeout=timeout)

    async def get_orders_opened_async(self, timeout: float = 10.0) -> Any:
        await self.event_registry.clear_event("s_orders/opened/list")
        self.fetch_orders_opened()
        return await self.event_registry.wait_event("s_orders/opened/list", timeout=timeout)

    async def get_orders_closed_async(self, timeout: float = 10.0) -> Any:
        await self.event_registry.clear_event("s_orders/closed/list")
        self.fetch_orders_closed()
        return await self.event_registry.wait_event("s_orders/closed/list", timeout=timeout)

    async def get_history_last_async(self, timeout: float = 10.0) -> Any:
        await self.event_registry.clear_event("s_history/last")
        self.fetch_history_last()
        return await self.event_registry.wait_event("s_history/last", timeout=timeout)


# ==============================================================================
# SECTION 8: BINOLLA STABLE CLIENT (واجهة مستخدم + جلب الشموع)
# ==============================================================================
class Binolla:
    """واجهة عالية المستوى للاستخدام التفاعلي."""

    def __init__(self, token: str = "", is_demo: bool = True,
                 user_data_dir: str = ".", proxies: Optional[str] = None):
        self.token = token
        self.is_demo = is_demo
        self.user_data_dir = user_data_dir
        self.proxies = proxies
        self.api: Optional[BinollaAPI] = None

    async def connect(self) -> Tuple[bool, str]:
        self.api = BinollaAPI(
            token=self.token,
            is_demo=self.is_demo,
            user_data_dir=self.user_data_dir,
            proxies=self.proxies,
        )
        self.api._async_loop = asyncio.get_running_loop()
        return await self.api.connect()

    async def change_account(self, balance_mode: str) -> None:
        """يُبدّل بين الحساب الحقيقي والتجريبي."""
        is_demo = balance_mode.upper() != "REAL"
        self.is_demo = is_demo
        if self.api:
            self.api.state.userAccountType = 1 if is_demo else 0
            payload = {"userAccountType": self.api.state.userAccountType}
            data = '42["account/change",' + json.dumps(payload, separators=(",", ":")) + ']'
            self.api.send_websocket_request(data)

    async def start_candles_stream(self, asset: str = "EURUSD_otc",
                                    period: int = 1) -> None:
        if self.api:
            self.api.current_asset = asset
            self.api.current_period = period
            self.api.change_asset(asset, period)
            self.api.subscribe_quotes()

    async def fetch_candles(self, asset: str, days: int, timeframe_min: int,
                            timeout: int = 30, max_workers: int = 5,
                            progress_callback: Optional[Callable] = None) -> List[Dict]:
        """يجلب الشموع التاريخية من Binolla عبر `history/region` بنفس طريقة qx__1.py.

        آلية العمل:
        - عدد الثواني المطلوب = days * 86400
        - كل batch = `offset` شموع (افتراضي 1000) = offset * period * 60 ثانية
        - نقسّم النطاق الزمني على max_workers (5 افتراضياً) لجلب متوازٍ
        - كل worker يُرسل طلبات history/region بالتسلسل مع انتظار s_history/region_<index>
        - ندمج كل الشموع المستلمة من كل العمال، مع تجنّب التكرار (نفس الـ time)
        - نُعيد القائمة مرتّبة حسب time
        """
        if not self.api:
            return []
        # فعّل تدفق البيانات للأصل المطلوب
        await self.start_candles_stream(asset, timeframe_min)
        await asyncio.sleep(0.3)

        period_sec = timeframe_min * 60            # ثانية لكل شمعة
        chunk_size = FETCH_CHUNK_SIZE              # شمعة لكل batch (200 من qx__1.py)
        chunk_seconds = chunk_size * period_sec    # ثانية لكل batch
        amount_of_seconds = days * 86400            # ثانية إجمالية مطلوبة

        all_candles: Dict[int, Dict] = {}          # {time: candle} — للدمج دون تكرار
        current_time = int(time.time())
        target_start_time = current_time - amount_of_seconds
        block_size = amount_of_seconds // max_workers
        semaphore = asyncio.Semaphore(max_workers)

        async def worker(start_t: int, end_t: int, worker_id: int) -> List[Dict]:
            worker_candles: Dict[int, Dict] = {}
            async with semaphore:
                oldest_t = start_t
                consecutive_failures = 0
                while oldest_t > end_t:
                    # تحقق من الاتصال قبل كل batch
                    if not self.api or not getattr(self.api.state, 'check_accepted_connection', False):
                        break
                    # ولّد index فريد وأرسل الطلب
                    index = self.api.fetch_history_region(
                        asset=asset, time_sec=oldest_t, period=timeframe_min,
                        offset=chunk_size)
                    # انتظر الاستجابة (s_history/region_<index> يُطلق من _dispatch_event)
                    result = await self.api.event_registry.wait_event(
                        f's_history/region_{index}', timeout=timeout)
                    if not result:
                        # لا استجابة — حرّك نافذة الوقت للوراء
                        oldest_t -= chunk_seconds
                        consecutive_failures += 1
                        if consecutive_failures >= 3:
                            logger.warning("Worker %d: 3 consecutive failures — aborting.",
                                           worker_id)
                            break
                        await asyncio.sleep(FETCH_BATCH_DELAY * 2)
                        continue
                    consecutive_failures = 0
                    # حوّل الـ payload إلى شموع
                    new_batch = self._parse_history(result)
                    if not new_batch:
                        oldest_t -= chunk_seconds
                        continue
                    batch_times = []
                    for c in new_batch:
                        ts = c.get('time', 0)
                        if end_t <= ts <= start_t:
                            worker_candles[ts] = c
                            batch_times.append(ts)
                    if not batch_times:
                        oldest_t -= chunk_seconds
                        continue
                    # تحديث أقدم وقت للجلب التالي
                    new_oldest = min(batch_times)
                    if progress_callback:
                        progress_callback(start_t - new_oldest, start_t - end_t,
                                          len(worker_candles), f"Worker-{worker_id}")
                    oldest_t = new_oldest if new_oldest < oldest_t else oldest_t - chunk_seconds
                    await asyncio.sleep(FETCH_BATCH_DELAY)
            return list(worker_candles.values())

        # شغّل max_workers عمال بالتوازي
        tasks = []
        for i in range(max_workers):
            s = current_time - (i * block_size)
            e = max(target_start_time, s - block_size)
            tasks.append(worker(s, e, i))
        results = await asyncio.gather(*tasks)
        # ادمج كل النتائج
        for batch in results:
            for c in batch:
                all_candles[c['time']] = c
        # رتّب حسب time
        return sorted(all_candles.values(), key=lambda x: x['time'])

    def _parse_history(self, payload: Any) -> List[Dict]:
        """يُحوّل payload الـ s_history/region إلى قائمة شموع بصيغة OHLC.

        يدعم عدة بنى محتملة:
          1) {"index":..., "asset":..., "candles":[[time, OHLC, ...], ...]}
          2) {"index":..., "candles":[{"time":..., "open":..., ...}, ...]}
          3) {"data":{"candles":[...]}}
          4) [[time, open, close, high, low, vol], ...]
        """
        if not payload:
            return []
        # استخرج candles من payload
        candles = None
        if isinstance(payload, dict):
            candles = (payload.get("candles") or payload.get("data")
                       or payload.get("history") or payload.get("list"))
            # قد تكون candles داخل "data" sub-dict
            if candles is None and isinstance(payload.get("data"), dict):
                candles = (payload["data"].get("candles")
                           or payload["data"].get("data") or [])
        elif isinstance(payload, list):
            candles = payload
        else:
            return []
        if not candles:
            return []

        parsed = []
        for c in candles:
            try:
                if isinstance(c, dict):
                    t = int(c.get("time", c.get("timestamp", 0)) or 0)
                    o = float(c.get("open", 0) or 0)
                    h = float(c.get("high", c.get("max", 0)) or 0)
                    l = float(c.get("low", c.get("min", 0)) or 0)
                    cl = float(c.get("close", 0) or 0)
                    v = float(c.get("volume", 0) or 0)
                    if t > 0:
                        parsed.append({"time": t, "open": o, "high": h,
                                       "low": l, "close": cl, "volume": v})
                elif isinstance(c, list) and len(c) >= 5:
                    # صيغة Quotex الشائعة: [time, open, close, high, low, volume]
                    parsed.append({
                        "time": int(c[0]), "open": float(c[1]),
                        "high": float(c[3]), "low": float(c[4]),
                        "close": float(c[2]),
                        "volume": float(c[5]) if len(c) > 5 else 0.0,
                    })
            except Exception:
                continue
        return parsed

    async def close(self) -> bool:
        if self.api:
            return await self.api.close()
        return True


# ==============================================================================
# SECTION 9: CREDENTIALS MANAGEMENT
# ==============================================================================
def load_credentials() -> Optional[Dict[str, str]]:
    """يقرأ التوكن/الإيميل/كلمة المرور من credentials.json. يُعيد None إذا لم توجد."""
    if not CREDENTIALS_FILE.exists():
        return None
    try:
        data = json.loads(CREDENTIALS_FILE.read_text())
        if data.get("token") or (data.get("email") and data.get("password")):
            return data
        return None
    except Exception:
        return None


def save_credentials(token: str = "", email: str = "", password: str = "",
                     is_demo: bool = True, proxy: str = "") -> bool:
    """يحفظ التوكن والإيميل/كلمة المرور ونوع الحساب في credentials.json."""
    try:
        existing = {}
        if CREDENTIALS_FILE.exists():
            try:
                existing = json.loads(CREDENTIALS_FILE.read_text())
            except Exception:
                pass
        if token:
            existing["token"] = token
        if email:
            existing["email"] = email
        if password:
            existing["password"] = password
        existing["is_demo"] = is_demo
        if proxy:
            existing["proxy"] = proxy
        existing["saved_at"] = int(time.time())
        CREDENTIALS_FILE.write_text(json.dumps(existing, indent=2))
        return True
    except Exception as e:
        logmsg(f"Failed to save credentials: {e}")
        return False


def decode_jwt_exp(token: str) -> Optional[int]:
    """يستخرج حقل `exp` من JWT (دون التحقق من التوقيع). يُعيد timestamp أو None."""
    if not token or token.count(".") != 2:
        return None
    try:
        import base64
        payload_b64 = token.split(".")[1]
        # أضف padding إن لزم
        payload_b64 += "=" * (-len(payload_b64) % 4)
        decoded = base64.urlsafe_b64decode(payload_b64).decode("utf-8", errors="ignore")
        data = json.loads(decoded)
        if isinstance(data, dict) and "exp" in data:
            return int(data["exp"])
    except Exception:
        return None
    return None


def is_token_expired(token: str, leeway_seconds: int = 30) -> bool:
    """يتحقق إن كان التوكن منتهياً (مع فترة سماح)."""
    exp = decode_jwt_exp(token)
    if not exp:
        return True
    return time.time() >= (exp - leeway_seconds)


# ==============================================================================
# SECTION 9.5: HTTP LOGIN (Browser-based, مطابق لـ qx__1.py)
# ==============================================================================
# نموذج تسجيل الدخول في https://binolla.com/login يحتوي على:
#   - input[name="email"]     (type=text,    id ديناميكي مثل :r0:)
#   - input[name="password"]  (type=password, id ديناميكي مثل :r1:)
#   - input[name="remember"]  (type=checkbox)
#   - input[name="cf-turnstile-response"]  (مخفي - Cloudflare CAPTCHA)
#
# الصفحة React SPA، فلا يوجد <form action="..."> تقليدي.
# الـ JS bundle يبني عنوان الـ API ديناميكياً، لذا نجرب عدة endpoints محتملة:
#   /api/auth/login  /api/login  /api/v1/auth/login  /auth/login  /login
#
# نحاول:
#   1) POST form-urlencoded (مثل qx__1.py تماماً)
#   2) POST JSON  (fallback)
# ونستخرج JWT من:
#   - JSON response body
#   - Set-Cookie header
#   - redirect URL (Fragment)
#   - HTML response (regex search)

# endpoints محتملة لتسجيل الدخول إلى Binolla (تُجرّب بالترتيب)
_LOGIN_ENDPOINTS = (
    "/api/auth/login",
    "/api/login",
    "/api/v1/auth/login",
    "/api/v1/login",
    "/auth/login",
    "/login",
)

# أسماء مفاتيح JSON المحتملة التي قد يحملها الرد
_JWT_JSON_KEYS = (
    "token", "access_token", "auth_token", "authToken",
    "accessToken", "jwt", "binolla_token", "bnn_token", "idToken",
)

# أسماء cookies المحتملة
_JWT_COOKIE_NAMES = (
    "token", "access_token", "auth_token", "jwt",
    "bnn_token", "binolla_session",
)


def _looks_like_jwt(s: str) -> bool:
    """يتحقق هل النص يبدو JWT (header.payload.signature)."""
    if not s or not isinstance(s, str):
        return False
    if s.count(".") != 2:
        return False
    if len(s) < 40:
        return False
    # حاول فك payload
    try:
        import base64 as _b64
        pl = s.split(".")[1]
        pl += "=" * (-len(pl) % 4)
        decoded = _b64.urlsafe_b64decode(pl).decode("utf-8", errors="ignore")
        d = json.loads(decoded)
        return isinstance(d, dict) and ("iss" in d or "sub" in d or "aud" in d or "exp" in d)
    except Exception:
        return False


class Login(Browser):
    """تسجيل دخول HTTP إلى Binolla بنفس بنية qx__1.py Login.

    الاستخدام:
        login = Login(api)
        status, msg = await login(email, password)
    """
    base_url = HOST
    https_base_url = ORIGIN_URL
    login_url = f"{ORIGIN_URL}/login"

    def __init__(self, api, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.api = api
        self.headers = self.get_headers()
        # حافظ على رابط اللغة العربية إن اختار المستخدم
        self.full_url = f"{self.https_base_url}/{getattr(api, 'lang', 'en')}"

    def get_login_page(self) -> Optional[BeautifulSoup]:
        """يحضر صفحة /login لاستخراج أي CSRF token أو cookies أولية."""
        self.headers["Connection"] = "keep-alive"
        self.headers["Accept-Encoding"] = "gzip, deflate, br"
        self.headers["Accept-Language"] = "en-US,en;q=0.9,ar;q=0.8"
        self.headers["Accept"] = ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                                  "image/avif,image/webp,*/*;q=0.8")
        self.headers["Referer"] = self.https_base_url + "/"
        self.headers["Upgrade-Insecure-Requests"] = "1"
        self.headers["Sec-Ch-Ua-Mobile"] = "?0"
        self.headers["Sec-Ch-Ua-Platform"] = '"Windows"'
        self.headers["Sec-Fetch-Site"] = "same-origin"
        self.headers["Sec-Fetch-User"] = "?1"
        self.headers["Sec-Fetch-Dest"] = "document"
        self.headers["Sec-Fetch-Mode"] = "navigate"
        self.headers["Dnt"] = "1"
        try:
            self.send_request("GET", self.login_url)
            return self.get_soup()
        except Exception as e:
            logger.warning("GET /login failed: %s", e)
            return None

    def _extract_csrf(self, soup: Optional[BeautifulSoup]) -> Optional[str]:
        """يستخرج CSRF token من meta tag أو input hidden."""
        if not soup:
            return None
        # <meta name="csrf-token" content="...">
        meta = soup.find("meta", {"name": "csrf-token"})
        if meta and meta.get("content"):
            return meta["content"]
        # <input type="hidden" name="_token" value="...">
        for name_attr in ("_token", "csrf_token", "csrf", "_csrf"):
            inp = soup.find("input", {"name": name_attr})
            if inp and inp.get("value"):
                return inp["value"]
        return None

    def _extract_token_from_response(self) -> Optional[str]:
        """يستخرج JWT من آخر استجابة HTTP."""
        if not self.response:
            return None

        # 1) JSON response
        ctype = self.response.headers.get("Content-Type", "").lower()
        if "application/json" in ctype:
            try:
                data = self.response.json()
                if isinstance(data, dict):
                    for key in _JWT_JSON_KEYS:
                        val = data.get(key)
                        if isinstance(val, str) and _looks_like_jwt(val):
                            return val
                    # قد يكون في payload متداخل
                    for k1, v1 in data.items():
                        if isinstance(v1, dict):
                            for k2 in _JWT_JSON_KEYS:
                                val = v1.get(k2)
                                if isinstance(val, str) and _looks_like_jwt(val):
                                    return val
            except Exception:
                pass

        # 2) Set-Cookie
        for c in self.cookies:
            if c.name in _JWT_COOKIE_NAMES and _looks_like_jwt(c.value):
                return c.value

        # 3) HTML / JS في الرد (regex)
        try:
            body = self.response.text or ""
            import re as _re
            m = _re.search(r'["\']token["\']\s*:\s*["\']([^"\']{40,500})["\']', body)
            if m and _looks_like_jwt(m.group(1)):
                return m.group(1)
        except Exception:
            pass

        return None

    async def _post_form(self, data: Dict[str, Any], endpoint: str) -> Tuple[bool, str]:
        """POST كـ form-urlencoded (مثل qx__1.py)."""
        url = self.https_base_url + endpoint
        self.headers["Content-Type"] = "application/x-www-form-urlencoded"
        self.headers["Referer"] = self.login_url
        self.headers["Origin"] = self.https_base_url
        self.headers["Sec-Fetch-Site"] = "same-origin"
        self.headers["Sec-Fetch-Mode"] = "cors"
        self.headers["Sec-Fetch-Dest"] = "empty"
        self.headers["Accept"] = "application/json, text/plain, */*"
        self.headers["X-Requested-With"] = "XMLHttpRequest"
        try:
            self.send_request("POST", url, data=data)
        except Exception as e:
            return False, f"POST {endpoint} failed: {e}"
        # تحقق من الرد
        if self.response is None:
            return False, f"No response from {endpoint}"
        # Cloudflare challenge detection
        body = self.response.text or ""
        if self.response.status_code == 403 and "Just a moment" in body:
            return False, (f"Cloudflare challenge at {endpoint} — HTTP login blocked "
                          f"(need Turnstile CAPTCHA solved).")
        if self.response.status_code >= 400:
            return False, f"HTTP {self.response.status_code} from {endpoint}"
        token = self._extract_token_from_response()
        if token:
            return True, token
        return False, f"No JWT in response from {endpoint}"

    async def _post_json(self, data: Dict[str, Any], endpoint: str) -> Tuple[bool, str]:
        """POST كـ JSON (fallback لـ SPA endpoints)."""
        url = self.https_base_url + endpoint
        self.headers["Content-Type"] = "application/json"
        self.headers["Referer"] = self.login_url
        self.headers["Origin"] = self.https_base_url
        self.headers["Sec-Fetch-Site"] = "same-origin"
        self.headers["Sec-Fetch-Mode"] = "cors"
        self.headers["Sec-Fetch-Dest"] = "empty"
        self.headers["Accept"] = "application/json, text/plain, */*"
        self.headers["X-Requested-With"] = "XMLHttpRequest"
        try:
            self.send_request("POST", url, json=data)
        except Exception as e:
            return False, f"POST (JSON) {endpoint} failed: {e}"
        if self.response is None:
            return False, f"No response from {endpoint}"
        body = self.response.text or ""
        if self.response.status_code == 403 and "Just a moment" in body:
            return False, (f"Cloudflare challenge at {endpoint} — HTTP login blocked "
                          f"(need Turnstile CAPTCHA solved).")
        if self.response.status_code >= 400:
            return False, f"HTTP {self.response.status_code} from {endpoint} (JSON)"
        token = self._extract_token_from_response()
        if token:
            return True, token
        return False, f"No JWT in JSON response from {endpoint}"

    def success_login(self) -> Tuple[bool, str]:
        """يتحقق من نجاح تسجيل الدخول بناءً على URL الرد (مثل qx__1.py)."""
        if not self.response:
            return False, "No response"
        # بعد نجاح الدخول، يجب ألا يكون الـ URL ما زال على /login
        url = str(self.response.url)
        if "/login" in url and url.rstrip("/").endswith("/login"):
            return False, "Still on /login — login failed."
        return True, "Login successful."

    async def __call__(self, username: str, password: str,
                       user_data_dir: Optional[str] = None) -> Tuple[bool, str]:
        """المُدخل الرئيسي: username=email, password.

        يُعيد (True, "<JWT>") عند النجاح أو (False, "<error>") عند الفشل.
        """
        # 1) جلب /login لاستخراج CSRF والكوكيز
        soup = self.get_login_page()
        csrf = self._extract_csrf(soup)
        logmsg(f"GET /login — CSRF token: {'found' if csrf else 'none'}")

        # 2) بناء حمولة النموذج (مطابقة لـ qx__1.py + حقول Binolla)
        form_data = {
            "email": username,
            "password": password,
            "remember": "on",  # checkbox value
        }
        if csrf:
            form_data["_token"] = csrf

        # 3) جرّب POST كـ form-urlencoded على كل endpoint
        last_err = ""
        for ep in _LOGIN_ENDPOINTS:
            logmsg(f"Trying POST (form) {ep} ...")
            ok, msg = await self._post_form(form_data, ep)
            if ok:
                # نجاح
                self.cookies_str = self.get_cookies()
                self.api.session_data["cookies"] = self.cookies_str
                self.api.session_data["token"] = msg
                self.api.session_data["user_agent"] = self.headers["User-Agent"]
                return True, msg
            last_err = msg
            # إذا Cloudflare challenge، لا فائدة من المحاولة على endpoints أخرى
            if "Cloudflare" in msg:
                break

        # 4) جرّب POST كـ JSON على كل endpoint (fallback)
        if "Cloudflare" not in last_err:
            json_payload = {
                "email": username,
                "password": password,
                "remember": True,
            }
            for ep in _LOGIN_ENDPOINTS:
                logmsg(f"Trying POST (JSON) {ep} ...")
                ok, msg = await self._post_json(json_payload, ep)
                if ok:
                    self.cookies_str = self.get_cookies()
                    self.api.session_data["cookies"] = self.cookies_str
                    self.api.session_data["token"] = msg
                    self.api.session_data["user_agent"] = self.headers["User-Agent"]
                    return True, msg
                last_err = msg
                if "Cloudflare" in msg:
                    break

        return False, last_err or "Login failed. Invalid email or password."


class Settings(Browser):
    """يجلب إعدادات الحساب من /api/state و /api/dictionaries. مطابق لـ qx__1.py Settings."""

    def __init__(self, api):
        proxies_dict = api._normalize_proxies(api.proxies) if hasattr(api, '_normalize_proxies') else None
        super().__init__(proxies=proxies_dict)
        self.set_headers()
        self.api = api
        self.headers = self.get_headers()

    def get_settings(self):
        """يجلب /api/state — يحتوي على حالة الحساب بعد الدخول."""
        self.headers["content-type"] = "application/json"
        self.headers["referer"] = self.api.https_url + "/"
        self.headers["cookie"] = self.api.session_data.get("cookies", "")
        self.headers["user-agent"] = self.api.session_data.get("user_agent", "")
        self.headers["authorization"] = f'Bearer {self.api.session_data.get("token", "")}'
        try:
            r = self.send_request("GET", f"{self.api.https_url}/api/state")
            if r and r.status_code == 200:
                return r.json()
        except Exception as e:
            logger.warning("GET /api/state failed: %s", e)
        return None

    def get_dictionaries(self):
        """يجلب /api/dictionaries — قائمة الأصول والمعلومات المرجعية."""
        self.headers["content-type"] = "application/json"
        self.headers["cookie"] = self.api.session_data.get("cookies", "")
        self.headers["user-agent"] = self.api.session_data.get("user_agent", "")
        try:
            r = self.send_request("GET", f"{self.api.https_url}/api/dictionaries")
            if r and r.status_code == 200:
                return r.json()
        except Exception as e:
            logger.warning("GET /api/dictionaries failed: %s", e)
        return None


# ==============================================================================
# SECTION 10: ASSET NAME NORMALIZATION
# ==============================================================================
def normalize_asset(raw: str) -> str:
    """يُعيد اسم الأصل بصيغة Binolla الموحّدة: حروف كبيرة + لاحقة _otc.

    أمثلة:
      "EURUSD"     -> "EURUSD_otc"
      "EURUSD_otc" -> "EURUSD_otc"
      "EUR/USD"    -> "EURUSD_otc"
      "eur usd"    -> "EURUSD_otc"
    """
    import re as _re
    s = raw.strip()
    if not s:
        return ""
    s = _re.sub(r'[^a-zA-Z0-9]', '', s)
    if not s:
        return ""
    if s.upper().endswith("OTC"):
        s = s[:-3]
    s = s.upper()
    return f"{s}_otc"


def pretty_asset(symbol: str, timeframe_min: int) -> str:
    base = symbol
    suffix = ""
    if base.upper().endswith("_OTC"):
        base = base[:-4]
        suffix = " · OTC"
    if len(base) == 6 and base.isalpha():
        pretty = f"{base[:3]}/{base[3:]}{suffix}"
    else:
        pretty = f"{base}{suffix}"
    return f"{pretty} (M{timeframe_min})"


# ==============================================================================
# SECTION 11: SAVE CANDLES TO JSON
# ==============================================================================
def save_candles_to_json(candles: List[Dict], asset: str,
                          timeframe_min: int, days: int) -> Optional[Path]:
    if not candles:
        logmsg("No candles to save.")
        return None
    try:
        rnd = random.randint(1000, 9999)
        filename = f"{asset}_{timeframe_min}m_{days}d_{rnd}.json"
        filepath = DATA_DIR / filename
        payload = {
            "asset": asset,
            "timeframe_min": timeframe_min,
            "days": days,
            "count": len(candles),
            "fetched_at": int(time.time()),
            "candles": candles,
        }
        filepath.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
        return filepath
    except Exception as e:
        log_exception("save_candles_to_json", e)
        return None


# ==============================================================================
# SECTION 12: KEEPALIVE & CONNECT HELPERS
# ==============================================================================
async def keepalive_loop(client: "Binolla", stop_event: asyncio.Event) -> None:
    """يراقب صحة الاتصال دون إرسال أي رسالة بروتوكولية.

    في EIO=4 (Socket.IO v4)، **الخادم** هو من يُرسل "2" (PING) كل ~25 ثانية،
    والعميل يردّ بـ "3" (PONG) داخل `BinollaWebsocketClient.on_message`.
    إرسال "2" من العميل في EIO=4 يُعتبر مخالفة بروتوكول ويُغلق الاتصال فوراً.

    لذا هذه الحلقة لا ترسل شيئاً — فقط تراقب `last_message_at` وتُسلّط ضوءاً
    إذا بدا الاتصال معلّقاً (أكثر من 60 ثانية دون أي رسالة من الخادم).
    """
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=KEEPALIVE_INTERVAL)
        except asyncio.TimeoutError:
            pass
        if stop_event.is_set():
            break
        # فحص صحي فقط: هل لا تزال الرسائل تأتي؟
        if client.api:
            idle = time.time() - client.api.last_message_at
            if idle > 60.0:
                logger.warning("No WebSocket messages in %.0fs — connection may be stale.", idle)


async def connect_binolla(token: str, is_demo: bool = True,
                          max_attempts: int = 3, proxies: Optional[str] = None) -> Optional[Binolla]:
    for attempt in range(1, max_attempts + 1):
        logmsg(f"Connecting to Binolla (attempt {attempt}/{max_attempts})...")
        client = Binolla(token=token, is_demo=is_demo, proxies=proxies)
        try:
            ok, reason = await asyncio.wait_for(client.connect(), timeout=30)
            if ok:
                logmsg(f"{Colors.GREEN}Connected to Binolla (account={'demo' if is_demo else 'real'}).{Colors.RESET}")
                return client
            logmsg(f"{Colors.YELLOW}Attempt {attempt}/{max_attempts} failed: {reason}{Colors.RESET}")
        except asyncio.TimeoutError:
            logmsg(f"{Colors.YELLOW}Attempt {attempt}/{max_attempts} timed out.{Colors.RESET}")
            try:
                await client.close()
            except Exception:
                pass
        except Exception as e:
            log_exception(f"connect_binolla#{attempt}", e)
            try:
                await client.close()
            except Exception:
                pass
        await asyncio.sleep(1.5)
    return None


async def fetch_candles_for_asset(client: Binolla, asset: str, days: int,
                                    timeframe_min: int, idx: int = 1,
                                    total: int = 1) -> List[Dict]:
    display = pretty_asset(asset, timeframe_min)
    logmsg(f"[{idx}/{total}] Fetching candles for {display} ({days} days, M{timeframe_min})...")

    MAX_RETRIES = MAX_FETCH_RETRIES
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            if not client.api or not client.api.state.check_accepted_connection:
                logmsg(f"Connection dead before attempt {attempt}; aborting.")
                return []
            candles = await asyncio.wait_for(
                client.fetch_candles(asset, days, timeframe_min, timeout=30),
                timeout=45,
            )
            if candles:
                logmsg(f"{Colors.GREEN}Got {len(candles)} candles.{Colors.RESET}")
                return candles
            logmsg(f"Attempt {attempt}/{MAX_RETRIES}: empty response.")
        except asyncio.TimeoutError:
            logmsg(f"Attempt {attempt}/{MAX_RETRIES}: fetch timed out.")
        except Exception as e:
            logmsg(f"Attempt {attempt}/{MAX_RETRIES} raised: {e}")
        if attempt < MAX_RETRIES:
            delay = min(RETRY_BACKOFF_BASE ** attempt, RETRY_BACKOFF_MAX)
            logmsg(f"Retry in {delay:.1f}s...")
            await asyncio.sleep(delay)
    logmsg(f"All {MAX_RETRIES} attempts failed for {display}")
    return []


# ==============================================================================
# SECTION 13: INTERACTIVE INPUT (async)
# ==============================================================================
async def ainput(prompt: str = "") -> str:
    """input() يمنع الـ event loop؛ نُغلّفه في executor."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: input(prompt))


def print_banner() -> None:
    banner = r"""
============================================================
  BINOLLA - Binolla Candle Fetcher
  Simplified version: fetch candles and save as JSON
============================================================
  WebSocket : wss://ws3.binolla.com/socket.io/?EIO=4
  Login    : https://binolla.com/login
             (input[name="email"], input[name="password"],
              input[name="remember"])
  Speed    : 5 parallel workers
  Timeframes: 1, 5, 15, 30, 60 (minutes)
============================================================
"""
    print(f"{Colors.CYAN}{banner}{Colors.RESET}")


async def prompt_token() -> Optional[str]:
    """يطلب JWT token من المستخدم. يُعيد None للخروج."""
    while True:
        try:
            raw = (await ainput(
                f"{Colors.YELLOW}Paste JWT token (or 'exit' to quit): {Colors.RESET}"
            )).strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if not raw:
            continue
        if raw.lower() in ('exit', 'quit', 'q'):
            return None
        # تحقق بسيط من الصيغة (3 أجزاء مفصولة بنقاط)
        if raw.count('.') != 2:
            print(f"{Colors.RED}Invalid JWT format (expected 3 dot-separated parts).{Colors.RESET}")
            continue
        return raw


async def prompt_asset() -> Optional[str]:
    while True:
        try:
            raw = (await ainput(
                f"{Colors.YELLOW}Asset name (e.g. EURUSD_otc, or 'exit'): {Colors.RESET}"
            )).strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if not raw:
            continue
        if raw.lower() in ('exit', 'quit', 'q'):
            return None
        normalized = normalize_asset(raw)
        if not normalized:
            print(f"{Colors.RED}Invalid name.{Colors.RESET}")
            continue
        return normalized


async def prompt_days() -> Optional[int]:
    while True:
        try:
            raw = (await ainput(
                f"{Colors.YELLOW}Number of days (e.g. 7, 30): {Colors.RESET}"
            )).strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if not raw:
            continue
        if raw.lower() in ('exit', 'quit', 'q'):
            return None
        try:
            days = int(float(raw))
            if days <= 0:
                print(f"{Colors.RED}Days must be positive.{Colors.RESET}")
                continue
            return days
        except ValueError:
            print(f"{Colors.RED}Please enter a valid integer.{Colors.RESET}")


async def prompt_timeframe() -> Optional[int]:
    while True:
        try:
            raw = (await ainput(
                f"{Colors.YELLOW}Timeframe in minutes (1, 5, 15, 30, 60): {Colors.RESET}"
            )).strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if not raw:
            continue
        if raw.lower() in ('exit', 'quit', 'q'):
            return None
        try:
            tf = int(raw)
            if tf <= 0:
                print(f"{Colors.RED}Timeframe must be positive.{Colors.RESET}")
                continue
            return tf
        except ValueError:
            print(f"{Colors.RED}Please enter a valid integer.{Colors.RESET}")


async def prompt_account_type() -> bool:
    """يُسأل المستخدم: demo أم real. يُعيد True=demo."""
    raw = (await ainput(
        f"{Colors.YELLOW}Account type (D=Demo / R=Real) [D]: {Colors.RESET}"
    )).strip().lower()
    if raw.startswith('r'):
        return False
    return True


async def prompt_email_password() -> Tuple[Optional[str], Optional[str]]:
    """يطلب الإيميل وكلمة المرور من المستخدم.

    يُعيد (None, None) إذا اختار المستخدم الخروج.
    """
    print(f"{Colors.CYAN}Enter your Binolla account credentials:{Colors.RESET}")
    print(f"{Colors.DIM}  These will be sent to binolla.com/login via a real browser.{Colors.RESET}")
    try:
        email = (await ainput(
            f"{Colors.YELLOW}Email: {Colors.RESET}"
        )).strip()
    except (EOFError, KeyboardInterrupt):
        return None, None
    if not email or email.lower() in ('exit', 'quit', 'q'):
        return None, None

    try:
        password = (await ainput(
            f"{Colors.YELLOW}Password: {Colors.RESET}"
        )).strip()
    except (EOFError, KeyboardInterrupt):
        return None, None
    if not password:
        return None, None

    return email, password


# ==============================================================================
# SECTION 14: COMMAND-LINE INTERFACE
# ==============================================================================
def parse_args() -> Dict[str, Any]:
    """معالجة بسيطة لوسائط سطر الأوامر."""
    args = {
        "token": os.environ.get("BINOLLA_TOKEN", ""),
        "email": os.environ.get("BINOLLA_EMAIL", ""),
        "password": os.environ.get("BINOLLA_PASSWORD", ""),
        "asset": os.environ.get("BINOLLA_ASSET", "EURUSD_otc"),
        "days": int(os.environ.get("BINOLLA_DAYS", "7")),
        "timeframe": int(os.environ.get("BINOLLA_TIMEFRAME", "1")),
        "is_demo": os.environ.get("BINOLLA_ACCOUNT", "demo").lower() != "real",
        "proxies": os.environ.get("BINOLLA_PROXY", ""),
        "headless": os.environ.get("BINOLLA_HEADLESS", "0") == "1",
        "non_interactive": False,
    }
    # وسيطات سطر الأوامر البسيطة
    rest = sys.argv[1:]
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in ("--token",) and i + 1 < len(rest):
            args["token"] = rest[i + 1]; i += 2; continue
        if a in ("--email",) and i + 1 < len(rest):
            args["email"] = rest[i + 1]; i += 2; continue
        if a in ("--password", "--pass") and i + 1 < len(rest):
            args["password"] = rest[i + 1]; i += 2; continue
        if a in ("--asset",) and i + 1 < len(rest):
            args["asset"] = rest[i + 1]; i += 2; continue
        if a in ("--days",) and i + 1 < len(rest):
            args["days"] = int(rest[i + 1]); i += 2; continue
        if a in ("--period", "--timeframe") and i + 1 < len(rest):
            args["timeframe"] = int(rest[i + 1]); i += 2; continue
        if a in ("--real",):
            args["is_demo"] = False; i += 1; continue
        if a in ("--demo",):
            args["is_demo"] = True; i += 1; continue
        if a in ("--proxy",) and i + 1 < len(rest):
            args["proxies"] = rest[i + 1]; i += 2; continue
        if a in ("--headless",):
            args["headless"] = True; i += 1; continue
        if a in ("--non-interactive", "--yes", "-y"):
            args["non_interactive"] = True; i += 1; continue
        if a in ("-h", "--help"):
            print(__doc__)
            sys.exit(0)
        i += 1
    return args


# ==============================================================================
# SECTION 15: MAIN INTERACTIVE LOOP
# ==============================================================================
async def main_async():
    args = parse_args()
    print_banner()

    # ===== 1) حدّد طريقة المصادقة =====
    token = args["token"]
    email = args["email"]
    password = args["password"]

    # جرّب credentials.json إن لم يُمرّر شيء
    if not token and not (email and password):
        creds = load_credentials()
        if creds:
            print(f"{Colors.GREEN}Found saved credentials "
                  f"(saved at {datetime.fromtimestamp(creds.get('saved_at', 0)).isoformat()}).{Colors.RESET}")
            if creds.get("token") and not is_token_expired(creds["token"]):
                print(f"  {Colors.DIM}Saved JWT still valid.{Colors.RESET}")
            elif creds.get("token"):
                print(f"  {Colors.YELLOW}Saved JWT expired — will re-login.{Colors.RESET}")

            # اختر الطريقة
            if creds.get("email") and creds.get("password"):
                print(f"  Saved email: {creds['email']}")
            use_choice = (await ainput(
                f"{Colors.YELLOW}Choose: [J]=use saved JWT, [E]=re-login with email/password, "
                f"[N]=new JWT paste, (J/e/n): {Colors.RESET}"
            )).strip().lower() if not args["non_interactive"] else "j"

            if use_choice in ('n', 'N'):
                token = await prompt_token()
                if token is None:
                    return
            elif use_choice == "e":
                if not (creds.get("email") and creds.get("password")):
                    email, password = await prompt_email_password()
                    if email is None:
                        return
                else:
                    email = creds["email"]
                    password = creds["password"]
            else:  # default J
                if creds.get("token") and not is_token_expired(creds["token"]):
                    token = creds["token"]
                    args["is_demo"] = creds.get("is_demo", True)
                elif creds.get("email") and creds.get("password"):
                    # الـ JWT منتهٍ لكن لدينا إيميل/كلمة مرور — أعد الدخول
                    print(f"  {Colors.YELLOW}Saved JWT expired — re-logging in via browser...{Colors.RESET}")
                    email = creds["email"]
                    password = creds["password"]
                else:
                    # لا JWT ولا إيميل — اطلب JWT
                    token = await prompt_token()
                    if token is None:
                        return
        else:
            # لا توجد اعتمادات محفوظة — اسأل المستخدم
            if args["non_interactive"]:
                print(f"{Colors.RED}No credentials provided. Set BINOLLA_TOKEN or "
                      f"BINOLLA_EMAIL+BINOLLA_PASSWORD env vars.{Colors.RESET}")
                return
            choice = (await ainput(
                f"{Colors.YELLOW}Choose authentication: [J]=paste JWT, "
                f"[E]=email+password via browser, (J/e): {Colors.RESET}"
            )).strip().lower()
            if choice == "e":
                email, password = await prompt_email_password()
                if email is None:
                    return
            else:
                token = await prompt_token()
                if token is None:
                    return

    # إذا قُدّم الإيميل فقط (بدون كلمة مرور) — اطلبها
    if email and not password and not args["non_interactive"]:
        password = (await ainput(
            f"{Colors.YELLOW}Password for {email}: {Colors.RESET}"
        )).strip()
        if not password:
            return
    if password and not email and not args["non_interactive"]:
        email = (await ainput(
            f"{Colors.YELLOW}Email: {Colors.RESET}"
        )).strip()
        if not email:
            return

    # ===== 2) إن وُجد إيميل/كلمة مرور (ولم يُمرّر JWT) — سجّل الدخول عبر HTTP =====
    if email and password and not token:
        logmsg(f"Logging in as {email} via HTTP (qx__1.py-style)...")
        # أنشئ كائن Login مرتبط بـ API وهمي (سنبني API الحقيقي بعد استخراج التوكن)
        from types import SimpleNamespace
        proxy_dict = None
        if args["proxies"]:
            from urllib.parse import urlparse
            p = urlparse(args["proxies"])
            if p.hostname and p.port:
                proxy_dict = {"http": args["proxies"], "https": args["proxies"]}
        login_api = SimpleNamespace(
            host=HOST, https_url=ORIGIN_URL, lang="en",
            session_data={"user_agent": USER_AGENT, "cookies": ""},
            _normalize_proxies=staticmethod(lambda x: {"http": x, "https": x} if x else None)
            if False else (lambda x: {"http": x, "https": x} if x else None),
            proxies=args["proxies"] or None,
        )
        login = Login(login_api, proxies=proxy_dict)
        try:
            ok, jwt_or_err = await login(email, password)
        except Exception as e:
            ok, jwt_or_err = False, f"HTTP login exception: {e}"
        if not ok:
            print(f"{Colors.RED}HTTP login failed: {jwt_or_err}{Colors.RESET}")
            print(f"{Colors.YELLOW}Hint: Binolla uses Cloudflare Turnstile on /login.{Colors.RESET}")
            print(f"{Colors.YELLOW}      If HTTP login fails, paste a JWT manually (extract from DevTools → "
                  f"Application → Local Storage → 'token' key).{Colors.RESET}")
            # Fallback: اطلب JWT يدوياً
            token = await prompt_token()
            if token is None:
                return
        else:
            token = jwt_or_err
            logmsg(f"{Colors.GREEN}Got JWT from HTTP login.{Colors.RESET}")

    if not token:
        print(f"{Colors.RED}No token available.{Colors.RESET}")
        return

    # تحقق من صلاحية التوكن
    if is_token_expired(token):
        print(f"{Colors.YELLOW}Warning: JWT appears expired. WebSocket auth may fail.{Colors.RESET}")
        if email and password:
            logmsg("Re-logging in via HTTP...")
            from types import SimpleNamespace
            proxy_dict = None
            if args["proxies"]:
                proxy_dict = {"http": args["proxies"], "https": args["proxies"]}
            login_api = SimpleNamespace(
                host=HOST, https_url=ORIGIN_URL, lang="en",
                session_data={"user_agent": USER_AGENT, "cookies": ""},
                _normalize_proxies=(lambda x: {"http": x, "https": x} if x else None),
                proxies=args["proxies"] or None,
            )
            login = Login(login_api, proxies=proxy_dict)
            try:
                ok, jwt_or_err = await login(email, password)
                if ok:
                    token = jwt_or_err
            except Exception:
                pass

    # ===== 3) نوع الحساب =====
    if not args["non_interactive"]:
        is_demo = await prompt_account_type()
        args["is_demo"] = is_demo

    # ===== 4) الاتصال =====
    logmsg(f"Connecting to Binolla ({'demo' if args['is_demo'] else 'real'} account)...")
    client = await connect_binolla(token, is_demo=args["is_demo"],
                                   max_attempts=3, proxies=args["proxies"] or None)
    if client is None:
        print(f"\n{Colors.RED}Connection failed after multiple attempts.{Colors.RESET}")
        return

    # حفظ الاعتمادات (JWT + إيميل/كلمة مرور إن وُجدت)
    save_credentials(
        token=token,
        email=email,
        password=password,
        is_demo=args["is_demo"],
        proxy=args["proxies"],
    )
    print(f"{Colors.GREEN}Credentials saved to {CREDENTIALS_FILE.name}{Colors.RESET}\n")

    # ابدأ keepalive
    stop_keepalive = asyncio.Event()
    keepalive_task = asyncio.create_task(keepalive_loop(client, stop_keepalive))

    # ملاحظة: لا نُرسل طلبات أولية إضافية — الخادم يُرسل تلقائياً بعد المصادقة:
    #   s_assets/list, s_settings/list, s_balances/list, s_history/last, s_quotes/list
    # ننتظر مباشرةً إدخال المستخدم لاسم العملة والفريم وعدد الأيام.

    try:
        fetch_count = 0
        while True:
            print(f"\n{Colors.CYAN}{'-'*60}{Colors.RESET}")
            print(f"{Colors.BOLD}  New fetch request{Colors.RESET}")
            print(f"{Colors.CYAN}{'-'*60}{Colors.RESET}")

            asset = args["asset"] if args["non_interactive"] else await prompt_asset()
            if asset is None:
                break
            days = args["days"] if args["non_interactive"] else await prompt_days()
            if days is None:
                break
            timeframe = args["timeframe"] if args["non_interactive"] else await prompt_timeframe()
            if timeframe is None:
                break

            print(f"\n{Colors.CYAN}Summary:{Colors.RESET}")
            print(f"  Asset:     {Colors.BOLD}{pretty_asset(asset, timeframe)}{Colors.RESET}")
            print(f"  Days:      {days}")
            print(f"  Timeframe: M{timeframe}")

            fetch_count += 1
            candles = await fetch_candles_for_asset(
                client, asset, days, timeframe,
                idx=fetch_count, total=fetch_count,
            )
            if not candles:
                print(f"{Colors.RED}No candles fetched.{Colors.RESET}")
            else:
                filepath = save_candles_to_json(candles, asset, timeframe, days)
                if filepath:
                    print(f"{Colors.GREEN}OK Saved {len(candles)} candles to:{Colors.RESET}")
                    print(f"  {Colors.CYAN}{filepath.absolute()}{Colors.RESET}")
                else:
                    print(f"{Colors.RED}Failed to save file.{Colors.RESET}")

            if args["non_interactive"]:
                break

            print(f"\n{Colors.YELLOW}Press Enter to fetch another asset, or type 'exit' to quit.{Colors.RESET}")
            try:
                choice = (await ainput()).strip().lower()
                if choice in ('exit', 'quit', 'q'):
                    break
            except (EOFError, KeyboardInterrupt):
                break
    finally:
        stop_keepalive.set()
        try:
            await asyncio.wait_for(keepalive_task, timeout=2.0)
        except Exception:
            pass
        try:
            await client.close()
        except Exception:
            pass
        print(f"{Colors.CYAN}Shutdown complete.{Colors.RESET}")


def _count_items(x: Any) -> str:
    if x is None:
        return "n/a"
    if isinstance(x, (list, tuple)):
        return str(len(x))
    if isinstance(x, dict):
        # قد يحتوي على list داخلية
        for k in ("assets", "data", "list", "items"):
            if k in x and isinstance(x[k], (list, tuple)):
                return f"{len(x[k])} (in .{k})"
        return str(len(x))
    return "?"


def _format_balances(x: Any) -> str:
    if x is None:
        return "n/a"
    if isinstance(x, dict):
        # Binolla قد يرسل: {"demoBalance": ..., "liveBalance": ...}
        parts = []
        for k in ("liveBalance", "demoBalance", "realBalance", "balance"):
            if k in x:
                parts.append(f"{k}={x[k]}")
        if parts:
            return ", ".join(parts)
    return _summary(x)


def _summary(x: Any, max_len: int = 80) -> str:
    if x is None:
        return "n/a"
    try:
        s = json.dumps(x, ensure_ascii=False)
    except Exception:
        s = str(x)
    if len(s) > max_len:
        return s[:max_len] + "..."
    return s


def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Stopped.{Colors.RESET}")
    except Exception as e:
        log_exception("main", e)


if __name__ == "__main__":
    main()
