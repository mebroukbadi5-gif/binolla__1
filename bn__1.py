#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BINOLLA — Binolla WebSocket API Client (نسخة مبسّطة)
=====================================================
يتصل بمنصة Binolla (https://binolla.com/ar/) عبر WebSocket
باستخدام بروتوكول Socket.IO v4 / Engine.IO v4:

    wss://ws3.binolla.com/socket.io/?EIO=4&transport=websocket

يدعم:
  - مصادقة JWT مباشرة (بدون HTTP login، يكفي تمرير الـ token).
  - استلام الرسائل الثنائية (binary events بصيغة 451-[...]).
  - جلب: الأصول، الأرصدة، الإعدادات، الطلبات المفتوحة/المغلقة،
    التنبيهات، الشموع التاريخية، الاقتباسات اللحظية (quotes).
  - تغيير الأصل والفريم عبر asset/list/change.
  - وضع صفقات (binary options) عبر orders/open.
  - حفظ التوكن والبيانات محلياً.

مبني على نفس بنية qx__1.py (Quotex) مع تعديلات لبروتوكول EIO=4.

البروتوكول باختصار:
  - 0{...}        Engine.IO OPEN  (sid, pingInterval=25s, pingTimeout=20s)
  - 40            Socket.IO CONNECT (من العميل إلى الخادم)
  - 40{...}       Socket.IO CONNECT_ACK (من الخادم)
  - 42[event,data] Socket.IO EVENT (نصّي)
  - 451-[event,{_placeholder:true,num:0}]  Socket.IO BINARY EVENT
                                              (متبوع بإطار ثنائي واحد)
  - 2 / 3         Engine.IO PING / PONG (الخادم يرسل 2، العميل يردّ بـ 3)

الاستخدام:
    python bn__1.py
  ثم أدخل JWT token (يُستخرج من Local Storage في متصفحك بعد تسجيل الدخول
  إلى binolla.com). التوكن يُحفظ في credentials.json لإعادة الاستخدام.

  أو بصيغة non-interactive:
    BINOLLA_TOKEN="eyJ0eXA..." python bn__1.py --asset EURUSD_otc --period 1 --days 7
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
import websocket

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
        # عندما يصل us a `45N-<json>` text packet:
        #   نُخزّنه هنا مع عدد الـ attachments المتوقّعة،
        #   ثم نبدأ بجمع الإطارات الثنائية التالية ونُوزّعها على الـ placeholders.
        self._binary_packet_queue: List[Dict] = []
        # كل عنصر = {"parts": [json_obj], "expected": N, "received": 0}

        # إعدادات heartbeat
        self._ping_interval = 25.0  # ثانية (يُحدّث من رسالة 0{...})
        self._ping_timeout = 20.0
        self._last_server_ping_at: float = time.time()

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
            self.wss.send(data)
            logger.info("Authorization sent (token=%s...).", token[:24])
            logmsg("Sent authorization frame to Binolla server...")
            self.state.auth_status = AuthStatus.PENDING
        except Exception as e:
            logger.error("Failed to send authorization: %s", e)
            self.state.signal_auth_rejected()

    # ---- اشتراك ما بعد المصادقة ----
    def _send_post_auth_subscriptions(self) -> None:
        """يرسل الطلبات الأولية بعد تأكيد المصادقة (يطابق الترتيب المُلتقط)."""
        try:
            # 1) الطلبات النصية (تُرجع data ثنائية عبر s_*)
            self.wss.send('42["orders/opened/list"]')
            self.wss.send('42["orders/closed/list"]')
            self.wss.send('42["assets/list"]')
            self.wss.send('42["alert/list"]')
            self.wss.send('42["alert/closed/list"]')
            self.wss.send('42["indicator/list"]')
            self.wss.send('42["drawing/load"]')
            self.wss.send('42["balances/list"]')
            self.wss.send('42["settings/list"]')
            self.wss.send('42["history/last"]')
            self.wss.send('42["quotes/list"]')

            # 2) تغيير الأصل الافتراضي
            asset = self.api.current_asset or "EURUSD_otc"
            period = self.api.current_period or 1
            change_payload = [{"asset": asset, "period": period}]
            data = '42["asset/list/change",' + json.dumps(change_payload,
                                                          separators=(",", ":")) + ']'
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
            "ping_interval": int(self.websocket_client._ping_interval),
            "ping_timeout": int(self.websocket_client._ping_timeout),
            "ping_payload": "2",
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
        """يجلب الشموع التاريخية من Binolla.

        ملاحظة: Binolla يوفّر `history/last` فقط (آخر N شمعة)، لذا نعتمد على
        دورة إعادة طلب مع تغيير الـ index للحصول على شموع أبعد.
        """
        if not self.api:
            return []
        # Binolla لا يكشف عن endpoint تاريخي صريح مثل history/load في Quotex.
        # نعتمد على history/last الذي يرجع آخر شموع للأصل الحالي.
        await self.start_candles_stream(asset, timeframe_min)
        await asyncio.sleep(0.5)

        # امسح أي حدث سابق
        await self.api.event_registry.clear_event("s_history/last")
        self.api.fetch_history_last()
        data = await self.api.event_registry.wait_event(
            "s_history/last", timeout=timeout)

        if not data:
            return []
        # data هو list من args، args[0] هو الـ payload الثنائي
        try:
            payload = data[0] if isinstance(data, list) and data else data
        except Exception:
            payload = data

        return self._parse_history(payload)

    def _parse_history(self, payload: Any) -> List[Dict]:
        """يُحوّل payload الأصلي إلى قائمة شموع بصيغة OHLC."""
        if not payload:
            return []
        # Binolla قد يرسل: {"candles": [...]}, أو [...]، أو {"data":[...]}
        if isinstance(payload, dict):
            candles = (payload.get("candles") or payload.get("data")
                       or payload.get("history") or [])
        elif isinstance(payload, list):
            candles = payload
        else:
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
    """يقرأ التوكن من credentials.json. يُعيد None إذا لم توجد."""
    if not CREDENTIALS_FILE.exists():
        return None
    try:
        data = json.loads(CREDENTIALS_FILE.read_text())
        if data.get("token"):
            return data
        return None
    except Exception:
        return None


def save_credentials(token: str, is_demo: bool = True, proxy: str = "") -> bool:
    """يحفظ التوكن ونوع الحساب والبروكسي في credentials.json."""
    try:
        existing = {}
        if CREDENTIALS_FILE.exists():
            try:
                existing = json.loads(CREDENTIALS_FILE.read_text())
            except Exception:
                pass
        existing.update({
            "token": token,
            "is_demo": is_demo,
            "proxy": proxy,
            "saved_at": int(time.time()),
        })
        CREDENTIALS_FILE.write_text(json.dumps(existing, indent=2))
        return True
    except Exception as e:
        logmsg(f"Failed to save credentials: {e}")
        return False


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
async def keepalive_loop(client: Binolla, stop_event: asyncio.Event) -> None:
    """يرسل PING كل KEEPALIVE_INTERVAL ثانية للحفاظ على الاتصال حياً."""
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=KEEPALIVE_INTERVAL)
        except asyncio.TimeoutError:
            pass
        if stop_event.is_set():
            break
        if client.api and client.api.websocket_client and client.api.websocket_client.wss:
            try:
                # في EIO=4 نُرسل "2" (PING) للخادم، يردّ بـ "3"
                client.api.send_websocket_request("2", no_force_send=True)
            except Exception as e:
                logger.debug("Keepalive ping failed: %s", e)


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
 ____  _ _ _                     _
| __ _) (_) | |_ ___ ___ _ _ _ _| |_ ___
| _ \ \| | |  _/ -_) -_) '_| ' \  _(_-<
|___/|_|_|\__\__\__\___|_| |_| |_||/__/
        Binolla WebSocket API  |  bn__1.py
"""
    print(f"{Colors.CYAN}{banner}{Colors.RESET}")
    print(f"  {Colors.DIM}EIO=4 / Socket.IO v4 — JWT auth — Binary events{Colors.RESET}")
    print()


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


# ==============================================================================
# SECTION 14: COMMAND-LINE INTERFACE
# ==============================================================================
def parse_args() -> Dict[str, Any]:
    """معالجة بسيطة لوسائط سطر الأوامر."""
    args = {
        "token": os.environ.get("BINOLLA_TOKEN", ""),
        "asset": os.environ.get("BINOLLA_ASSET", "EURUSD_otc"),
        "days": int(os.environ.get("BINOLLA_DAYS", "7")),
        "timeframe": int(os.environ.get("BINOLLA_TIMEFRAME", "1")),
        "is_demo": os.environ.get("BINOLLA_ACCOUNT", "demo").lower() != "real",
        "proxies": os.environ.get("BINOLLA_PROXY", ""),
        "non_interactive": False,
    }
    # وسيطات سطر الأوامر البسيطة
    rest = sys.argv[1:]
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in ("--token",) and i + 1 < len(rest):
            args["token"] = rest[i + 1]; i += 2; continue
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

    # ===== قراءة التوكن =====
    token = args["token"]
    if not token:
        # جرّب credentials.json
        creds = load_credentials()
        if creds:
            print(f"{Colors.GREEN}Found saved token (saved at "
                  f"{datetime.fromtimestamp(creds.get('saved_at', 0)).isoformat()}).{Colors.RESET}")
            use_saved = (await ainput(
                f"{Colors.YELLOW}Use saved token? (Y/n): {Colors.RESET}"
            )).strip().lower()
            if use_saved in ('y', '', 'yes'):
                token = creds["token"]
                args["is_demo"] = creds.get("is_demo", True)
            else:
                token = await prompt_token()
                if token is None:
                    print(f"\n{Colors.YELLOW}Shutting down...{Colors.RESET}")
                    return
        else:
            print(f"{Colors.CYAN}Enter your Binolla JWT token (will be saved automatically).{Colors.RESET}")
            print(f"{Colors.DIM}  Tip: Open binolla.com in your browser, log in, then open DevTools → "
                  f"Application → Local Storage → find the 'token' key and copy its value.{Colors.RESET}")
            token = await prompt_token()
            if token is None:
                print(f"\n{Colors.YELLOW}Shutting down...{Colors.RESET}")
                return

    if not token:
        print(f"{Colors.RED}No token provided.{Colors.RESET}")
        return

    # ===== نوع الحساب =====
    if not args["non_interactive"]:
        is_demo = await prompt_account_type()
        args["is_demo"] = is_demo

    # ===== الاتصال =====
    logmsg(f"Connecting to Binolla ({'demo' if args['is_demo'] else 'real'} account)...")
    client = await connect_binolla(token, is_demo=args["is_demo"],
                                   max_attempts=3, proxies=args["proxies"] or None)
    if client is None:
        print(f"\n{Colors.RED}Connection failed after multiple attempts.{Colors.RESET}")
        return

    # حفظ التوكن
    save_credentials(token, is_demo=args["is_demo"], proxy=args["proxies"])
    print(f"{Colors.GREEN}Token saved to {CREDENTIALS_FILE.name}{Colors.RESET}\n")

    # ابدأ keepalive
    stop_keepalive = asyncio.Event()
    keepalive_task = asyncio.create_task(keepalive_loop(client, stop_keepalive))

    # جلب أولي للمعلومات
    logmsg("Fetching initial data (assets, balances, settings)...")
    try:
        assets = await asyncio.wait_for(client.api.get_assets_async(), timeout=10)
        balances = await asyncio.wait_for(client.api.get_balances_async(), timeout=10)
        settings = await asyncio.wait_for(client.api.get_settings_async(), timeout=10)
        print(f"  {Colors.CYAN}Assets count :{Colors.RESET} "
              f"{_count_items(assets)}")
        print(f"  {Colors.CYAN}Balances    :{Colors.RESET} "
              f"{_format_balances(balances)}")
        print(f"  {Colors.CYAN}Settings    :{Colors.RESET} "
              f"{_summary(settings)}")
    except Exception as e:
        logmsg(f"Initial fetch failed: {e}")

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
