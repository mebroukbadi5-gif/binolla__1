#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CANDAL — Quotex Candle Fetcher (نسخة مبسّطة)
======================================================
هذه نسخة معدّلة من BOT.py تُركّز على جلب الشموع من Quotex وحفظها كـ JSON.

التغييرات الرئيسية:
  - تم نزع جزء MT4 بالكامل (Writer, .hst, MT4 sync engine, dashboard اللحظي).
  - تم نزع حلقات keepalive/health/auto_reconnect/streaming التي تُبقي البوت حياً للأبد.
  - أصبح البوت تفاعلياً: المستخدم يُدخل اسم العملة + عدد الأيام + الفريم (دقائق).
  - يُحفظ الإيميل وكلمة المرور في credentials.json لإعادة الاستخدام.
  - يحفظ الشموع في candles_data/{asset}_{timeframe}m_{days}d_{random}.json
  - بعد كل جلب، ينتظر Enter للجلب التالي أو الخروج.

النواة المثبتة (من BOT.py الأصلي):
  - إعداد SSL + logging
  - HTTP Navigator (CipherSuiteAdapter, Browser)
  - HTTP Login & Settings
  - WebSocket Client & State
  - Quotex API Core
  - Quotex Stable API + candle parsing
"""

import os
import sys
import ssl
import json
import time
import random
import re
import shutil
import logging
import asyncio
import threading
import traceback
import itertools
import contextlib
import platform
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional

import certifi
import requests
import websocket
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

try:
    import orjson as _orjson
    HAS_ORJSON = True
except ImportError:
    _orjson = None
    HAS_ORJSON = False


# ==============================================================================
# SECTION 1: LOGGING & SSL SETUP
# ==============================================================================
def _prepare_logging():
    logger = logging.getLogger(__name__)
    logger.addHandler(logging.NullHandler())
    websocket_logger = logging.getLogger("websocket")
    websocket_logger.setLevel(logging.INFO)
    websocket_logger.addHandler(logging.NullHandler())

_prepare_logging()
logger = logging.getLogger(__name__)

cert_path = certifi.where()
os.environ['SSL_CERT_FILE'] = cert_path
os.environ['WEBSOCKET_CLIENT_CA_BUNDLE'] = cert_path
cacert = os.environ.get('WEBSOCKET_CLIENT_CA_BUNDLE')

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
ssl_context.load_verify_locations(cert_path)


# ==============================================================================
# SECTION 1.5: EVENT-DRIVEN WAIT PRIMITIVES
# ==============================================================================
async def wait_until(predicate: Callable[[], bool], *, timeout: float = 10.0,
                      poll_interval: float = 0.05) -> None:
    """يستدعي predicate() كل poll_interval ثانية حتى يُعيد True أو ينتهي timeout."""
    async def _loop():
        while not predicate():
            await asyncio.sleep(poll_interval)
    await asyncio.wait_for(_loop(), timeout=timeout)


async def wait_for_first_event(*events: asyncio.Event, timeout: float = 10.0) -> int:
    """ينتظر أول event يُطلق من القائمة ويعيد indexه. يطلق TimeoutError عند المهلة."""
    if not events:
        raise ValueError("wait_for_first_event requires at least one event")
    tasks = [asyncio.ensure_future(e.wait()) for e in events]
    try:
        done, pending = await asyncio.wait(tasks, timeout=timeout,
                                           return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        for i, t in enumerate(tasks):
            if t in done and t.result() and not t.cancelled():
                return i
        raise asyncio.TimeoutError()
    except asyncio.CancelledError:
        for t in tasks:
            if not t.done():
                t.cancel()
        raise


def _schedule_event_set(event: Optional[asyncio.Event],
                        loop: Optional[asyncio.AbstractEventLoop]) -> None:
    if event is None or loop is None:
        return
    try:
        if not loop.is_closed() and loop.is_running():
            loop.call_soon_threadsafe(event.set)
    except RuntimeError:
        pass


# ==============================================================================
# SECTION 2: CONSTANTS & SESSION
# ==============================================================================
USER_AGENT = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0"
base_dir = Path.cwd()
session_lock = threading.Lock()


def resource_path(relative_path: str) -> Path:
    global base_dir
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        base_dir = Path(sys._MEIPASS)
    return base_dir / relative_path


def load_session(email: str, user_agent: str = None) -> dict:
    if user_agent is None:
        try:
            user_agent = UserAgent().random
        except Exception:
            user_agent = USER_AGENT
    output_file = Path(resource_path("session.json"))
    with session_lock:
        all_sessions = {}
        if output_file.exists():
            try:
                all_sessions = json.loads(output_file.read_text())
            except json.JSONDecodeError:
                pass
        else:
            output_file.parent.mkdir(exist_ok=True, parents=True)
        if email not in all_sessions:
            all_sessions[email] = {"cookies": None, "token": None, "user_agent": user_agent}
        output_file.write_text(json.dumps(all_sessions, indent=4))
        return all_sessions.get(email)


def update_session(email: str, d: dict) -> dict:
    output_file = Path(resource_path("session.json"))
    with session_lock:
        current_sessions = {}
        if output_file.exists():
            try:
                current_sessions = json.loads(output_file.read_text())
            except json.JSONDecodeError:
                pass
        else:
            output_file.parent.mkdir(exist_ok=True, parents=True)
        current_sessions[email] = d
        output_file.write_text(json.dumps(current_sessions, indent=4))
        return current_sessions.get(email)


# ==============================================================================
# SECTION 3: HTTP NAVIGATOR (PROVEN WORKING METHOD)
# ==============================================================================
retry_strategy = Retry(
    total=3, backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504, 104],
    allowed_methods=["HEAD", "POST", "PUT", "GET", "OPTIONS"],
)


class CipherSuiteAdapter(HTTPAdapter):
    __attrs__ = ['ssl_context', 'max_retries', 'config', '_pool_connections',
                 '_pool_maxsize', '_pool_block', 'source_address']

    def __init__(self, *args, **kwargs):
        self.ssl_context = kwargs.pop('ssl_context', None)
        self.cipherSuite = kwargs.pop('cipherSuite',
            'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:'
            'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:'
            'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:'
            'DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384')
        self.source_address = kwargs.pop('source_address', None)
        self.server_hostname = kwargs.pop('server_hostname', None)
        self.ecdhCurve = kwargs.pop('ecdhCurve', 'prime256v1')
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
        super().__init__(**kwargs)

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
    def __init__(self, *args, **kwargs):
        self.response = None
        self.default_headers = None
        self.ecdhCurve = kwargs.pop('ecdhCurve', 'prime256v1')
        self.cipherSuite = kwargs.pop('cipherSuite',
            'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:'
            'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:'
            'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:'
            'DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384')
        self.source_address = kwargs.pop('source_address', None)
        self.server_hostname = kwargs.pop('server_hostname', None)
        # استخرج proxies قبل super().__init__ (الذي يعيد ضبط self.proxies إلى {})
        _proxies = kwargs.pop('proxies', None)
        super().__init__(*args, **kwargs)
        # اضبط proxies بعد super().__init__ حتى لا تُكتب فوقها بـ {}
        # هذا يحل المشكلة: send_request يفحص self.proxies لكن Session.__init__ يفرغها
        self.proxies = _proxies
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
# SECTION 4: HTTP LOGIN & SETTINGS
# ==============================================================================
class Login(Browser):
    url = ""
    cookies = None
    ssid = None
    base_url = 'qxbroker.com'
    https_base_url = f'https://{base_url}'

    def __init__(self, api, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.api = api
        self.headers = self.get_headers()
        self.full_url = f"{self.https_base_url}/{api.lang}"

    def get_token(self):
        self.headers["Connection"] = "keep-alive"
        self.headers["Accept-Encoding"] = "gzip, deflate, br"
        self.headers["Accept-Language"] = "pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3"
        self.headers["Accept"] = ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                                  "image/avif,image/webp,*/*;q=0.8")
        self.headers["Referer"] = f"{self.full_url}/sign-in"
        self.headers["Upgrade-Insecure-Requests"] = "1"
        self.headers["Sec-Ch-Ua-Mobile"] = "?0"
        self.headers["Sec-Ch-Ua-Platform"] = '"Linux"'
        self.headers["Sec-Fetch-Site"] = "same-origin"
        self.headers["Sec-Fetch-User"] = "?1"
        self.headers["Sec-Fetch-Dest"] = "document"
        self.headers["Sec-Fetch-Mode"] = "navigate"
        self.headers["Dnt"] = "1"
        self.send_request("GET", f"{self.full_url}/sign-in/modal/")
        html = self.get_soup()
        match = html.find("input", {"name": "_token"})
        return None if not match else match.get("value")

    async def awaiting_pin(self, data, input_message):
        self.headers["Content-Type"] = "application/x-www-form-urlencoded"
        self.headers["Referer"] = f"{self.full_url}/sign-in/modal"
        data["keep_code"] = 1
        try:
            code = input(input_message)
            if not code.isdigit():
                print("Please enter a valid code.")
                await self.awaiting_pin(data, input_message)
            data["code"] = code
        except KeyboardInterrupt:
            print("\nClosing program.")
            sys.exit()
        await asyncio.sleep(1)
        self.send_request(method="POST", url=f"{self.full_url}/sign-in/modal", data=data)

    def get_profile(self):
        self.response = self.send_request(method="GET", url=f"{self.full_url}/trade")
        if self.response:
            script = self.get_soup().find_all("script", {"type": "text/javascript"})
            script = script[0].get_text() if script else "{}"
            match = script.strip().replace(";", "").replace("window.settings = ", "")
            self.cookies = self.get_cookies()
            try:
                settings_dict = json.loads(match)
                self.ssid = settings_dict.get("token")
            except json.JSONDecodeError:
                self.ssid = None
            self.api.session_data["cookies"] = self.cookies
            self.api.session_data["token"] = self.ssid
            self.api.session_data["user_agent"] = self.headers["User-Agent"]
            update_session(self.api.username, self.api.session_data)
            return self.response, settings_dict if self.ssid else None
        return None, None

    async def _post(self, data):
        self.response = self.send_request(method="POST", url=f"{self.full_url}/sign-in/", data=data)
        required_keep_code = self.get_soup().find("input", {"name": "keep_code"})
        if required_keep_code:
            auth_body = self.get_soup().find("main", {"class": "auth__body"})
            input_message = (f'{auth_body.find("p").text}: '
                             if auth_body.find("p")
                             else "Enter the PIN code sent to your email: ")
            await self.awaiting_pin(data, input_message)
            await asyncio.sleep(1)
            return self.success_login()
        return self.success_login()

    def success_login(self):
        if "trade" in str(self.response.url):
            return True, "Login successful."
        soup = self.get_soup()
        not_available = soup.select_one("#tab-1 > div > div.modal-sign__not-avalible__title")
        if not_available:
            return False, f"Service unavailable: {not_available.get_text(strip=True)}"
        error = soup.select_one("#tab-1 form > div:nth-child(2) > div")
        msg = error.get_text(strip=True) if error else "Unknown error"
        return False, f"Login failed. {msg}"

    async def __call__(self, username, password, user_data_dir=None):
        data = {"_token": self.get_token(), "email": username,
                "password": password, "remember": 1}
        status, msg = await self._post(data)
        if status:
            self.get_profile()
        return status, msg


class Settings(Browser):
    def __init__(self, api):
        # مرّر proxies من api إلى Settings
        proxies_dict = api._normalize_proxies(api.proxies) if hasattr(api, '_normalize_proxies') else None
        super().__init__(proxies=proxies_dict)
        self.set_headers()
        self.api = api
        self.headers = self.get_headers()

    def get_settings(self):
        self.headers["content-type"] = "application/json"
        self.headers["referer"] = f"{self.api.https_url}/{self.api.lang}/trade"
        self.headers["cookie"] = self.api.session_data.get("cookies", "")
        self.headers["user-agent"] = self.api.session_data.get("user_agent", "")
        response = self.send_request("GET", f"{self.api.https_url}/api/v1/cabinets/digest")
        return response.json()


# ==============================================================================
# SECTION 5: WEBSOCKET CLIENT & STATE
# ==============================================================================
class WebsocketStatus(IntEnum):
    DISCONNECTED = 0
    CONNECTED = 1
    CONNECTING = 2
    ERROR = -1


class AuthStatus(IntEnum):
    NOT_AUTHENTICATED = 0
    AUTHENTICATING = 1
    AUTHENTICATED = 2
    FAILED = -1


class ConnectionState:
    def __init__(self):
        self.SSID = None
        self.status = WebsocketStatus.DISCONNECTED
        self.auth_status = AuthStatus.NOT_AUTHENTICATED
        self.ssl_Mutual_exclusion = False
        self.ssl_Mutual_exclusion_write = False
        self.check_rejected_connection = False
        self.check_accepted_connection = False
        self.check_websocket_if_error = False
        self.check_websocket_if_connect = None
        self.websocket_error_reason = None
        # EVENT-DRIVEN: تُهيّأ lazily من async context
        self.ws_connected_event: Optional[asyncio.Event] = None
        self.ws_closed_event: Optional[asyncio.Event] = None
        self.auth_accepted_event: Optional[asyncio.Event] = None
        self.auth_rejected_event: Optional[asyncio.Event] = None
        self.ws_error_event: Optional[asyncio.Event] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def init_events(self) -> None:
        if self.ws_connected_event is None: self.ws_connected_event = asyncio.Event()
        if self.ws_closed_event is None: self.ws_closed_event = asyncio.Event()
        if self.auth_accepted_event is None: self.auth_accepted_event = asyncio.Event()
        if self.auth_rejected_event is None: self.auth_rejected_event = asyncio.Event()
        if self.ws_error_event is None: self.ws_error_event = asyncio.Event()
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None

    def reset_events(self) -> None:
        for ev in (self.ws_connected_event, self.ws_closed_event,
                   self.auth_accepted_event, self.auth_rejected_event,
                   self.ws_error_event):
            if ev is not None:
                ev.clear()

    def signal_ws_connected(self): _schedule_event_set(self.ws_connected_event, self._loop)
    def signal_ws_closed(self): _schedule_event_set(self.ws_closed_event, self._loop)
    def signal_auth_accepted(self): _schedule_event_set(self.auth_accepted_event, self._loop)
    def signal_auth_rejected(self): _schedule_event_set(self.auth_rejected_event, self._loop)
    def signal_ws_error(self): _schedule_event_set(self.ws_error_event, self._loop)


class WebsocketClient:
    def __init__(self, api):
        self.api = api
        self.state = api.state
        self.headers = {
            "User-Agent": self.api.session_data.get("user_agent", USER_AGENT),
            "Origin": self.api.https_url,
            "Host": f"ws2.{self.api.host}",
        }
        self.wss = websocket.WebSocketApp(
            self.api.wss_url,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close,
            on_open=self.on_open,
            on_ping=self.on_ping,
            on_pong=self.on_pong,
            header=self.headers,
            cookie=self.api.session_data.get("cookies"),
        )

    def on_message(self, wss, msg):
        self.state.ssl_Mutual_exclusion = True
        try:
            if self.api is not None:
                self.api.last_message_at = time.time()
            msg_str = msg.decode("utf-8", errors="ignore") if isinstance(msg, bytes) else str(msg)

            if msg_str == "2":
                try:
                    self.wss.send("3")
                except Exception:
                    pass
                self.state.ssl_Mutual_exclusion = False
                return
            if msg_str == "3":
                self.state.ssl_Mutual_exclusion = False
                return

            if "authorization/reject" in msg_str:
                logger.warning("Token rejected.")
                self.state.check_rejected_connection = True
                self.state.auth_status = AuthStatus.FAILED
                self.state.signal_auth_rejected()
            elif "s_authorization" in msg_str:
                self.state.check_accepted_connection = True
                self.state.check_rejected_connection = False
                self.state.auth_status = AuthStatus.AUTHENTICATED
                self.state.status = WebsocketStatus.CONNECTED
                self.state.signal_auth_accepted()

            message = None
            if len(msg_str) > 1 and msg_str[1] in ('[', '{'):
                try:
                    message = json.loads(msg_str[1:])
                except Exception:
                    pass

            if message is not None:
                self._process_message_and_raise_events(message)

            if str(msg_str) == "41":
                self.state.check_websocket_if_connect = 0
        except Exception as e:
            logger.error("Unhandled error in on_message: %s", e)
        self.state.ssl_Mutual_exclusion = False

    def _process_message_and_raise_events(self, message):
        try:
            loop = self.api._async_loop
            if loop is None or not loop.is_running():
                return
            if isinstance(message, dict):
                asset = message.get("asset")
                if asset and (message.get("candles") or message.get("data") or message.get("history")):
                    self.api.candle_v2_data[asset] = message
                    self.api.candles.candles_data = (message.get("candles")
                                                    or message.get("data")
                                                    or message.get("history"))
                    asyncio.run_coroutine_threadsafe(
                        self.api.event_registry.set_event(f'candles_ready_{asset}', message),
                        loop)
                    index = message.get("index")
                    if index is not None:
                        asyncio.run_coroutine_threadsafe(
                            self.api.event_registry.set_event(f'candles_ready_{asset}_{index}', message),
                            loop)
            if isinstance(message, dict) and (message.get("liveBalance") or message.get("demoBalance")):
                self.api.account_balance = message
        except Exception as e:
            logger.debug(f"Error processing message: {e}")

    def on_error(self, wss, error):
        logger.error(error)
        self.state.websocket_error_reason = str(error)
        self.state.check_websocket_if_error = True
        self.state.status = WebsocketStatus.ERROR
        self.state.check_accepted_connection = False
        self.state.signal_ws_error()

    def on_open(self, wss):
        logger.info("Websocket client connected.")
        self.state.check_websocket_if_connect = 1
        self.state.status = WebsocketStatus.CONNECTED
        self.state.signal_ws_connected()
        asset_name = self.api.current_asset or "EURUSD_otc"
        period = self.api.current_period or 60
        self.wss.send('42["tick"]')
        self.wss.send('42["indicator/list"]')
        self.wss.send('42["drawing/load"]')
        self.wss.send('42["pending/list"]')
        self.wss.send(f'42["instruments/update",{{"asset":"{asset_name}","period":{period}}}]')
        self.wss.send(f'42["depth/follow","{asset_name}"]')
        self.wss.send('42["chart_notification/get"]')
        self.wss.send('42["instruments/get"]')
        self.wss.send('42["tick"]')

    def on_close(self, wss, close_status_code, close_msg):
        logger.info("Websocket connection closed.")
        self.state.check_websocket_if_connect = 0
        self.state.status = WebsocketStatus.DISCONNECTED
        self.state.check_accepted_connection = False
        self.state.signal_ws_closed()

    def on_ping(self, wss, ping_msg): pass
    def on_pong(self, wss, pong_msg): pass


# ==============================================================================
# SECTION 6: QUOTEX API CORE
# ==============================================================================
class CandlesObj:
    def __init__(self): self.__candles_data = None
    @property
    def candles_data(self): return self.__candles_data
    @candles_data.setter
    def candles_data(self, candles_data): self.__candles_data = candles_data


class EventRegistry:
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


class QuotexAPI:
    def __init__(self, host, username, password, lang, proxies=None, user_data_dir="."):
        self.state = ConnectionState()
        self.trace_ws = False
        self.current_asset = None
        self.current_period = None
        self.account_balance = None
        self.account_type = 1
        self.instruments = None
        self.host = host
        self.https_url = f"https://{host}"
        self.wss_url = f"wss://ws2.{host}/socket.io/?EIO=3&transport=websocket"
        self.websocket_thread = None
        self.websocket_client = None
        self.username = username
        self.password = password
        self.proxies = proxies
        self.lang = lang
        self.user_data_dir = user_data_dir
        self.session_data = {}
        # مرّر proxies إلى Browser حتى يستخدمها HTTP (Login + Settings)
        # إذا proxy هو "http://1.2.3.4:8080" نُحوّله إلى dict متوافق مع requests
        proxies_dict = self._normalize_proxies(proxies)
        self.browser = Browser(proxies=proxies_dict)
        self.browser.set_headers()
        self.settings = Settings(self)
        self.settings.proxies = proxies_dict  # تأكد أن Settings أيضاً يستخدم البروكسي
        self.candles = CandlesObj()
        self.candle_v2_data = {}
        self.realtime_price = defaultdict(list)
        self.event_registry = EventRegistry()
        self._async_loop: Optional[asyncio.AbstractEventLoop] = None
        self.last_message_at: float = time.time()

    @staticmethod
    def _normalize_proxies(proxies) -> Optional[dict]:
        """يحوّل proxy string (أو dict) إلى dict صيغة requests."""
        if not proxies:
            return None
        if isinstance(proxies, dict):
            return proxies
        if isinstance(proxies, str):
            # صيغة مثل "http://1.2.3.4:8080" أو "socks5://1.2.3.4:1080"
            return {"http": proxies, "https": proxies}
        return None

    @property
    def login(self):
        # مرّر proxies إلى Login حتى يستخدمها طلبات HTTP لتسجيل الدخول
        return Login(self, proxies=self._normalize_proxies(self.proxies))

    def send_websocket_request(self, data, no_force_send=True):
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

    def subscribe_realtime_candle(self, asset, period):
        self.realtime_price[asset] = []
        data = f'42["instruments/update", {json.dumps({"asset": asset, "period": period})}]'
        return self.send_websocket_request(data)

    def follow_candle(self, asset):
        return self.send_websocket_request(f'42["depth/follow", {json.dumps(asset)}]')

    def chart_notification(self, asset):
        return self.send_websocket_request(
            f'42["chart_notification/get", {json.dumps({"asset": asset, "version": "1.0.0"})}]')

    def get_candles_ws(self, asset, index, time_val, offset, period):
        payload = {"asset": asset, "index": index, "time": time_val, "offset": offset, "period": period}
        data = f'42["history/load",{json.dumps(payload)}]'
        return self.send_websocket_request(data)

    async def authenticate(self):
        async with self.login as login:
            status, msg = await login(self.username, self.password, self.user_data_dir)
        if status:
            self.state.SSID = self.session_data.get("token")
        return status, msg

    async def start_websocket(self):
        self.state.check_websocket_if_connect = None
        self.state.check_websocket_if_error = False
        self.state.websocket_error_reason = None
        self.state.init_events()
        self.state.reset_events()
        try:
            self.state._loop = asyncio.get_running_loop()
        except RuntimeError:
            self.state._loop = None

        if not self.state.SSID:
            await self.authenticate()
        self.websocket_client = WebsocketClient(self)
        payload = {
            "suppress_origin": True, "ping_interval": 24, "ping_timeout": 20,
            "ping_payload": "2",
            "origin": self.https_url, "host": f"ws2.{self.host}",
            "sslopt": {"check_hostname": True, "cert_reqs": ssl.CERT_REQUIRED,
                       "ca_certs": cacert, "context": ssl_context},
        }
        # مرّر البروكسي إلى WebSocket إذا وُجد
        proxy_dict = self._normalize_proxies(self.proxies)
        if proxy_dict:
            proxy_url = proxy_dict.get("http") or proxy_dict.get("https")
            if proxy_url:
                # تحليل "http://host:port" أو "socks5://host:port"
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(proxy_url)
                    if parsed.hostname and parsed.port:
                        payload["http_proxy_host"] = parsed.hostname
                        payload["http_proxy_port"] = parsed.port
                        if parsed.scheme.startswith("socks"):
                            payload["http_proxy_auth_timeout"] = 30
                except Exception:
                    pass
        if platform.system() == "Linux":
            payload["sslopt"]["ssl_version"] = ssl.PROTOCOL_TLS
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
                timeout=10.0,
            )
        except asyncio.TimeoutError:
            return False, "Timeout waiting for websocket open"

        if idx == 0:
            return True, "Websocket connected successfully!!!"
        elif idx == 1:
            self.state.SSID = None
            return False, "Websocket Token Rejected."
        elif idx == 2:
            return False, self.state.websocket_error_reason or "Websocket error"
        elif idx == 3:
            return False, "Websocket connection closed."
        return False, "Unknown websocket state"

    async def send_ssid(self, timeout=10):
        if not self.state.SSID:
            return False
        if self.state.auth_accepted_event is None:
            self.state.init_events()
        self.state.auth_accepted_event.clear()
        self.state.auth_rejected_event.clear()

        payload = {"session": self.state.SSID, "isDemo": self.account_type, "tournamentId": 0}
        data = f'42["authorization",{json.dumps(payload)}]'
        self.send_websocket_request(data)

        try:
            idx = await wait_for_first_event(
                self.state.auth_accepted_event,
                self.state.auth_rejected_event,
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            return False
        return idx == 0

    async def connect(self, is_demo):
        self.account_type = 1 if is_demo else 0
        self.state.ssl_Mutual_exclusion = False
        self.state.ssl_Mutual_exclusion_write = False
        check_websocket, websocket_reason = await self.start_websocket()
        if not check_websocket:
            return check_websocket, websocket_reason
        check_ssid = await self.send_ssid()
        if not check_ssid:
            await self.authenticate()
            if self.state.SSID:
                await self.send_ssid()
        return check_websocket, websocket_reason

    async def close(self):
        if self.websocket_client and self.websocket_client.wss:
            self.websocket_client.wss.close()
            await asyncio.sleep(1)
        if self.websocket_thread and self.websocket_thread.is_alive():
            self.websocket_thread.join(timeout=5)
        return True


# ==============================================================================
# SECTION 7: QUOTEX STABLE API + CANDLE PARSING
# ==============================================================================
_request_counter = itertools.count(int(time.time() * 1000))


def _parse_raw_candles(raw_candles):
    """يُحوّل الشموع الخام من WebSocket إلى قائمة dicts بصيغة OHLC موحّدة.

    يدعم ثلاث صيغ يمكن أن يُرسلها الخادم عبر "history/load":
      1) [time, open, close, high, low]       — صيغة Quotex الشائعة (5 عناصر)
      2) [time, open, close, high, low, vol] — نفس الصيغة مع volume (6 عناصر)
      3) {"time", "open", "high", "low", "close", ...} — dict
      4) [time, price(, volume)] — tick فردي (يُحوّل إلى شمعة بسيطة)
    """
    if not raw_candles:
        return []
    parsed = []
    for c in raw_candles:
        try:
            if isinstance(c, dict) and 'time' in c:
                t = int(c.get('time', c.get('timestamp', 0)))
                o = float(c.get('open', 0) or 0)
                h = float(c.get('high', c.get('max', 0)) or 0)
                l = float(c.get('low', c.get('min', 0)) or 0)
                cl = float(c.get('close', c.get('c', 0)) or 0)
                v = int(c.get('volume', c.get('vol', 0)) or 0)
                if t > 0 and o > 0 and h > 0 and l > 0 and cl > 0:
                    parsed.append({'time': t, 'open': o, 'high': h, 'low': l,
                                   'close': cl, 'volume': v})
            elif isinstance(c, (list, tuple)) and len(c) >= 5:
                t = int(c[0]); o = float(c[1]); cl = float(c[2])
                h = float(c[3]); l = float(c[4])
                v = int(c[5]) if len(c) >= 6 else 0
                if t > 0 and o > 0 and h > 0 and l > 0 and cl > 0:
                    parsed.append({'time': t, 'open': o, 'high': h, 'low': l,
                                   'close': cl, 'volume': v})
            elif isinstance(c, (list, tuple)) and len(c) >= 2:
                t = int(c[0]); p = float(c[1])
                v = int(c[2]) if len(c) >= 3 else 0
                if t > 0 and p > 0:
                    parsed.append({'time': t, 'open': p, 'high': p, 'low': p,
                                   'close': p, 'volume': v})
        except (TypeError, ValueError):
            continue
    return parsed


def process_candles_v2(history, asset, data):
    if not history or not isinstance(history, dict):
        return data if data else []
    candles_data = history.get(asset, {})
    candles = candles_data.get("candles", [])[1:] if candles_data else []
    combined = candles + (data if data else [])
    if combined:
        candle_dict = {c.get('time'): c for c in combined if isinstance(c, dict) and 'time' in c}
        return list(candle_dict.values()) if candle_dict else []
    return combined


def merge_candles(candles_data):
    if not candles_data:
        return []
    candle_dict = {c['time']: c for c in candles_data if isinstance(c, dict) and 'time' in c}
    return sorted(candle_dict.values(), key=lambda x: x['time']) if candle_dict else []


class Quotex:
    def __init__(self, email=None, password=None, host="qxbroker.com", lang="en",
                 proxies=None, user_data_dir="browser",
                 asset_default="EURUSD_otc", period_default=60):
        self.email = email
        self.password = password
        self.host = host
        self.lang = lang
        self.proxies = proxies
        self.user_data_dir = user_data_dir
        self.asset_default = asset_default
        self.period_default = period_default
        self.account_is_demo = 1
        self.codes_asset = {}
        self.api = None
        self.subscribe_candle = []
        self.subscribe_candle_all_size = []
        self.subscribe_mood = []
        session = load_session(self.email, USER_AGENT)
        self.session_data = session

    async def check_connect(self):
        if self.api is None:
            return False
        try:
            await wait_until(
                lambda: self.api.state.check_accepted_connection == 1,
                timeout=2.0, poll_interval=0.05,
            )
            return True
        except asyncio.TimeoutError:
            return self.api.state.check_accepted_connection == 1

    async def connect(self):
        self.api = QuotexAPI(self.host, self.email, self.password, self.lang,
                             proxies=self.proxies, user_data_dir=self.user_data_dir)
        self.api.session_data = self.session_data
        self.api.state.SSID = self.session_data.get("token")
        self.api._async_loop = asyncio.get_running_loop()
        if not self.session_data.get("token"):
            check, reason = await self.api.authenticate()
            if not check:
                return check, reason
        check, reason = await self.api.connect(self.account_is_demo == 1)
        if not check:
            self.session_data = {}
            return False, "Websocket connection rejected."
        return check, reason

    async def change_account(self, balance_mode: str):
        self.account_is_demo = 0 if balance_mode.upper() == "REAL" else 1
        self.api.account_type = self.account_is_demo
        payload = {"demo": self.api.account_type, "tournamentId": 0}
        self.api.send_websocket_request(f'42["account/change",{json.dumps(payload)}]')

    async def start_candles_stream(self, asset="EURUSD_otc", period=60):
        if self.api:
            self.api.current_asset = asset
            self.api.current_period = period
            self.api.subscribe_realtime_candle(asset, period)
            self.api.chart_notification(asset)
            self.api.follow_candle(asset)

    async def _fetch_historical_batch(self, asset, fetch_time, offset, period, index, timeout):
        if self.api is None:
            return None
        payload = {"asset": asset, "index": index, "time": fetch_time,
                   "offset": offset, "period": period}
        ws_msg = f'42["history/load",{json.dumps(payload)}]'
        event_name = f'candles_ready_{asset}_{index}'
        await self.api.event_registry.clear_event(event_name)
        self.api.send_websocket_request(ws_msg)
        try:
            return await self.api.event_registry.wait_event(event_name, timeout=timeout)
        except Exception:
            return None

    def _parse_historical_candles(self, raw_data):
        if raw_data is None:
            return []
        raw_candles = raw_data.get("data", []) or raw_data.get("candles", [])
        if not raw_candles:
            return []
        parsed = []
        for c in raw_candles:
            if isinstance(c, list) and len(c) >= 5:
                parsed.append({
                    "time": int(c[0]), "open": float(c[1]),
                    "close": float(c[2]), "high": float(c[3]), "low": float(c[4]),
                })
            elif isinstance(c, dict) and "time" in c:
                parsed.append(c)
        return parsed

    async def get_historical_candles(self, asset, amount_of_seconds, period,
                                     timeout=30, max_workers=5, progress_callback=None):
        """يجلب شموع تاريخية للأصل المطلوب.

        المعاملات:
          asset            : اسم الأصل بصيغة Quotex (مثلاً EURUSD_otc)
          amount_of_seconds: عدد الثواني المطلوب جلبها للماضي
          period           : طول الشمعة بالثواني (60 = M1, 300 = M5, 3600 = H1)
          max_workers      : عدد العمال المتوازين (5 = السرعة الأصلية)
        """
        max_workers = max_workers or 1
        chunk_seconds = period * FETCH_CHUNK_SIZE  # period * 200 = عدد الثواني لكل batch
        all_candles = {}
        current_time = int(time.time())
        target_start_time = current_time - amount_of_seconds
        block_size = amount_of_seconds // max_workers
        semaphore = asyncio.Semaphore(max_workers)

        async def worker(start_t, end_t, worker_id):
            worker_candles = {}
            async with semaphore:
                oldest_t = start_t
                consecutive_failures = 0
                while oldest_t > end_t:
                    # تحقق من الاتصال قبل كل batch
                    if not self.api or not getattr(self.api.state, 'check_accepted_connection', False):
                        break
                    index = next(_request_counter)
                    batch_data = await self._fetch_historical_batch(
                        asset, oldest_t, chunk_seconds, period, index, timeout)
                    if not batch_data:
                        oldest_t -= chunk_seconds
                        consecutive_failures += 1
                        if consecutive_failures >= 3:
                            break
                        await asyncio.sleep(FETCH_BATCH_DELAY * 2)
                        continue
                    consecutive_failures = 0
                    new_batch = self._parse_historical_candles(batch_data)
                    if not new_batch:
                        oldest_t -= chunk_seconds
                        continue
                    batch_times = []
                    for c in new_batch:
                        ts = c['time']
                        if ts >= end_t and ts <= start_t:
                            worker_candles[ts] = c
                            batch_times.append(ts)
                    if not batch_times:
                        oldest_t -= chunk_seconds
                        continue
                    batch_times.sort()
                    new_oldest = batch_times[0]
                    if progress_callback:
                        progress_callback(start_t - new_oldest, start_t - end_t,
                                          len(worker_candles), f"Worker-{worker_id}")
                    oldest_t = new_oldest if new_oldest < oldest_t else oldest_t - chunk_seconds
                    await asyncio.sleep(FETCH_BATCH_DELAY)
            return list(worker_candles.values())

        await self.start_candles_stream(asset, period)
        tasks = []
        for i in range(max_workers):
            s = current_time - (i * block_size)
            e = max(target_start_time, s - block_size)
            tasks.append(worker(s, e, i))
        results = await asyncio.gather(*tasks)
        for batch in results:
            for c in batch:
                all_candles[c['time']] = c
        return sorted(all_candles.values(), key=lambda x: x['time'])

    async def close(self):
        if self.api:
            return await self.api.close()
        return True


# ==============================================================================
# SECTION 8: CONSTANTS & CONFIG (جديد)
# ==============================================================================
CREDENTIALS_FILE = Path("credentials.json")
CANDLES_DIR = Path("candles_data")
CANDLES_DIR.mkdir(exist_ok=True)

# إعدادات الجلب — متوازي 5 workers (السرعة الأصلية ~4s لكل 1000 شمعة)
FETCH_MAX_WORKERS = 5
FETCH_CHUNK_SIZE = 200         # 200 شمعة لكل batch
FETCH_BATCH_DELAY = 0.1        # 0.1s بين batches
MAX_FETCH_RETRIES = 5
RETRY_BACKOFF_BASE = 2
RETRY_BACKOFF_MAX = 15
KEEPALIVE_INTERVAL = 5         # ping كل 5 ثوانٍ للحفاظ على الاتصال بين عمليات الجلب

# أدوات التسجيل
LOG_FILE = Path("candal.log")


def logmsg(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"  \033[2m[{ts}]\033[0m {msg}")
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass


def log_exception(context: str, exc: BaseException):
    ts = datetime.now().strftime("%H:%M:%S")
    tb_text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    print(f"  \033[91m[{ts}] FATAL in {context}: {exc}\033[0m")
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] FATAL in {context}: {exc}\n{tb_text}\n")
    except Exception:
        pass


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


# التقاط استثناءات الـ threads
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
# SECTION 9: CREDENTIALS MANAGEMENT (حفظ الإيميل وكلمة المرور)
# ==============================================================================
SESSION_FILE = Path("session.json")
BROWSER_DIR = Path("browser")


def purge_old_session() -> None:
    """Delete any saved Quotex session so we always log in fresh.

    Quotex may reject connections that reuse a stale token from a previous
    run. By deleting session.json and the browser/ cache directory on
    startup, we force a brand-new login every time.
    """
    try:
        if SESSION_FILE.exists():
            SESSION_FILE.unlink()
    except Exception:
        pass
    try:
        if BROWSER_DIR.exists():
            shutil.rmtree(BROWSER_DIR, ignore_errors=True)
    except Exception:
        pass


def load_credentials() -> Optional[Dict[str, str]]:
    """يقرأ بيانات الدخول من credentials.json. يُعيد None إذا لم توجد."""
    if not CREDENTIALS_FILE.exists():
        return None
    try:
        data = json.loads(CREDENTIALS_FILE.read_text())
        if data.get("email") and data.get("password"):
            return data
        return None
    except Exception:
        return None


def save_credentials(email: str, password: str, proxy: str = "") -> bool:
    """يحفظ بيانات الدخول والبروكسي في credentials.json لإعادة الاستخدام لاحقاً."""
    try:
        existing = {}
        if CREDENTIALS_FILE.exists():
            try: existing = json.loads(CREDENTIALS_FILE.read_text())
            except Exception: pass
        existing.update({
            "email": email,
            "password": password,
            "proxy": proxy,
            "saved_at": int(time.time())
        })
        CREDENTIALS_FILE.write_text(json.dumps(existing, indent=2))
        return True
    except Exception as e:
        logmsg(f"Failed to save credentials: {e}")
        return False


# ==============================================================================
# SECTION 10: ASSET NAME NORMALIZATION (جديد)
# ==============================================================================
def normalize_asset(raw: str) -> str:
    """يُعيد اسم الأصل بصيغة Quotex الموحّدة: حروف كبيرة + لاحقة _otc.

    أمثلة:
      "EURUSD"     -> "EURUSD_otc"
      "EURUSD_otc" -> "EURUSD_otc"
      "EUR/USD"    -> "EURUSD_otc"
      "eur usd"    -> "EURUSD_otc"
      "EURUSDOtC"  -> "EURUSD_otc"
    """
    s = raw.strip()
    if not s:
        return ""
    # حذف كل الرموز غير الحروف/الأرقام
    s = re.sub(r'[^a-zA-Z0-9]', '', s)
    if not s:
        return ""
    # حذف لاحقة OTC إن وُجدت، سنعيد إضافتها بصيغة موحّدة
    if s.upper().endswith("OTC"):
        s = s[:-3]
    s = s.upper()
    return f"{s}_otc"


def pretty_asset(symbol: str, timeframe_min: int) -> str:
    """يُعيد اسم عرض جميل: EUR/USD · OTC (M5)"""
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
# SECTION 11: JSON FILE SAVING (جديد)
# ==============================================================================
def save_candles_to_json(candles: List[Dict], asset: str, timeframe_min: int, days: int) -> Optional[Path]:
    """يحفظ الشموع في ملف JSON باسم: {asset}_{timeframe}m_{days}d_{random}.json

    اسم الملف يحتوي على رقم عشوائي (8 خانات hex) لمنع الكتابة فوق الملف القديم
    عند إعادة جلب نفس العملة بنفس الإعدادات.

    هيكل الملف:
    {
      "metadata": {
        "asset": "EURUSD_otc",
        "timeframe_minutes": 1,
        "days_requested": 7,
        "candle_count": 10080,
        "fetch_time": "2026-09-29T12:34:56",
        "fetch_timestamp": 1234567890,
        "first_candle_time": 1234500000,
        "last_candle_time": 1234567890
      },
      "candles": [
        {"time": 1234567890, "open": 1.05, "high": 1.06, "low": 1.04, "close": 1.05, "volume": 100},
        ...
      ]
    }
    """
    if not candles:
        logmsg("No candles to save.")
        return None

    random_suffix = ''.join(random.choices('0123456789abcdef', k=8))
    filename = f"{asset}_{timeframe_min}m_{days}d_{random_suffix}.json"
    filepath = CANDLES_DIR / filename

    payload = {
        "metadata": {
            "asset": asset,
            "timeframe_minutes": timeframe_min,
            "days_requested": days,
            "candle_count": len(candles),
            "fetch_time": datetime.now().isoformat(),
            "fetch_timestamp": int(time.time()),
            "first_candle_time": candles[0]['time'] if candles else None,
            "last_candle_time": candles[-1]['time'] if candles else None,
        },
        "candles": candles,
    }

    try:
        if HAS_ORJSON:
            with open(filepath, 'wb') as f:
                f.write(_orjson.dumps(payload))
        else:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
        return filepath
    except Exception as e:
        log_exception("save_candles_to_json", e)
        return None


# ==============================================================================
# SECTION 12: FETCH LOGIC (جديد)
# ==============================================================================
async def keepalive_loop(client: Quotex, stop_event: asyncio.Event):
    """حلقة keepalive بسيطة ترسل ping كل KEEPALIVE_INTERVAL ثانية.
    تحافظ على اتصال WebSocket حياً بين عمليات الجلب، وتتوقف فوراً عند ضبط stop_event."""
    while not stop_event.is_set():
        try:
            if client and client.api:
                client.api.send_websocket_request("2", no_force_send=False)
                client.api.send_websocket_request('42["tick"]', no_force_send=False)
        except Exception:
            pass
        # انتظار قابل للإيقاف: يخرج فوراً عند ضبط stop_event
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=KEEPALIVE_INTERVAL)
        except asyncio.TimeoutError:
            pass  # انتهى المحدّد = أرسل ping التالي


async def connect_quotex(email: str, password: str, max_attempts: int = 3,
                         proxies: Optional[str] = None) -> Optional[Quotex]:
    """يتصل بـ Quotex ويعيد كائن Quotex. يُعيد None عند الفشل.

    المعاملات:
      email      : بريد Quotex
      password   : كلمة المرور
      max_attempts: عدد محاولات الاتصال
      proxies    : URL البروكسي (مثل "http://1.2.3.4:8080" أو "socks5://1.2.3.4:1080")
    """
    for attempt in range(1, max_attempts + 1):
        try:
            client = Quotex(email=email, password=password,
                            host="qxbroker.com", lang="en",
                            proxies=proxies)
            check, reason = await client.connect()
            if check:
                try:
                    await client.change_account("PRACTICE")
                    await asyncio.sleep(0.5)
                except Exception:
                    pass
                logmsg(f"Connected to Quotex as {email}")
                return client
            else:
                err = str(reason) if reason else "Unknown error"
                logmsg(f"Login attempt {attempt}/{max_attempts} failed: {err}")
        except Exception as e:
            logmsg(f"Login attempt {attempt}/{max_attempts} raised: {e}")
        if attempt < max_attempts:
            await asyncio.sleep(3 * attempt)
    return None


async def fetch_candles_for_asset(client: Quotex, asset: str, days: int,
                                   timeframe_min: int, idx: int = 1, total: int = 1) -> List[Dict]:
    """Fetches candles for the requested asset. Returns a list of candles (empty on failure).

    Parameters:
      client       : connected Quotex client
      asset        : asset name in Quotex format (e.g. EURUSD_otc)
      days         : number of days to fetch
      timeframe_min: candle length in minutes (1, 5, 15, 30, 60)
    """
    amount_of_seconds = int(days * 86400)
    period_seconds = int(timeframe_min * 60)
    display = pretty_asset(asset, timeframe_min)
    # Flexible timeout: 60s minimum, increases with days
    timeout = max(60, days * 60)

    print(f"\n  {Colors.BOLD}{Colors.CYAN}[{idx}/{total}] Fetching {display}{Colors.RESET}")
    print(f"  Duration: {days} days | Timeframe: M{timeframe_min} | Workers: {FETCH_MAX_WORKERS}")
    print(f"  {Colors.DIM}Estimated candles: ~{days * 1440 // timeframe_min:,}{Colors.RESET}\n")

    for attempt in range(1, MAX_FETCH_RETRIES + 1):
        # Check connection before each attempt
        if client is None or client.api is None or not getattr(client.api.state, 'check_accepted_connection', False):
            logmsg(f"Connection dead before attempt {attempt}; aborting.")
            return []

        # Progress tracker (thread-safe) — shared by all 5 workers
        progress = {
            'candles': 0,            # total candles fetched so far
            'oldest_ts': int(time.time()),  # oldest timestamp fetched
            'start_ts': int(time.time()),   # latest timestamp (now)
            'target_ts': int(time.time()) - amount_of_seconds,  # target end timestamp
            'lock': threading.Lock(),
            'last_print': 0.0,       # last print time
            'fetch_start': time.time(),  # when fetch started
            'worker_candles': [0] * FETCH_MAX_WORKERS,  # candles per worker
        }

        def progress_callback(seconds_done, total_seconds, candles_count, worker_label):
            """Called by each worker after every batch. Throttled to once per 0.3s."""
            now = time.time()
            with progress['lock']:
                # Aggregate candles from this worker
                try:
                    wid = int(worker_label.split('-')[1]) if '-' in worker_label else 0
                    if 0 <= wid < FETCH_MAX_WORKERS:
                        progress['worker_candles'][wid] = candles_count
                except Exception:
                    pass
                progress['candles'] = sum(progress['worker_candles'])
                # Track oldest timestamp seen across workers
                current_oldest = progress['start_ts'] - seconds_done
                if current_oldest < progress['oldest_ts']:
                    progress['oldest_ts'] = current_oldest
                # Throttle prints to avoid terminal flicker
                if now - progress['last_print'] < 0.3:
                    return
                progress['last_print'] = now

                elapsed = now - progress['fetch_start']
                total_span = progress['start_ts'] - progress['target_ts']
                done_span = progress['start_ts'] - progress['oldest_ts']
                pct = min(done_span / total_span, 1.0) if total_span > 0 else 0
                bar_len = 30
                filled = int(bar_len * pct)
                bar = '#' * filled + '-' * (bar_len - filled)
                # Speed: candles per second
                speed = progress['candles'] / elapsed if elapsed > 0 else 0
                # ETA: based on pct and elapsed
                if pct > 0.01:
                    eta = elapsed * (1.0 - pct) / pct
                    eta_str = f"{int(eta//60):02d}:{int(eta%60):02d}"
                else:
                    eta_str = "  ?  "
                elapsed_str = f"{int(elapsed//60):02d}:{int(elapsed%60):02d}"
                sys.stdout.write(
                    f"\r  {Colors.CYAN}[{bar}]{Colors.RESET} "
                    f"{pct*100:5.1f}% | "
                    f"{Colors.GREEN}{progress['candles']:>6,}{Colors.RESET} candles | "
                    f"{elapsed_str} | "
                    f"{speed:>5.0f} c/s | "
                    f"ETA {eta_str}   "
                )
                sys.stdout.flush()

        print(f"  {Colors.YELLOW}Attempt {attempt}/{MAX_FETCH_RETRIES} ...{Colors.RESET}")
        try:
            candles = await asyncio.wait_for(
                client.get_historical_candles(
                    asset,
                    amount_of_seconds=amount_of_seconds,
                    period=period_seconds,
                    max_workers=FETCH_MAX_WORKERS,
                    progress_callback=progress_callback,
                ),
                timeout=timeout,
            )
            # Final progress print (force a 100% update)
            with progress['lock']:
                progress['candles'] = len(candles)
                progress['oldest_ts'] = progress['target_ts']
                progress['last_print'] = 0  # force print
            progress_callback(amount_of_seconds, amount_of_seconds, len(candles), "Worker-0")
            print()  # newline after progress bar
        except asyncio.TimeoutError:
            print()
            logmsg(f"Attempt {attempt}/{MAX_FETCH_RETRIES}: fetch timed out.")
            candles = []
        except Exception as e:
            print()
            logmsg(f"Attempt {attempt}/{MAX_FETCH_RETRIES} raised: {e}")
            candles = []

        if candles:
            # Format candles + dedupe + align timestamps
            formatted = []
            seen_times = set()
            for c in candles:
                if not isinstance(c, dict):
                    continue
                try:
                    ts = int(c.get("time", c.get("timestamp", 0)))
                    aligned = (ts // period_seconds) * period_seconds
                    o = float(c.get("open", 0))
                    h = float(c.get("high", c.get("max", 0)))
                    l = float(c.get("low", c.get("min", 0)))
                    cl = float(c.get("close", 0))
                    if aligned in seen_times:
                        continue
                    if o > 0 and h > 0 and l > 0 and cl > 0:
                        formatted.append({
                            'time': aligned, 'open': o, 'high': h, 'low': l,
                            'close': cl, 'volume': int(c.get("volume", 0) or 0),
                        })
                        seen_times.add(aligned)
                except Exception:
                    continue
            formatted.sort(key=lambda x: x['time'])
            # Compute final stats
            fetch_elapsed = time.time() - progress['fetch_start']
            avg_speed = len(formatted) / fetch_elapsed if fetch_elapsed > 0 else 0
            logmsg(
                f"OK Fetched {Colors.GREEN}{len(formatted):,}{Colors.RESET} candles "
                f"in {int(fetch_elapsed//60):02d}:{int(fetch_elapsed%60):02d} "
                f"({avg_speed:.0f} c/s) - {display} (attempt {attempt})"
            )
            return formatted

        # exponential backoff between retries
        if attempt < MAX_FETCH_RETRIES:
            delay = min(RETRY_BACKOFF_BASE * (2 ** (attempt - 1)), RETRY_BACKOFF_MAX)
            logmsg(f"Retry in {delay:.1f}s...")
            await asyncio.sleep(delay)

    logmsg(f"All {MAX_FETCH_RETRIES} attempts failed for {display}")
    return []


# ==============================================================================
# SECTION 13: INTERACTIVE MAIN
# ==============================================================================

# IMPORTANT: input() blocks the event loop. If we use it directly, keepalive_loop
# (which is an async task in the same loop) cannot send pings while the user is
# typing. The connection then dies after ~30s of silence and the next fetch
# sees "Connection dead". To avoid this, all input() calls go through this
# async wrapper that runs them in a worker thread, freeing the event loop.
async def ainput(prompt: str = "") -> str:
    """Async wrapper around input() that does NOT block the event loop."""
    return await asyncio.to_thread(input, prompt)


def print_banner():
    print(f"{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  CANDAL - Quotex Candle Fetcher{Colors.RESET}")
    print(f"{Colors.BOLD}  Simplified version: fetch candles and save as JSON{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.YELLOW}  Save folder: {CANDLES_DIR.absolute()}{Colors.RESET}")
    print(f"{Colors.YELLOW}  Speed:       {FETCH_MAX_WORKERS} parallel workers{Colors.RESET}")
    print(f"{Colors.YELLOW}  Timeframes:  1, 5, 15, 30, 60 (minutes){Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")


async def prompt_asset() -> Optional[str]:
    """Asks the user for the asset name. Returns None to exit."""
    while True:
        try:
            raw = (await ainput(f"{Colors.YELLOW}Asset name (or 'exit' to quit): {Colors.RESET}")).strip()
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
    """Asks for the number of days. Returns None to exit, or a positive int."""
    while True:
        try:
            raw = (await ainput(f"{Colors.YELLOW}Number of days (e.g. 7, 30, 100): {Colors.RESET}")).strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if not raw:
            continue
        if raw.lower() in ('exit', 'quit', 'q'):
            return None
        try:
            days = int(float(raw))
            if days <= 0:
                print(f"{Colors.RED}Days must be a positive number.{Colors.RESET}")
                continue
            return days
        except ValueError:
            print(f"{Colors.RED}Please enter a valid integer.{Colors.RESET}")


async def prompt_timeframe() -> Optional[int]:
    """Asks for the timeframe in minutes. Returns None to exit, or a number."""
    while True:
        try:
            raw = (await ainput(f"{Colors.YELLOW}Timeframe in minutes (1, 5, 15, 30, 60): {Colors.RESET}")).strip()
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
            if tf not in (1, 5, 15, 30, 60):
                print(f"{Colors.YELLOW}Warning: timeframe {tf} is unusual - continuing anyway.{Colors.RESET}")
            return tf
        except ValueError:
            print(f"{Colors.RED}Please enter a valid integer.{Colors.RESET}")


async def main_async():
    print_banner()

    # ===== Purge any stale Quotex session so we always log in fresh =====
    purge_old_session()

    # ===== Read credentials (auto-saved, includes password) =====
    creds = load_credentials()
    if creds:
        print(f"{Colors.GREEN}Found saved credentials for: {creds['email']}{Colors.RESET}")
        use_saved = (await ainput(f"{Colors.YELLOW}Use saved credentials? (Y/n): {Colors.RESET}")).strip().lower()
        if use_saved in ('y', '', 'yes'):
            email, password = creds['email'], creds['password']
        else:
            email = (await ainput(f"{Colors.YELLOW}Email: {Colors.RESET}")).strip()
            password = (await ainput(f"{Colors.YELLOW}Password: {Colors.RESET}")).strip()
    else:
        print(f"{Colors.CYAN}Enter your Quotex credentials (will be saved automatically){Colors.RESET}")
        email = (await ainput(f"{Colors.YELLOW}Email: {Colors.RESET}")).strip()
        password = (await ainput(f"{Colors.YELLOW}Password: {Colors.RESET}")).strip()

    if not email or not password:
        print(f"{Colors.RED}Invalid credentials.{Colors.RESET}")
        return

    # ===== Connect to Quotex =====
    logmsg("Connecting to Quotex...")
    client = await connect_quotex(email, password, max_attempts=3)
    if client is None:
        print(f"\n{Colors.RED}Connection failed after multiple attempts.{Colors.RESET}")
        return

    # Save credentials (including password) after successful connection
    save_credentials(email, password)
    print(f"{Colors.GREEN}Credentials saved to {CREDENTIALS_FILE.name}{Colors.RESET}\n")

    # ===== Start keepalive in the background =====
    stop_keepalive = asyncio.Event()
    keepalive_task = asyncio.create_task(keepalive_loop(client, stop_keepalive))

    try:
        fetch_count = 0
        while True:
            print(f"\n{Colors.CYAN}{'-'*60}{Colors.RESET}")
            print(f"{Colors.BOLD}  New fetch request{Colors.RESET}")
            print(f"{Colors.CYAN}{'-'*60}{Colors.RESET}")

            asset = await prompt_asset()
            if asset is None:
                print(f"\n{Colors.YELLOW}Shutting down...{Colors.RESET}")
                break

            days = await prompt_days()
            if days is None:
                print(f"\n{Colors.YELLOW}Shutting down...{Colors.RESET}")
                break

            timeframe = await prompt_timeframe()
            if timeframe is None:
                print(f"\n{Colors.YELLOW}Shutting down...{Colors.RESET}")
                break

            # Summary
            print(f"\n{Colors.CYAN}Summary:{Colors.RESET}")
            print(f"  Asset:     {Colors.BOLD}{pretty_asset(asset, timeframe)}{Colors.RESET}")
            print(f"  Days:      {days}")
            print(f"  Timeframe: M{timeframe}")
            print(f"  Estimated: ~{days * 1440 // timeframe:,} candles\n")

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

            # Wait for Enter for next fetch
            print(f"\n{Colors.YELLOW}Press Enter to fetch another asset, or type 'exit' to quit.{Colors.RESET}")
            try:
                choice = (await ainput()).strip().lower()
                if choice in ('exit', 'quit', 'q'):
                    print(f"\n{Colors.YELLOW}Shutting down...{Colors.RESET}")
                    break
            except (EOFError, KeyboardInterrupt):
                print(f"\n{Colors.YELLOW}Shutting down...{Colors.RESET}")
                break
    finally:
        # Cleanup
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


def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Stopped.{Colors.RESET}")
    except Exception as e:
        log_exception("main", e)


if __name__ == "__main__":
    main()
