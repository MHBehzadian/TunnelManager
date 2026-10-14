"""Telegram bot: pushes every event to the configured chats and answers a few
commands (/status, /links, /domains, /check, /help)."""

from __future__ import annotations

import asyncio
import html
import logging
from typing import Awaitable, Callable

import httpx

from .models import Telegram

log = logging.getLogger(__name__)

Handler = Callable[[str, list[str]], Awaitable[str]]

ICON = {"info": "ℹ️", "success": "✅", "warning": "⚠️", "error": "🚨"}


def esc(s: str) -> str:
    return html.escape(str(s), quote=False)


class TelegramBot:
    def __init__(self, get_cfg: Callable[[], Telegram], handler: Handler | None = None):
        self.get_cfg = get_cfg
        self.handler = handler
        self.queue: asyncio.Queue[str] = asyncio.Queue(maxsize=500)
        self._tasks: list[asyncio.Task] = []
        self._offset = 0
        self._cfg_key: tuple | None = None
        self._client: httpx.AsyncClient | None = None

    # ---- plumbing ------------------------------------------------------
    def _http(self, cfg: Telegram) -> httpx.AsyncClient:
        key = (cfg.api_base, cfg.proxy)
        if self._client is None or key != self._cfg_key:
            if self._client is not None:
                asyncio.ensure_future(self._client.aclose())
            self._client = httpx.AsyncClient(timeout=40, proxy=cfg.proxy or None)
            self._cfg_key = key
        return self._client

    def _url(self, cfg: Telegram, method: str) -> str:
        return f"{cfg.api_base.rstrip('/')}/bot{cfg.bot_token}/{method}"

    async def call(self, method: str, cfg: Telegram | None = None, **params):
        cfg = cfg or self.get_cfg()
        r = await self._http(cfg).post(self._url(cfg, method), json=params)
        body = r.json()
        if not body.get("ok"):
            raise RuntimeError(body.get("description", f"HTTP {r.status_code}"))
        return body["result"]

    def active(self) -> bool:
        cfg = self.get_cfg()
        return bool(cfg.enabled and cfg.bot_token)

    # ---- outgoing ------------------------------------------------------
    def notify(self, text: str) -> None:
        if not self.active():
            return
        try:
            self.queue.put_nowait(text)
        except asyncio.QueueFull:
            log.warning("telegram queue full, dropping message")

    async def send_to(self, chat_id: str, text: str, cfg: Telegram | None = None) -> None:
        await self.call(
            "sendMessage", cfg, chat_id=chat_id, text=text[:4000], parse_mode="HTML", disable_web_page_preview=True
        )

    async def _sender(self) -> None:
        while True:
            text = await self.queue.get()
            cfg = self.get_cfg()
            for chat in cfg.chat_ids:
                for attempt in range(3):
                    try:
                        await self.send_to(chat, text, cfg)
                        break
                    except Exception as e:  # network blips, 429s
                        log.warning("telegram send to %s failed: %s", chat, e)
                        await asyncio.sleep(3 * (attempt + 1))
            await asyncio.sleep(0.4)  # stay well under Telegram's rate limit

    # ---- incoming ------------------------------------------------------
    async def _poller(self) -> None:
        while True:
            cfg = self.get_cfg()
            if not (cfg.enabled and cfg.bot_token):
                await asyncio.sleep(5)
                continue
            try:
                updates = await self.call("getUpdates", cfg, offset=self._offset, timeout=25)
            except Exception as e:
                log.debug("telegram poll: %s", e)
                await asyncio.sleep(10)
                continue
            for u in updates:
                self._offset = u["update_id"] + 1
                msg = u.get("message") or {}
                text = (msg.get("text") or "").strip()
                chat = str((msg.get("chat") or {}).get("id", ""))
                if not text.startswith("/") or not chat:
                    continue
                await self._handle(cfg, chat, text)

    async def _handle(self, cfg: Telegram, chat: str, text: str) -> None:
        cmd, *args = text.split()
        cmd = cmd.split("@")[0].lower()
        if chat not in cfg.chat_ids:
            if cmd == "/start":
                await self.send_to(
                    chat,
                    f"این چت هنوز به پنل اضافه نشده.\nChat ID: <code>{esc(chat)}</code>\n"
                    "این شناسه را در تنظیمات تلگرام پنل وارد کنید.",
                    cfg,
                )
            return
        try:
            reply = await self.handler(cmd, args) if self.handler else "no handler"
        except Exception as e:
            reply = f"خطا: {esc(e)}"
        await self.send_to(chat, reply, cfg)

    async def test(self, cfg: Telegram) -> None:
        me = await self.call("getMe", cfg)
        for chat in cfg.chat_ids:
            await self.send_to(chat, f"🔌 اتصال پنل TunnelManager به ربات <b>@{esc(me.get('username'))}</b> برقرار است.", cfg)

    def start(self) -> None:
        self._tasks = [asyncio.create_task(self._sender()), asyncio.create_task(self._poller())]

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        if self._client:
            await self._client.aclose()
