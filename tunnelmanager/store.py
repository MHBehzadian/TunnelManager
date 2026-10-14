"""In-memory state persisted to a single JSON file (atomic writes)."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .models import (
    IRAN,
    KHAREJ,
    L_SUSPENDED,
    DNSProvider,
    Domain,
    Event,
    Link,
    Server,
    Settings,
)

MAX_EVENTS = 1000


class Store:
    def __init__(self, path: Path | str | None):
        self.path = Path(path) if path else None
        self.servers: dict[str, Server] = {}
        self.links: dict[str, Link] = {}
        self.domains: dict[str, Domain] = {}
        self.providers: dict[str, DNSProvider] = {}
        self.settings = Settings()
        self.events: list[Event] = []
        # kharej failover: dead kharej id -> kharej id now carrying its ports
        self.takeover: dict[str, str] = {}
        if self.path and self.path.exists():
            self.load()

    # ---- persistence -------------------------------------------------
    def load(self) -> None:
        assert self.path
        raw = json.loads(self.path.read_text())
        self.servers = {d["id"]: Server.from_dict(d) for d in raw.get("servers", [])}
        self.links = {d["id"]: Link.from_dict(d) for d in raw.get("links", [])}
        self.domains = {d["id"]: Domain.from_dict(d) for d in raw.get("domains", [])}
        self.providers = {d["id"]: DNSProvider.from_dict(d) for d in raw.get("providers", [])}
        self.settings = Settings.from_dict(raw.get("settings", {}))
        self.events = [Event.from_dict(d) for d in raw.get("events", [])]
        self.takeover = dict(raw.get("takeover", {}))

    def save(self) -> None:
        if not self.path:
            return
        data = {
            "servers": [s.to_dict() for s in self.servers.values()],
            "links": [x.to_dict() for x in self.links.values()],
            "domains": [d.to_dict() for d in self.domains.values()],
            "providers": [p.to_dict() for p in self.providers.values()],
            "settings": self.settings.to_dict(),
            "events": [e.to_dict() for e in self.events[-MAX_EVENTS:]],
            "takeover": self.takeover,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".state-")
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
        os.chmod(tmp, 0o600)  # holds SSH passwords and API tokens
        os.replace(tmp, self.path)

    # ---- queries -----------------------------------------------------
    def by_role(self, role: str) -> list[Server]:
        return sorted(
            (s for s in self.servers.values() if s.role == role),
            key=lambda s: (s.priority, s.name),
        )

    def irans(self) -> list[Server]:
        return self.by_role(IRAN)

    def kharejs(self) -> list[Server]:
        return self.by_role(KHAREJ)

    def link_for(self, iran_id: str, kharej_id: str) -> Link | None:
        for link in self.links.values():
            if link.iran_id == iran_id and link.kharej_id == kharej_id:
                return link
        return None

    def links_of(self, server_id: str) -> list[Link]:
        return [x for x in self.links.values() if server_id in (x.iran_id, x.kharej_id)]

    def effective_kharej(self, kharej_id: str) -> str:
        """Follow the takeover chain: whose tunnels carry this kharej's ports now."""
        seen = set()
        while kharej_id in self.takeover and kharej_id not in seen:
            seen.add(kharej_id)
            kharej_id = self.takeover[kharej_id]
        return kharej_id

    def link_ports(self, link: Link) -> list[str]:
        """Forwarded ports the Iran end of a link exposes: its own kharej's
        ports plus those of every kharej it took over. A suspended link
        exposes nothing (its ports moved elsewhere)."""
        if link.status == L_SUSPENDED or link.kharej_id in self.takeover:
            return []
        out: list[str] = []
        listening: set[str] = set()
        owners = [link.kharej_id] + [
            k for k in self.takeover if self.effective_kharej(k) == link.kharej_id
        ]
        for kid in owners:
            k = self.servers.get(kid)
            if not k:
                continue
            for p in k.ports:
                key = p.split("=", 1)[0].strip()
                if key not in listening:  # the owner's own mapping wins a clash
                    listening.add(key)
                    out.append(p)
        return out

    def next_port(self, iran_id: str, attr: str, base: int) -> int:
        used = {getattr(x, attr) for x in self.links.values() if x.iran_id == iran_id}
        p = base
        while p in used:
            p += 1
        return p

    def ensure_links(self) -> list[Link]:
        """Make sure every Iran x kharej pair has a link object."""
        created = []
        for i in self.irans():
            for k in self.kharejs():
                if self.link_for(i.id, k.id) is None:
                    link = Link(
                        iran_id=i.id,
                        kharej_id=k.id,
                        tunnel_port=self.next_port(i.id, "tunnel_port", self.settings.tunnel_port_base),
                        probe_port=self.next_port(i.id, "probe_port", self.settings.probe_port_base),
                    )
                    self.links[link.id] = link
                    created.append(link)
        return created

    def remove_server(self, server_id: str) -> list[Link]:
        removed = [x for x in self.links.values() if server_id in (x.iran_id, x.kharej_id)]
        for x in removed:
            del self.links[x.id]
        self.servers.pop(server_id, None)
        self.takeover = {k: v for k, v in self.takeover.items() if server_id not in (k, v)}
        for d in self.domains.values():
            if d.iran_id == server_id:
                d.iran_id = ""
        return removed

    def snapshot(self) -> dict[str, Any]:
        """What the dashboard renders. Secrets are masked."""
        return {
            "servers": [s.public() for s in self.servers.values()],
            "links": [
                {**x.to_dict(), "token": "", "ports": self.link_ports(x)} for x in self.links.values()
            ],
            "domains": [
                {**d.to_dict(), "effective_kharej_id": self.effective_kharej(d.kharej_id)}
                for d in self.domains.values()
            ],
            "providers": [p.public() for p in self.providers.values()],
            "takeover": self.takeover,
        }
