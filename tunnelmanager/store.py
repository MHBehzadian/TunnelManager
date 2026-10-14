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
    L_PENDING,
    DNSProvider,
    Domain,
    Event,
    Link,
    Server,
    Settings,
)

MAX_EVENTS = 1000


def listen_key(mapping: str) -> str:
    """The listening half of a port mapping: "443", "1.2.3.4:443", "2053-2060"."""
    return mapping.split("=", 1)[0].strip()


class Store:
    def __init__(self, path: Path | str | None):
        self.path = Path(path) if path else None
        self.servers: dict[str, Server] = {}
        self.links: dict[str, Link] = {}
        self.domains: dict[str, Domain] = {}
        self.providers: dict[str, DNSProvider] = {}
        self.settings = Settings()
        self.events: list[Event] = []
        # port handover: link id -> link id (same Iran server) now exposing its ports
        self.handover: dict[str, str] = {}
        # dashboard canvas: node id -> [x, y]
        self.layout: dict[str, list[float]] = {}
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
        self.handover = dict(raw.get("handover", {}))
        self.layout = dict(raw.get("layout", {}))
        self._migrate(raw)

    def _migrate(self, raw: dict) -> None:
        # v0.1 kept forwarded ports on the kharej server; they belong to the
        # Iran side of each tunnel
        for s in raw.get("servers", []):
            if s.get("role") == KHAREJ and s.get("ports"):
                for link in self.links.values():
                    if link.kharej_id == s["id"] and not link.ports:
                        link.ports = list(s["ports"])
                        link.accept_udp = bool(s.get("accept_udp"))
        for link in self.links.values():
            if link.status == "suspended":
                link.status = L_PENDING if not link.transport else "down"
        # v0.1 domains pointed at an Iran server rather than a tunnel
        for raw_d in raw.get("domains", []):
            d = self.domains.get(raw_d.get("id", ""))
            if d and not d.link_id and d.kharej_id and raw_d.get("iran_id"):
                link = self.link_for(raw_d["iran_id"], d.kharej_id)
                if link:
                    d.link_id = link.id

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
            "handover": self.handover,
            "layout": self.layout,
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

    def links_between(self, iran_id: str, kharej_id: str) -> list[Link]:
        return sorted(
            (x for x in self.links.values() if x.iran_id == iran_id and x.kharej_id == kharej_id),
            key=lambda x: (x.priority, x.status == L_PENDING, x.id),
        )

    def link_for(self, iran_id: str, kharej_id: str) -> Link | None:
        found = self.links_between(iran_id, kharej_id)
        return found[0] if found else None

    def links_of(self, server_id: str) -> list[Link]:
        return [x for x in self.links.values() if server_id in (x.iran_id, x.kharej_id)]

    def carrier(self, link_id: str) -> str:
        """Follow the handover chain: which link exposes this link's ports now."""
        seen = set()
        while link_id in self.handover and link_id not in seen:
            seen.add(link_id)
            link_id = self.handover[link_id]
        return link_id

    def link_ports(self, link: Link) -> list[str]:
        """Forwarded ports the Iran end of a link exposes: its own (unless it
        handed them over) plus those of every link handed over to it."""
        if link.id in self.handover:
            return []
        out: list[str] = []
        listening: set[str] = set()
        owners = [link] + [
            self.links[s] for s in self.handover if s in self.links and self.carrier(s) == link.id
        ]
        for owner in owners:
            for p in owner.ports:
                key = listen_key(p)
                if key not in listening:  # the carrier's own mapping wins a clash
                    listening.add(key)
                    out.append(p)
        return out

    def used_ports(self, iran_id: str) -> set[int]:
        used: set[int] = set()
        for x in self.links.values():
            if x.iran_id == iran_id:
                used.add(x.tunnel_port)
                if x.probe_port:
                    used.add(x.probe_port)
        return used

    def free_port(self, iran_id: str, base: int) -> int:
        used = self.used_ports(iran_id)
        p = base
        while p in used:
            p += 1
        return p

    def ensure_links(self) -> list[Link]:
        """Offer a (not yet built) tunnel for every Iran x kharej pair that has none."""
        created: list[Link] = []
        if not self.settings.auto_mesh:
            return created
        for i in self.irans():
            for k in self.kharejs():
                if self.link_for(i.id, k.id) is None:
                    link = Link(
                        iran_id=i.id,
                        kharej_id=k.id,
                        tunnel_port=self.free_port(i.id, self.settings.tunnel_port_base),
                    )
                    link.probe_port = self.free_port(i.id, self.settings.probe_port_base)
                    # start from the ports this kharej is already served on elsewhere
                    sibling = next((x for x in self.links.values() if x.kharej_id == k.id and x.ports), None)
                    if sibling:
                        link.ports = list(sibling.ports)
                    self.links[link.id] = link
                    created.append(link)
        return created

    def remove_link(self, link_id: str) -> Link | None:
        link = self.links.pop(link_id, None)
        self.handover = {k: v for k, v in self.handover.items() if link_id not in (k, v)}
        for d in self.domains.values():
            d.group = [x for x in d.group if x != link_id]
            if d.link_id == link_id:
                d.link_id = ""
        self.layout.pop(link_id, None)
        return link

    def remove_server(self, server_id: str) -> list[Link]:
        removed = [x for x in self.links.values() if server_id in (x.iran_id, x.kharej_id)]
        for x in removed:
            self.remove_link(x.id)
        self.servers.pop(server_id, None)
        self.layout.pop(server_id, None)
        return removed

    # ---- domains -----------------------------------------------------
    def group_of(self, d: Domain) -> list[Link]:
        """The tunnels a domain may use, most preferred first."""
        if d.group:
            return [self.links[x] for x in d.group if x in self.links]
        if not d.kharej_id:
            return [self.links[d.link_id]] if d.link_id in self.links else []
        prio = {s.id: (s.priority, s.name) for s in self.servers.values()}
        own = [x for x in self.links.values() if x.kharej_id == d.kharej_id]
        own.sort(key=lambda x: (prio.get(x.iran_id, (999, "")), x.priority, x.id))
        # when the kharej itself is gone, other kharejs can stand in
        others = [x for x in self.links.values() if x.kharej_id != d.kharej_id]
        others.sort(key=lambda x: (prio.get(x.kharej_id, (999, "")), prio.get(x.iran_id, (999, "")), x.priority, x.id))
        # tunnels not built yet go last: never the primary, only a last resort to build
        ordered = own + others
        return [x for x in ordered if x.status != L_PENDING] + [x for x in ordered if x.status == L_PENDING]

    def primary_of(self, d: Domain) -> Link | None:
        g = self.group_of(d)
        return g[0] if g else None

    def snapshot(self) -> dict[str, Any]:
        """What the dashboard renders. Secrets are masked."""
        links = []
        for x in self.links.values():
            d = x.to_dict()
            d.pop("iran_base", None)
            d.pop("kharej_base", None)
            d["token"] = ""
            d["exposed"] = self.link_ports(x)
            d["carrier"] = self.carrier(x.id)
            links.append(d)
        domains = []
        for d in self.domains.values():
            dd = d.to_dict()
            dd["carrier_id"] = self.carrier(d.link_id) if d.link_id else ""
            dd["effective_group"] = [x.id for x in self.group_of(d)]
            p = self.primary_of(d)
            dd["primary_id"] = p.id if p else ""
            domains.append(dd)
        return {
            "servers": [s.public() for s in self.servers.values()],
            "links": links,
            "domains": domains,
            "providers": [p.public() for p in self.providers.values()],
            "handover": self.handover,
            "layout": self.layout,
        }

