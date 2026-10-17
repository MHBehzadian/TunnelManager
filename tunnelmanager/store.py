"""In-memory state persisted to a single JSON file (atomic writes)."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .backpack import RANGE_TO, kharej_dest, listen_ports, target_host
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
        self.meta: dict[str, Any] = {}  # bookkeeping, e.g. when the last backup ran
        if self.path and self.path.exists():
            self.load()

    # ---- persistence -------------------------------------------------
    def load(self) -> None:
        assert self.path
        self.apply(json.loads(self.path.read_text()))

    def apply(self, raw: dict) -> None:
        """Replace everything with a saved state (a state file or a backup)."""
        self.servers = {d["id"]: Server.from_dict(d) for d in raw.get("servers", [])}
        self.links = {d["id"]: Link.from_dict(d) for d in raw.get("links", [])}
        self.domains = {d["id"]: Domain.from_dict(d) for d in raw.get("domains", [])}
        self.providers = {d["id"]: DNSProvider.from_dict(d) for d in raw.get("providers", [])}
        self.settings = Settings.from_dict(raw.get("settings", {}))
        self.events = [Event.from_dict(d) for d in raw.get("events", [])]
        self.handover = dict(raw.get("handover", {}))
        self.layout = dict(raw.get("layout", {}))
        self.meta = dict(raw.get("meta", {}))
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
            if link.transport and link.status != L_PENDING:
                link.built = True
            if link.status == "suspended":
                link.status = L_PENDING if not link.transport else "down"
        for d in self.domains.values():
            if d.iran_id and not d.primary_iran:
                d.primary_iran = d.iran_id
        # v0.2 domains followed one tunnel: take its Iran server and ports
        for d in self.domains.values():
            link = self.links.get(d.link_id)
            if link and not d.iran_id:
                d.iran_id = link.iran_id
                if not d.ports:
                    d.ports = list(link.ports)
        # v0.1 domains pointed at an Iran server rather than a tunnel
        for raw_d in raw.get("domains", []):
            d = self.domains.get(raw_d.get("id", ""))
            if d and raw_d.get("iran_id") and not d.ports:
                d.iran_id = raw_d["iran_id"]
                link = self.link_for(raw_d["iran_id"], d.kharej_id) if d.kharej_id else None
                if link:
                    d.ports = list(link.ports)

    def raw(self) -> dict[str, Any]:
        return {
            "servers": [s.to_dict() for s in self.servers.values()],
            "links": [x.to_dict() for x in self.links.values()],
            "domains": [d.to_dict() for d in self.domains.values()],
            "providers": [p.to_dict() for p in self.providers.values()],
            "settings": self.settings.to_dict(),
            "events": [e.to_dict() for e in self.events[-MAX_EVENTS:]],
            "handover": self.handover,
            "layout": self.layout,
            "meta": self.meta,
        }

    def save(self) -> None:
        if not self.path:
            return
        data = self.raw()
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
    # ---- ports and routes ----------------------------------------------
    def port_map(self, iran_id: str) -> dict[int, Link]:
        """Which link exposes each forwarded port on an Iran server right now
        (a port can only be bound once per server, so this is unambiguous)."""
        out: dict[int, Link] = {}
        for x in self.links.values():
            if x.iran_id == iran_id and x.status != L_PENDING:
                for p in listen_ports(self.link_ports(x)):
                    out.setdefault(p, x)
        return out

    def owner(self, iran_id: str, spec: str) -> Link | None:
        """The link whose own port list holds this port (handover or not)."""
        port = first_port(spec)
        for x in self.links.values():
            if x.iran_id == iran_id and port in listen_ports(x.ports):
                return x
        return None

    def domain_specs(self, d: Domain) -> list[str]:
        if d.ports:
            return list(d.ports)
        if d.kharej_id and d.iran_id:
            out: list[str] = []
            for x in self.links_between(d.iran_id, d.kharej_id):
                out += [p for p in x.ports if p not in out]
            return out
        return []

    def group_of(self, d: Domain) -> list[Link]:
        """The tunnels a domain may use, most preferred first."""
        if d.group:
            return [self.links[x] for x in d.group if x in self.links]
        prio = {s.id: (s.priority, s.name) for s in self.servers.values()}
        wanted = set()
        for spec in self.domain_specs(d):
            wanted |= listen_ports([spec])
        kharejs = {d.kharej_id} if d.kharej_id else set()
        if d.iran_id:  # the kharejs the domain's ports reach today
            pm = self.port_map(d.iran_id)
            kharejs |= {pm[p].kharej_id for p in wanted if p in pm}
        own = [x for x in self.links.values() if x.kharej_id in kharejs or (wanted & listen_ports(x.ports))]
        own.sort(key=lambda x: (prio.get(x.iran_id, (999, "")), x.priority, x.id))
        # when the kharej itself is gone, other kharejs can stand in
        own_ids = {x.id for x in own}
        others = [x for x in self.links.values() if x.id not in own_ids]
        others.sort(key=lambda x: (prio.get(x.kharej_id, (999, "")), prio.get(x.iran_id, (999, "")), x.priority, x.id))
        # tunnels not built yet go last: never the primary, only a last resort to build
        ordered = own + others
        return [x for x in ordered if x.status != L_PENDING] + [x for x in ordered if x.status == L_PENDING]

    def primary_of(self, d: Domain) -> Link | None:
        g = self.group_of(d)
        return g[0] if g else None

    def iran_order(self, d: Domain) -> list[str]:
        """Iran servers in the order the domain prefers them: its primary
        first, then the backups in the group's order (server priority)."""
        out: list[str] = []
        if d.primary_iran in self.servers and not d.group:
            out.append(d.primary_iran)
        for x in self.group_of(d):
            if x.status != L_PENDING and x.iran_id not in out:
                out.append(x.iran_id)
        return out

    # ---- exits: where a port finally leaves from --------------------------
    def kharej_ports(self, kharej_id: str, limit: int = 200) -> tuple[list[int], list[str]]:
        """Ports the kharej's tunnels deliver to on the kharej itself, and the
        ones BackPack sends straight on to another host ("443=1.2.3.4:5201")."""
        local: list[int] = []
        remote: list[str] = []
        for x in self.links.values():
            if x.kharej_id != kharej_id or x.status == L_PENDING:
                continue
            for m in x.ports:
                dest = kharej_dest(m)
                if not dest:
                    continue
                host, port = dest
                if host:
                    t = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
                    if t not in remote:
                        remote.append(t)
                elif "=" not in m and not RANGE_TO.match(m) and "-" in m:
                    local += sorted(listen_ports([m], limit=20))  # a plain range: the same ports
                else:
                    local.append(port)
        return sorted(set(local))[:limit], remote

    def exit_of(self, link: Link | None, port: int) -> dict[str, Any] | None:
        """Where traffic for this Iran-side port leaves from after the tunnel:
        None = from the kharej itself."""
        if link is None:
            return None
        mapping = next((m for m in self.link_ports(link) if port in listen_ports([m])), None)
        dest = kharej_dest(mapping) if mapping else None
        k = self.servers.get(link.kharej_id)
        if not dest or not k:
            return None
        host, kport = dest
        if not host and "=" not in mapping and not RANGE_TO.match(mapping):
            kport = port  # "2053-2060": each port goes to the same port
        if host:
            t = f"[{host}]:{kport}" if ":" in host else f"{host}:{kport}"
            hop = {"method": "backpack", "targets": [t], "via": "", "inferred": False}
        else:
            hop = k.exits.get(str(kport))
        if not hop:
            return None
        by_ip = {s.ip: s.id for s in self.servers.values()}
        targets = []
        for t in hop["targets"]:
            r = k.exit_reach.get(t) or {}
            targets.append({"addr": t, "server_id": by_ip.get(target_host(t), ""), "ok": r.get("ok")})
        return {"from": k.id, "port": kport, "method": hop["method"], "inferred": hop.get("inferred", False), "targets": targets}

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
            d["exits"] = {}
            for m in d["exposed"]:
                port = first_port(m)
                e = self.exit_of(x, port)
                if e:
                    d["exits"][m] = e
            links.append(d)
        domains = []
        for d in self.domains.values():
            dd = d.to_dict()
            dd["effective_group"] = [x.id for x in self.group_of(d)]
            dd["specs"] = self.domain_specs(d)
            order = self.iran_order(d)
            dd["primary_iran"] = order[0] if order else ""
            pm = self.port_map(d.iran_id) if d.iran_id else {}
            dd["routes"] = [
                {"spec": spec, "link_id": pm[first_port(spec)].id if first_port(spec) in pm else ""}
                for spec in dd["specs"]
            ]
            domains.append(dd)
        return {
            "servers": [s.public() for s in self.servers.values()],
            "links": links,
            "domains": domains,
            "providers": [p.public() for p in self.providers.values()],
            "handover": self.handover,
            "layout": self.layout,
        }


def first_port(spec: str) -> int:
    ports = listen_ports([spec])
    return min(ports) if ports else -1
