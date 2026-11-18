"""Network routing engine implementing Dijkstra and Distance Vector (Bellman-Ford).

Course Mapping:
- CO4 (Routing algorithms): Computes shortest-delay paths using both centralized
  link-state Dijkstra and distributed-style Distance Vector (Bellman-Ford) over
  the same 8-node emergency topology, supporting link/node failures and algorithm
  comparison.
"""

from __future__ import annotations

import heapq
import math
from dataclasses import dataclass, field
from typing import Any

from backend.db import Database


@dataclass
class RouteResult:
    algorithm: str
    src: str
    dst: str
    reachable: bool
    path: list[str]
    links: list[str]
    total_delay_ms: float | None
    hops: int
    convergence_rounds: int = 0


class RoutingEngine:
    """Computes and compares Dijkstra and Bellman-Ford routes over SQLite topology."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self._baseline_paths: dict[tuple[str, str], list[str]] = {}
        self._compute_baseline()

    def _compute_baseline(self) -> None:
        topo = self.db.get_topology()
        all_nodes = [{**n, "is_up": True} for n in topo["nodes"]]
        all_links = [{**l, "is_up": True} for l in topo["links"]]
        for n in all_nodes:
            nid = n["node_id"]
            if nid != "ECC_HQ":
                res = self.dijkstra("ECC_HQ", nid, nodes=all_nodes, links=all_links)
                if res.reachable:
                    self._baseline_paths[("ECC_HQ", nid)] = res.path

    def get_baseline_path(self, src: str, dst: str) -> list[str]:
        return list(self._baseline_paths.get((src, dst), []))

    @staticmethod
    def _build_graph(
        nodes: list[dict[str, Any]],
        links: list[dict[str, Any]],
    ) -> tuple[set[str], dict[str, list[tuple[str, float, str]]]]:
        active_nodes = {n["node_id"] for n in nodes if n.get("is_up", True)}
        adj: dict[str, list[tuple[str, float, str]]] = {nid: [] for nid in active_nodes}
        for link in links:
            if not link.get("is_up", True):
                continue
            u, v = link["src"], link["dst"]
            if u in active_nodes and v in active_nodes:
                w = float(link["delay_ms"])
                lid = link["link_id"]
                adj[u].append((v, w, lid))
                adj[v].append((u, w, lid))
        # Deterministic ordering
        for nid in adj:
            adj[nid].sort(key=lambda item: (item[1], item[0], item[2]))
        return active_nodes, adj

    def dijkstra(
        self,
        src: str,
        dst: str,
        *,
        nodes: list[dict[str, Any]] | None = None,
        links: list[dict[str, Any]] | None = None,
    ) -> RouteResult:
        if nodes is None or links is None:
            topo = self.db.get_topology()
            nodes = topo["nodes"]
            links = topo["links"]

        active_nodes, adj = self._build_graph(nodes, links)
        if src not in active_nodes or dst not in active_nodes:
            return RouteResult("dijkstra", src, dst, False, [], [], None, 0)
        if src == dst:
            return RouteResult("dijkstra", src, dst, True, [src], [], 0.0, 0)

        dist: dict[str, float] = {nid: math.inf for nid in active_nodes}
        prev: dict[str, tuple[str, str] | None] = {nid: None for nid in active_nodes}
        dist[src] = 0.0
        heap: list[tuple[float, str]] = [(0.0, src)]

        while heap:
            d, u = heapq.heappop(heap)
            if d > dist[u]:
                continue
            if u == dst:
                break
            for v, w, lid in adj[u]:
                nd = d + w
                if nd < dist[v]:
                    dist[v] = nd
                    prev[v] = (u, lid)
                    heapq.heappush(heap, (nd, v))

        if math.isinf(dist[dst]):
            return RouteResult("dijkstra", src, dst, False, [], [], None, 0)

        path: list[str] = []
        used_links: list[str] = []
        cur = dst
        while cur != src:
            path.append(cur)
            step = prev[cur]
            assert step is not None
            parent, lid = step
            used_links.append(lid)
            cur = parent
        path.append(src)
        path.reverse()
        used_links.reverse()
        return RouteResult(
            algorithm="dijkstra",
            src=src,
            dst=dst,
            reachable=True,
            path=path,
            links=used_links,
            total_delay_ms=round(dist[dst], 3),
            hops=len(used_links),
        )

    def distance_vector(
        self,
        src: str,
        dst: str,
        *,
        nodes: list[dict[str, Any]] | None = None,
        links: list[dict[str, Any]] | None = None,
    ) -> RouteResult:
        """Bellman-Ford Distance Vector routing computation."""
        if nodes is None or links is None:
            topo = self.db.get_topology()
            nodes = topo["nodes"]
            links = topo["links"]

        active_nodes, adj = self._build_graph(nodes, links)
        if src not in active_nodes or dst not in active_nodes:
            return RouteResult("distance_vector", src, dst, False, [], [], None, 0, 0)
        if src == dst:
            return RouteResult("distance_vector", src, dst, True, [src], [], 0.0, 0, 0)

        # Build directed edge list from undirected topology
        edges: list[tuple[str, str, float, str]] = []
        for u, nbrs in adj.items():
            for v, w, lid in nbrs:
                edges.append((u, v, w, lid))

        dist: dict[str, float] = {nid: math.inf for nid in active_nodes}
        prev: dict[str, tuple[str, str] | None] = {nid: None for nid in active_nodes}
        dist[src] = 0.0

        rounds = 0
        max_rounds = max(0, len(active_nodes) - 1)
        for _ in range(max_rounds):
            rounds += 1
            updated = False
            for u, v, w, lid in edges:
                if math.isinf(dist[u]):
                    continue
                cand = dist[u] + w
                if cand < dist[v] - 1e-9:
                    dist[v] = cand
                    prev[v] = (u, lid)
                    updated = True
            if not updated:
                break

        if math.isinf(dist[dst]):
            return RouteResult("distance_vector", src, dst, False, [], [], None, 0, rounds)

        path: list[str] = []
        used_links: list[str] = []
        seen: set[str] = set()
        cur = dst
        while cur != src:
            if cur in seen:
                return RouteResult("distance_vector", src, dst, False, [], [], None, 0, rounds)
            seen.add(cur)
            path.append(cur)
            step = prev[cur]
            assert step is not None
            parent, lid = step
            used_links.append(lid)
            cur = parent
        path.append(src)
        path.reverse()
        used_links.reverse()
        return RouteResult(
            algorithm="distance_vector",
            src=src,
            dst=dst,
            reachable=True,
            path=path,
            links=used_links,
            total_delay_ms=round(dist[dst], 3),
            hops=len(used_links),
            convergence_rounds=rounds,
        )

    @staticmethod
    def _build_hop_ips(path: list[str], node_map: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
        hops: list[dict[str, str]] = []
        for nid in path:
            n = node_map.get(nid, {})
            hops.append(
                {
                    "node_id": nid,
                    "ip_address": n.get("ip_address", ""),
                    "subnet_mask": n.get("subnet_mask", ""),
                    "gateway": n.get("gateway", ""),
                }
            )
        return hops

    def compare_routes(self, src: str, dst: str) -> dict[str, Any]:
        topo = self.db.get_topology()
        nodes, links = topo["nodes"], topo["links"]
        node_map = {n["node_id"]: n for n in nodes}
        dij = self.dijkstra(src, dst, nodes=nodes, links=links)
        dv = self.distance_vector(src, dst, nodes=nodes, links=links)
        baseline = self.get_baseline_path(src, dst)
        rerouted = bool(dij.reachable and baseline and dij.path != baseline)
        costs_match = (
            dij.reachable == dv.reachable
            and (
                (not dij.reachable)
                or abs((dij.total_delay_ms or 0.0) - (dv.total_delay_ms or 0.0)) < 1e-6
            )
        )
        dij_hops = self._build_hop_ips(dij.path, node_map)
        dv_hops = self._build_hop_ips(dv.path, node_map)
        return {
            "src": src,
            "dst": dst,
            "costs_match": costs_match,
            "rerouted_from_baseline": rerouted,
            "baseline_path": baseline,
            "dijkstra": {
                "reachable": dij.reachable,
                "path": dij.path,
                "ip_path": [h["ip_address"] for h in dij_hops if h["ip_address"]],
                "hop_ips": dij_hops,
                "links": dij.links,
                "total_delay_ms": dij.total_delay_ms,
                "hops": dij.hops,
            },
            "distance_vector": {
                "reachable": dv.reachable,
                "path": dv.path,
                "ip_path": [h["ip_address"] for h in dv_hops if h["ip_address"]],
                "hop_ips": dv_hops,
                "links": dv.links,
                "total_delay_ms": dv.total_delay_ms,
                "hops": dv.hops,
                "convergence_rounds": dv.convergence_rounds,
            },
        }

    def all_routing_tables_from(self, src: str = "ECC_HQ") -> dict[str, Any]:
        topo = self.db.get_topology()
        nodes, links = topo["nodes"], topo["links"]
        node_map = {n["node_id"]: n for n in nodes}
        comparisons: list[dict[str, Any]] = []
        for node in nodes:
            dst = node["node_id"]
            if dst == src:
                continue
            dij = self.dijkstra(src, dst, nodes=nodes, links=links)
            dv = self.distance_vector(src, dst, nodes=nodes, links=links)
            dij_hops = self._build_hop_ips(dij.path, node_map)
            dv_hops = self._build_hop_ips(dv.path, node_map)
            comparisons.append(
                {
                    "dst": dst,
                    "dst_ip": node.get("ip_address", ""),
                    "subnet_mask": node.get("subnet_mask", ""),
                    "gateway": node.get("gateway", ""),
                    "label": node["label"],
                    "dijkstra_path": dij.path,
                    "dijkstra_ip_path": [h["ip_address"] for h in dij_hops if h["ip_address"]],
                    "dijkstra_delay_ms": dij.total_delay_ms,
                    "dv_path": dv.path,
                    "dv_ip_path": [h["ip_address"] for h in dv_hops if h["ip_address"]],
                    "dv_delay_ms": dv.total_delay_ms,
                    "dv_rounds": dv.convergence_rounds,
                    "reachable": dij.reachable,
                    "costs_match": (
                        dij.reachable == dv.reachable
                        and (not dij.reachable or abs((dij.total_delay_ms or 0.0) - (dv.total_delay_ms or 0.0)) < 1e-6)
                    ),
                }
            )
        return {"src": src, "routes": comparisons}

