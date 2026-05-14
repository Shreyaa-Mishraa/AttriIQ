"""
PHASE 7: Infrastructure graph export (NetworkX → node-link JSON).

Usage:
    python src/07_graph.py
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

import networkx as nx
import pandas as pd
import yaml

random.seed(42)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def _cfg(root: Path) -> dict:
    p = root / "config.yaml"
    if not p.is_file():
        return {}
    with open(p, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def build_graph(camps: pd.DataFrame, enr: pd.DataFrame) -> nx.DiGraph:
    g = nx.DiGraph()
    if camps.empty:
        return g

    for _, r in enr.iterrows() if not enr.empty else []:
        ip = str(r.get("ip", ""))
        if not ip:
            continue
        cid = int(r.get("campaign_id", -1))
        g.add_node(ip, type="ip", campaign_id=cid)
        asn = str(r.get("asn", ""))
        if asn and asn.upper().startswith("AS"):
            g.add_node(asn, type="asn")
            g.add_edge(ip, asn, relation="belongs_to_asn")
        fam = str(r.get("iot_family", "")) if "iot_family" in r else ""
        if fam and fam not in ("", "None", "nan"):
            g.add_node(fam, type="malware_family")
            g.add_edge(ip, fam, relation="associated_malware")

    # Campaign cohesion edges (star topology to avoid O(n^2) blowups on large clusters)
    for cid, sub in camps.groupby("campaign_id"):
        ips = sub["SrcAddr"].astype(str).unique().tolist()
        hub = f"campaign_{int(cid)}"
        g.add_node(hub, type="campaign", campaign_id=int(cid))
        for ip in ips:
            if ip not in g:
                g.add_node(ip, type="ip", campaign_id=int(cid))
            g.add_edge(ip, hub, relation="shares_campaign")

    return g


def annotate_centralities(G: nx.DiGraph) -> None:
    """Attach degree_centrality and betweenness_centrality to each node (in-place)."""
    if G.number_of_nodes() == 0:
        return
    try:
        deg = nx.degree_centrality(G)
        bet = nx.betweenness_centrality(G, normalized=True)
    except Exception:
        return
    for n in G.nodes:
        G.nodes[n]["degree_centrality"] = round(float(deg.get(n, 0.0)), 6)
        G.nodes[n]["betweenness_centrality"] = round(float(bet.get(n, 0.0)), 6)


def to_node_link(G: nx.DiGraph) -> dict:
    return nx.node_link_data(G, edges="links")


def get_subgraph(graph_path: Path, cluster_id: int) -> dict:
    with open(graph_path, encoding="utf-8") as f:
        data = nx.node_link_graph(json.load(f), directed=True, edges="links")
    nodes = [n for n, d in data.nodes(data=True) if d.get("campaign_id") == cluster_id]
    return to_node_link(data.subgraph(nodes).copy())


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    cfg = _cfg(root)
    paths = cfg.get("paths") or {}
    camps_path = root / (paths.get("campaigns") or "output/03_campaigns.csv")
    enr_path = root / (paths.get("enriched") or "output/04_enriched.csv")
    out_path = root / (paths.get("attack_graph") or "output/attack_graph.json")

    camps = pd.read_csv(camps_path, low_memory=False) if camps_path.is_file() else pd.DataFrame()
    enr = pd.read_csv(enr_path, low_memory=False) if enr_path.is_file() else pd.DataFrame()

    # Merge IoT family from attribution if present
    attr_path = root / (paths.get("attribution_scores") or "output/attribution_scores.json")
    if attr_path.is_file():
        with open(attr_path, encoding="utf-8") as f:
            att = json.load(f)
        fam_map = {}
        for c in att.get("clusters", []) or []:
            cid = int(c.get("cluster_id", c.get("campaign_id", -1)))
            if "iot_family" in c and c["iot_family"]:
                fam_map[cid] = c["iot_family"]
        if not enr.empty and "campaign_id" in enr.columns:
            enr = enr.copy()
            enr["iot_family"] = enr["campaign_id"].map(lambda x: fam_map.get(int(x), ""))

    G = build_graph(camps, enr)
    annotate_centralities(G)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(to_node_link(G), f, indent=2)
    print(f"[OK] Wrote attack graph -> {out_path} ({G.number_of_nodes()} nodes, {G.number_of_edges()} edges)")


if __name__ == "__main__":
    main()
    root = Path(__file__).resolve().parents[1]
    outp = root / "output" / "attack_graph.json"
    if outp.is_file():
        sg = get_subgraph(outp, cluster_id=0)
        print(f"[test] subgraph cluster 0 links: {len(sg.get('links', []))}")
