"""
PHASE 3b: IoT attack-family labeling from cluster SubLabel aggregation.
Merges results into output/attribution_scores.json for dashboard / reporting.

Usage:
    python src/09_iot_labels.py
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Keyword (substring match, order matters — more specific first)
SUB_LABEL_RULES: list[tuple[str, str, list[str]]] = [
    ("HorizontalPortScan", "Scanner", ["T1046"]),
    ("PortScan", "Scanner", ["T1046"]),
    ("Okiru", "Okiru/Bashlite", ["T1498", "T1571"]),
    ("Mirai", "Mirai", ["T1498", "T1021", "T1078"]),
    ("Torii", "Torii", ["T1573", "T1033"]),
    ("Hakai", "Hakai", ["T1498", "T1190"]),
    ("DDoS", "DDoS Bot", ["T1498"]),
    ("C&C", "C2 Implant", ["T1071", "T1573"]),
    ("FileDownload", "Dropper", ["T1105"]),
]


def map_sublabel(s: str) -> tuple[str, list[str]]:
    s = (s or "").strip()
    if not s:
        return "Unknown IoT", []
    low = s.lower()
    for kw, family, tactics in SUB_LABEL_RULES:
        if kw.lower() in low:
            return family, list(tactics)
    return "Unknown IoT", []


def majority_label(labels: list[str]) -> str:
    labels = [str(x).strip() for x in labels if str(x).strip()]
    if not labels:
        return ""
    return Counter(labels).most_common(1)[0][0]


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)

    parser = argparse.ArgumentParser(description="IoT cluster family / MITRE labeling")
    parser.add_argument(
        "--flows",
        type=str,
        default=str(root / "output" / "unified_flows.parquet"),
        help="Unified flows with SubLabel",
    )
    parser.add_argument(
        "--campaigns",
        type=str,
        default=str(root / "output" / "03_campaigns.csv"),
    )
    parser.add_argument(
        "--out",
        type=str,
        default=str(root / "output" / "attribution_scores.json"),
    )
    args = parser.parse_args()

    if not os.path.isfile(args.campaigns):
        print(f"[!] Missing campaigns file: {args.campaigns}. Skipping IoT labeling.")
        return

    camps = pd.read_csv(args.campaigns)
    if "SrcAddr" not in camps.columns or "campaign_id" not in camps.columns:
        print("[!] campaigns CSV missing SrcAddr or campaign_id.")
        return

    flows_path = args.flows
    if not os.path.isfile(flows_path):
        print(f"[!] Missing unified flows: {flows_path}. IoT family mapping may be empty.")
        flows = pd.DataFrame(columns=["SrcAddr", "SubLabel", "DatasetSource"])
    else:
        if flows_path.lower().endswith(".parquet"):
            flows = pd.read_parquet(flows_path, columns=None)
        else:
            flows = pd.read_csv(flows_path, low_memory=False)

    if "SubLabel" not in flows.columns:
        flows["SubLabel"] = ""
    if "DatasetSource" not in flows.columns:
        flows["DatasetSource"] = ""

    existing: dict = {}
    if os.path.isfile(args.out):
        try:
            with open(args.out, encoding="utf-8") as f:
                existing = json.load(f)
        except json.JSONDecodeError:
            existing = {}

    cluster_entries: list[dict] = []

    for cid in sorted(camps["campaign_id"].unique()):
        ips = camps.loc[camps["campaign_id"] == cid, "SrcAddr"].astype(str).unique().tolist()
        sub_rows = flows[flows["SrcAddr"].astype(str).isin(ips)]
        if "DatasetSource" in sub_rows.columns:
            sub_rows = sub_rows[sub_rows["DatasetSource"].astype(str).str.contains("IoT", na=False)]
        maj = majority_label(sub_rows["SubLabel"].tolist()) if len(sub_rows) else ""
        family, tactics = map_sublabel(maj)

        cluster_entries.append(
            {
                "cluster_id": int(cid),
                "campaign_id": int(cid),
                "majority_sublabel": maj,
                "iot_family": family,
                "ttps": tactics,
                "iot_tactics": tactics,
            }
        )

    merged_clusters: dict[int, dict] = {}
    for e in existing.get("clusters", []) or []:
        if not isinstance(e, dict):
            continue
        key = int(e.get("cluster_id", e.get("campaign_id", -1)))
        if key >= 0:
            merged_clusters[key] = e
    for e in cluster_entries:
        key = int(e.get("cluster_id", e.get("campaign_id", -1)))
        merged_clusters[key] = {**merged_clusters.get(key, {}), **e}

    out_obj = {
        **{k: v for k, v in existing.items() if k not in ("clusters",)},
        "clusters": [merged_clusters[k] for k in sorted(merged_clusters.keys())],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out_obj, f, indent=2)

    print(f"[✓] Wrote IoT attribution merge → {args.out} ({len(out_obj['clusters'])} clusters)")


if __name__ == "__main__":
    main()
