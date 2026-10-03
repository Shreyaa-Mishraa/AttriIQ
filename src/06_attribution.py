"""
PHASE 6: Attribution confidence scoring + temporal drift analysis.

Reads clustered fingerprints, enrichment, and unified flows; writes
``output/attribution_scores.json`` and ``output/drift_report.json``.
"""

from __future__ import annotations

import json
import math
import random
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import yaml
from scipy.stats import pearsonr
from sklearn.metrics.pairwise import cosine_similarity

random.seed(42)
np.random.seed(42)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

FORMULA_REGISTRY: dict[str, Any] = {
    "confidence_score": {
        "formula": "C(k) = w1·B(k) + w2·I(k) + w3·T(k) + w4·M(k)",
        "weights": {"w1": 0.35, "w2": 0.25, "w3": 0.20, "w4": 0.20},
        "components": {
            "B(k)": "Average pairwise cosine similarity of per-IP feature vectors in cluster k",
            "I(k)": "Fraction of IPs sharing ASN or /24 with the cluster majority network footprint",
            "T(k)": "|PearsonCorr(cluster_hourly_counts, global_hourly_counts)|",
            "M(k)": "Fraction of IPs with VT malicious>0 OR AbuseIPDB score>25",
        },
    },
    "temporal_drift": {
        "formula": "drift(w,w+1) = 1 - cos(centroid_w, centroid_{w+1})",
        "description": "Centroid is mean feature vector in time window w; flag if drift > drift_threshold",
    },
}


def _load_cfg(root: Path) -> dict:
    p = root / "config.yaml"
    if not p.is_file():
        return {}
    with open(p, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _feat_cols(df: pd.DataFrame) -> list[str]:
    base = [
        "conn_count", "unique_dst_ips", "unique_dst_ports",
        "proto_entropy", "avg_duration", "avg_bytes", "bytes_per_packet",
        "scan_score", "night_ratio", "burst_score", "src_bytes_ratio",
        "device_role_score", "scan_entropy", "c2_beacon_score",
        "protocol_diversity", "iot_port_affinity", "payload_asymmetry",
        "horizontal_scan_flag", "vertical_scan_flag",
    ]
    return [c for c in base if c in df.columns]


def behavioral_cohesion(X: np.ndarray) -> float:
    """B(k): mean pairwise cosine similarity for i<j.

    Uses sum_{i,j} u_i·u_j = ||sum u_i||^2 on L2-normalised rows, so the mean is
    exact without materialising the n x n similarity matrix (n can be >100k).
    """
    n = X.shape[0]
    if n < 2:
        return 0.0
    U = np.asarray(X, dtype=np.float64)
    norms = np.linalg.norm(U, axis=1, keepdims=True)
    U = np.divide(U, norms, out=np.zeros_like(U), where=norms > 0)
    total = float(np.dot(U.sum(axis=0), U.sum(axis=0)))
    # Zero rows have self-similarity 0, matching cosine_similarity's convention.
    diag = float((norms > 0).sum())
    return (total - diag) / (n * (n - 1))


def _asn_key(s: str) -> str:
    s = str(s or "")
    if s.upper().startswith("AS"):
        return s.upper().split()[0]
    return ""


def _subnet24(ip: str) -> str:
    parts = str(ip).split(".")
    if len(parts) >= 3 and all(p.isdigit() for p in parts[:3]):
        return ".".join(parts[:3])
    return ""


def infrastructure_overlap(ips: list[str], asn_by_ip: dict[str, str]) -> float:
    """I(k) fraction sharing ASN or /24 with majority."""
    if not ips:
        return 0.0
    asns = [_asn_key(asn_by_ip.get(ip, "")) for ip in ips]
    subs = [_subnet24(ip) for ip in ips]
    maj_asn = pd.Series([a for a in asns if a]).mode()
    maj_sub = pd.Series([s for s in subs if s]).mode()
    maj_a = str(maj_asn.iloc[0]) if len(maj_asn) else ""
    maj_s = str(maj_sub.iloc[0]) if len(maj_sub) else ""
    hit = 0
    for ip, a, s in zip(ips, asns, subs):
        ok = False
        if maj_a and a == maj_a:
            ok = True
        if maj_s and s == maj_s:
            ok = True
        if ok:
            hit += 1
    return float(hit / len(ips))


def timing_correlation(flows: pd.DataFrame, ips: list[str]) -> float:
    """T(k): Pearson correlation between hourly counts (cluster vs global)."""
    if flows is None or flows.empty or "StartTime" not in flows.columns:
        return 0.0
    f = flows.copy()
    f["StartTime"] = pd.to_datetime(f["StartTime"], errors="coerce")
    f = f.dropna(subset=["StartTime"])
    f["hour"] = f["StartTime"].dt.floor("h")
    g_all = f.groupby("hour").size()
    sub = f[f["SrcAddr"].astype(str).isin(set(ips))]
    g_sub = sub.groupby("hour").size()
    idx = g_all.index.union(g_sub.index).sort_values()
    a = g_all.reindex(idx, fill_value=0).to_numpy(dtype=float)
    b = g_sub.reindex(idx, fill_value=0).to_numpy(dtype=float)
    if len(a) < 3 or np.std(a) == 0 or np.std(b) == 0:
        return 0.0
    r, _ = pearsonr(a, b)
    return float(abs(r))


def threat_match_fraction(enriched_rows: pd.DataFrame) -> float:
    """M(k): fraction with VT>0 or Abuse>25."""
    if enriched_rows is None or enriched_rows.empty:
        return 0.0
    vt = pd.to_numeric(enriched_rows.get("vt_malicious", 0), errors="coerce").fillna(0)
    ab = pd.to_numeric(enriched_rows.get("abuse_score", 0), errors="coerce").fillna(0)
    hit = ((vt > 0) | (ab > 25)).sum()
    return float(hit / len(enriched_rows))


def confidence_score(B: float, I: float, T: float, M: float, w: dict[str, float]) -> float:
    """C(k) in [0,1] after clamping components."""
    w1, w2, w3, w4 = w.get("w1", 0.35), w.get("w2", 0.25), w.get("w3", 0.2), w.get("w4", 0.2)
    return float(w1 * B + w2 * I + w3 * T + w4 * M)


def compute_drift(
    camps: pd.DataFrame,
    feat_cols: list[str],
    window: str = "6h",
    threshold: float = 0.15,
) -> tuple[dict[int, list[dict]], dict[int, bool]]:
    """
    Temporal drift using windowed centroids.

    .. math::

        \\mathrm{drift}(w,w+1) = 1 - \\cos(\\bar{f}_w, \\bar{f}_{w+1})
    """
    if camps.empty or "time_window" not in camps.columns:
        return {}, {}
    df = camps.copy()
    df["tw"] = pd.to_datetime(df["time_window"], errors="coerce")
    df = df.dropna(subset=["tw"])
    df["wbin"] = df["tw"].dt.floor(window)

    drifts: dict[int, list[dict]] = {}
    flags: dict[int, bool] = {}

    for cid, sub in df.groupby("campaign_id"):
        cents: list[tuple[pd.Timestamp, np.ndarray]] = []
        for wb, g in sub.groupby("wbin"):
            vec = g[feat_cols].fillna(0).mean().to_numpy(dtype=float)
            if np.linalg.norm(vec) == 0:
                continue
            cents.append((pd.Timestamp(wb), vec))
        cents.sort(key=lambda x: x[0])
        series: list[dict] = []
        drift_any = False
        for i in range(len(cents) - 1):
            a = cents[i][1]
            b = cents[i + 1][1]
            na = np.linalg.norm(a)
            nb = np.linalg.norm(b)
            if na == 0 or nb == 0:
                continue
            cos_sim = float(np.dot(a, b) / (na * nb))
            d = 1.0 - cos_sim
            drift_any = drift_any or (d > threshold)
            series.append(
                {
                    "window_start": cents[i][0].isoformat(),
                    "window_next": cents[i + 1][0].isoformat(),
                    "drift": round(d, 4),
                }
            )
        drifts[int(cid)] = series
        flags[int(cid)] = bool(drift_any)
    return drifts, flags


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    cfg = _load_cfg(root)
    w = cfg.get("attribution_weights") or {"w1": 0.35, "w2": 0.25, "w3": 0.2, "w4": 0.2}
    drift_thr = float(cfg.get("drift_threshold", 0.15))
    drift_wh = str(cfg.get("drift_window_hours", 6)) + "h"
    paths = cfg.get("paths") or {}

    camps_path = root / (paths.get("campaigns") or "output/03_campaigns.csv")
    enr_path = root / (paths.get("enriched") or "output/04_enriched.csv")
    flows_path = root / (paths.get("unified_flows") or "output/unified_flows.parquet")
    out_attr = root / (paths.get("attribution_scores") or "output/attribution_scores.json")
    out_drift = root / (paths.get("drift_report") or "output/drift_report.json")
    summ_path = root / (paths.get("cluster_summary") or "output/cluster_summary.json")

    if not camps_path.is_file():
        print(f"[!] Missing campaigns: {camps_path}")
        return

    camps = pd.read_csv(camps_path, low_memory=False)
    feat_cols = _feat_cols(camps)
    enr = pd.read_csv(enr_path, low_memory=False) if enr_path.is_file() else pd.DataFrame()
    flows = pd.read_parquet(flows_path) if flows_path.is_file() else pd.DataFrame()

    asn_by_ip: dict[str, str] = {}
    if not enr.empty and "ip" in enr.columns:
        for _, r in enr.iterrows():
            asn_by_ip[str(r["ip"])] = str(r.get("asn", ""))

    # IP -> cluster (latest time_window)
    if "time_window" in camps.columns:
        camps_sorted = camps.sort_values("time_window")
        last_c = camps_sorted.drop_duplicates("SrcAddr", keep="last")[["SrcAddr", "campaign_id"]]
    else:
        last_c = camps.drop_duplicates("SrcAddr", keep="last")[["SrcAddr", "campaign_id"]]
    ip_to_c = {str(r.SrcAddr): int(r.campaign_id) for _, r in last_c.iterrows()}

    cluster_summary = {}
    if summ_path.is_file():
        with open(summ_path, encoding="utf-8") as f:
            cluster_summary = {int(x["campaign_id"]): x for x in (json.load(f).get("clusters") or [])}

    drift_series, drift_flags = compute_drift(camps, feat_cols, window=drift_wh, threshold=drift_thr)

    clusters_out: list[dict] = []
    for cid in sorted(camps["campaign_id"].unique()):
        sub = camps[camps["campaign_id"] == cid]
        ips = sub["SrcAddr"].astype(str).unique().tolist()
        X = sub[feat_cols].fillna(0).to_numpy(dtype=float)
        B = behavioral_cohesion(X)
        I = infrastructure_overlap(ips, asn_by_ip)
        T = timing_correlation(flows, ips) if not flows.empty else 0.0
        enr_sub = enr[enr["campaign_id"] == cid] if not enr.empty and "campaign_id" in enr.columns else pd.DataFrame()
        M = threat_match_fraction(enr_sub)
        C = confidence_score(B, I, T, M, w)
        meta = cluster_summary.get(int(cid), {})
        cross = bool(meta.get("cross_dataset", False))

        top_ttps: list[str] = []
        if not enr_sub.empty and "technique_id" in enr_sub.columns:
            top_ttps = [str(x) for x in enr_sub["technique_id"].dropna().unique().tolist()[:5]]

        atk = str(sub["attack_type"].mode().iloc[0]) if "attack_type" in sub.columns and len(sub) else "Unknown"
        lbl = str(sub["label"].mode().iloc[0]) if "label" in sub.columns and len(sub) else ""

        clusters_out.append(
            {
                "cluster_id": int(cid),
                "confidence_pct": round(100.0 * max(0.0, min(1.0, C)), 2),
                "label": lbl,
                "attack_type": atk,
                "contributing_factors": {
                    "B": round(B, 4),
                    "I": round(I, 4),
                    "T": round(T, 4),
                    "M": round(M, 4),
                },
                "top_ttps": top_ttps,
                "drift_detected": bool(drift_flags.get(int(cid), False)),
                "cross_dataset": cross,
                "iot_family": None,
            }
        )

    existing: dict = {}
    if out_attr.is_file():
        try:
            with open(out_attr, encoding="utf-8") as f:
                existing = json.load(f)
        except json.JSONDecodeError:
            existing = {}

    old_clusters = {int(c.get("cluster_id", c.get("campaign_id", -1))): c for c in existing.get("clusters", []) if isinstance(c, dict)}
    merged: list[dict] = []
    for c in clusters_out:
        cid = int(c["cluster_id"])
        merged.append({**old_clusters.get(cid, {}), **c})

    out_obj = {
        **{k: v for k, v in existing.items() if k not in ("clusters", "formula_registry")},
        "clusters": merged,
        "formula_registry": FORMULA_REGISTRY,
    }
    out_attr.parent.mkdir(parents=True, exist_ok=True)
    with open(out_attr, "w", encoding="utf-8") as f:
        json.dump(out_obj, f, indent=2)
    print(f"[✓] Wrote attribution scores → {out_attr}")

    drift_obj = {
        "generated_at": pd.Timestamp.utcnow().isoformat(),
        "drift_threshold": drift_thr,
        "windows": drift_series,
    }
    with open(out_drift, "w", encoding="utf-8") as f:
        json.dump(drift_obj, f, indent=2)
    print(f"[✓] Wrote drift report → {out_drift}")
    print("\n── FORMULA_REGISTRY (confidence + drift) ───────────────")
    print(json.dumps(FORMULA_REGISTRY, indent=2))


if __name__ == "__main__":
    main()
