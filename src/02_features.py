"""
PHASE 3: Behavioral Fingerprinting  →  Bᵢ = φ(Iᵢ, H)
--------------------------------------------------------
Per-source-IP (per time window) behavioral features + IoT-specific signals.
Reads unified flows Parquet; writes extended features Parquet.

Usage:
    python src/02_features.py
"""

from __future__ import annotations

import argparse
import os
import random
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np
import pandas as pd
import yaml
from scipy.stats import entropy as scipy_entropy

random.seed(42)
np.random.seed(42)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

IOT_PORTS_DEFAULT = {23, 2323, 7547, 8080, 8443, 5555, 48101, 37215}

BASE_FEATURE_COLS = [
    "conn_count", "unique_dst_ips", "unique_dst_ports",
    "proto_entropy", "avg_duration", "avg_bytes", "bytes_per_packet",
    "scan_score", "night_ratio", "burst_score", "src_bytes_ratio",
]

IOT_FEATURE_COLS = [
    "device_role_score", "scan_entropy", "c2_beacon_score",
    "protocol_diversity", "iot_port_affinity", "payload_asymmetry",
    "horizontal_scan_flag", "vertical_scan_flag",
]

FEATURE_COLS = BASE_FEATURE_COLS + IOT_FEATURE_COLS


def _load_iot_ports(root: Path) -> set[int]:
    cfgp = root / "config.yaml"
    if not cfgp.is_file():
        return set(IOT_PORTS_DEFAULT)
    with open(cfgp, encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    ports = cfg.get("iot_ports") or list(IOT_PORTS_DEFAULT)
    return {int(p) for p in ports}


def _numeric_col(frame: pd.DataFrame, name: str) -> pd.Series:
    """Numeric view of ``name``, or an aligned zero column when it is absent.

    ``frame.get(name, 0)`` returns a bare int for a missing column, which has no
    Series methods - datasets without Sport/SrcBytes (Zeek, CICFlowMeter) used to
    crash feature extraction here.
    """
    if name not in frame.columns:
        return pd.Series(0.0, index=frame.index, dtype=float)
    return pd.to_numeric(frame[name], errors="coerce").fillna(0.0)


def compute_scan_entropy(flows_df: pd.DataFrame) -> float:
    """
    Scan entropy over destination addresses.

    .. math::

        H(\\mathrm{dst}) = -\\sum_i p(\\mathrm{dst}_i)\\cdot\\log_2 p(\\mathrm{dst}_i)

    where :math:`p(\\mathrm{dst}_i)=\\frac{\\#\\ flows\\ to\\ \\mathrm{dst}_i}{\\#\\ flows}`.
    """
    if flows_df is None or flows_df.empty or "DstAddr" not in flows_df.columns:
        return 0.0
    vc = flows_df["DstAddr"].astype(str).value_counts()
    if len(vc) <= 1:
        return 0.0
    p = vc.to_numpy(dtype=float) / float(vc.sum())
    return float(-np.sum(p * np.log2(np.clip(p, 1e-12, None))))


def compute_beacon_score(flows_df: pd.DataFrame) -> float:
    """
    Beacon score as coefficient of variation of inter-flow intervals.

    .. math::

        \\mathrm{CoV} = \\frac{\\sigma(\\Delta t)}{\\mu(\\Delta t)},\\quad
        \\Delta t_i = t_{i}-t_{i-1}\\ (\\mathrm{sorted\\ by\\ StartTime})
    """
    if flows_df is None or len(flows_df) < 2 or "StartTime" not in flows_df.columns:
        return 1.0
    st = pd.to_datetime(flows_df["StartTime"], errors="coerce").sort_values()
    gaps = st.diff().dt.total_seconds().dropna()
    gaps = gaps[gaps >= 0]
    if len(gaps) == 0:
        return 1.0
    mu = float(np.mean(gaps))
    sig = float(np.std(gaps))
    if mu <= 1e-9:
        return 0.0
    return float(sig / mu)


def compute_payload_asymmetry(flows_df: pd.DataFrame) -> float:
    """
    Payload asymmetry ratio.

    .. math::

        R = \\frac{\\mathrm{mean}(\\mathrm{SrcBytes})}{\\mathrm{mean}(\\mathrm{DstBytes})}
    """
    if flows_df is None or flows_df.empty:
        return 1.0
    sb = _numeric_col(flows_df, "SrcBytes")
    db = _numeric_col(flows_df, "DstBytes")
    ms = float(sb.mean())
    md = float(db.mean())
    if md <= 1e-9:
        return float(ms) if ms > 0 else 1.0
    return float(ms / md)


def compute_port_affinity(flows_df: pd.DataFrame, iot_ports: set[int]) -> float:
    """
    Port affinity to known IoT service ports.

    .. math::

        PA = \\frac{|\\{f : \\mathrm{Dport}(f)\\in \\mathcal{P}_{IoT}\\}|}{|\\mathrm{flows}|}
    """
    if flows_df is None or flows_df.empty or "Dport" not in flows_df.columns:
        return 0.0
    dp = pd.to_numeric(flows_df["Dport"], errors="coerce").fillna(0).astype(int)
    hits = int(dp.isin(list(iot_ports)).sum())
    return float(hits / len(flows_df))


def compute_horizontal_scan(flows_df: pd.DataFrame) -> bool:
    """
    Horizontal scan indicator.

    .. math::

        \\mathrm{horizontal}=\\mathbb{1}\\{|\\mathrm{unique\\ DstAddr}|>50 \\wedge |\\mathrm{unique\\ Dport}|<3\\}
    """
    if flows_df is None or flows_df.empty:
        return False
    udst = flows_df["DstAddr"].nunique() if "DstAddr" in flows_df else 0
    uport = flows_df["Dport"].nunique() if "Dport" in flows_df else 0
    return bool(udst > 50 and uport < 3)


def compute_vertical_scan(flows_df: pd.DataFrame) -> bool:
    """
    Vertical scan indicator.

    .. math::

        \\mathrm{vertical}=\\mathbb{1}\\{|\\mathrm{unique\\ Dport}|>20 \\wedge |\\mathrm{unique\\ DstAddr}|<5\\}
    """
    if flows_df is None or flows_df.empty:
        return False
    udst = flows_df["DstAddr"].nunique() if "DstAddr" in flows_df else 0
    uport = flows_df["Dport"].nunique() if "Dport" in flows_df else 0
    return bool(uport > 20 and udst < 5)


def classify_attack_type(feature_row: dict) -> str:
    """
    Rule-based attack label from per-window features.

    Uses:
      - ``c2_beacon_score`` as CoV (:math:`\\mathrm{CoV}`),
      - ``scan_entropy`` as :math:`H(\\mathrm{dst})`,
      - ``payload_asymmetry`` as :math:`R`,
      - ``iot_port_affinity`` as :math:`PA`,
      - ``vt_score`` (optional) as VirusTotal-style malicious count.
    """
    cov = float(feature_row.get("c2_beacon_score", 99.0))
    r = float(feature_row.get("payload_asymmetry", 1.0))
    h = float(feature_row.get("scan_entropy", 0.0))
    pa = float(feature_row.get("iot_port_affinity", 0.0))
    horiz = bool(int(feature_row.get("horizontal_scan_flag", 0)))
    vert = bool(int(feature_row.get("vertical_scan_flag", 0)))
    vt = float(feature_row.get("vt_score", 0.0))

    if cov < 0.3 and r < 0.5:
        return "C2_Beaconing"
    if h > 3.5 and horiz:
        return "Horizontal_PortScan"
    if vert:
        return "Vertical_PortScan"
    if pa > 0.6:
        return "IoT_Malware"
    if r > 10:
        return "Data_Exfiltration"
    if cov < 0.3 and vt > 5:
        return "Known_Botnet_C2"
    return "Unknown"


def compute_entropy(series: pd.Series) -> float:
    counts = series.value_counts(normalize=True)
    return float(scipy_entropy(counts)) if len(counts) > 1 else 0.0


def extract_features_for_ip(group: pd.DataFrame, iot_ports: set[int]) -> dict:
    n = len(group)
    conn_count = n
    unique_dst_ips = group["DstAddr"].nunique() if "DstAddr" in group else 0
    unique_dst_ports = group["Dport"].nunique() if "Dport" in group else 0
    proto_entropy = compute_entropy(group["Proto"]) if "Proto" in group else 0.0

    if "TotBytes" not in group.columns:
        tot_b = _numeric_col(group, "SrcBytes") + _numeric_col(group, "DstBytes")
    else:
        tot_b = pd.to_numeric(group["TotBytes"], errors="coerce").fillna(0)

    avg_duration = group["Dur"].mean() if "Dur" in group else 0.0
    avg_bytes = float(tot_b.mean()) if len(tot_b) else 0.0
    avg_packets = group["TotPkts"].mean() if "TotPkts" in group else 0.0
    bytes_per_pkt = (avg_bytes / avg_packets) if avg_packets and avg_packets > 0 else 0.0
    scan_score = unique_dst_ips / conn_count if conn_count > 0 else 0.0

    if "StartTime" in group.columns:
        night_ratio = (group["StartTime"].dt.hour < 6).sum() / conn_count
    else:
        night_ratio = 0.0

    if "StartTime" in group.columns and n > 1:
        sorted_times = group["StartTime"].sort_values()
        inter_arrival = sorted_times.diff().dt.total_seconds().dropna()
        burst_score = float(inter_arrival.std()) if len(inter_arrival) > 0 else 0.0
    else:
        burst_score = 0.0

    src_bytes = float(_numeric_col(group, "SrcBytes").sum())
    total_bytes = float(tot_b.sum()) if len(tot_b) else 1.0
    src_bytes_ratio = src_bytes / total_bytes if total_bytes > 0 else 0.0

    label = -1
    if "is_malicious" in group.columns:
        label = int(group["is_malicious"].mode().iloc[0])
    elif "Label" in group.columns:
        label = int(pd.to_numeric(group["Label"], errors="coerce").fillna(0).mode().iloc[0])

    sport_vals = _numeric_col(group, "Sport")
    low = (sport_vals < 1024).sum()
    high = (sport_vals > 1024).sum()
    denom = low + high
    device_role_score = float(low / denom) if denom > 0 else 0.5

    scan_entropy = compute_scan_entropy(group)
    c2_beacon_score = compute_beacon_score(group)
    protocol_diversity = int(group["Proto"].nunique()) if "Proto" in group else 0
    iot_port_affinity = compute_port_affinity(group, iot_ports)
    payload_asymmetry = compute_payload_asymmetry(group)
    horizontal_scan_flag = int(compute_horizontal_scan(group))
    vertical_scan_flag = int(compute_vertical_scan(group))

    ds = "Mixed"
    if "DatasetSource" in group.columns:
        vc = group["DatasetSource"].astype(str).value_counts()
        if len(vc) == 1:
            ds = str(vc.index[0])
        else:
            ds = "Mixed"

    feat_for_cls = {
        "c2_beacon_score": c2_beacon_score,
        "payload_asymmetry": payload_asymmetry,
        "scan_entropy": scan_entropy,
        "horizontal_scan_flag": horizontal_scan_flag,
        "vertical_scan_flag": vertical_scan_flag,
        "iot_port_affinity": iot_port_affinity,
        "vt_score": 0.0,
    }
    attack_type = classify_attack_type(feat_for_cls)

    return {
        "conn_count": conn_count,
        "unique_dst_ips": unique_dst_ips,
        "unique_dst_ports": unique_dst_ports,
        "proto_entropy": round(proto_entropy, 4),
        "avg_duration": round(float(avg_duration), 4),
        "avg_bytes": round(avg_bytes, 4),
        "bytes_per_packet": round(bytes_per_pkt, 4),
        "scan_score": round(scan_score, 4),
        "night_ratio": round(float(night_ratio), 4),
        "burst_score": round(burst_score, 4),
        "src_bytes_ratio": round(src_bytes_ratio, 4),
        "device_role_score": round(device_role_score, 4),
        "scan_entropy": round(scan_entropy, 4),
        "c2_beacon_score": round(c2_beacon_score, 4),
        "protocol_diversity": protocol_diversity,
        "iot_port_affinity": round(iot_port_affinity, 4),
        "payload_asymmetry": round(payload_asymmetry, 4),
        "horizontal_scan_flag": horizontal_scan_flag,
        "vertical_scan_flag": vertical_scan_flag,
        "label": label,
        "dataset_source": ds,
        "attack_type": attack_type,
    }


# Below this many groups the process pool costs more than the loop it replaces.
PARALLEL_MIN_GROUPS = 20_000


def _fingerprint_groups(shard: pd.DataFrame, iot_ports: set[int], report: bool = False) -> list[dict]:
    """Fingerprint every (SrcAddr, time_window) group in one shard of flows."""
    records: list[dict] = []
    groups = shard.groupby(["SrcAddr", "time_window"], sort=False)
    total = len(groups)
    for i, ((src_ip, time_win), group) in enumerate(groups):
        if report and i % 500 == 0:
            print(f"    Processing group {i:,}/{total:,}...", end="\r")
        feats = extract_features_for_ip(group, iot_ports)
        feats["SrcAddr"] = src_ip
        feats["time_window"] = time_win
        records.append(feats)
    return records


def _shard_worker(payload: tuple[pd.DataFrame, set[int]]) -> list[dict]:
    return _fingerprint_groups(payload[0], payload[1])


def extract_features(
    df: pd.DataFrame,
    window: str = "1h",
    iot_ports: set[int] | None = None,
    jobs: int = 1,
) -> pd.DataFrame:
    print(f"[+] Extracting behavioral + IoT features (window={window})...")

    if "StartTime" not in df.columns:
        raise ValueError("StartTime column required.")

    if iot_ports is None:
        iot_ports = set(IOT_PORTS_DEFAULT)

    df = df.copy()
    df["StartTime"] = pd.to_datetime(df["StartTime"])
    df["time_window"] = df["StartTime"].dt.floor(window)

    n_groups = df.groupby(["SrcAddr", "time_window"], sort=False).ngroups
    records: list[dict] = []

    if jobs > 1 and n_groups >= PARALLEL_MIN_GROUPS:
        # Shard on SrcAddr so every group stays whole inside one worker.
        codes = pd.factorize(df["SrcAddr"])[0] % jobs
        shards = [df[codes == s] for s in range(jobs)]
        shards = [s for s in shards if not s.empty]
        print(f"    {n_groups:,} groups across {len(shards)} parallel workers...")
        with ProcessPoolExecutor(max_workers=len(shards)) as pool:
            for done, recs in enumerate(
                pool.map(_shard_worker, [(s, iot_ports) for s in shards]), start=1
            ):
                records.extend(recs)
                print(f"    Worker {done}/{len(shards)} done ({len(records):,} fingerprints)")
    else:
        records = _fingerprint_groups(df, iot_ports, report=True)

    print(f"\n    Extracted {len(records):,} fingerprints")
    out = pd.DataFrame(records)
    # Sharding changes arrival order, so fix a stable order for reproducibility.
    out = out.sort_values(["SrcAddr", "time_window"]).reset_index(drop=True)
    cols = ["SrcAddr", "time_window", "dataset_source"] + FEATURE_COLS + ["label", "attack_type"]
    cols = [c for c in cols if c in out.columns]
    return out[cols]


def normalize(df: pd.DataFrame) -> pd.DataFrame:
    from sklearn.preprocessing import MinMaxScaler

    scaler = MinMaxScaler()
    df_norm = df.copy()
    cols_to_scale = [c for c in BASE_FEATURE_COLS if c in df_norm.columns]
    if cols_to_scale:
        df_norm[cols_to_scale] = scaler.fit_transform(df_norm[cols_to_scale])
        print(f"[+] Min-max normalized {len(cols_to_scale)} base feature columns (IoT scores left raw)")
    return df_norm


def read_flows(path: Path) -> pd.DataFrame:
    if path.suffix.lower() == ".parquet":
        df = pd.read_parquet(path)
    else:
        df = pd.read_csv(path, low_memory=False)
    if "TotBytes" not in df.columns and "SrcBytes" in df.columns and "DstBytes" in df.columns:
        df = df.copy()
        df["TotBytes"] = (
            pd.to_numeric(df["SrcBytes"], errors="coerce").fillna(0)
            + pd.to_numeric(df["DstBytes"], errors="coerce").fillna(0)
        )
    return df


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    default_parquet = root / "output" / "unified_flows.parquet"
    default_csv = root / "output" / "01_cleaned.csv"

    parser = argparse.ArgumentParser(description="Extract behavioral + IoT features per IP")
    parser.add_argument("--input", type=str, default=None, help="unified_flows.parquet or 01_cleaned.csv")
    parser.add_argument("--output", type=str, default=str(root / "output" / "features_iot_extended.parquet"))
    parser.add_argument("--output-csv", type=str, default=str(root / "output" / "02_features.csv"))
    parser.add_argument("--window", type=str, default="1h")
    parser.add_argument("--jobs", type=int, default=0, help="Worker processes; 0 = auto")
    args = parser.parse_args()

    jobs = args.jobs if args.jobs > 0 else min(8, os.cpu_count() or 1)

    in_path = Path(args.input) if args.input else None
    if in_path is None or not in_path.is_file():
        in_path = default_parquet if default_parquet.is_file() else default_csv
    if not in_path.is_file():
        raise FileNotFoundError(f"Input not found: {in_path}. Run 01_preprocess.py first.")

    iot_ports = _load_iot_ports(root)
    df = read_flows(in_path)
    if "StartTime" in df.columns:
        df["StartTime"] = pd.to_datetime(df["StartTime"])

    features_df = extract_features(df, window=args.window, iot_ports=iot_ports, jobs=jobs)
    features_df = normalize(features_df)

    out_p = Path(args.output)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    features_df.to_parquet(out_p, index=False)
    print(f"[✓] Saved extended features → {out_p}")

    if args.output_csv:
        Path(args.output_csv).parent.mkdir(parents=True, exist_ok=True)
        features_df.to_csv(args.output_csv, index=False)
        print(f"[✓] Saved CSV mirror → {args.output_csv}")

    print("\n── Feature Preview ──────────────────────────────────────")
    print(features_df[FEATURE_COLS].describe().round(3))

    # Standalone micro-tests
    tiny = pd.DataFrame(
        {
            "StartTime": pd.date_range("2024-01-01", periods=5, freq="30s"),
            "DstAddr": list("ABABA"),
            "SrcBytes": [10, 10, 10, 10, 10],
            "DstBytes": [100, 100, 100, 100, 100],
            "Dport": [23, 23, 23, 23, 23],
        }
    )
    assert compute_beacon_score(tiny) < 0.2
    assert compute_port_affinity(tiny, {23}) == 1.0
