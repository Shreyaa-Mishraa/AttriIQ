"""
PHASE 2: Dataset Loading & Preprocessing
-----------------------------------------
Loads CTU-13 .binetflow files, IoT-23 Zeek conn.log.labeled, or PCAP (via CICFlowMeter).
Merges into a unified schema and writes Parquet (+ legacy CSV for compatibility).

Usage:
    python src/01_preprocess.py
    python src/01_preprocess.py --input data/capture20110810.binetflow
"""

from __future__ import annotations

import argparse
import glob
import os
import subprocess
import sys
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

try:
    import yaml
except ImportError:
    yaml = None


def load_yaml_config(config_path: Path) -> dict:
    if yaml is None or not config_path.is_file():
        return {}
    with open(config_path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

# ── Column names for CTU-13 binetflow format (unchanged) ─────────────────────
CTU13_COLUMNS = [
    "StartTime", "Dur", "Proto", "SrcAddr", "Sport",
    "Dir", "DstAddr", "Dport", "State", "sTos", "dTos",
    "TotPkts", "TotBytes", "SrcBytes", "Label",
]

PROTO_MAP = {"tcp": 0, "udp": 1, "icmp": 2, "arp": 3}

UNIFIED_COLS = [
    "StartTime", "SrcAddr", "Sport", "DstAddr", "Dport", "Proto", "Dur",
    "SrcBytes", "DstBytes", "TotPkts", "Label", "SubLabel", "DatasetSource",
]


def load_ctu13(filepath: str) -> pd.DataFrame:
    """Load a CTU-13 .binetflow file into a DataFrame (original schema)."""
    print(f"[+] Loading CTU-13 file: {filepath}")
    df = pd.read_csv(filepath, names=CTU13_COLUMNS, header=0, low_memory=False)
    print(f"    Loaded {len(df):,} rows")
    return df


def load_generic_csv(filepath: str) -> pd.DataFrame:
    """Load any CSV with auto-detected headers."""
    print(f"[+] Loading CSV file: {filepath}")
    df = pd.read_csv(filepath, low_memory=False)
    print(f"    Loaded {len(df):,} rows, columns: {list(df.columns)}")
    return df


def _norm_col(name: str) -> str:
    return name.strip().lower().replace(" ", "_").replace(".", "")


def _build_col_lookup(df: pd.DataFrame) -> dict[str, str]:
    return {_norm_col(c): c for c in df.columns}


def _pick_col(lookup: dict[str, str], *needles: str) -> str | None:
    for n in needles:
        key = _norm_col(n)
        if key in lookup:
            return lookup[key]
        for lk, orig in lookup.items():
            if key in lk or lk in key:
                return orig
    return None


def run_cicflowmeter(pcap_path: str, out_csv: str) -> None:
    """Convert PCAP to flow CSV using the cicflowmeter CLI (subprocess)."""
    os.makedirs(os.path.dirname(out_csv) or ".", exist_ok=True)
    pcap_abs = os.path.abspath(pcap_path)
    out_abs = os.path.abspath(out_csv)
    cmd = ["cicflowmeter", "-f", pcap_abs, "-c", out_abs]
    print(f"[+] Running CICFlowMeter: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except FileNotFoundError as e:
        raise RuntimeError(
            "cicflowmeter executable not found. Install with: pip install cicflowmeter"
        ) from e
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"CICFlowMeter failed (exit {e.returncode}): {e.stderr or e.stdout}"
        ) from e
    if not os.path.isfile(out_abs):
        raise RuntimeError(f"CICFlowMeter did not produce expected CSV: {out_abs}")
    print(f"    [✓] Wrote converted flows → {out_abs}")


def load_cicflowmeter_csv(csv_path: str) -> pd.DataFrame:
    """Load a CICFlowMeter CSV and map to the unified flow schema (best-effort)."""
    print(f"[+] Loading CICFlowMeter CSV: {csv_path}")
    df = pd.read_csv(csv_path, low_memory=False)
    lu = _build_col_lookup(df)

    def col(*names: str) -> pd.Series:
        c = _pick_col(lu, *names)
        if c is None:
            return pd.Series(np.nan, index=df.index)
        return df[c]

    ts_col = _pick_col(lu, "timestamp", "flow_start_timestamp", "start_time", "stime")
    start = col("timestamp", "flow_start_timestamp") if ts_col else pd.NaT
    if start.isna().all():
        start = pd.to_datetime(df.index, errors="coerce")  # unlikely

    dur = pd.to_numeric(col("flow_duration", "duration", "flow_duration_sec"), errors="coerce")
    sport = pd.to_numeric(col("source_port", "src_port", "sport"), errors="coerce")
    dport = pd.to_numeric(col("destination_port", "dst_port", "dport"), errors="coerce")
    src_ip = col("source_ip", "src_ip", "srcip")
    dst_ip = col("destination_ip", "dst_ip", "dstip")
    proto = col("protocol", "proto").astype(str)

    tot_fwd = pd.to_numeric(col("total_fwd_packets", "tot_fwd_pkts"), errors="coerce").fillna(0)
    tot_bwd = pd.to_numeric(col("total_backward_packets", "tot_bwd_pkts"), errors="coerce").fillna(0)
    tot_pkts = tot_fwd + tot_bwd
    tot_pkts = tot_pkts.replace(0, np.nan)

    fwd_bytes = pd.to_numeric(col("total_length_of_fwd_packets", "totlen_fwd_pkts"), errors="coerce").fillna(0)
    bwd_bytes = pd.to_numeric(col("total_length_of_bwd_packets", "totlen_bwd_pkts"), errors="coerce").fillna(0)

    label_col = _pick_col(lu, "label")
    sublabel_col = _pick_col(lu, "detailed_label", "sublabel")

    out = pd.DataFrame(
        {
            "StartTime": pd.to_datetime(start, errors="coerce"),
            "SrcAddr": src_ip.astype(str),
            "Sport": sport,
            "DstAddr": dst_ip.astype(str),
            "Dport": dport,
            "Proto": proto.str.lower().str.strip(),
            "Dur": dur.fillna(0),
            "SrcBytes": fwd_bytes,
            "DstBytes": bwd_bytes,
            "TotPkts": tot_pkts.fillna(0),
            "Label": 0,
            "SubLabel": "",
            "DatasetSource": "IoT-23",
        }
    )
    if label_col is not None:
        lr = df[label_col].astype(str).str.lower()
        out["Label"] = lr.str.contains("malicious|attack|bot", na=False).astype(int)
    if sublabel_col is not None:
        out["SubLabel"] = df[sublabel_col].astype(str)
    print(f"    Mapped CICFlowMeter → unified ({len(out):,} rows)")
    return out


def parse_zeek_conn_labeled(filepath: str) -> pd.DataFrame:
    """Parse Zeek/Bro conn.log.labeled (tab-separated, #fields header)."""
    print(f"[+] Parsing Zeek conn.log.labeled: {filepath}")
    fieldnames: list[str] | None = None
    rows: list[dict[str, str]] = []
    with open(filepath, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#fields"):
                parts = line.split("\t")
                fieldnames = [p.strip() for p in parts[1:]]
                continue
            if line.startswith("#") or fieldnames is None:
                continue
            parts = line.split("\t")
            if len(parts) < len(fieldnames):
                parts = parts + [""] * (len(fieldnames) - len(parts))
            rows.append({fieldnames[i]: parts[i] for i in range(len(fieldnames))})

    if not rows:
        print("    [!] No data rows parsed.")
        return pd.DataFrame(columns=UNIFIED_COLS)

    raw = pd.DataFrame(rows)

    def getc(*names: str) -> pd.Series:
        for n in names:
            if n in raw.columns:
                return raw[n]
        return pd.Series("", index=raw.index)

    ts = pd.to_numeric(getc("ts"), errors="coerce")
    start = pd.to_datetime(ts, unit="s", errors="coerce")

    label_raw = getc("label").astype(str).str.strip()
    lab = np.where(
        label_raw.str.lower().eq("malicious"),
        1,
        np.where(label_raw.str.lower().isin(["benign", "background"]), 0, 0),
    )

    # TotPkts maps from orig_pkts per IoT-23 unified schema (originating packets).
    tot_pkts = pd.to_numeric(getc("orig_pkts"), errors="coerce").fillna(0)

    out = pd.DataFrame(
        {
            "StartTime": start,
            "SrcAddr": getc("id.orig_h").astype(str),
            "Sport": pd.to_numeric(getc("id.orig_p"), errors="coerce"),
            "DstAddr": getc("id.resp_h").astype(str),
            "Dport": pd.to_numeric(getc("id.resp_p"), errors="coerce"),
            "Proto": getc("proto").astype(str).str.lower().str.strip(),
            "Dur": pd.to_numeric(getc("duration"), errors="coerce").fillna(0),
            "SrcBytes": pd.to_numeric(getc("orig_bytes"), errors="coerce").fillna(0),
            "DstBytes": pd.to_numeric(getc("resp_bytes"), errors="coerce").fillna(0),
            "TotPkts": tot_pkts.fillna(0),
            "Label": lab.astype(int),
            "SubLabel": getc("detailed-label").astype(str).str.strip(),
            "DatasetSource": "IoT-23",
        }
    )
    print(f"    Parsed {len(out):,} Zeek flows")
    return out


def ctu13_to_unified(df: pd.DataFrame) -> pd.DataFrame:
    """Attach CTU-13 metadata columns expected by the unified schema."""
    u = df.copy()
    u["SubLabel"] = ""
    u["DatasetSource"] = "CTU-13"
    if "DstBytes" not in u.columns and "TotBytes" in u.columns and "SrcBytes" in u.columns:
        u["DstBytes"] = (pd.to_numeric(u["TotBytes"], errors="coerce").fillna(0)
                         - pd.to_numeric(u["SrcBytes"], errors="coerce").fillna(0)).clip(lower=0)
    elif "DstBytes" not in u.columns:
        u["DstBytes"] = 0
    return u


def auto_detect_load(path: str) -> pd.DataFrame:
    """
    Load a single file into the unified schema.
    - .binetflow → CTU-13 loader (unchanged)
    - .pcap → CICFlowMeter → CSV in data/converted/
    - filename contains conn.log.labeled → Zeek parser
    - otherwise → generic CSV mapped if possible else generic load + infer
    """
    path = str(path)
    base = os.path.basename(path).lower()
    ext = os.path.splitext(path)[1].lower()

    if ext == ".binetflow":
        return ctu13_to_unified(load_ctu13(path))

    if "conn.log.labeled" in base:
        return parse_zeek_conn_labeled(path)

    if ext == ".pcap":
        root = Path(__file__).resolve().parents[1]
        conv_dir = root / "data" / "converted"
        conv_dir.mkdir(parents=True, exist_ok=True)
        stem = Path(path).stem
        out_csv = str(conv_dir / f"{stem}_cicflowmeter.csv")
        run_cicflowmeter(path, out_csv)
        return load_cicflowmeter_csv(out_csv)

    # Fallback: try CIC-shaped CSV, else generic
    try:
        probe = pd.read_csv(path, nrows=5, low_memory=False)
        lu = _build_col_lookup(probe)
        if _pick_col(lu, "flow_duration", "total_fwd_packets", "source_ip"):
            return load_cicflowmeter_csv(path)
    except Exception:
        pass

    g = load_generic_csv(path)
    if set(["StartTime", "SrcAddr", "DstAddr"]).issubset(g.columns):
        g = g.copy()
        g.setdefault("SubLabel", "")
        g.setdefault("DatasetSource", "IoT-23")
        g.setdefault("DstBytes", 0)
        return g
    raise ValueError(f"Unsupported file format: {path}")


def load_config_paths(config_path: str) -> tuple[list[str], list[str], list[str]]:
    cfg = load_yaml_config(Path(config_path))
    return (
        list(cfg.get("ctu13_paths") or []),
        list(cfg.get("iot23_paths") or []),
        list(cfg.get("demo_paths") or []),
    )


def expand_inputs(patterns: Iterable[str], root: Path, exclude: Iterable[Path] = ()) -> list[Path]:
    skip = {Path(p).resolve() for p in exclude}
    out: list[Path] = []
    for pat in patterns:
        for m in glob.glob(str(root / pat), recursive=True):
            p = Path(m)
            if p.is_file() and p.resolve() not in skip:
                out.append(p)
    return sorted(set(out))


def clean(df: pd.DataFrame) -> pd.DataFrame:
    """
    Core cleaning on the unified schema (+ legacy CTU columns allowed).
    """
    print("[+] Cleaning unified data...")

    if "TotBytes" not in df.columns and "SrcBytes" in df.columns and "DstBytes" in df.columns:
        df = df.copy()
        df["TotBytes"] = (
            pd.to_numeric(df["SrcBytes"], errors="coerce").fillna(0)
            + pd.to_numeric(df["DstBytes"], errors="coerce").fillna(0)
        )

    if "StartTime" in df.columns:
        df["StartTime"] = pd.to_datetime(df["StartTime"], errors="coerce")
        df = df.dropna(subset=["StartTime"])
        df = df.sort_values("StartTime").reset_index(drop=True)

    required = [c for c in ["SrcAddr", "DstAddr", "Proto"] if c in df.columns]
    before = len(df)
    df = df.dropna(subset=required)
    print(f"    Dropped {before - len(df):,} rows with missing key fields")

    if "Proto" in df.columns:
        df["Proto"] = df["Proto"].astype(str).str.lower().str.strip()
        df["ProtoCode"] = df["Proto"].map(PROTO_MAP).fillna(99).astype(int)

    if "Label" in df.columns and pd.api.types.is_numeric_dtype(df["Label"]):
        df["is_malicious"] = pd.to_numeric(df["Label"], errors="coerce").fillna(0).astype(int)
    elif "Label" in df.columns:
        df["Label_raw"] = df["Label"].astype(str)
        df["is_malicious"] = df["Label_raw"].str.contains(
            "Botnet|Attack|Malicious|PortScan|C&C|C2", case=False, na=False
        ).astype(int)
    else:
        df["is_malicious"] = 0

    mal_count = int(df["is_malicious"].sum())
    print(f"    Malicious flows: {mal_count:,} ({mal_count/ max(len(df),1)*100:.1f}%)")
    print(f"    Benign flows:    {len(df)-mal_count:,}")

    for col in ["Dur", "TotPkts", "TotBytes", "SrcBytes", "DstBytes"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    for col in ["Sport", "Dport"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)

    df["Label"] = df["is_malicious"].astype(int)
    if "SubLabel" not in df.columns:
        df["SubLabel"] = ""
    df["SubLabel"] = df["SubLabel"].fillna("").astype(str)
    if "DatasetSource" not in df.columns:
        df["DatasetSource"] = "CTU-13"

    before = len(df)
    df = df.drop_duplicates()
    print(f"    Removed {before - len(df):,} duplicate rows")
    print(f"    Final dataset size: {len(df):,} rows")
    return df.reset_index(drop=True)


def save_unified(df: pd.DataFrame, parquet_path: str, csv_path: str | None) -> None:
    os.makedirs(os.path.dirname(parquet_path) or ".", exist_ok=True)
    df_out = df.copy()
    for c in UNIFIED_COLS:
        if c not in df_out.columns:
            if c == "SubLabel":
                df_out[c] = ""
            elif c == "Label":
                df_out[c] = df_out.get("is_malicious", 0)
            elif c == "DatasetSource":
                df_out[c] = "CTU-13"
            else:
                df_out[c] = np.nan
    df_out = df_out[[c for c in UNIFIED_COLS if c in df_out.columns]]
    df_out.to_parquet(parquet_path, index=False)
    print(f"[✓] Saved unified flows (parquet) → {parquet_path}")
    if csv_path:
        os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
        # Widen CSV with helpful extra columns for legacy steps
        df.to_csv(csv_path, index=False)
        print(f"[✓] Saved legacy cleaned CSV → {csv_path}")


def print_summary(df: pd.DataFrame):
    print("\n── Dataset Summary ──────────────────────────────────────")
    print(f"  Total flows     : {len(df):,}")
    print(f"  Columns         : {list(df.columns)}")
    if "StartTime" in df.columns:
        print(f"  Time range      : {df['StartTime'].min()} → {df['StartTime'].max()}")
    if "SrcAddr" in df.columns:
        print(f"  Unique src IPs  : {df['SrcAddr'].nunique():,}")
    if "DstAddr" in df.columns:
        print(f"  Unique dst IPs  : {df['DstAddr'].nunique():,}")
    if "DatasetSource" in df.columns:
        print(df["DatasetSource"].value_counts(dropna=False).to_string())
    print("─────────────────────────────────────────────────────────\n")


def generate_demo_data(n: int = 5000) -> pd.DataFrame:
    print("[!] No input files from config. Generating synthetic demo data (CTU-like)...")
    rng = np.random.default_rng(42)
    timestamps = pd.date_range("2024-01-01", periods=n, freq="10s")
    botnet_ips = [f"192.168.1.{i}" for i in range(1, 6)]
    c2_ips = [f"85.17.{i}.{j}" for i in range(1, 4) for j in range(1, 4)]
    benign_ips = [f"10.0.0.{i}" for i in range(10, 60)]
    server_ips = [f"172.16.0.{i}" for i in range(1, 20)]

    rows = []
    for i in range(int(n * 0.8)):
        rows.append(
            {
                "StartTime": timestamps[i],
                "Dur": rng.exponential(2.0),
                "Proto": rng.choice(["tcp", "udp"]),
                "SrcAddr": rng.choice(benign_ips),
                "Sport": int(rng.integers(1024, 65535)),
                "DstAddr": rng.choice(server_ips),
                "Dport": int(rng.choice([80, 443, 53, 22])),
                "TotPkts": int(rng.integers(1, 50)),
                "TotBytes": int(rng.integers(100, 50000)),
                "SrcBytes": int(rng.integers(50, 25000)),
                "DstBytes": int(rng.integers(50, 25000)),
                "Label": "Normal",
                "SubLabel": "",
                "DatasetSource": "CTU-13",
            }
        )
    for i in range(int(n * 0.8), n):
        rows.append(
            {
                "StartTime": timestamps[i],
                "Dur": rng.exponential(0.5),
                "Proto": rng.choice(["tcp", "udp", "icmp"]),
                "SrcAddr": rng.choice(botnet_ips),
                "Sport": int(rng.integers(1024, 65535)),
                "DstAddr": rng.choice(c2_ips),
                "Dport": int(rng.choice([6667, 80, 443, 4444])),
                "TotPkts": int(rng.integers(1, 10)),
                "TotBytes": int(rng.integers(50, 5000)),
                "SrcBytes": int(rng.integers(20, 2000)),
                "DstBytes": int(rng.integers(20, 2000)),
                "Label": "Botnet",
                "SubLabel": "C&C",
                "DatasetSource": "CTU-13",
            }
        )
    df = pd.DataFrame(rows).sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"    Generated {len(df):,} synthetic flows")
    return df


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Preprocess CTU-13 / IoT-23 network flows")
    parser.add_argument("--input", type=str, default=None, help="Single file override")
    parser.add_argument("--config", type=str, default=str(root / "config.yaml"))
    parser.add_argument("--output-parquet", type=str, default=str(root / "output" / "unified_flows.parquet"))
    parser.add_argument("--output", type=str, default=str(root / "output" / "01_cleaned.csv"),
                        help="Legacy wide CSV mirror")
    args = parser.parse_args()

    frames: list[pd.DataFrame] = []

    if args.input and os.path.exists(args.input):
        frames.append(auto_detect_load(args.input))
    else:
        cfg = load_yaml_config(Path(args.config))
        demo_mode = bool(cfg.get("DEMO_MODE", False))
        ctu_pats, iot_pats, demo_pats = load_config_paths(args.config)
        # Demo files live under data/, so keep them out of the real-dataset globs.
        demo_files = expand_inputs(demo_pats, root)
        if demo_mode:
            frames.extend(auto_detect_load(str(p)) for p in demo_files)
        frames.extend(auto_detect_load(str(p)) for p in expand_inputs(ctu_pats, root, exclude=demo_files))
        frames.extend(auto_detect_load(str(p)) for p in expand_inputs(iot_pats, root, exclude=demo_files))
        if not frames and demo_pats:
            print("[!] WARNING: no CTU-13 / IoT-23 files matched the config globs.")
            print("[!] Falling back to SYNTHETIC demo data - results are not from a real dataset.")
            print(f"[!] Checked: {ctu_pats + iot_pats} (relative to {root})")
            frames.extend(auto_detect_load(str(p)) for p in expand_inputs(demo_pats, root))

    if frames:
        df_raw = pd.concat(frames, ignore_index=True)
    else:
        df_raw = generate_demo_data()

    df_clean = clean(df_raw)
    print_summary(df_clean)
    save_unified(df_clean, args.output_parquet, args.output)
