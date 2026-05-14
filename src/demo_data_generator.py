"""
Synthetic CTU-13-compatible demo dataset (40k flows) + mock threat-intel JSON.

Reproducibility: random.seed(42) and numpy.random.seed(42) for identical runs.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

import numpy as np
import pandas as pd

random.seed(42)
np.random.seed(42)
RNG = np.random.default_rng(42)

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

SYNTHETIC_DATA_DOCUMENTATION: dict = {
    "Campaign_A": {
        "real_world_basis": "Mirai botnet - scans for Telnet on IoT devices",
        "flow_count": 25000,
        "distinguishing_features": "horizontal scan, bursty timing, high src/dst byte ratio",
        "timing_distribution": "Poisson(lambda=0.8) models IoT scanner burst behavior",
        "reference": "Antonakakis et al. 2017 - Understanding the Mirai Botnet",
    },
    "Campaign_B": {
        "real_world_basis": "Periodic C2 beaconing over HTTPS",
        "flow_count": 8000,
        "distinguishing_features": "fixed C2 endpoints, low CoV inter-arrival, polling byte ratio",
        "timing_distribution": "Normal(mean=30s, std=2s) models jittered beacon intervals",
        "reference": "MITRE ATT&CK T1071 - Application Layer Protocol",
    },
    "Campaign_C": {
        "real_world_basis": "Slow horizontal / vertical reconnaissance",
        "flow_count": 7000,
        "distinguishing_features": "many destinations, sparse timing, small payloads",
        "timing_distribution": "Uniform(120s,300s) models stealthy scanner pacing",
        "reference": "MITRE ATT&CK T1046 - Network Service Discovery",
    },
}


def _print_doc_table() -> None:
    try:
        from tabulate import tabulate

        rows = []
        for k, v in SYNTHETIC_DATA_DOCUMENTATION.items():
            rows.append(
                [
                    k,
                    v.get("real_world_basis", ""),
                    v.get("flow_count", ""),
                    v.get("distinguishing_features", ""),
                    v.get("timing_distribution", ""),
                    v.get("reference", ""),
                ]
            )
        hdr = ["Campaign", "Basis", "Flows", "Features", "Timing", "Reference"]
        print(tabulate(rows, headers=hdr, tablefmt="github"))
    except ImportError:
        print(json.dumps(SYNTHETIC_DATA_DOCUMENTATION, indent=2))


def _ctu_row(
    ts: pd.Timestamp,
    dur: float,
    proto: str,
    src: str,
    sport: int,
    dst: str,
    dport: int,
    tot_pkts: int,
    tot_bytes: int,
    src_bytes: int,
    label: str,
) -> dict:
    dst_bytes = max(int(tot_bytes - src_bytes), 0)
    return {
        "StartTime": ts,
        "Dur": float(dur),
        "Proto": proto,
        "SrcAddr": src,
        "Sport": int(sport),
        "Dir": "->",
        "DstAddr": dst,
        "Dport": int(dport),
        "State": "INT",
        "sTos": 0,
        "dTos": 0,
        "TotPkts": int(tot_pkts),
        "TotBytes": int(tot_bytes),
        "SrcBytes": int(src_bytes),
        "Label": label,
    }


def generate_campaign_a(n: int = 25000) -> pd.DataFrame:
    """Mirai-like: bursty Exp inter-arrival (mean 0.8s) within a 2h burst window."""
    src_ips = [f"192.168.10.{i}" for i in range(1, 16)]  # 15 IPs in /24
    t0 = pd.Timestamp("2024-06-01 08:00:00")
    window_sec = 2 * 3600 - 5  # ~2 hours
    dst_pool = [f"10.{(i // 256) % 256}.{(i % 256)}.{(i * 7) % 254 + 1}" for i in range(220)]

    # Exp(scale=0.8): models short idle gaps typical of high-rate Telnet scanning bursts.
    gaps = RNG.exponential(0.8, size=n)
    scale = window_sec / max(float(np.sum(gaps)), 1e-6)
    gaps = gaps * scale
    times = np.cumsum(gaps)

    rows: list[dict] = []
    for i in range(n):
        cur = t0 + pd.Timedelta(seconds=float(times[i] % window_sec))
        src = random.choice(src_ips)
        dst = random.choice(dst_pool)
        dport = int(RNG.choice([23, 23, 23, 23, 23, 2323]))  # heavy Telnet / alt Telnet
        sport = int(RNG.integers(40000, 60000))
        # Small scanner payloads: Normal(120,20) - many short probes.
        tot_b = max(int(RNG.normal(120, 20)), 20)
        dst_b = max(int(tot_b / (1.0 + 8.5)), 1)
        src_b = max(tot_b - dst_b, 1)
        tot_p = int(RNG.integers(2, 12))
        lab = "Botnet" if RNG.random() < 0.9 else "Background"
        rows.append(
            _ctu_row(
                cur,
                dur=max(RNG.normal(0.05, 0.02), 0.001),
                proto="tcp",
                src=src,
                sport=sport,
                dst=dst,
                dport=dport,
                tot_pkts=tot_p,
                tot_bytes=tot_b,
                src_bytes=src_b,
                label=lab,
            )
        )
    return pd.DataFrame(rows)


def generate_campaign_b(n: int = 8000) -> pd.DataFrame:
    """C2 beaconing: Normal inter-arrival ~30s (tight jitter -> low CoV)."""
    src_ips = [f"10.20.0.{i}" for i in range(1, 6)]
    dst_ips = ["203.0.113.5", "203.0.113.6", "203.0.113.7"]
    t0 = pd.Timestamp("2024-06-01 14:00:00")
    rows: list[dict] = []
    cur = t0
    for _ in range(n):
        # Normal(30,2): models low-jitter beaconing seen in some HTTP C2 implants.
        gap = float(RNG.normal(30.0, 2.0))
        gap = max(gap, 5.0)
        cur = cur + pd.Timedelta(seconds=gap)
        src = random.choice(src_ips)
        dst = random.choice(dst_ips)
        dport = int(RNG.choice([443, 8080]))
        sport = int(RNG.integers(30000, 50000))
        tot_b = max(int(RNG.normal(850, 50)), 200)
        dst_b = max(int(tot_b / (1.0 + 1.0 / 0.15)), 1)  # mean Src/Dst ~ 0.15
        src_b = max(tot_b - dst_b, 1)
        tot_p = int(RNG.integers(8, 30))
        rows.append(
            _ctu_row(
                cur,
                dur=max(RNG.normal(2.0, 0.3), 0.05),
                proto="tcp",
                src=src,
                sport=sport,
                dst=dst,
                dport=dport,
                tot_pkts=tot_p,
                tot_bytes=tot_b,
                src_bytes=src_b,
                label="C&C",
            )
        )
    return pd.DataFrame(rows)


def generate_campaign_c(n: int = 7000) -> pd.DataFrame:
    """Slow scanner: Uniform long gaps, many destinations, SSH/RDP ports."""
    src_ips = [f"172.31.0.{i}" for i in range(1, 4)]
    dst_pool = [f"198.51.100.{(i % 200) + 1}" for i in range(320)]
    t0 = pd.Timestamp("2024-06-02 00:00:00")
    t_end = t0 + pd.Timedelta(hours=12)
    rows: list[dict] = []
    cur = t0
    for _ in range(n):
        # Uniform(120,300): models deliberately slow scan pacing to evade rate limits.
        gap = float(RNG.uniform(120.0, 300.0))
        cur = cur + pd.Timedelta(seconds=gap)
        if cur >= t_end:
            cur = t0 + pd.Timedelta(seconds=float(RNG.uniform(0.0, (t_end - t0).total_seconds() - 1.0)))
        ts = cur
        src = random.choice(src_ips)
        dst = random.choice(dst_pool)
        dport = int(RNG.choice([22, 3389]))
        sport = int(RNG.integers(45000, 55000))
        tot_b = max(int(RNG.normal(60, 10)), 10)
        dst_b = max(int(tot_b * 0.55), 1)
        src_b = max(tot_b - dst_b, 1)
        tot_p = int(RNG.integers(2, 8))
        rows.append(
            _ctu_row(
                ts,
                dur=max(RNG.normal(1.0, 0.2), 0.02),
                proto="tcp",
                src=src,
                sport=sport,
                dst=dst,
                dport=dport,
                tot_pkts=tot_p,
                tot_bytes=tot_b,
                src_bytes=src_b,
                label="PortScan",
            )
        )
    return pd.DataFrame(rows)


def build_mock_ti() -> dict:
    """Mock VT/Abuse/ASN/country keyed by IP for DEMO_MODE enrichment."""
    out: dict[str, dict] = {}
    a_ips = [f"192.168.10.{i}" for i in range(1, 16)]
    malicious_a = set(a_ips[:9])  # 60% of 15
    for ip in a_ips:
        if ip in malicious_a:
            out[ip] = {
                "vt_malicious": int(RNG.integers(7, 10)),
                "abuse_score": int(RNG.integers(80, 96)),
                "asn": "AS64496",
                "country": "CN",
                "shodan_ports": "23,2323,80",
                "shodan_tags": "telnet,router",
            }
        else:
            out[ip] = {
                "vt_malicious": 0,
                "abuse_score": 0,
                "asn": "AS64496",
                "country": "CN",
                "shodan_ports": "",
                "shodan_tags": "",
            }
    b_ips = [f"10.20.0.{i}" for i in range(1, 6)]
    for ip in b_ips:
        out[ip] = {
            "vt_malicious": int(RNG.integers(4, 7)),
            "abuse_score": int(RNG.integers(40, 61)),
            "asn": "AS64497",
            "country": "RU",
            "shodan_ports": "443,8080",
            "shodan_tags": "https,c2-like",
        }
    c_ips = [f"172.31.0.{i}" for i in range(1, 4)]
    for ip in c_ips:
        out[ip] = {
            "vt_malicious": int(RNG.integers(2, 5)),
            "abuse_score": int(RNG.integers(20, 41)),
            "asn": "AS64498",
            "country": "BR",
            "shodan_ports": "22,3389",
            "shodan_tags": "ssh,rdp",
        }
    return out


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    out_csv = root / "data" / "demo" / "synthetic_demo.binetflow"
    out_ti = root / "data" / "demo" / "mock_ti_responses.json"
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    print("--- SYNTHETIC_DATA_DOCUMENTATION ---")
    _print_doc_table()
    print("--------------------------------------\n")

    df_a = generate_campaign_a(25000)
    df_b = generate_campaign_b(8000)
    df_c = generate_campaign_c(7000)
    df = pd.concat([df_a, df_b, df_c], ignore_index=True)
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    df.sort_values("StartTime", inplace=True)
    df.reset_index(drop=True, inplace=True)

    cols = [
        "StartTime",
        "Dur",
        "Proto",
        "SrcAddr",
        "Sport",
        "Dir",
        "DstAddr",
        "Dport",
        "State",
        "sTos",
        "dTos",
        "TotPkts",
        "TotBytes",
        "SrcBytes",
        "Label",
    ]
    df[cols].to_csv(out_csv, index=False)
    print(f"[OK] Wrote {len(df):,} flows -> {out_csv}")

    with open(out_ti, "w", encoding="utf-8") as f:
        json.dump(build_mock_ti(), f, indent=2)
    print(f"[OK] Wrote mock TI -> {out_ti}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate 40k-flow synthetic demo + mock TI JSON")
    args = parser.parse_args()
    main()
