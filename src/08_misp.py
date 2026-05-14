"""
PHASE 8: MISP correlation (optional).

Usage:
    python src/08_misp.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import yaml
from dotenv import load_dotenv

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

load_dotenv()


def _cfg(root: Path) -> dict:
    p = root / "config.yaml"
    if not p.is_file():
        return {}
    with open(p, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def search_misp(ips: list[str]) -> list[dict]:
    url = os.getenv("MISP_URL", "").rstrip("/")
    key = os.getenv("MISP_KEY", "")
    if not url or not key:
        print("[!] MISP_URL / MISP_KEY not set — skipping MISP search.")
        return []

    try:
        from pymisp import ExpandedPyMISP  # type: ignore
    except ImportError:
        print("[!] pymisp not installed — skipping MISP search.")
        return []

    misp = ExpandedPyMISP(url, key, ssl=True)
    out: list[dict] = []
    for ip in ips[:25]:
        try:
            res = misp.search(controller="attributes", value=ip, pythonify=True)
            for attr in res or []:
                ev = getattr(attr, "Event", None)
                out.append(
                    {
                        "ip": ip,
                        "event": getattr(ev, "info", "") if ev else "",
                        "threat_actor": "",
                        "tlp": getattr(ev, "distribution", ""),
                    }
                )
        except Exception as e:
            out.append({"ip": ip, "error": str(e)})
    return out


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    cfg = _cfg(root)
    paths = cfg.get("paths") or {}
    camps_path = root / (paths.get("campaigns") or "output/03_campaigns.csv")
    out_path = root / (paths.get("misp_matches") or "output/misp_matches.json")

    if not camps_path.is_file():
        print(f"[!] Missing {camps_path}")
        return

    import pandas as pd

    df = pd.read_csv(camps_path, low_memory=False)
    ips = df["SrcAddr"].astype(str).unique().tolist() if "SrcAddr" in df.columns else []
    matches = search_misp(ips)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"matches": matches}, f, indent=2)
    print(f"[✓] Wrote MISP matches → {out_path} ({len(matches)} rows)")


if __name__ == "__main__":
    main()
