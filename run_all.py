"""
Master runner for the attack-attribution pipeline.

Reads ``config.yaml`` (``DEMO_MODE``). If ``DEMO_MODE=true``, generates synthetic data first.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

import yaml

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

ROOT = Path(__file__).resolve().parent


def _cfg() -> dict:
    p = ROOT / "config.yaml"
    if not p.is_file():
        return {}
    with open(p, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _run(cmd: list[str]) -> int:
    print("\n" + "=" * 60)
    print(" ", " ".join(cmd))
    print("=" * 60 + "\n")
    return subprocess.call(cmd, cwd=str(ROOT))


def _summary_line(phase: str, text: str) -> None:
    # ASCII-only: Windows cp1252 consoles cannot print checkmarks / em dashes.
    print(f"[OK] {phase} - {text}")


def main() -> int:
    cfg = _cfg()
    demo = bool(cfg.get("DEMO_MODE", False))

    steps = []
    if demo:
        steps.append(("demo-gen", [sys.executable, str(ROOT / "src" / "demo_data_generator.py")]))

    steps.extend(
        [
            ("01", [sys.executable, "src/01_preprocess.py"]),
            ("02", [sys.executable, "src/02_features.py"]),
            ("03", [sys.executable, "src/03_clustering.py"]),
            ("04", [sys.executable, "src/04_threat_intel.py"]),
            ("06", [sys.executable, "src/06_attribution.py"]),
            ("09", [sys.executable, "src/09_iot_labels.py"]),
            ("07", [sys.executable, "src/07_graph.py"]),
            ("08", [sys.executable, "src/08_misp.py"]),
            ("05", [sys.executable, "src/05_dashboard.py", "--artifacts", "output_demo" if demo else "output"]),
        ]
    )

    dash_cmd = None
    pipe_steps: list[tuple[str, list[str]]] = []
    for sid, cmd in steps:
        if sid == "05":
            dash_cmd = cmd
        else:
            pipe_steps.append((sid, cmd))

    try:
        from tqdm import tqdm as _tqdm
    except Exception:  # pragma: no cover
        _tqdm = None

    _iter = _tqdm(pipe_steps, desc="Pipeline", unit="step") if _tqdm else pipe_steps
    for sid, cmd in _iter:
        code = _run(cmd)
        if code != 0:
            print(f"[!] Step {sid} failed with exit code {code}")
            return code

    if demo:
        # Keep a standalone synthetic snapshot so the demo dashboard survives
        # the next real run overwriting output/.
        import shutil

        snap = ROOT / "output_demo"
        snap.mkdir(parents=True, exist_ok=True)
        copied = 0
        for item in (ROOT / "output").iterdir():
            if item.is_file() and item.suffix.lower() not in (".log", ".err"):
                shutil.copy2(item, snap / item.name)
                copied += 1
        print(f"\n[+] Snapshotted {copied} synthetic artifacts -> output_demo/")

    # --- Post-run summaries (best-effort) ---------------------------------
    try:
        flows = 0
        up = ROOT / "output" / "unified_flows.parquet"
        if up.is_file():
            import pandas as pd

            flows = len(pd.read_parquet(up))
        camps = ROOT / "output" / "03_campaigns.csv"
        n_ips = 0
        n_feat_rows = 0
        if Path(camps).is_file():
            import pandas as pd

            dfc = pd.read_csv(camps, low_memory=False)
            n_ips = int(dfc["SrcAddr"].nunique()) if "SrcAddr" in dfc.columns else 0
            n_feat_rows = len(dfc)
        summ = ROOT / "output" / "cluster_summary.json"
        sil = db = "n/a"
        n_clusters = 0
        if summ.is_file():
            with open(summ, encoding="utf-8") as f:
                sj = json.load(f)
            sil = sj.get("silhouette", "n/a")
            db = sj.get("davies_bouldin", "n/a")
            n_clusters = len(sj.get("clusters") or [])

        n_feat_cols = 0
        featp = ROOT / "output" / "features_iot_extended.parquet"
        if featp.is_file():
            try:
                import pyarrow.parquet as pq

                skip = {
                    "SrcAddr",
                    "dataset_source",
                    "time_window",
                    "campaign_id",
                    "label",
                    "attack_type",
                }
                names = pq.ParquetFile(featp).schema_arrow.names
                n_feat_cols = len([n for n in names if n not in skip])
            except Exception:
                n_feat_cols = 0

        n_enr_ips = 0
        enrp = ROOT / "output" / "04_enriched.csv"
        if enrp.is_file():
            try:
                import pandas as pd

                de = pd.read_csv(enrp, usecols=["ip"], low_memory=False)
                n_enr_ips = int(de["ip"].nunique())
            except Exception:
                n_enr_ips = 0
        att = ROOT / "output" / "attribution_scores.json"
        confs: list[str] = []
        n_iot_families = 0
        if att.is_file():
            with open(att, encoding="utf-8") as f:
                aj = json.load(f)
            fams = {
                str(x.get("iot_family"))
                for x in (aj.get("clusters") or [])
                if str(x.get("iot_family") or "").strip() not in ("", "None", "null")
            }
            n_iot_families = len(fams)
            letters = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J"]
            for i, c in enumerate(aj.get("clusters", []) or []):
                pct = c.get("confidence_pct", 0)
                letter = letters[i] if i < len(letters) else str(i)
                confs.append(f"{letter}={pct}%")
        graphp = ROOT / "output" / "attack_graph.json"
        nodes = edges = 0
        if graphp.is_file():
            with open(graphp, encoding="utf-8") as f:
                gj = json.load(f)
            nodes = len(gj.get("nodes", []))
            edges = len(gj.get("links", []))

        demo_tag = "[DEMO - mock responses] " if demo else ""

        _summary_line(
            "Phase 1 — Preprocessing",
            f"{flows:,} flows loaded, {n_clusters} campaigns detected" if n_clusters else f"{flows:,} flows loaded (unified parquet)",
        )
        _summary_line(
            "Phase 2 — Features",
            f"{n_ips:,} IPs fingerprinted, {n_feat_cols} feature columns" if n_feat_cols else f"{n_ips:,} IPs fingerprinted, {n_feat_rows:,} rows",
        )
        _summary_line(
            "Phase 3 — Clustering",
            f"{n_clusters} clusters (silhouette={sil}, DB={db})" if n_clusters else f"clusters saved (silhouette={sil}, DB={db})",
        )
        _summary_line("Phase 4 — Threat Intel", f"{n_enr_ips or n_ips:,} IPs enriched {demo_tag}".strip())
        dash = cfg.get("dashboard", {}) or {}
        bind_h = str(dash.get("host", "127.0.0.1"))
        port = int(dash.get("port", 8050))
        show_host = "127.0.0.1" if bind_h in ("0.0.0.0", "::", "") else bind_h
        _summary_line("Phase 5 — Dashboard", f"ready at http://{show_host}:{port}")
        _summary_line("Phase 6 — Attribution", " ".join(confs) if confs else "scores written")
        _summary_line("Phase 7 — Graph", f"{nodes} nodes, {edges} edges")
        misp_path = ROOT / "output" / "misp_matches.json"
        misp_note = "matches written"
        if misp_path.is_file():
            try:
                with open(misp_path, encoding="utf-8") as f:
                    mj = json.load(f)
                ev = mj.get("events") or mj.get("matches") or []
                if isinstance(ev, list) and len(ev) == 0:
                    misp_note = "no matches (or skipped - no MISP key)"
            except Exception:
                misp_note = "file present"
        else:
            misp_note = "skipped (no key or not run)"
        _summary_line("Phase 8 — MISP", misp_note)
        _summary_line(
            "Phase 9 — IoT Labels",
            f"{n_iot_families} distinct IoT families in attribution JSON" if n_iot_families else "families merged into attribution JSON",
        )
    except Exception as e:
        print(f"[!] Summary generation skipped: {e}")

    dash = cfg.get("dashboard", {}) or {}
    bind_host = str(dash.get("host", "127.0.0.1"))
    port = int(dash.get("port", 8050))
    # Browser URL: when server binds 0.0.0.0 / ::, still use loopback for local viewing.
    open_host = "127.0.0.1" if bind_host in ("0.0.0.0", "::", "") else bind_host
    startup_delay = float(dash.get("startup_delay_sec", 2))

    if dash_cmd:
        log_path = ROOT / "output" / "dashboard.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        print("\n[+] Launching Dash dashboard (background)...")
        print(f"    Log file: {log_path}")
        try:
            log_f = open(log_path, "ab", buffering=0)
        except OSError as e:
            print(f"[!] Could not open log file ({e}); dashboard stdout/stderr go to console only")
            log_f = None
        proc = subprocess.Popen(
            dash_cmd,
            cwd=str(ROOT),
            stdout=log_f or subprocess.DEVNULL,
            stderr=subprocess.STDOUT if log_f else subprocess.DEVNULL,
        )
        time.sleep(max(0.5, startup_delay))
        if proc.poll() is not None:
            print(f"[!] Dashboard process exited immediately (code {proc.returncode}).")
            print(f"    Read errors in: {log_path}" if log_f else "    Re-run: python src/05_dashboard.py")
        else:
            print(f"[+] Dashboard PID {proc.pid} - open http://{open_host}:{port} in your browser")

    try:
        webbrowser.open(f"http://{open_host}:{port}")
    except Exception:
        print(f"[i] Open manually: http://{open_host}:{port}")

    print(
        """
================================================================
DEMO READY - suggested walkthrough (10 min):
 1. Tab 1: campaigns on timeline - color coding by confidence
 2. Tab 1: KPI cards - flows to campaigns
 3. Tab 2: select Campaign A - confidence + formula breakdown
 4. Tab 2: click an IP node - VT/Abuse/Shodan/ASN
 5. Tab 3: heatmap - factor strengths
 6. Tab 4: replay - burst window
 7. Tab 5: filter + export JSON + PDF report
 8. Tab 6: IoT profiler scatter
================================================================
"""
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
