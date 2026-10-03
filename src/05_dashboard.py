"""
PHASE 5: Dash / Plotly interactive dashboard (AttribIQ — light enterprise theme).

Run:
    python src/05_dashboard.py
"""

from typing import Any
import io
import json
import random
import sys
from datetime import datetime
from pathlib import Path

import dash_cytoscape as cyto
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import yaml
from dash import Dash, Input, Output, State, ALL, ctx, dash_table, dcc, html, no_update

random.seed(42)
np.random.seed(42)

ROOT = Path(__file__).resolve().parents[1]

THEME = {
    "page_bg": "#F6F8FA",
    "card_bg": "#FFFFFF",
    "card_border": "#E1E4E8",
    "card_shadow": "0 1px 3px rgba(0,0,0,0.08)",
    "primary": "#2563EB",
    "success": "#16A34A",
    "warning": "#D97706",
    "danger": "#DC2626",
    "text": "#0F172A",
    "text_secondary": "#64748B",
    "text_muted": "#94A3B8",
    "table_header": "#F1F5F9",
    "row_hover": "#F8FAFC",
    "radius": "8px",
    "plot_paper": "#FFFFFF",
    "plot_bg": "#F6F8FA",
    "grid": "#E1E4E8",
}

FONT_UI = "Inter, system-ui, -apple-system, sans-serif"
FONT_MONO = '"JetBrains Mono", ui-monospace, monospace'


def _card(extra: dict | None = None) -> dict:
    s = {
        "background": THEME["card_bg"],
        "border": f"1px solid {THEME['card_border']}",
        "borderRadius": THEME["radius"],
        "padding": "20px",
        "boxShadow": THEME["card_shadow"],
        "transition": "0.15s ease",
    }
    if extra:
        s.update(extra)
    return s


def _plotly_base(title: str | None = None, height: int | None = None) -> dict:
    u = dict(
        template="plotly_white",
        paper_bgcolor=THEME["plot_paper"],
        plot_bgcolor=THEME["plot_bg"],
        font=dict(color=THEME["text"], family=FONT_UI),
        xaxis=dict(gridcolor=THEME["grid"], zerolinecolor=THEME["grid"]),
        yaxis=dict(gridcolor=THEME["grid"], zerolinecolor=THEME["grid"]),
        margin=dict(l=48, r=24, t=48, b=48),
    )
    if title:
        u["title"] = dict(text=title, font=dict(size=15, color=THEME["text"]))
    if height:
        u["height"] = height
    return u


def _empty_chart(title: str, message: str, height: int = 260) -> go.Figure:
    """Placeholder chart when there is nothing to plot (avoids empty default axes)."""
    fig = go.Figure()
    fig.add_annotation(
        text=f"<b>{message}</b>",
        xref="paper",
        yref="paper",
        x=0.5,
        y=0.55,
        showarrow=False,
        font=dict(size=14, color=THEME["text_secondary"]),
        align="center",
    )
    base = dict(_plotly_base(title, height=height))
    base.pop("xaxis", None)
    base.pop("yaxis", None)
    base.pop("margin", None)
    fig.update_layout(
        **base,
        xaxis=dict(visible=False, showgrid=False, zeroline=False),
        yaxis=dict(visible=False, showgrid=False, zeroline=False),
        margin=dict(l=24, r=24, t=56, b=24),
    )
    return fig


GRAPH_CONFIG = {
    "displayModeBar": True,
    "displaylogo": False,
    "responsive": True,
    "modeBarButtonsToRemove": ["lasso2d", "select2d", "autoScale2d"],
}


# A real capture has millions of distinct timestamps, and the replay timeline is
# shipped to the browser in a dcc.Store - so sample it down to a usable slider.
REPLAY_MAX_STEPS = 1500


def _replay_timeline(flows: pd.DataFrame) -> list[pd.Timestamp]:
    """Evenly spaced replay steps across the capture window."""
    if flows.empty or "StartTime" not in flows.columns:
        return []
    ts = pd.to_datetime(flows["StartTime"], errors="coerce").dropna()
    if ts.empty:
        return []
    uniq = np.sort(ts.unique())
    if len(uniq) > REPLAY_MAX_STEPS:
        picks = np.unique(np.linspace(0, len(uniq) - 1, REPLAY_MAX_STEPS).round().astype(int))
        uniq = uniq[picks]
    return [pd.Timestamp(t) for t in uniq]


def _replay_seed_indices(
    flows: pd.DataFrame, camps: pd.DataFrame, clusters: list, timeline: list
) -> tuple[int, int, int]:
    """Pick replay slider defaults from flows + campaigns (no fixed IPs)."""
    if not clusters:
        return 0, 0, 0
    anchor_cid = int(clusters[0].get("cluster_id", clusters[0].get("campaign_id", 0)))
    if flows.empty or "StartTime" not in flows.columns or not timeline:
        return 0, 0, anchor_cid
    uniq = timeline
    nmax = max(0, len(uniq) - 1)
    default_idx, peak_idx = 0, min(nmax, max(0, nmax // 2))
    sub_f = flows
    if not camps.empty and "campaign_id" in camps.columns and "SrcAddr" in camps.columns:
        sub_c = camps.loc[camps["campaign_id"] == anchor_cid]
        if not sub_c.empty:
            ips = [str(x) for x in sub_c["SrcAddr"].dropna().astype(str).unique().tolist()]
            v4 = [p for p in ips if isinstance(p, str) and p.count(".") == 3]
            if v4:
                pfx = _ip_24_prefix(v4[0])
                sub_f = flows.loc[flows["SrcAddr"].astype(str).str.startswith(pfx + ".")]
    if sub_f.empty:
        return default_idx, peak_idx, anchor_cid
    st = pd.to_datetime(sub_f["StartTime"], errors="coerce").dropna()
    if st.empty:
        return default_idx, peak_idx, anchor_cid
    t0 = st.min()
    t1 = min(t0 + pd.Timedelta(hours=2), st.max())
    idx_lo = min(range(len(uniq)), key=lambda i: abs((uniq[i] - t0).total_seconds()))
    idx_hi = min(range(len(uniq)), key=lambda i: abs((uniq[i] - t1).total_seconds()))
    default_idx = max(0, min(nmax, idx_lo))
    peak_idx = min(nmax, max(default_idx, (idx_lo + idx_hi) // 2))
    return default_idx, peak_idx, anchor_cid


def _conf_tier(pct: float) -> str:
    if pct < 50:
        return "low"
    if pct < 75:
        return "mid"
    return "high"


def _conf_color(pct: float) -> str:
    t = _conf_tier(pct)
    if t == "low":
        return THEME["danger"]
    if t == "mid":
        return THEME["warning"]
    return THEME["success"]


def _short_ip_last_octets(ip: str) -> str:
    parts = str(ip).split(".")
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}"
    return str(ip)[:12]


def _ip_24_prefix(ip: str) -> str:
    parts = str(ip).split(".")
    if len(parts) >= 3:
        return ".".join(parts[:3])
    return str(ip)


def _attack_type_badge_text(attack: str) -> str:
    s = str(attack).lower()
    if "mirai" in s or "bot" in s:
        return f"⚡ {attack}"
    if "c2" in s or "beacon" in s:
        return f"📡 {attack}"
    if "scan" in s:
        return f"🔍 {attack}"
    return f"◆ {attack}"


def _build_gantt_figure(agg: pd.DataFrame, camp_attack: dict[int, str]) -> go.Figure:
    if agg.empty or "t0" not in agg.columns:
        return _empty_chart("Campaign timeline", "No timestamps in campaign data. Re-run the pipeline so the campaigns export includes time windows.")
    labs: list[str] = []
    for _, r in agg.iterrows():
        cid = int(r["campaign_id"])
        atk = camp_attack.get(cid, str(r.get("attack_type", "")))
        labs.append(f"{r.get('ylab', '')} · {_attack_type_badge_text(atk)}")
    fig = go.Figure()
    n_trace = 0
    for i, r in enumerate(agg.itertuples()):
        t0, t1 = r.t0, r.t1
        if pd.isna(t0) or pd.isna(t1):
            continue
        t0, t1 = pd.Timestamp(t0), pd.Timestamp(t1)
        if t1 <= t0:
            t1 = t0 + pd.Timedelta(hours=1)
        conf = float(getattr(r, "confidence_pct", 0) or 0)
        col = _conf_color(conf)
        atk = camp_attack.get(int(r.campaign_id), "")
        n_ips = int(getattr(r, "n_ips", 0) or 0)
        top_ttp = str(getattr(r, "top_ttp", "") or "")
        drift = str(getattr(r, "drift", "") or "")
        dur = pd.Timestamp(t1) - pd.Timestamp(t0)
        dur_s = int(dur.total_seconds())
        h, m = divmod(max(0, dur_s) // 60, 60)
        m2 = max(0, dur_s) % 60
        drift_txt = "Yes" if drift.lower() in ("true", "1") else "No"
        lab = labs[i]
        ht = (
            f"<b>{getattr(r, 'ylab', '')}</b> · {atk}<br>"
            f"Confidence: {conf:.0f}% · IPs: {n_ips} · Duration: {h}h {m}m {m2}s<br>"
            f"Top TTP: {top_ttp or '—'} · Drift: {drift_txt}<extra></extra>"
        )
        fig.add_trace(
            go.Scatter(
                x=[t0, t1],
                y=[lab, lab],
                mode="lines",
                line=dict(width=22, color=col),
                hovertemplate=ht,
                showlegend=False,
            )
        )
        n_trace += 1
    if n_trace == 0:
        return _empty_chart("Campaign timeline", "Timestamps are missing or invalid for every campaign row.")
    height = max(220, 80 + len(agg) * 56)
    base = dict(_plotly_base("Campaign timeline", height=height))
    base.pop("xaxis", None)
    base.pop("yaxis", None)
    fig.update_layout(
        **base,
        hovermode="closest",
        yaxis=dict(
            type="category",
            categoryorder="array",
            categoryarray=labs[::-1],
            showgrid=True,
            gridcolor=THEME["grid"],
            zeroline=False,
            tickfont=dict(size=11, color=THEME["text"]),
        ),
        xaxis=dict(
            type="date",
            showgrid=True,
            gridcolor=THEME["grid"],
            zeroline=False,
            tickfont=dict(size=11, color=THEME["text_secondary"]),
        ),
    )
    return fig


# The element list is also shipped to the browser in a dcc.Store, so a real
# capture (>100k source IPs) has to be trimmed before it reaches Cytoscape.
MAX_IP_NODES_PER_CAMPAIGN = 3000


def _cap_ip_nodes(graph: dict) -> dict:
    """Keep the most central IPs per campaign; other node types are untouched."""
    nodes = graph.get("nodes") or []
    ips_by_campaign: dict[object, list[dict]] = {}
    kept: list[dict] = []
    for n in nodes:
        if str(n.get("type", "ip")) == "ip":
            ips_by_campaign.setdefault(n.get("campaign_id", -1), []).append(n)
        else:
            kept.append(n)

    dropped = 0
    for ips in ips_by_campaign.values():
        if len(ips) > MAX_IP_NODES_PER_CAMPAIGN:
            ips = sorted(
                ips, key=lambda n: float(n.get("degree_centrality") or 0.0), reverse=True
            )
            dropped += len(ips) - MAX_IP_NODES_PER_CAMPAIGN
            ips = ips[:MAX_IP_NODES_PER_CAMPAIGN]
        kept.extend(ips)

    if not dropped:
        return graph

    kept_ids = {str(n.get("id")) for n in kept}
    links = [
        e
        for e in (graph.get("links") or [])
        if str(e.get("source")) in kept_ids and str(e.get("target")) in kept_ids
    ]
    print(
        f"[i] Graph trimmed for display: {len(kept):,} nodes kept, {dropped:,} low-centrality "
        f"IP nodes dropped (cap {MAX_IP_NODES_PER_CAMPAIGN:,}/campaign)"
    )
    return {**graph, "nodes": kept, "links": links}


def _elements_from_graph(graph: dict) -> list[dict]:
    """Build cytoscape elements with full node data (campaign_id, relations, etc.)."""
    graph = _cap_ip_nodes(graph)
    elements: list[dict] = []
    for n in graph.get("nodes", []) or []:
        nid = str(n.get("id"))
        ntype = str(n.get("type", "ip"))
        data = {k: v for k, v in n.items() if k not in ("type",)}
        data["id"] = nid
        if ntype == "ip":
            data["label"] = _short_ip_last_octets(nid)
            data["full_ip"] = nid
        elif ntype == "campaign":
            data["label"] = f"C{n.get('campaign_id', '')}"
        elif ntype == "malware_family":
            data["label"] = str(nid)[:18]
        elif ntype == "domain":
            data["label"] = str(nid)[:16]
        elif ntype == "asn":
            org = str(n.get("asn_org", "") or "")[:14]
            data["label"] = f"{nid}\n{org}" if org else nid
        else:
            data["label"] = str(nid)[:16]
        elements.append({"data": data, "classes": ntype})
    for e in graph.get("links", []) or []:
        rel = str(e.get("relation", ""))
        elements.append(
            {
                "data": {
                    "source": str(e.get("source")),
                    "target": str(e.get("target")),
                    "label": rel,
                    "relation": rel,
                }
            }
        )
    return elements


def _parse_elements(full_el: list) -> tuple[dict[str, dict], list[dict]]:
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    for el in full_el or []:
        d = el.get("data") or {}
        if "source" in d:
            edges.append(el)
        else:
            nid = str(d.get("id", ""))
            if nid:
                nodes[nid] = el
    return nodes, edges


def _inspector_elements(full_el: list, campaign_id: int, expanded_24: set[str]) -> list:
    """Campaign-scoped graph; collapse IPs into /24 subnet nodes when >20 IPs in cluster."""
    nodes, edges = _parse_elements(full_el)
    hub = f"campaign_{int(campaign_id)}"
    cid = int(campaign_id)

    ip_ids = [
        nid
        for nid, el in nodes.items()
        if el.get("classes") == "ip" and int((el.get("data") or {}).get("campaign_id", -99999)) == cid
    ]
    if not ip_ids:
        return [nodes[hub]] if hub in nodes else []
    if hub not in nodes:
        return []
    by_pfx: dict[str, list[str]] = {}
    for ip in ip_ids:
        by_pfx.setdefault(_ip_24_prefix(ip), []).append(ip)

    use_subnet = len(ip_ids) > 20

    def _subnet_id(pfx: str) -> str:
        return f"__subnet__{pfx.replace('.', '_')}"

    remap: dict[str, str] = {}
    synthetic: list[dict] = []
    if use_subnet:
        for pfx, ips in by_pfx.items():
            if pfx in expanded_24:
                for ip in ips:
                    remap[ip] = ip
            else:
                sid = _subnet_id(pfx)
                synthetic.append(
                    {
                        "data": {
                            "id": sid,
                            "label": f"{pfx}.x ({len(ips)} IPs)",
                            "subnet_prefix": pfx,
                            "ip_count": len(ips),
                        },
                        "classes": "subnet",
                    }
                )
                for ip in ips:
                    remap[ip] = sid
    else:
        for ip in ip_ids:
            remap[ip] = ip

    def _map_endpoint(nid: str) -> str | None:
        if nid not in nodes:
            return nid if nid.startswith("__subnet__") else None
        el = nodes[nid]
        cls = el.get("classes") or ""
        if cls == "ip":
            if int((el.get("data") or {}).get("campaign_id", -999)) != cid:
                return None
            return remap.get(nid, nid)
        if cls == "campaign":
            return nid if nid == hub else None
        return nid

    out_e_raw: list[tuple[str, str, str, dict]] = []
    for el in edges:
        d = el.get("data") or {}
        s, t = str(d.get("source")), str(d.get("target"))
        rel = str(d.get("relation", ""))
        if rel == "shares_campaign":
            if t != hub and s != hub:
                continue
            if t.startswith("campaign_") and t != hub:
                continue
            if s.startswith("campaign_") and s != hub:
                continue
        s2, t2 = _map_endpoint(s), _map_endpoint(t)
        if s2 is None or t2 is None or s2 == t2:
            continue
        out_e_raw.append((s2, t2, rel, d))

    node_ids: set[str] = set()
    for s2, t2, _, _ in out_e_raw:
        node_ids.add(s2)
        node_ids.add(t2)
    if hub in nodes:
        node_ids.add(hub)

    out_nodes: dict[str, dict] = {}
    for sid in node_ids:
        if sid.startswith("__subnet__"):
            for syn in synthetic:
                if str((syn.get("data") or {}).get("id")) == sid:
                    out_nodes[sid] = syn
                    break
        elif sid in nodes:
            out_nodes[sid] = nodes[sid]

    seen: set[tuple[str, str, str]] = set()
    out_edges: list[dict] = []
    for s2, t2, rel, d in out_e_raw:
        if s2 not in out_nodes or t2 not in out_nodes:
            continue
        key = (s2, t2, rel)
        if key in seen:
            continue
        seen.add(key)
        out_edges.append({"data": {**d, "source": s2, "target": t2, "relation": rel, "label": rel}})

    return list(out_nodes.values()) + out_edges


def _replay_ip_only_elements(full_el: list, visible_ip_ids: set[str]) -> list:
    nodes, edges = _parse_elements(full_el)
    out: list[dict] = []
    for ip in visible_ip_ids:
        if ip in nodes and nodes[ip].get("classes") == "ip":
            out.append(nodes[ip])
    for el in edges:
        d = el.get("data") or {}
        s, t = str(d.get("source")), str(d.get("target"))
        if s in visible_ip_ids and t in visible_ip_ids:
            out.append(el)
    return out


DEMO_ARTIFACTS_DIR = "output_demo"


def load_cfg() -> dict:
    p = ROOT / "config.yaml"
    if not p.is_file():
        return {}
    with open(p, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def retarget_artifacts(cfg: dict, artifacts: str) -> dict:
    """Serve a different artifact directory than the pipeline's default ``output/``.

    Lets a demo-data dashboard stay up while the real pipeline rewrites ``output/``.
    """
    artifacts = artifacts.rstrip("/\\")
    paths = dict(cfg.get("paths") or {})
    for key, val in paths.items():
        normalised = str(val).replace("\\", "/")
        if normalised.startswith("output/"):
            paths[key] = f"{artifacts}/{normalised.split('/', 1)[1]}"
    out = {**cfg, "paths": paths}
    # The badge and PDF header must describe the data actually on screen.
    out["DEMO_MODE"] = artifacts == DEMO_ARTIFACTS_DIR
    return out


def load_table(path: Path) -> pd.DataFrame:
    if not path.is_file():
        return pd.DataFrame()
    if path.suffix.lower() == ".parquet":
        return pd.read_parquet(path)
    return pd.read_csv(path, low_memory=False)


def load_json(path: Path) -> dict:
    if not path.is_file():
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _kpi_card(title: str, val, accent: str, footer: Any = None, val_id: str | None = None) -> html.Div:
    val_style = {
        "fontSize": "36px",
        "fontWeight": 700,
        "color": THEME["text"],
        "fontFamily": FONT_UI,
        "lineHeight": 1.1,
        "margin": "8px 0",
    }
    val_el = html.Div(str(val), id=val_id, style=val_style) if val_id else html.Div(str(val), style=val_style)
    return html.Div(
        style={**_card(), "borderLeft": f"4px solid {accent}", "padding": "16px 20px"},
        children=[
            html.Div(
                title.upper(),
                style={
                    "color": THEME["text_secondary"],
                    "fontSize": "11px",
                    "letterSpacing": "0.08em",
                    "fontWeight": 600,
                    "fontFamily": FONT_UI,
                },
            ),
            val_el,
            footer if footer is not None else html.Div(),
        ],
    )


def _btn(primary: bool = False) -> dict:
    if primary:
        return {
            "background": THEME["primary"],
            "color": "#FFFFFF",
            "border": "none",
            "padding": "8px 14px",
            "cursor": "pointer",
            "borderRadius": "6px",
            "fontFamily": FONT_UI,
            "fontWeight": 600,
            "fontSize": "13px",
            "transition": "0.15s ease",
        }
    return {
        "background": THEME["card_bg"],
        "color": THEME["text"],
        "border": f"1px solid {THEME['card_border']}",
        "padding": "8px 14px",
        "cursor": "pointer",
        "borderRadius": "6px",
        "fontFamily": FONT_UI,
        "fontSize": "13px",
        "transition": "0.15s ease",
    }


def _input_style(w: str | None = None) -> dict:
    s = {
        "width": w or "160px",
        "background": THEME["card_bg"],
        "color": THEME["text"],
        "border": f"1px solid {THEME['card_border']}",
        "padding": "8px 10px",
        "borderRadius": "6px",
        "fontFamily": FONT_UI,
        "fontSize": "13px",
        "transition": "0.15s ease",
    }
    return s


def _skeleton(h: str = "120px") -> html.Div:
    return html.Div(
        className="attrib-skeleton",
        style={
            "height": h,
            "borderRadius": THEME["radius"],
            "background": "#E2E8F0",
            "animation": "attrib-pulse 1.2s ease-in-out infinite",
        },
    )


def _empty_state(msg: str, icon: str = "📭") -> html.Div:
    return html.Div(
        style={"textAlign": "center", "padding": "48px 24px", "color": THEME["text_secondary"], "fontFamily": FONT_UI},
        children=[html.Div(icon, style={"fontSize": "32px", "marginBottom": "12px"}), html.Div(msg, style={"fontSize": "15px"})],
    )


def _canvas_wrapped_lines(c, text: str, x: float, y: float, max_width: int, line_height: float, font: str = "Helvetica", size: int = 9) -> float:
    """Draw wrapped text on a reportlab canvas; returns final y."""
    from reportlab.pdfbase.pdfmetrics import stringWidth

    c.setFont(font, size)
    words = text.replace("\n", " \n ").split()
    line = ""
    for w in words:
        if w == "\n":
            c.drawString(x, y, line)
            y -= line_height
            line = ""
            continue
        trial = (line + " " + w).strip()
        if stringWidth(trial, font, size) <= max_width:
            line = trial
        else:
            if line:
                c.drawString(x, y, line)
                y -= line_height
            line = w
    if line:
        c.drawString(x, y, line)
        y -= line_height
    return y


def _factor_heatmap_png(campaigns: list[dict]) -> bytes | None:
    """Render the B/I/T/M factor matrix to PNG so the PDF can embed it."""
    if not campaigns:
        return None
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    keys = ["B", "I", "T", "M"]
    mat = [[float((c.get("contributing_factors") or {}).get(k, 0.0)) for k in keys] for c in campaigns]
    ylabs = [f"Campaign {c.get('campaign_id')}" for c in campaigns]

    fig, ax = plt.subplots(figsize=(6.4, max(1.8, 0.42 * len(ylabs) + 1.2)))
    im = ax.imshow(mat, cmap="Blues", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(keys)), ["Behavioral\n(B)", "Infrastructure\n(I)", "Timing\n(T)", "Threat Intel\n(M)"], fontsize=8)
    ax.set_yticks(range(len(ylabs)), ylabs, fontsize=8)
    for i, row in enumerate(mat):
        for j, v in enumerate(row):
            ax.text(j, i, f"{v * 100:.0f}%", ha="center", va="center", fontsize=8,
                    color="white" if v > 0.6 else "#0F172A")
    ax.set_title("Confidence factors by campaign", fontsize=10)
    fig.colorbar(im, ax=ax, shrink=0.85)
    fig.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150)
    plt.close(fig)
    return buf.getvalue()


def _build_incident_pdf(payload: dict) -> bytes:
    """Multi-page incident report: summary, factor heatmap, per-campaign detail, formulas."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfgen import canvas as pdf_canvas

    buf = io.BytesIO()
    c = pdf_canvas.Canvas(buf, pagesize=A4)
    width, height = A4
    margin = 48
    text_width = int(width - 2 * margin)
    state = {"page": 0, "y": 0.0}

    def new_page(heading: str = "") -> None:
        if state["page"]:
            c.showPage()
        state["page"] += 1
        c.setFont("Helvetica-Bold", 9)
        c.setFillColorRGB(0.145, 0.388, 0.922)
        c.drawString(margin, height - 34, "AttribIQ - Post-Incident Attack Attribution")
        c.setFont("Helvetica", 8)
        c.setFillColorRGB(0.45, 0.45, 0.45)
        c.drawRightString(width - margin, height - 34, f"Page {state['page']}")
        c.setStrokeColorRGB(0.88, 0.89, 0.90)
        c.line(margin, height - 40, width - margin, height - 40)
        c.setFillColorRGB(0, 0, 0)
        state["y"] = height - 66
        if heading:
            c.setFont("Helvetica-Bold", 14)
            c.drawString(margin, state["y"], heading)
            state["y"] -= 24

    def ensure(space: float, heading: str = "") -> None:
        if state["y"] - space < margin:
            new_page(heading)

    def write(text: str, size: int = 9, bold: bool = False, dy: float = 13.0,
              color: tuple[float, float, float] = (0, 0, 0)) -> None:
        c.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        c.setFillColorRGB(*color)
        c.drawString(margin, state["y"], text)
        c.setFillColorRGB(0, 0, 0)
        state["y"] -= dy

    rep = payload.get("report") or {}
    ds = payload.get("dataset") or {}
    campaigns = payload.get("campaigns") or []

    # ── Page 1: header block + campaign summary ──────────────────────────
    new_page("Incident Report")
    write(f"Generated: {rep.get('generated_at', '')}", 9, color=(0.4, 0.4, 0.4))
    if rep.get("demo_mode"):
        write("DATA SOURCE: DEMO MODE - synthetic flows and mocked threat intel", 9, bold=True,
              color=(0.85, 0.47, 0.02))
    else:
        write("DATA SOURCE: live capture with live threat-intel lookups", 9, color=(0.09, 0.64, 0.29))
    filt = rep.get("filters") or {}
    write(
        f"Filters: campaigns={filt.get('campaigns') or 'all'}, min confidence={filt.get('min_confidence_pct', 0)}%",
        9, color=(0.4, 0.4, 0.4),
    )
    state["y"] -= 6

    write("Dataset", 11, bold=True, dy=16)
    for label, key in (
        ("Total flows analysed", "total_flows"),
        ("Unique source IPs", "unique_source_ips"),
        ("Behavioral fingerprints", "fingerprints"),
        ("Campaigns detected", "campaigns_total"),
        ("Campaigns in this report", "campaigns_selected"),
        ("Enriched IPs", "enriched_ips"),
    ):
        val = ds.get(key)
        if val is not None:
            write(f"  {label}: {val:,}" if isinstance(val, int) else f"  {label}: {val}")
    state["y"] -= 8

    write("Campaign summary", 11, bold=True, dy=16)
    c.setFont("Helvetica-Bold", 8)
    cols = [(0, "CAMPAIGN"), (80, "CONFIDENCE"), (160, "BAND"), (215, "IPS"), (270, "ATTACK TYPE"), (400, "TTPs"), (480, "DRIFT")]
    for dx, name in cols:
        c.drawString(margin + dx, state["y"], name)
    state["y"] -= 12
    c.setStrokeColorRGB(0.88, 0.89, 0.90)
    c.line(margin, state["y"] + 4, width - margin, state["y"] + 4)

    for camp in campaigns:
        ensure(26, "Campaign summary (continued)")
        c.setFont("Helvetica", 8)
        conf = float(camp.get("confidence_pct", 0))
        band = str(camp.get("confidence_band", ""))
        rgb = (0.86, 0.15, 0.15) if conf < 50 else ((0.85, 0.47, 0.02) if conf < 75 else (0.09, 0.64, 0.29))
        c.drawString(margin, state["y"], f"Campaign {camp.get('campaign_id')}")
        c.setFillColorRGB(*rgb)
        c.drawString(margin + 80, state["y"], f"{conf:.2f}%")
        c.drawString(margin + 160, state["y"], band)
        c.setFillColorRGB(0, 0, 0)
        c.drawString(margin + 215, state["y"], f"{int(camp.get('ip_count', 0)):,}")
        c.drawString(margin + 270, state["y"], str(camp.get("attack_type", ""))[:22])
        c.drawString(margin + 400, state["y"], ", ".join(camp.get("top_ttps") or [])[:14])
        c.drawString(margin + 480, state["y"], "YES" if camp.get("drift_detected") else "no")
        state["y"] -= 14

    # ── Factor heatmap ───────────────────────────────────────────────────
    png = _factor_heatmap_png(campaigns)
    if png:
        img = ImageReader(io.BytesIO(png))
        iw, ih = img.getSize()
        draw_w = width - 2 * margin
        draw_h = draw_w * ih / iw
        ensure(draw_h + 30, "Confidence factor breakdown")
        state["y"] -= 10
        c.drawImage(img, margin, state["y"] - draw_h, width=draw_w, height=draw_h, mask="auto")
        state["y"] -= draw_h + 16

    # ── Per-campaign detail ──────────────────────────────────────────────
    for camp in campaigns:
        new_page(f"Campaign {camp.get('campaign_id')} - detail")
        conf = float(camp.get("confidence_pct", 0))
        rgb = (0.86, 0.15, 0.15) if conf < 50 else ((0.85, 0.47, 0.02) if conf < 75 else (0.09, 0.64, 0.29))
        write(f"Confidence C(k) = {conf:.2f}%  ({camp.get('confidence_band', '')})", 11, bold=True, dy=18, color=rgb)
        write(f"Attack type: {camp.get('attack_type', 'Unknown')}", 9)
        write(f"Source IPs in campaign: {int(camp.get('ip_count', 0)):,}", 9)
        write(f"MITRE techniques: {', '.join(camp.get('top_ttps') or []) or 'none mapped'}", 9)
        write(f"Temporal drift detected: {'yes' if camp.get('drift_detected') else 'no'}", 9)
        write(f"Cross-dataset: {'yes' if camp.get('cross_dataset') else 'no'}", 9)
        if camp.get("iot_family"):
            write(f"IoT family: {camp.get('iot_family')}", 9)
        state["y"] -= 6

        write("Confidence components", 10, bold=True, dy=15)
        factors = camp.get("contributing_factors") or {}
        weights = ((payload.get("formula_registry") or {}).get("confidence_score") or {}).get("weights") or {}
        names = {
            "B": ("Behavioral cohesion", "w1"),
            "I": ("Infrastructure overlap", "w2"),
            "T": ("Timing correlation", "w3"),
            "M": ("Threat-intel match", "w4"),
        }
        for key, (desc, wkey) in names.items():
            val = float(factors.get(key, 0.0))
            wt = float(weights.get(wkey, 0.0))
            write(f"  {key}(k) {desc:<26} {val:.4f}  x weight {wt:.2f}  = {val * wt:.4f}")
        state["y"] -= 6

        ips = camp.get("enriched_ips") or []
        if ips:
            write(f"Enriched indicators ({len(ips)})", 10, bold=True, dy=15)
            c.setFont("Helvetica-Bold", 8)
            for dx, name in ((0, "IP"), (110, "THREAT"), (170, "VT"), (205, "ABUSE"), (255, "ASN"), (320, "ORG / COUNTRY")):
                c.drawString(margin + dx, state["y"], name)
            state["y"] -= 12
            for row in ips:
                ensure(24, f"Campaign {camp.get('campaign_id')} - indicators (continued)")
                c.setFont("Helvetica", 8)
                c.drawString(margin, state["y"], str(row.get("ip", ""))[:20])
                c.drawString(margin + 110, state["y"], str(row.get("threat_level", ""))[:8])
                c.drawString(margin + 170, state["y"], str(row.get("vt_malicious", "")))
                c.drawString(margin + 205, state["y"], str(row.get("abuse_score", "")))
                c.drawString(margin + 255, state["y"], str(row.get("asn", ""))[:10])
                org = f"{str(row.get('asn_org', ''))[:28]} / {str(row.get('country', ''))}"
                c.drawString(margin + 320, state["y"], org)
                state["y"] -= 12
        else:
            write("No enriched indicators for this campaign.", 9, color=(0.45, 0.45, 0.45))

    # ── Formula appendix ─────────────────────────────────────────────────
    new_page("Appendix - formula registry")
    registry = payload.get("formula_registry") or {}
    for name, body in registry.items():
        ensure(70, "Appendix - formula registry (continued)")
        write(str(name).replace("_", " ").title(), 11, bold=True, dy=16)
        if isinstance(body, dict):
            if body.get("formula"):
                write(f"  {body['formula']}", 10, bold=True, dy=15)
            if body.get("description"):
                state["y"] = _canvas_wrapped_lines(c, f"  {body['description']}", margin, state["y"], text_width, 12)
            for wk, wv in (body.get("weights") or {}).items():
                write(f"    {wk} = {wv}")
            for ck, cv in (body.get("components") or {}).items():
                ensure(28)
                state["y"] = _canvas_wrapped_lines(c, f"    {ck}: {cv}", margin, state["y"], text_width, 12)
        state["y"] -= 8

    c.save()
    return buf.getvalue()


def build_app(cfg: dict) -> Dash:
    demo = bool(cfg.get("DEMO_MODE", False))
    paths = cfg.get("paths") or {}

    camps = load_table(ROOT / (paths.get("campaigns") or "output/03_campaigns.csv"))
    att = load_json(ROOT / (paths.get("attribution_scores") or "output/attribution_scores.json"))
    drift = load_json(ROOT / (paths.get("drift_report") or "output/drift_report.json"))
    graph = load_json(ROOT / (paths.get("attack_graph") or "output/attack_graph.json"))
    enr = load_table(ROOT / (paths.get("enriched") or "output/04_enriched.csv"))
    feats = load_table(ROOT / (paths.get("features") or "output/features_iot_extended.parquet"))
    flows = load_table(ROOT / (paths.get("unified_flows") or "output/unified_flows.parquet"))

    clusters = att.get("clusters", []) or []
    dash_cfg = cfg.get("dashboard", {}) or {}
    host = str(dash_cfg.get("host", "127.0.0.1"))
    port = int(dash_cfg.get("port", 8050))

    banner = None  # DEMO badge lives in fixed navbar

    kpi_campaigns = int(camps["campaign_id"].nunique()) if not camps.empty and "campaign_id" in camps else 0
    if not camps.empty and "label" in camps.columns:
        kpi_mal_ips = int((pd.to_numeric(camps["label"], errors="coerce").fillna(-1) > 0).sum())
    else:
        kpi_mal_ips = 0
    conf_vals = [float(c.get("confidence_pct", 0)) for c in clusters if "confidence_pct" in c]
    kpi_avg_conf = float(np.mean(conf_vals)) if conf_vals else 0.0
    drift_flags = [bool(c.get("drift_detected")) for c in clusters]
    kpi_drift = int(sum(drift_flags))

    camp_rows = []
    for c in clusters:
        cid = int(c.get("cluster_id", c.get("campaign_id", -1)))
        sub = camps[camps["campaign_id"] == cid] if not camps.empty else pd.DataFrame()
        n_ips = int(sub["SrcAddr"].nunique()) if not sub.empty and "SrcAddr" in sub.columns else 0
        camp_rows.append(
            {
                "campaign_id": cid,
                "label": str(c.get("label", "")),
                "attack_type": str(c.get("attack_type", "")),
                "n_ips": n_ips,
                "confidence_pct": round(float(c.get("confidence_pct", 0)), 2),
                "top_ttp": ", ".join(c.get("top_ttps", []) or []),
                "drift": str(c.get("drift_detected", False)),
                "cross_dataset": str(c.get("cross_dataset", False)),
            }
        )
    camp_df = pd.DataFrame(camp_rows)

    misp_path = ROOT / (paths.get("misp_matches") or "output/misp_matches.json")
    misp_data = load_json(misp_path)

    # --- Replay timeline (indices into sorted unique flow times) ------------
    flow_times: list[pd.Timestamp] = []
    replay_default_idx = 0
    mirai_peak_idx = 0
    campaign_a_id = int(clusters[0].get("cluster_id", 0)) if clusters else 0
    flow_times = _replay_timeline(flows)
    if flow_times:
        replay_default_idx, mirai_peak_idx, campaign_a_id = _replay_seed_indices(
            flows, camps, clusters, flow_times
        )

    ip_first_seen: dict[str, pd.Timestamp] = {}
    if not flows.empty and "SrcAddr" in flows.columns and "StartTime" in flows.columns:
        ff = flows.copy()
        ff["StartTime"] = pd.to_datetime(ff["StartTime"], errors="coerce")
        ip_first_seen = ff.groupby(ff["SrcAddr"].astype(str))["StartTime"].min().to_dict()

    flow_times_iso = [t.isoformat() for t in flow_times]

    camp_attack: dict[int, str] = {}
    if not camp_df.empty:
        for _, r in camp_df.iterrows():
            camp_attack[int(r["campaign_id"])] = str(r.get("attack_type", ""))

    agg_gantt = pd.DataFrame()
    ts_col = None
    if not camps.empty and "campaign_id" in camps.columns:
        if "StartTime" in camps.columns:
            ts_col = "StartTime"
        elif "time_window" in camps.columns:
            ts_col = "time_window"
    if ts_col:
        cg = camps.copy()
        cg["StartTime"] = pd.to_datetime(cg[ts_col], errors="coerce")
        agg_gantt = cg.groupby("campaign_id").agg(t0=("StartTime", "min"), t1=("StartTime", "max")).reset_index()
        if not camp_df.empty:
            merge_cols = ["campaign_id", "confidence_pct", "n_ips", "top_ttp", "drift", "attack_type"]
            mcols = [c for c in merge_cols if c in camp_df.columns]
            agg_gantt = agg_gantt.merge(camp_df[mcols], on="campaign_id", how="left")
        else:
            agg_gantt["confidence_pct"] = 0.0
        agg_gantt["ylab"] = agg_gantt["campaign_id"].map(lambda x: f"Campaign {int(x)}")

    fig_gantt = _build_gantt_figure(agg_gantt, camp_attack)

    flows_w = flows.copy()
    if not flows_w.empty and "SrcAddr" in flows_w.columns and not camps.empty and "SrcAddr" in camps.columns:
        cx = (
            camps.sort_values("time_window").drop_duplicates("SrcAddr", keep="last")
            if "time_window" in camps.columns
            else camps.drop_duplicates("SrcAddr", keep="last")
        )
        mp_c = dict(zip(cx["SrcAddr"].astype(str), cx["campaign_id"]))
        flows_w["_campaign"] = flows_w["SrcAddr"].astype(str).map(mp_c)
        if "attack_type" in cx.columns:
            at = dict(zip(cx["SrcAddr"].astype(str), cx["attack_type"]))
            flows_w["_attack_type"] = flows_w["SrcAddr"].astype(str).map(at)
        else:
            flows_w["_attack_type"] = ""

    misp_by_ip: dict[str, list[str]] = {}
    for m in misp_data.get("matches") or []:
        if not isinstance(m, dict):
            continue
        ip = str(m.get("ip", ""))
        if not ip:
            continue
        misp_by_ip.setdefault(ip, []).append(f"{m.get('event', '')} | TLP={m.get('tlp', '')}")

    elements = _elements_from_graph(graph)
    letters = "ABCDEFGHIJ"
    dd_options = []
    for i, c in enumerate(clusters):
        cid = int(c.get("cluster_id", c.get("campaign_id", -1)))
        lab = letters[i] if i < len(letters) else str(i)
        dd_options.append({"label": f"Campaign {lab} (id={cid})", "value": cid})
    default_cid = int(clusters[0].get("cluster_id", clusters[0].get("campaign_id", 0))) if clusters else 0

    hm_dd_opts = (
        [{"label": f"Campaign {letters[i]} (id={int(cid)})", "value": int(cid)} for i, cid in enumerate(camp_df["campaign_id"].tolist())]
        if not camp_df.empty
        else []
    )

    cy_layout = {
        "name": "cose",
        "idealEdgeLength": 120,
        "nodeOverlap": 8,
        "refresh": 20,
        "randomize": False,
        "animate": True,
        "animationDuration": 800,
        "nodeRepulsion": 12000,
        "componentSpacing": 80,
        "padding": 48,
        "fit": True,
    }
    cy_stylesheet = [
        # Base node — clean, no heavy outlines
        {
            "selector": "node",
            "style": {
                "text-valign": "center",
                "text-halign": "center",
                "text-outline-width": 0,
                "font-family": FONT_UI,
                "transition-property": "background-color border-color",
                "transition-duration": "0.15s",
            },
        },
        {
            "selector": ".ip",
            "style": {
                "shape": "ellipse",
                "width": 44,
                "height": 44,
                "background-color": "#DBEAFE",
                "border-width": 2,
                "border-color": "#2563EB",
                "label": "data(label)",
                "font-size": "10px",
                "color": "#1E40AF",
                "font-family": FONT_MONO,
            },
        },
        # Subnet: dashed blue border, blue-tinted fill
        {
            "selector": ".subnet",
            "style": {
                "shape": "round-rectangle",
                "width": 130,
                "height": 40,
                "background-color": "#EFF6FF",
                "border-width": 2,
                "border-color": "#2563EB",
                "border-style": "dashed",
                "label": "data(label)",
                "font-size": "10px",
                "color": "#1D4ED8",
                "font-family": FONT_MONO,
                "text-wrap": "wrap",
                "text-max-width": "118px",
            },
        },
        {
            "selector": ".domain",
            "style": {
                "shape": "round-rectangle",
                "width": 80,
                "height": 36,
                "background-color": "#FEF3C7",
                "border-width": 2,
                "border-color": "#D97706",
                "label": "data(label)",
                "font-size": "10px",
                "color": "#92400E",
                "font-family": FONT_UI,
            },
        },
        {
            "selector": ".asn",
            "style": {
                "shape": "round-rectangle",
                "width": 90,
                "height": 36,
                "background-color": "#F1F5F9",
                "border-width": 1,
                "border-color": "#94A3B8",
                "label": "data(label)",
                "font-size": "10px",
                "color": "#475569",
                "font-family": FONT_UI,
                "text-wrap": "wrap",
                "text-max-width": "80px",
            },
        },
        {
            "selector": ".malware_family",
            "style": {
                "shape": "diamond",
                "width": 50,
                "height": 50,
                "background-color": "#FEE2E2",
                "border-width": 2,
                "border-color": "#DC2626",
                "label": "data(label)",
                "font-size": "11px",
                "font-weight": "bold",
                "color": "#991B1B",
                "font-family": FONT_UI,
            },
        },
        {
            "selector": ".campaign",
            "style": {
                "shape": "round-rectangle",
                "width": 72,
                "height": 32,
                "background-color": "#EFF6FF",
                "border-width": 2,
                "border-color": "#2563EB",
                "label": "data(label)",
                "font-size": "11px",
                "color": "#1D4ED8",
                "font-weight": "600",
                "font-family": FONT_UI,
            },
        },
        # Selected node highlight
        {
            "selector": "node:selected",
            "style": {
                "border-width": 3,
                "border-color": "#1D4ED8",
                "background-color": "#BFDBFE",
                "overlay-opacity": 0.08,
            },
        },
        # Edges — bezier, minimal arrows
        {
            "selector": "edge",
            "style": {
                "curve-style": "bezier",
                "target-arrow-shape": "triangle",
                "arrow-scale": 0.9,
                "opacity": 0.7,
                "target-arrow-color": "#94A3B8",
                "line-color": "#CBD5E1",
                "width": 1,
            },
        },
        {
            "selector": "edge[relation = 'resolves_to']",
            "style": {"line-style": "dashed", "line-color": "#94A3B8", "target-arrow-color": "#94A3B8", "width": 1.5},
        },
        {
            "selector": "edge[relation = 'belongs_to_asn']",
            "style": {"line-style": "solid", "line-color": "#CBD5E1", "target-arrow-color": "#CBD5E1", "width": 1},
        },
        {
            "selector": "edge[relation = 'shares_campaign']",
            "style": {"line-style": "solid", "line-color": "#2563EB", "target-arrow-color": "#2563EB", "width": 2, "opacity": 0.55},
        },
        {
            "selector": "edge[relation = 'associated_malware']",
            "style": {"line-style": "solid", "line-color": "#DC2626", "target-arrow-color": "#DC2626", "width": 2, "opacity": 0.8},
        },
    ]

    global_css = f"""
/* ── animations ──────────────────────────────────────────── */
@keyframes attrib-pulse {{
  0%, 100% {{ opacity: 1; }}
  50%       {{ opacity: 0.45; }}
}}
@keyframes attrib-skeleton {{
  0%   {{ background-position: -400px 0; }}
  100% {{ background-position: 400px 0; }}
}}
@keyframes attrib-fade-in {{
  from {{ opacity: 0; transform: translateY(6px); }}
  to   {{ opacity: 1; transform: none; }}
}}

/* ── page shell ──────────────────────────────────────────── */
*, *::before, *::after {{ box-sizing: border-box; }}
html, body, #react-entry-point, ._dash-app-content {{
  background: {THEME["page_bg"]} !important;
  color: {THEME["text"]} !important;
  font-family: {FONT_UI};
  min-height: 100vh;
}}

/* ── tabs ────────────────────────────────────────────────── */
#tabs .tab {{
  padding: 14px 20px !important;
  font-family: {FONT_UI} !important;
  font-size: 13px !important;
  font-weight: 500 !important;
  border: none !important;
  border-bottom: 2px solid transparent !important;
  background: transparent !important;
  color: {THEME["text_secondary"]} !important;
  transition: color 0.15s ease, border-color 0.15s ease !important;
}}
#tabs .tab:hover {{
  color: {THEME["text"]} !important;
}}
#tabs .tab--selected {{
  color: {THEME["primary"]} !important;
  font-weight: 600 !important;
  border-bottom: 2px solid {THEME["primary"]} !important;
}}

/* ── replay slider ───────────────────────────────────────── */
#replay-slider .rc-slider-track  {{ background-color: {THEME["primary"]} !important; }}
#replay-slider .rc-slider-handle {{
  border: 2px solid {THEME["primary"]} !important;
  background: #fff !important;
  box-shadow: 0 0 0 3px rgba(37,99,235,0.15) !important;
}}

/* ── Dash/React-Select dropdowns ────────────────────────── */
.Select-control, .Select-value-label, .Select-placeholder {{
  background: {THEME["card_bg"]} !important;
  border-color: {THEME["card_border"]} !important;
  color: {THEME["text"]} !important;
  font-family: {FONT_UI} !important;
}}
.Select-menu-outer {{ background: {THEME["card_bg"]} !important; border: 1px solid {THEME["card_border"]} !important; box-shadow: 0 4px 12px rgba(0,0,0,0.08) !important; border-radius: 6px !important; }}
.Select-option {{ color: {THEME["text"]} !important; font-family: {FONT_UI} !important; }}
.Select-option.is-focused {{ background: {THEME["row_hover"]} !important; }}
.Select-option.is-selected {{ background: #EFF6FF !important; color: {THEME["primary"]} !important; font-weight: 600 !important; }}

/* ── DataTable tooltips ──────────────────────────────────── */
.dash-table-tooltip {{
  background: #fff !important;
  box-shadow: 0 4px 12px rgba(0,0,0,0.10) !important;
  border-radius: 8px !important;
  font-size: 12px !important;
  color: {THEME["text"]} !important;
  font-family: {FONT_UI} !important;
}}

/* ── skeleton loaders ────────────────────────────────────── */
.attrib-skeleton {{
  border-radius: {THEME["radius"]};
  background: linear-gradient(90deg, #E2E8F0 25%, #F1F5F9 50%, #E2E8F0 75%);
  background-size: 800px 100%;
  animation: attrib-skeleton 1.4s infinite linear;
}}

/* ── live feed rows ──────────────────────────────────────── */
.attrib-feed-row {{ animation: attrib-fade-in 0.3s ease; }}

/* ── tab-body min-height ─────────────────────────────────── */
#tab-body, #tab-body-loading {{ min-height: 280px; }}

/* ── card hover lift ─────────────────────────────────────── */
.attrib-card-hover:hover {{
  box-shadow: 0 4px 12px rgba(0,0,0,0.10) !important;
  transform: translateY(-1px);
}}

/* ── button focus ring ───────────────────────────────────── */
button:focus-visible {{
  outline: 2px solid {THEME["primary"]};
  outline-offset: 2px;
}}
"""

    app = Dash(__name__, suppress_callback_exceptions=True)
    app.title = "AttribIQ — Attack Attribution"
    _idx = app.index_string or ""
    if "</head>" in _idx:
        app.index_string = _idx.replace("</head>", f"<style>{global_css}</style></head>", 1)

    demo_pill = (
        html.Span(
            "DEMO MODE",
            style={
                "background": "#FEF3C7",
                "color": "#92400E",
                "padding": "5px 14px",
                "borderRadius": "999px",
                "fontSize": "11px",
                "fontWeight": 700,
                "letterSpacing": "0.06em",
                "fontFamily": FONT_UI,
            },
        )
        if demo
        else None
    )

    navbar = html.Div(
        style={
            "position": "fixed",
            "top": 0,
            "left": 0,
            "right": 0,
            "height": "56px",
            "background": THEME["card_bg"],
            "borderBottom": f"1px solid {THEME['card_border']}",
            "zIndex": 1000,
            "display": "flex",
            "alignItems": "center",
            "justifyContent": "space-between",
            "padding": "0 32px",
            "boxSizing": "border-box",
        },
        children=[
            html.Div(
                style={"display": "flex", "alignItems": "center", "gap": "10px"},
                children=[
                    html.Span("AttribIQ", style={"fontWeight": 800, "fontSize": "18px", "color": THEME["primary"], "fontFamily": FONT_UI, "letterSpacing": "-0.01em"}),
                    html.Span("·", style={"color": THEME["card_border"], "fontSize": "18px", "lineHeight": 1}),
                    html.Span(
                        "Attack Attribution",
                        style={"color": THEME["text_secondary"], "fontSize": "13px", "fontFamily": FONT_UI, "fontWeight": 500},
                    ),
                ],
            ),
            html.Div(children=[demo_pill] if demo_pill else [], style={"display": "flex", "alignItems": "center"}),
        ],
    )

    tab_bar = html.Div(
        style={
            "background": THEME["card_bg"],
            "borderBottom": f"2px solid {THEME['card_border']}",
            "marginTop": "56px",
        },
        children=[
            dcc.Tabs(
                id="tabs",
                value="tab1",
                className="attrib-tabs-wrap",
                children=[
                    dcc.Tab(label="Overview", value="tab1"),
                    dcc.Tab(label="Inspector", value="tab2"),
                    dcc.Tab(label="Heatmap", value="tab3"),
                    dcc.Tab(label="Replay", value="tab4"),
                    dcc.Tab(label="Reports", value="tab5"),
                    dcc.Tab(label="IoT Profiler", value="tab6"),
                ],
                style={"maxWidth": "1400px", "margin": "0 auto", "fontFamily": FONT_UI},
                colors={"border": THEME["card_border"], "primary": THEME["primary"], "background": THEME["card_bg"]},
            )
        ],
    )

    replay_time_label = html.Div(id="replay-time-label", style={"marginTop": "8px", "fontSize": "13px", "color": THEME["text_secondary"], "fontFamily": FONT_MONO})


    app.layout = html.Div(
        style={"background": THEME["page_bg"], "minHeight": "100vh", "color": THEME["text"], "fontFamily": FONT_UI},
        children=[
            html.Link(
                rel="stylesheet",
                href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap",
            ),
            navbar,
            tab_bar,
            html.Div(
                style={"maxWidth": "1400px", "margin": "0 auto", "padding": "24px", "boxSizing": "border-box"},
                children=[
                    html.Div(
                        style={**_card(), "padding": "12px 20px", "marginBottom": "16px", "display": "flex", "flexWrap": "wrap", "gap": "16px", "alignItems": "center"},
                        children=[
                            html.Span("Campaign", style={"fontSize": "12px", "color": THEME["text_secondary"], "fontWeight": 600}),
                            dcc.Dropdown(
                                id="dd-campaign",
                                options=dd_options,
                                value=default_cid,
                                clearable=False,
                                style={"minWidth": "280px", "flex": "1"},
                            ),
                            html.Span("Heatmap highlight", style={"fontSize": "12px", "color": THEME["text_secondary"], "fontWeight": 600}),
                            dcc.Dropdown(
                                id="hm-highlight-dd",
                                options=hm_dd_opts,
                                value=None,
                                clearable=True,
                                placeholder="Optional campaign row highlight",
                                style={"minWidth": "260px", "flex": "1"},
                            ),
                        ],
                    ),
                    dcc.Store(id="kpi-targets", data={"campaigns": kpi_campaigns, "mal": kpi_mal_ips, "avg": kpi_avg_conf, "drift": kpi_drift}),
                    dcc.Store(id="replay-flow-times", data=flow_times_iso),
                    dcc.Store(id="replay-meta", data={"default_idx": replay_default_idx, "peak_idx": mirai_peak_idx, "campaign_a": campaign_a_id}),
                    dcc.Store(id="cyto-elements-full", data=elements),
                    dcc.Store(id="replay-idx", data=replay_default_idx),
                    dcc.Store(id="flash-campaign", data=None),
                    dcc.Download(id="dl-report-json"),
                    dcc.Download(id="dl-report-pdf"),
                    dcc.Store(id="heatmap-focus", data=None),
                    dcc.Store(id="subnet-expanded", data=[]),
                    dcc.Store(id="cyto-zoom", data=1.0),
                    dcc.Store(id="cyto-layout-tick", data=0),
                    dcc.Store(id="heatmap-cell", data=None),
                    html.Div(
                        id="below-tabs",
                        style={"display": "block"},
                        children=[
                            html.Div(
                                id="replay-controls-bar",
                                style={"display": "none", "marginBottom": "12px"},
                                children=[
                                    html.Div(
                                        style={**_card(), "padding": "14px 18px", "display": "flex", "flexWrap": "wrap", "gap": "12px", "alignItems": "center"},
                                        children=[
                                            html.Button("◀◀ Reset", id="btn-replay-reset", n_clicks=0, style=_btn(False)),
                                            html.Button("▶ Play", id="btn-play", n_clicks=0, style=_btn(True)),
                                            html.Button("⏸ Pause", id="btn-pause", n_clicks=0, style=_btn(False)),
                                            html.Div(
                                                style={"flex": "1", "minWidth": "200px", "padding": "0 8px"},
                                                children=[
                                                    dcc.Slider(
                                                        id="replay-slider",
                                                        min=0,
                                                        max=max(0, len(flow_times_iso) - 1),
                                                        step=1,
                                                        value=int(replay_default_idx),
                                                    ),
                                                    replay_time_label,
                                                ],
                                            ),
                                            dcc.Dropdown(
                                                id="replay-speed",
                                                options=[{"label": "1x", "value": 1}, {"label": "2x", "value": 2}, {"label": "5x", "value": 5}],
                                                value=1,
                                                clearable=False,
                                                style={"width": "100px"},
                                            ),
                                        ],
                                    ),
                                ],
                            ),
                            html.Div(
                                id="cyto-wrap",
                                style={"display": "none", "minWidth": 0},
                                children=[
                                    html.Div(
                                        style={
                                            "display": "flex",
                                            "alignItems": "center",
                                            "justifyContent": "space-between",
                                            "marginBottom": "10px",
                                        },
                                        children=[
                                            html.Span(
                                                "Infrastructure Graph",
                                                style={"fontSize": "13px", "fontWeight": 600, "color": THEME["text_secondary"], "fontFamily": FONT_UI},
                                            ),
                                        ],
                                    ),
                                    html.Div(
                                        style={"position": "relative", "minHeight": "520px"},
                                        children=[
                                            # Graph controls — top-right corner
                                            html.Div(
                                                style={"position": "absolute", "top": "10px", "right": "10px", "zIndex": 5, "display": "flex", "gap": "6px"},
                                                children=[
                                                    html.Button("+", id="btn-cyto-in", n_clicks=0, style={**_btn(False), "width": "32px", "padding": "4px 0", "fontWeight": 700, "fontSize": "15px"}),
                                                    html.Button("−", id="btn-cyto-out", n_clicks=0, style={**_btn(False), "width": "32px", "padding": "4px 0", "fontWeight": 700, "fontSize": "15px"}),
                                                    html.Button("⊡ Fit", id="btn-cyto-fit", n_clicks=0, style={**_btn(True), "padding": "4px 10px", "fontSize": "12px"}),
                                                ],
                                            ),
                                            cyto.Cytoscape(
                                                id="cyto",
                                                elements=elements,
                                                layout=cy_layout,
                                                zoom=float(1),
                                                pan={"x": 0, "y": 0},
                                                style={
                                                    "width": "100%",
                                                    "height": "520px",
                                                    "background": THEME["plot_bg"],
                                                    "border": f"1px solid {THEME['card_border']}",
                                                    "borderRadius": THEME["radius"],
                                                },
                                                stylesheet=cy_stylesheet,
                                                wheelSensitivity=0.35,
                                            ),
                                            # Minimap hint — bottom-right
                                            html.Div(
                                                style={
                                                    "position": "absolute",
                                                    "right": "10px",
                                                    "bottom": "10px",
                                                    "width": "120px",
                                                    "height": "80px",
                                                    "background": THEME["card_bg"],
                                                    "border": f"1px solid {THEME['card_border']}",
                                                    "borderRadius": "6px",
                                                    "boxShadow": THEME["card_shadow"],
                                                    "fontSize": "10px",
                                                    "color": THEME["text_muted"],
                                                    "padding": "8px",
                                                    "fontFamily": FONT_UI,
                                                    "lineHeight": 1.4,
                                                    "pointerEvents": "none",
                                                },
                                                children=[
                                                    html.Div("Minimap", style={"fontWeight": 600, "marginBottom": "4px"}),
                                                    html.Span("Scroll to zoom · drag to pan", style={"fontSize": "9px"}),
                                                ],
                                            ),
                                        ],
                                    ),
                                ],
                            ),
                            # Node detail panel — right column, shown when a node is selected
                            html.Div(
                                id="node-panel-slide",
                                style={"display": "none", "flexShrink": 0},
                                children=[
                                    html.Div(
                                        style={
                                            **_card(),
                                            "padding": "0",
                                            "borderLeft": f"3px solid {THEME['primary']}",
                                            "height": "100%",
                                            "overflowY": "auto",
                                        },
                                        children=[
                                            html.Div(id="node-panel", style={"padding": "16px", "fontFamily": FONT_UI}),
                                        ],
                                    ),
                                ],
                            ),
                            dcc.Loading(
                                id="tab-body-loading",
                                type="circle",
                                color=THEME["primary"],
                                parent_style={"flex": "1", "minWidth": 0, "alignSelf": "stretch"},
                                style={"minHeight": "280px"},
                                children=[
                                    html.Div(
                                        id="tab-body",
                                        style={"flex": "1", "minWidth": 0, "minHeight": "240px"},
                                        children=[
                                            html.Div(
                                                [
                                                    html.Div(
                                                        "Loading dashboard…",
                                                        style={
                                                            "padding": "48px 24px 8px",
                                                            "textAlign": "center",
                                                            "color": THEME["text_secondary"],
                                                            "fontSize": "15px",
                                                            "fontFamily": FONT_UI,
                                                        },
                                                    ),
                                                    html.Div(
                                                        "Use the URL printed in the terminal (config dashboard.port). "
                                                        "Do not use http://0.0.0.0 — use http://127.0.0.1:PORT on this PC.",
                                                        style={
                                                            "textAlign": "center",
                                                            "color": THEME["text_muted"],
                                                            "fontSize": "12px",
                                                            "maxWidth": "560px",
                                                            "margin": "0 auto",
                                                            "lineHeight": 1.45,
                                                            "fontFamily": FONT_UI,
                                                        },
                                                    ),
                                                ],
                                            )
                                        ],
                                    )
                                ],
                            ),
                            html.Div(
                                id="replay-standalone",
                                style={"display": "none", "flex": "0 0 35%", "minWidth": "280px"},
                                children=[
                                    html.Div(
                                        style={**_card(), "padding": "16px", "minHeight": "200px", "display": "flex", "flexDirection": "column", "gap": "10px"},
                                        children=[
                                            html.Div(
                                                style={"display": "flex", "alignItems": "center", "justifyContent": "space-between"},
                                                children=[
                                                    html.Span("Live Event Feed", style={"fontWeight": 700, "fontSize": "14px", "color": THEME["text"]}),
                                                    html.Div(id="replay-live-dot", children=[]),
                                                ],
                                            ),
                                            html.Div(id="replay-feed", style={"flex": "1", "overflowY": "auto", "minHeight": "200px"}),
                                        ],
                                    ),
                                ],
                            ),
                        ],
                    ),
                    dcc.Interval(id="replay-tick", interval=500, disabled=True),
                    dcc.Interval(id="kpi-anim", interval=90, n_intervals=0, max_intervals=32, disabled=False),
                    html.Div(id="toast", style={"padding": "12px 0", "color": THEME["primary"], "fontFamily": FONT_UI}),
                ],
            ),
        ],
    )

    @app.callback(Output("tab-body", "children"), Input("tabs", "value"), Input("dd-campaign", "value"), Input("heatmap-focus", "data"), Input("flash-campaign", "data"))
    def render_tab(tab, camp_sel, hm_focus, flash_cid):
        def _render_error(exc: BaseException) -> html.Div:
            import traceback

            return html.Div(
                [
                    html.H3("Dashboard could not render this view", style={"color": THEME["danger"], "fontFamily": FONT_UI}),
                    html.P(
                        "Check that pipeline outputs exist under output/ (run run_all.py from the attack_attribution folder). "
                        "Details below.",
                        style={"color": THEME["text_secondary"], "fontSize": "14px", "maxWidth": "640px", "lineHeight": 1.5},
                    ),
                    html.Pre(
                        f"{exc!r}\n\n{traceback.format_exc()}",
                        style={
                            "whiteSpace": "pre-wrap",
                            "fontSize": "11px",
                            "fontFamily": FONT_MONO,
                            "background": THEME["row_hover"],
                            "padding": "16px",
                            "borderRadius": THEME["radius"],
                            "overflow": "auto",
                            "maxHeight": "360px",
                            "border": f"1px solid {THEME['card_border']}",
                        },
                    ),
                ],
                style={"padding": "24px"},
            )

        try:
            return _render_tab_body(tab, camp_sel, hm_focus, flash_cid)
        except Exception as e:
            return _render_error(e)

    def _render_tab_body(tab, camp_sel, hm_focus, flash_cid):
        inspect_row = html.Div(
            style={"display": "flex", "gap": "8px", "flexWrap": "wrap", "marginTop": "10px"},
            children=[
                html.Button(f"Select campaign {int(cid)}", id={"type": "ins-camp", "index": int(cid)}, n_clicks=0, style=_btn(False))
                for cid in (camp_df["campaign_id"].tolist() if not camp_df.empty else [])
            ],
        )
        if tab == "tab1":
            flash_id = int(flash_cid) if flash_cid is not None else None
            tbl_hdr = {
                "backgroundColor": THEME["table_header"],
                "color": THEME["text_secondary"],
                "fontWeight": "600",
                "fontSize": "11px",
                "textTransform": "uppercase",
                "fontFamily": FONT_UI,
                "border": "none",
            }
            tbl_cell = {
                "fontFamily": FONT_MONO,
                "fontSize": "12px",
                "border": "none",
                "borderBottom": f"1px solid {THEME['card_border']}",
                "color": THEME["text"],
                "backgroundColor": THEME["card_bg"],
            }
            row_styles = [{"if": {"row_index": "odd"}, "backgroundColor": THEME["row_hover"]}]
            if flash_id is not None:
                row_styles.append(
                    {
                        "if": {"filter_query": f"{{campaign_id}} = {flash_id}"},
                        "backgroundColor": "#EFF6FF",
                        "borderLeft": f"4px solid {THEME['primary']}",
                    }
                )
            high_conf_n = int((pd.to_numeric(camp_df["confidence_pct"], errors="coerce") >= 75).sum()) if not camp_df.empty else 0
            avg_conf = float(np.mean(pd.to_numeric(camp_df["confidence_pct"], errors="coerce"))) if not camp_df.empty else 0.0
            avg_accent = _conf_color(avg_conf)
            kpi_footer_c = html.Span(
                [html.Span("● ", style={"color": THEME["success"]}), f"{high_conf_n} high confidence"],
                style={"fontSize": "12px", "color": THEME["text_secondary"], "fontFamily": FONT_UI},
            )
            camp_tbl_data: list[dict] = []
            if not camp_df.empty:
                for r in camp_df.to_dict("records"):
                    atk = str(r.get("attack_type", ""))
                    drift_raw = str(r.get("drift", "")).lower() in ("true", "1")
                    camp_tbl_data.append(
                        {
                            **r,
                            "attack_display": _attack_type_badge_text(atk),
                            "drift_display": "✓ Drifting" if drift_raw else "— Stable",
                            "actions": "Inspect →",
                        }
                    )
            tbl_cols = (
                [{"name": "ID", "id": "campaign_id"}, {"name": "Label", "id": "label"}, {"name": "Attack Type", "id": "attack_display"}]
                + [{"name": c, "id": c} for c in ["n_ips", "confidence_pct", "top_ttp", "drift_display", "cross_dataset"]]
                + [{"name": "Actions", "id": "actions"}]
            )
            conf_cell = [
                {"if": {"filter_query": "{confidence_pct} >= 75", "column_id": "confidence_pct"}, "backgroundColor": "#DCFCE7", "color": THEME["success"], "fontWeight": "700", "borderRadius": "6px"},
                {"if": {"filter_query": "{confidence_pct} >= 50 && {confidence_pct} < 75", "column_id": "confidence_pct"}, "backgroundColor": "#FEF3C7", "color": THEME["warning"], "fontWeight": "700", "borderRadius": "6px"},
                {"if": {"filter_query": "{confidence_pct} < 50", "column_id": "confidence_pct"}, "backgroundColor": "#FEE2E2", "color": THEME["danger"], "fontWeight": "700", "borderRadius": "6px"},
            ]
            body: list = [
                html.Div(
                    style={"display": "flex", "flexDirection": "row", "gap": "16px", "flexWrap": "wrap", "marginBottom": "20px"},
                    children=[
                        html.Div(style={"flex": "1 1 220px", "minWidth": "200px"}, children=[_kpi_card("Total Campaigns", 0, THEME["primary"], kpi_footer_c, "kpi-val-campaigns")]),
                        html.Div(
                            style={"flex": "1 1 220px", "minWidth": "200px"},
                            children=[
                                _kpi_card(
                                    "Malicious IPs",
                                    0,
                                    THEME["danger"],
                                    html.Span("Malicious source IPs (campaign rows)", style={"fontSize": "12px", "color": THEME["text_secondary"], "fontFamily": FONT_UI}),
                                    "kpi-val-mal",
                                )
                            ],
                        ),
                        html.Div(
                            style={"flex": "1 1 220px", "minWidth": "200px"},
                            children=[
                                _kpi_card(
                                    "Avg Confidence",
                                    0,
                                    avg_accent,
                                    html.Span("Across attributed clusters", style={"fontSize": "12px", "color": THEME["text_secondary"], "fontFamily": FONT_UI}),
                                    "kpi-val-avg",
                                )
                            ],
                        ),
                        html.Div(
                            style={"flex": "1 1 220px", "minWidth": "200px"},
                            children=[
                                _kpi_card(
                                    "Drift Detected",
                                    0,
                                    THEME["warning"],
                                    html.Span("Drift flag from temporal windows", style={"fontSize": "12px", "color": THEME["text_secondary"], "fontFamily": FONT_UI}),
                                    "kpi-val-drift",
                                )
                            ],
                        ),
                    ],
                ),
            ]
            if camp_df.empty:
                body.append(_empty_state("No campaigns found — run the pipeline first", "📭"))
            else:
                body.append(html.Div(style=_card(), children=[dcc.Graph(figure=fig_gantt, config=GRAPH_CONFIG)]))
            body.extend(
                [
                    html.Div(style={"marginTop": "16px"}, children=[html.Span("Bulk actions: ", style={"color": THEME["text_secondary"]}), inspect_row]),
                    dash_table.DataTable(
                        id="camp-overview-dt",
                        columns=tbl_cols,
                        data=camp_tbl_data,
                        page_size=15,
                        sort_action="native",
                        export_format="none",
                        style_header=tbl_hdr,
                        style_cell=tbl_cell,
                        style_cell_conditional=[
                            {"if": {"column_id": "actions"}, "color": THEME["primary"], "fontWeight": 600, "cursor": "pointer", "fontFamily": FONT_UI},
                            {"if": {"column_id": "drift_display"}, "fontFamily": FONT_UI},
                            {"if": {"column_id": "attack_display"}, "fontFamily": FONT_UI},
                        ]
                        + conf_cell,
                        style_data_conditional=row_styles
                        + [
                            {"if": {"filter_query": '{drift_display} contains "Drifting"'}, "color": THEME["warning"], "fontWeight": "600"},
                            {"if": {"filter_query": '{drift_display} contains "Stable"'}, "color": THEME["text_muted"]},
                        ],
                    ),
                ]
            )
            return html.Div(body)

        if tab == "tab2":
            csel = int(camp_sel) if camp_sel is not None else 0
            cobj = next((c for c in clusters if int(c.get("cluster_id", c.get("campaign_id", -999))) == csel), {})
            factors = cobj.get("contributing_factors", {}) or {}
            b, i_, t_, m_ = (float(factors.get(k, 0) or 0) for k in ("B", "I", "T", "M"))
            conf = float(cobj.get("confidence_pct", 0))

            def _factor_row(label: str, val: float) -> html.Div:
                w = max(2, min(100, int(val * 100)))
                return html.Div(
                    style={"display": "flex", "alignItems": "center", "gap": "10px", "marginBottom": "8px"},
                    children=[
                        html.Span(label, style={"width": "100px", "fontSize": "12px", "color": THEME["text"], "flexShrink": 0}),
                        html.Div(
                            style={"flex": "1", "height": "8px", "background": "#E2E8F0", "borderRadius": "4px", "overflow": "hidden"},
                            children=[html.Div(style={"width": f"{w}%", "height": "100%", "background": THEME["primary"], "borderRadius": "4px", "transition": "width 0.4s ease"})],
                        ),
                        html.Span(f"{val:.2f}", style={"fontFamily": FONT_MONO, "fontSize": "12px", "color": THEME["text_secondary"], "width": "36px", "textAlign": "right", "flexShrink": 0}),
                    ],
                )

            conf_color = _conf_color(conf)
            conf_bar = html.Div(
                style=_card(),
                children=[
                    html.Div(
                        style={"display": "flex", "justifyContent": "space-between", "alignItems": "flex-start", "marginBottom": "16px"},
                        children=[
                            html.Div([
                                html.Div("Attribution Confidence", style={"fontSize": "11px", "color": THEME["text_muted"], "textTransform": "uppercase", "letterSpacing": "0.06em", "fontWeight": 600}),
                                html.Div(f"{conf:.0f}%", style={"fontSize": "36px", "fontWeight": 700, "color": conf_color, "lineHeight": 1.1, "marginTop": "4px"}),
                            ]),
                        ],
                    ),
                    # Horizontal gradient progress bar
                    html.Div(
                        style={"position": "relative", "height": "12px", "borderRadius": "6px", "background": f"linear-gradient(90deg, {THEME['danger']} 0%, {THEME['warning']} 50%, {THEME['success']} 100%)", "marginBottom": "20px"},
                        children=[
                            html.Div(
                                style={
                                    "position": "absolute",
                                    "left": f"{max(0, min(98, conf))}%",
                                    "top": "-4px",
                                    "width": "4px",
                                    "height": "20px",
                                    "background": "#0F172A",
                                    "borderRadius": "2px",
                                    "marginLeft": "-2px",
                                    "boxShadow": "0 0 0 2px #fff",
                                }
                            ),
                        ],
                    ),
                    html.Div("Factor Contributions", style={"fontSize": "11px", "color": THEME["text_muted"], "textTransform": "uppercase", "letterSpacing": "0.06em", "fontWeight": 600, "marginBottom": "10px"}),
                    _factor_row("Behavioral", b),
                    _factor_row("Infrastructure", i_),
                    _factor_row("Timing", t_),
                    _factor_row("Threat Intel", m_),
                    html.Div("C(k) = B·0.35 + I·0.25 + T·0.20 + M·0.20", style={"fontSize": "11px", "color": THEME["text_muted"], "marginTop": "12px", "fontFamily": FONT_MONO}),
                ],
            )

            windows = drift.get("windows", {}) or {}
            drift_rows = windows.get(str(csel), windows.get(csel, []))
            xs = [d.get("window_start", "") for d in drift_rows] if isinstance(drift_rows, list) else []
            ys = [float(d.get("drift", 0) or 0) for d in drift_rows] if isinstance(drift_rows, list) else []
            drift_detected = bool(cobj.get("drift_detected"))
            if not xs or not ys:
                fig_spark = _empty_chart("Temporal drift (6h windows)", "No drift series for this campaign in the drift report.", height=240)
            else:
                fig_spark = go.Figure()
                # Shade above-threshold region first (below the line trace)
                if drift_detected:
                    y_upper = [max(yv, 0.15) for yv in ys]
                    fig_spark.add_trace(
                        go.Scatter(
                            x=xs + xs[::-1],
                            y=y_upper + [0.15] * len(xs),
                            fill="toself",
                            fillcolor="#FEF2F2",
                            line=dict(color="rgba(0,0,0,0)"),
                            showlegend=False,
                            hoverinfo="skip",
                        )
                    )
                fig_spark.add_trace(
                    go.Scatter(
                        x=xs, y=ys,
                        mode="lines+markers",
                        line=dict(color=THEME["primary"], width=2),
                        marker=dict(size=5, color=THEME["primary"]),
                        name="Drift score",
                    )
                )
                fig_spark.add_hline(
                    y=0.15,
                    line_dash="dash",
                    line_color=THEME["danger"],
                    line_width=1.5,
                    annotation_text="Threshold 0.15",
                    annotation_font_color=THEME["danger"],
                    annotation_font_size=11,
                )
                _base_spark = dict(_plotly_base("Temporal drift (6h windows)", height=220))
                _base_spark.pop("margin", None)
                fig_spark.update_layout(**_base_spark, showlegend=False, margin=dict(l=24, r=16, t=40, b=40))

            return html.Div(
                style={"display": "flex", "flexDirection": "column", "gap": "16px"},
                children=[
                    conf_bar,
                    html.Div(style=_card(), children=[dcc.Graph(figure=fig_spark, config=GRAPH_CONFIG)]),
                    html.Div(
                        style={**_card(), "padding": "10px 16px", "fontSize": "12px", "color": THEME["text_muted"]},
                        children="Click any node on the graph to see threat intel, network context, and attack profile.",
                    ),
                ],
            )

        if tab == "tab3":
            x_factors = ["Behavioral (B)", "Infrastructure (I)", "Timing (T)", "Threat Intel (M)"]
            mat = []
            ylabs = []
            for c in clusters:
                cid = int(c.get("cluster_id", c.get("campaign_id", -1)))
                f = c.get("contributing_factors", {}) or {}
                mat.append([float(f.get("B", 0)), float(f.get("I", 0)), float(f.get("T", 0)), float(f.get("M", 0))])
                ylabs.append(f"Campaign {cid}")
            z_text = [[f"{v * 100:.0f}%" for v in row] for row in mat] if mat else []
            if not mat:
                fig_h = _empty_chart("Confidence factors heatmap", "Run attribution to populate per-campaign factor scores.", height=280)
            else:
                # Build per-cell text with dynamic color (white on dark cells)
                z_text_colored = [[f"{v * 100:.0f}%" for v in row] for row in mat]
                fig_h = go.Figure(
                    data=go.Heatmap(
                        z=mat,
                        x=x_factors,
                        y=ylabs,
                        text=z_text_colored,
                        texttemplate="%{text}",
                        textfont=dict(size=12, family=FONT_UI),
                        colorscale=[(0, "#FFFFFF"), (0.5, "#DBEAFE"), (1, THEME["primary"])],
                        zmin=0,
                        zmax=1,
                        xgap=3,
                        ygap=3,
                        hovertemplate="Factor=%{x}<br>Campaign=%{y}<br>Value=%{z:.2f}<extra></extra>",
                        colorbar=dict(title="Score", tickfont=dict(family=FONT_UI, size=11)),
                    )
                )
                # Overlay white text for dark cells (z > 0.6)
                for ri, row in enumerate(mat):
                    for ci, v in enumerate(row):
                        if v > 0.6:
                            fig_h.add_annotation(
                                x=x_factors[ci],
                                y=ylabs[ri],
                                text=f"{v * 100:.0f}%",
                                showarrow=False,
                                font=dict(color="#FFFFFF", size=12, family=FONT_UI),
                                xref="x",
                                yref="y",
                            )
            _base_hm = dict(_plotly_base("Confidence factors heatmap", height=max(360, 80 + 48 * len(ylabs))))
            _base_hm.pop("xaxis", None)
            _base_hm.pop("yaxis", None)
            _base_hm.pop("margin", None)
            fig_h.update_layout(
                **_base_hm,
                xaxis=dict(side="bottom", tickangle=0, tickfont=dict(size=12, family=FONT_UI), gridcolor=THEME["grid"]),
                yaxis=dict(autorange="reversed", tickfont=dict(size=12, family=FONT_UI), gridcolor=THEME["grid"]),
                margin=dict(l=100, r=24, t=56, b=40),
            )
            low = camp_df[camp_df["confidence_pct"] < 60].copy() if not camp_df.empty else camp_df
            if not low.empty:
                low["risk_badge"] = low["confidence_pct"].apply(lambda x: "LOW CONF" if float(x) < 60 else "")
            hm_styles = [{"if": {"row_index": "odd"}, "backgroundColor": THEME["row_hover"]}]
            if hm_focus and hm_focus.get("y"):
                yv = str(hm_focus["y"])
                if yv.startswith("Campaign "):
                    try:
                        cid_h = int(yv.replace("Campaign", "").strip())
                        hm_styles.append(
                            {
                                "if": {"filter_query": f"{{campaign_id}} = {cid_h}"},
                                "backgroundColor": "#EFF6FF",
                                "borderLeft": f"3px solid {THEME['primary']}",
                            }
                        )
                    except ValueError:
                        pass
            low_tbl = []
            if low.empty:
                low_tbl = [html.P("No campaigns under 60% confidence.", style={"color": THEME["text_secondary"]})]
            else:
                low_tbl = [
                    dash_table.DataTable(
                        columns=[{"name": c, "id": c} for c in low.columns],
                        data=low.to_dict("records"),
                        page_size=10,
                        export_format="none",
                        style_header={
                            "backgroundColor": THEME["table_header"],
                            "color": THEME["text_secondary"],
                            "fontWeight": "600",
                            "fontSize": "11px",
                            "textTransform": "uppercase",
                            "fontFamily": FONT_UI,
                            "border": "none",
                        },
                        style_cell={
                            "fontFamily": FONT_MONO,
                            "border": "none",
                            "borderBottom": f"1px solid {THEME['card_border']}",
                            "backgroundColor": THEME["card_bg"],
                            "color": THEME["text"],
                        },
                        style_data_conditional=hm_styles
                        + [
                            {
                                "if": {"filter_query": '{risk_badge} contains "LOW"'},
                                "color": THEME["danger"],
                                "fontWeight": "700",
                            }
                        ],
                    )
                ]
            return html.Div(
                [
                    html.Div(style=_card(), children=[dcc.Graph(id="heatmap-fig", figure=fig_h, config=GRAPH_CONFIG)]),
                    html.H3("Campaigns under 60% confidence", style={"color": THEME["text"], "fontFamily": FONT_UI, "fontSize": "16px", "marginTop": "16px"}),
                    *low_tbl,
                ]
            )

        if tab == "tab4":
            return html.Div(style={"display": "none"})

        if tab == "tab5":
            if camp_df.empty:
                return _empty_state("No campaigns to report on. Run the pipeline first.", "📄")
            rep_cols = [c for c in ["campaign_id", "attack_type", "n_ips", "confidence_pct", "top_ttp", "drift"] if c in camp_df.columns]
            return html.Div(
                [
                    html.Div(
                        style={**_card(), "marginBottom": "16px"},
                        children=[
                            html.H3("Report filters", style={"margin": "0 0 14px", "fontSize": "15px", "fontFamily": FONT_UI}),
                            html.Div(
                                style={"display": "flex", "gap": "20px", "flexWrap": "wrap", "alignItems": "flex-start"},
                                children=[
                                    html.Div(
                                        style={"flex": "1", "minWidth": "300px"},
                                        children=[
                                            html.Label("Campaigns (empty = all)", style={"fontSize": "12px", "fontWeight": 600, "color": THEME["text_secondary"]}),
                                            dcc.Dropdown(
                                                id="rep-campaigns",
                                                options=[{"label": f"Campaign {int(c)}", "value": int(c)} for c in camp_df["campaign_id"].tolist()],
                                                value=[],
                                                multi=True,
                                                placeholder="All campaigns",
                                            ),
                                        ],
                                    ),
                                    html.Div(
                                        style={"flex": "1", "minWidth": "280px"},
                                        children=[
                                            html.Label("Minimum confidence", style={"fontSize": "12px", "fontWeight": 600, "color": THEME["text_secondary"]}),
                                            dcc.Slider(
                                                id="rep-min-conf",
                                                min=0, max=100, step=5, value=0,
                                                marks={i: f"{i}%" for i in range(0, 101, 25)},
                                                tooltip={"placement": "bottom", "always_visible": False},
                                            ),
                                        ],
                                    ),
                                    html.Div(
                                        style={"minWidth": "220px"},
                                        children=[
                                            html.Label("Include", style={"fontSize": "12px", "fontWeight": 600, "color": THEME["text_secondary"]}),
                                            dcc.Checklist(
                                                id="rep-include",
                                                options=[
                                                    {"label": " Enriched IP indicators", "value": "ips"},
                                                    {"label": " Temporal drift windows", "value": "drift"},
                                                ],
                                                value=["ips", "drift"],
                                                style={"fontSize": "13px", "fontFamily": FONT_UI},
                                                inputStyle={"marginRight": "4px"},
                                            ),
                                        ],
                                    ),
                                ],
                            ),
                            html.Div(
                                style={"display": "flex", "gap": "10px", "marginTop": "18px", "alignItems": "center", "flexWrap": "wrap"},
                                children=[
                                    html.Button("⬇ Export JSON", id="btn-export-json", n_clicks=0, style=_btn(False)),
                                    html.Button("📄 Generate Incident Report (PDF)", id="btn-export-pdf", n_clicks=0, style=_btn(True)),
                                    html.Span(id="rep-status", style={"fontSize": "12px", "color": THEME["text_secondary"], "fontFamily": FONT_MONO}),
                                ],
                            ),
                        ],
                    ),
                    html.H3("Campaigns included", style={"fontSize": "16px", "fontFamily": FONT_UI, "marginTop": "4px"}),
                    dash_table.DataTable(
                        id="rep-preview",
                        columns=[{"name": c, "id": c} for c in rep_cols],
                        data=camp_df[rep_cols].to_dict("records"),
                        page_size=12,
                        export_format="none",
                        style_header={
                            "backgroundColor": THEME["table_header"],
                            "color": THEME["text_secondary"],
                            "fontWeight": "600",
                            "fontSize": "11px",
                            "textTransform": "uppercase",
                            "fontFamily": FONT_UI,
                            "border": "none",
                        },
                        style_cell={
                            "fontFamily": FONT_MONO,
                            "fontSize": "12px",
                            "border": "none",
                            "borderBottom": f"1px solid {THEME['card_border']}",
                            "backgroundColor": THEME["card_bg"],
                            "color": THEME["text"],
                        },
                        style_data_conditional=[
                            {"if": {"row_index": "odd"}, "backgroundColor": THEME["row_hover"]},
                            {"if": {"filter_query": "{confidence_pct} < 50"}, "color": THEME["danger"], "fontWeight": "700"},
                            {"if": {"filter_query": "{confidence_pct} >= 75"}, "color": THEME["success"], "fontWeight": "700"},
                        ],
                    ),
                    html.P(
                        "JSON export contains the full attribution payload (factors, TTPs, drift, indicators). "
                        "The PDF is a multi-page incident report including the factor heatmap and the formula registry.",
                        style={"fontSize": "12px", "color": THEME["text_secondary"], "marginTop": "12px", "maxWidth": "760px", "lineHeight": 1.5},
                    ),
                ]
            )

        if tab == "tab6":
            if camps.empty or not {"scan_entropy", "c2_beacon_score"}.issubset(camps.columns):
                return _empty_state("Feature columns missing. Re-run phases 02 and 03.", "📡")
            prof = camps.copy()
            prof["campaign_id"] = pd.to_numeric(prof.get("campaign_id"), errors="coerce").fillna(-1).astype(int)
            prof["scan_entropy"] = pd.to_numeric(prof["scan_entropy"], errors="coerce")
            prof["c2_beacon_score"] = pd.to_numeric(prof["c2_beacon_score"], errors="coerce")
            prof = prof.dropna(subset=["scan_entropy", "c2_beacon_score"])
            is_mal = pd.to_numeric(prof.get("label", 0), errors="coerce").fillna(0) > 0

            fig_p = go.Figure()
            palette = ["#2563EB", "#D97706", "#16A34A", "#7C3AED", "#0891B2", "#DB2777", "#65A30D", "#DC2626"]
            for i, cid in enumerate(sorted(prof["campaign_id"].unique())):
                sub = prof[(prof["campaign_id"] == cid) & (~is_mal)]
                if sub.empty:
                    continue
                if len(sub) > 4000:
                    sub = sub.sample(4000, random_state=42)
                fig_p.add_trace(
                    go.Scattergl(
                        x=sub["scan_entropy"], y=sub["c2_beacon_score"],
                        mode="markers", name=f"Campaign {int(cid)}",
                        marker=dict(size=5, opacity=0.55, color=palette[i % len(palette)]),
                        customdata=sub["SrcAddr"] if "SrcAddr" in sub.columns else None,
                        hovertemplate="%{customdata}<br>scan entropy=%{x:.3f}<br>beacon score=%{y:.3f}<extra></extra>",
                    )
                )
            mal = prof[is_mal]
            if not mal.empty:
                fig_p.add_trace(
                    go.Scattergl(
                        x=mal["scan_entropy"], y=mal["c2_beacon_score"],
                        mode="markers", name=f"Labelled malicious ({len(mal):,})",
                        marker=dict(size=10, color=THEME["danger"], symbol="x", line=dict(width=1, color="#7F1D1D")),
                        customdata=mal["SrcAddr"] if "SrcAddr" in mal.columns else None,
                        hovertemplate="%{customdata}<br>scan entropy=%{x:.3f}<br>beacon score=%{y:.3f}<extra></extra>",
                    )
                )
            fig_p.update_layout(
                **_plotly_base("Scan entropy vs C2 beacon score", height=560),
                legend=dict(orientation="h", y=-0.16, font=dict(size=11, family=FONT_UI)),
            )
            fig_p.update_xaxes(title_text="Scan entropy H(dst)  -  higher = more destinations probed")
            fig_p.update_yaxes(title_text="C2 beacon score  -  higher = more regular intervals")

            n_shown = min(len(prof), 4000 * max(1, prof["campaign_id"].nunique()))
            return html.Div(
                [
                    html.Div(style=_card(), children=[dcc.Graph(figure=fig_p, config=GRAPH_CONFIG)]),
                    html.P(
                        f"Each point is one source IP in one time window ({len(prof):,} fingerprints; "
                        f"up to 4,000 sampled per campaign, showing ~{n_shown:,}). Labelled-malicious "
                        "fingerprints are drawn as red crosses on top. Beaconing hosts cluster high on the "
                        "y-axis; horizontal scanners push right on the x-axis.",
                        style={"fontSize": "12px", "color": THEME["text_secondary"], "marginTop": "12px", "maxWidth": "820px", "lineHeight": 1.5},
                    ),
                ]
            )

        return _empty_state("Tab not found.", "❓")

    def _report_payload(sel_ids, min_conf, include) -> dict:
        include = include or []
        want = {int(s) for s in (sel_ids or [])}
        floor = float(min_conf or 0)

        rows: list[dict] = []
        for cl in clusters:
            cid = int(cl.get("cluster_id", cl.get("campaign_id", -1)))
            conf = float(cl.get("confidence_pct", 0))
            if want and cid not in want:
                continue
            if conf < floor:
                continue
            n_ips = 0
            if not camps.empty and "SrcAddr" in camps.columns:
                n_ips = int(camps[camps["campaign_id"] == cid]["SrcAddr"].nunique())
            row = {
                "campaign_id": cid,
                "attack_type": str(cl.get("attack_type", "Unknown")),
                "confidence_pct": round(conf, 2),
                "confidence_band": "low" if conf < 50 else ("medium" if conf < 75 else "high"),
                "contributing_factors": cl.get("contributing_factors") or {},
                "top_ttps": cl.get("top_ttps") or [],
                "drift_detected": bool(cl.get("drift_detected", False)),
                "cross_dataset": bool(cl.get("cross_dataset", False)),
                "iot_family": cl.get("iot_family"),
                "ip_count": n_ips,
            }
            if "ips" in include and not enr.empty and "campaign_id" in enr.columns:
                keep = [
                    c
                    for c in ["ip", "threat_level", "vt_malicious", "abuse_score", "abuse_isp",
                              "asn", "asn_org", "country", "technique_id", "technique_name"]
                    if c in enr.columns
                ]
                sub = enr[pd.to_numeric(enr["campaign_id"], errors="coerce") == cid][keep]
                row["enriched_ips"] = sub.to_dict("records")
            if "drift" in include:
                row["drift_windows"] = (drift.get("windows") or {}).get(str(cid), [])
            rows.append(row)

        total_flows = int(len(flows)) if not flows.empty else 0
        uniq_src = int(flows["SrcAddr"].nunique()) if not flows.empty and "SrcAddr" in flows.columns else 0
        return {
            "report": {
                "tool": "AttribIQ - Post-Incident Attack Attribution",
                "generated_at": datetime.now().isoformat(timespec="seconds"),
                "demo_mode": demo,
                "filters": {
                    "campaigns": sorted(want) or None,
                    "min_confidence_pct": floor,
                    "include": include,
                },
            },
            "dataset": {
                "total_flows": total_flows,
                "unique_source_ips": uniq_src,
                "fingerprints": int(len(camps)) if not camps.empty else 0,
                "campaigns_total": len(clusters),
                "campaigns_selected": len(rows),
                "enriched_ips": int(enr["ip"].nunique()) if not enr.empty and "ip" in enr.columns else 0,
            },
            "formula_registry": att.get("formula_registry") or {},
            "campaigns": rows,
            "misp_matches": (misp_data.get("matches") if isinstance(misp_data, dict) else []) or [],
        }

    @app.callback(
        Output("dl-report-json", "data"),
        Output("rep-status", "children"),
        Input("btn-export-json", "n_clicks"),
        State("rep-campaigns", "value"),
        State("rep-min-conf", "value"),
        State("rep-include", "value"),
        prevent_initial_call=True,
    )
    def export_json(n_clicks, sel_ids, min_conf, include):
        if not n_clicks:
            return no_update, no_update
        payload = _report_payload(sel_ids, min_conf, include)
        if not payload["campaigns"]:
            return no_update, "No campaigns match the filters."
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return (
            dcc.send_string(json.dumps(payload, indent=2, default=str), f"attribiq_export_{stamp}.json"),
            f"Exported {len(payload['campaigns'])} campaign(s) as JSON.",
        )

    @app.callback(
        Output("dl-report-pdf", "data"),
        Output("rep-status", "children", allow_duplicate=True),
        Input("btn-export-pdf", "n_clicks"),
        State("rep-campaigns", "value"),
        State("rep-min-conf", "value"),
        State("rep-include", "value"),
        prevent_initial_call=True,
    )
    def export_pdf(n_clicks, sel_ids, min_conf, include):
        if not n_clicks:
            return no_update, no_update
        payload = _report_payload(sel_ids, min_conf, include)
        if not payload["campaigns"]:
            return no_update, "No campaigns match the filters."
        try:
            pdf_bytes = _build_incident_pdf(payload)
        except Exception as exc:  # reportlab missing or draw failure
            return no_update, f"PDF generation failed: {exc!r}"
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return (
            dcc.send_bytes(pdf_bytes, f"attribiq_incident_report_{stamp}.pdf"),
            f"Incident report ready ({len(pdf_bytes) // 1024} KB, {len(payload['campaigns'])} campaign(s)).",
        )

    @app.callback(
        Output("below-tabs", "style"),
        Output("cyto-wrap", "style"),
        Output("replay-standalone", "style"),
        Output("replay-controls-bar", "style"),
        Output("tab-body-loading", "parent_style"),
        Input("tabs", "value"),
    )
    def flex_below(tab):
        _tab_body_shown  = {"flex": "1", "minWidth": 0, "alignSelf": "stretch"}
        _tab_body_hidden = {"display": "none"}

        if tab == "tab2":
            return (
                {"display": "flex", "flexDirection": "row", "alignItems": "flex-start", "gap": "20px", "flexWrap": "nowrap"},
                {"display": "block", "flex": "0 0 45%", "minWidth": 0},
                {"display": "none"},
                {"display": "none"},
                _tab_body_shown,
            )

        if tab == "tab4":
            # flexWrap lets replay-controls-bar (width:100%) sit on its own top line;
            # cyto-wrap and replay-standalone then share the second line.
            return (
                {"display": "flex", "flexDirection": "row", "alignItems": "flex-start", "gap": "16px", "flexWrap": "wrap"},
                {"display": "block", "flex": "1 1 60%", "minWidth": "320px"},
                {"display": "block", "flex": "0 0 320px"},
                {"display": "block", "width": "100%", "marginBottom": "4px"},
                _tab_body_hidden,
            )

        return (
            {"display": "block"},
            {"display": "none", "minWidth": 0},
            {"display": "none"},
            {"display": "none"},
            _tab_body_shown,
        )

    @app.callback(
        Output("kpi-val-campaigns", "children"),
        Output("kpi-val-mal", "children"),
        Output("kpi-val-avg", "children"),
        Output("kpi-val-drift", "children"),
        Input("kpi-anim", "n_intervals"),
        State("kpi-targets", "data"),
    )
    def anim_kpi(n, tgt):
        n = int(n or 0)
        if not tgt:
            return "0", "0", "0", "0"
        steps = 28.0
        p = min(1.0, n / steps)
        c = int(round(float(tgt.get("campaigns", 0) or 0) * p))
        m = int(round(float(tgt.get("mal", 0) or 0) * p))
        a = round(float(tgt.get("avg", 0) or 0) * p, 2)
        d = int(round(float(tgt.get("drift", 0) or 0) * p))
        return str(c), str(m), str(a), str(d)

    if not camp_df.empty:

        @app.callback(
            Output("dd-campaign", "value"),
            Input({"type": "ins-camp", "index": ALL}, "n_clicks"),
            Input("camp-overview-dt", "active_cell"),
            State("camp-overview-dt", "data"),
            prevent_initial_call=True,
        )
        def jump_campaign(_nc, ac, data):
            tid = ctx.triggered_id
            if tid == "camp-overview-dt" and ac and data:
                if ac.get("column_id") == "actions":
                    ri = ac.get("row")
                    if ri is not None and ri < len(data):
                        return int(data[ri].get("campaign_id", 0))
                return no_update
            if isinstance(tid, dict) and tid.get("type") == "ins-camp":
                return int(tid["index"])
            return no_update

    @app.callback(Output("heatmap-focus", "data"), Input("hm-highlight-dd", "value"))
    def hm_dd_sel(v):
        if v is None:
            return None
        return {"y": f"Campaign {int(v)}", "x": None}

    @app.callback(
        Output("replay-idx", "data"),
        Output("replay-slider", "value"),
        Input("replay-tick", "n_intervals"),
        Input("replay-slider", "value"),
        Input("btn-replay-reset", "n_clicks"),
        State("replay-idx", "data"),
        State("replay-speed", "value"),
        State("replay-flow-times", "data"),
    )
    def advance_replay(_tick, slider_val, _reset, cur, speed, times_iso):
        tid = ctx.triggered_id
        nmax = max(0, len(times_iso or []) - 1)
        cur = int(cur or 0)
        if tid == "btn-replay-reset":
            v0 = max(0, min(nmax, int(replay_default_idx)))
            return v0, v0
        if tid is None:
            v0 = max(0, min(nmax, int(replay_default_idx)))
            return v0, v0
        if tid == "replay-slider":
            v = int(slider_val or 0)
            v = max(0, min(nmax, v))
            return v, v
        if tid == "replay-tick":
            sp = int(speed or 1)
            nxt = min(nmax, cur + sp)
            return nxt, nxt
        return cur, cur

    @app.callback(
        Output("cyto", "elements"),
        Input("replay-idx", "data"),
        Input("tabs", "value"),
        Input("dd-campaign", "value"),
        Input("subnet-expanded", "data"),
        State("cyto-elements-full", "data"),
        State("replay-flow-times", "data"),
    )
    def filter_cyto(idx, tab, camp_id, subnet_exp, full_el, times_iso):
        if not full_el:
            return []
        cid = int(camp_id) if camp_id is not None else 0
        exp_set = {str(x) for x in (subnet_exp or [])}

        if tab == "tab2":
            return _inspector_elements(full_el, cid, exp_set)

        if tab == "tab4":
            if not times_iso:
                all_ips = {
                    str((e.get("data") or {}).get("id"))
                    for e in full_el
                    if not (e.get("data") or {}).get("source") and (e.get("classes") or "") == "ip"
                }
                return _replay_ip_only_elements(full_el, all_ips)
            idx = int(idx or 0)
            idx = max(0, min(len(times_iso) - 1, idx))
            cutoff = pd.Timestamp(times_iso[idx])
            vis_ips: set[str] = set()
            for el in full_el:
                d = el.get("data") or {}
                if "source" in d:
                    continue
                if (el.get("classes") or "") != "ip":
                    continue
                nid = str(d.get("id", ""))
                fst = ip_first_seen.get(nid)
                if fst is None or pd.isna(fst) or pd.Timestamp(fst) <= cutoff:
                    vis_ips.add(nid)
            return _replay_ip_only_elements(full_el, vis_ips)

        return full_el

    @app.callback(Output("flash-campaign", "data"), Input("replay-idx", "data"), Input("tabs", "value"), State("replay-meta", "data"))
    def do_flash(idx, tab, meta):
        if tab != "tab4":
            return None
        if not meta:
            return None
        try:
            if int(idx or -1) == int(meta.get("peak_idx", -2)):
                return int(meta.get("campaign_a", 0))
        except (TypeError, ValueError):
            pass
        return None

    @app.callback(
        Output("replay-feed", "children"),
        Input("replay-idx", "data"),
        State("replay-flow-times", "data"),
        State("tabs", "value"),
    )
    def replay_feed_rows(idx, times_iso, tab):
        hint = html.Div(
            "Open Replay, press Play, and scrub the timeline. Newest events stay at the top.",
            style={"color": THEME["text_secondary"], "fontSize": "13px", "padding": "12px"},
        )
        if tab != "tab4" or flows_w.empty or "StartTime" not in flows_w.columns or not times_iso:
            return hint
        idx = int(idx or 0)
        idx = max(0, min(len(times_iso) - 1, idx))
        cutoff = pd.Timestamp(times_iso[idx])
        ff = flows_w.copy()
        ff["StartTime"] = pd.to_datetime(ff["StartTime"], errors="coerce")
        sub = ff[ff["StartTime"] <= cutoff].sort_values("StartTime")
        tail = sub.tail(10)
        if tail.empty:
            return html.Div("(no events at this time)", style={"color": THEME["text_muted"], "padding": "12px"})
        rows = list(tail.iloc[::-1].iterrows())
        out = []
        for _, r in rows:
            atk = str(r.get("_attack_type", "") or "").lower()
            if "bot" in atk or "mirai" in atk:
                bg = "#FEF2F2"
                ev = "Botnet"
            elif "c2" in atk or "beacon" in atk:
                bg = "#EFF6FF"
                ev = "C2"
            elif "scan" in atk:
                bg = "#FFFBEB"
                ev = "Scanner"
            else:
                bg = "#F8FAFC"
                ev = (r.get("_attack_type") or "Flow")[:16]
            ts = r.get("StartTime")
            ts_s = pd.Timestamp(ts).strftime("%H:%M") if ts is not None and not pd.isna(ts) else "—"
            src = str(r.get("SrcAddr", ""))
            dst = str(r.get("DstAddr", ""))
            src_s = _short_ip_last_octets(src) if "." in src else src[:10]
            dst_s = _short_ip_last_octets(dst) if "." in dst else dst[:10]
            camp = str(r.get("_campaign", ""))
            out.append(
                html.Div(
                    className="attrib-feed-row",
                    style={
                        "display": "grid",
                        "gridTemplateColumns": "56px 1fr 80px 72px",
                        "gap": "8px",
                        "alignItems": "center",
                        "padding": "8px 10px",
                        "background": bg,
                        "borderBottom": f"1px solid {THEME['card_border']}",
                        "fontSize": "12px",
                        "fontFamily": FONT_UI,
                    },
                    children=[
                        html.Span(ts_s, style={"color": THEME["text_muted"], "fontFamily": FONT_MONO}),
                        html.Span(
                            [html.Span(src_s, style={"fontFamily": FONT_MONO, "color": THEME["text"]}), " → ", html.Span(dst_s, style={"fontFamily": FONT_MONO, "color": THEME["text"]})],
                        ),
                        html.Span(ev, style={"fontWeight": 600, "color": THEME["text_secondary"]}),
                        html.Span(f"C{camp}" if camp != "" else "—", style={"color": THEME["text_muted"], "fontFamily": FONT_MONO, "textAlign": "right"}),
                    ],
                )
            )
        return out

    @app.callback(Output("replay-tick", "disabled"), Input("btn-play", "n_clicks"), Input("btn-pause", "n_clicks"))
    def replay_toggle(play, pause):
        p, q = int(play or 0), int(pause or 0)
        return not (p > q)

    @app.callback(Output("replay-time-label", "children"), Input("replay-idx", "data"), State("replay-flow-times", "data"), State("tabs", "value"))
    def replay_time_lbl(idx, times_iso, tab):
        if tab != "tab4" or not times_iso:
            return ""
        i = int(idx or 0)
        i = max(0, min(len(times_iso) - 1, i))
        return pd.Timestamp(times_iso[i]).strftime("%b %d, %Y  %H:%M:%S")

    @app.callback(Output("replay-live-dot", "children"), Input("replay-tick", "disabled"))
    def replay_live_dot(disabled: bool):
        if disabled:
            return []
        return [
            html.Span(
                style={
                    "display": "inline-block",
                    "width": "10px",
                    "height": "10px",
                    "borderRadius": "50%",
                    "background": THEME["success"],
                    "marginRight": "8px",
                    "animation": "attrib-pulse 1.2s ease-in-out infinite",
                }
            ),
            html.Span("Live", style={"fontSize": "12px", "color": THEME["success"], "fontWeight": 600}),
        ]

    @app.callback(
        Output("cyto-zoom", "data"),
        Input("btn-cyto-in", "n_clicks"),
        Input("btn-cyto-out", "n_clicks"),
        State("cyto-zoom", "data"),
        prevent_initial_call=True,
    )
    def cy_zoom_btn(_inc, _out, z):
        z = float(z or 1.0)
        tid = ctx.triggered_id
        if tid == "btn-cyto-in":
            return min(2.5, z * 1.18)
        if tid == "btn-cyto-out":
            return max(0.35, z / 1.18)
        return z

    @app.callback(Output("cyto", "zoom"), Input("cyto-zoom", "data"))
    def cy_apply_zoom(z):
        return float(z or 1.0)

    @app.callback(Output("cyto", "layout"), Input("btn-cyto-fit", "n_clicks"), prevent_initial_call=True)
    def cy_fit_btn(n):
        n = int(n or 0)
        return {**cy_layout, "randomize": bool(n % 2)}

    @app.callback(Output("heatmap-cell", "data"), Input("heatmap-fig", "clickData"))
    def heatmap_cell_pick(cd):
        if not cd or not cd.get("points"):
            return None
        p = cd["points"][0]
        return {"x": p.get("x"), "y": p.get("y"), "z": p.get("z")}

    @app.callback(
        Output("node-panel", "children"),
        Output("subnet-expanded", "data"),
        Output("node-panel-slide", "style"),
        Input("cyto", "tapNodeData"),
        State("subnet-expanded", "data"),
        State("tabs", "value"),
    )
    def node_detail(data, subnet_exp, tab):
        _panel_hidden = {"display": "none", "flexShrink": 0}
        _panel_shown = {"display": "block", "flex": "0 0 55%", "minWidth": "280px", "flexShrink": 0}
        empty = html.Div(
            "Select a node on the graph to view threat intelligence, network context, and attack profile.",
            style={"color": THEME["text_secondary"], "fontSize": "13px", "lineHeight": 1.5},
        )
        if not data:
            return empty, no_update, _panel_hidden

        pfx = data.get("subnet_prefix")
        if tab == "tab2" and pfx:
            exp = list(subnet_exp or [])
            sp = str(pfx)
            if sp in exp:
                exp = [x for x in exp if x != sp]
            else:
                exp = exp + [sp]
            n_ips = int(data.get("ip_count") or 0)
            panel = html.Div(
                [
                    html.Div("Subnet group", style={"fontSize": "11px", "color": THEME["text_muted"], "textTransform": "uppercase", "letterSpacing": "0.06em"}),
                    html.Div(f"{sp}.x", style={"fontSize": "20px", "fontWeight": 700, "fontFamily": FONT_MONO, "color": THEME["text"], "marginTop": "6px"}),
                    html.P(f"{n_ips} IPs aggregated. Click again to toggle expansion.", style={"color": THEME["text_secondary"], "fontSize": "13px"}),
                ]
            )
            return panel, exp, _panel_shown

        nid = str(data.get("id", "") or data.get("full_ip", ""))
        if nid.startswith("__subnet__"):
            return empty, no_update, _panel_hidden

        row = enr[enr["ip"].astype(str) == nid] if not enr.empty and "ip" in enr.columns else pd.DataFrame()
        misp_txt = "\n".join(misp_by_ip.get(nid, [])[:5]) or "(no MISP matches)"

        def _bar(label: str, val: float, mx: float) -> html.Div:
            pct = max(0, min(100, int(100 * float(val) / max(mx, 1e-6))))
            return html.Div(
                style={"marginBottom": "10px"},
                children=[
                    html.Div(style={"display": "flex", "justifyContent": "space-between"}, children=[html.Span(label, style={"fontSize": "12px"}), html.Span(f"{val}", style={"fontFamily": FONT_MONO, "fontSize": "12px"})]),
                    html.Div(style={"height": "8px", "background": "#E2E8F0", "borderRadius": "4px", "overflow": "hidden"}, children=[html.Div(style={"width": f"{pct}%", "height": "100%", "background": THEME["primary"]})]),
                ],
            )

        def _sec(title: str, inner) -> html.Div:
            return html.Div(
                style={"marginTop": "16px", "paddingTop": "14px", "borderTop": f"1px solid {THEME['card_border']}"},
                children=[
                    html.Div(title, style={"fontSize": "11px", "color": THEME["text_muted"], "letterSpacing": "0.08em", "fontWeight": 700, "marginBottom": "10px"}),
                    inner,
                ],
            )

        if row.empty:
            inner = html.Pre(json.dumps(data, indent=2, default=str) + "\n\nMISP:\n" + misp_txt, style={"whiteSpace": "pre-wrap", "fontFamily": FONT_MONO, "fontSize": "11px", "color": THEME["text"]})
            return html.Div([inner]), no_update, _panel_shown

        r = row.iloc[0]
        atk = str(r.get("attack_type", r.get("campaign_type", "")) or "")
        vt = float(pd.to_numeric(r.get("vt_malicious"), errors="coerce") or 0)
        ab = float(pd.to_numeric(r.get("abuse_score"), errors="coerce") or 0)
        beacon = float(pd.to_numeric(r.get("c2_beacon_score"), errors="coerce") or 0)
        beacon_txt = "Strong" if beacon > 0.2 else "Moderate" if beacon > 0.08 else "Weak"
        country = str(r.get("country", "") or "")
        flag = "🌐" if not country else ("🇨🇳" if "china" in country.lower() else "🌍")

        badges = html.Div(
            style={"display": "flex", "gap": "8px", "flexWrap": "wrap", "marginTop": "8px"},
            children=[
                html.Span("Malicious", style={"background": "#FEE2E2", "color": THEME["danger"], "padding": "2px 8px", "borderRadius": "6px", "fontSize": "11px", "fontWeight": 600}),
                html.Span(atk or "Unknown", style={"background": "#F1F5F9", "color": THEME["text"], "padding": "2px 8px", "borderRadius": "6px", "fontSize": "11px"}),
            ],
        )

        panel = html.Div(
            [
                html.Div(
                    style={"display": "flex", "justifyContent": "space-between", "alignItems": "flex-start"},
                    children=[
                        html.Div(
                            [
                                html.Div("IP Address", style={"fontSize": "11px", "color": THEME["text_muted"], "textTransform": "uppercase", "letterSpacing": "0.06em"}),
                                html.Div(nid, style={"fontSize": "16px", "fontWeight": 700, "fontFamily": FONT_MONO, "color": THEME["text"], "marginTop": "4px"}),
                            ]
                        ),
                    ],
                ),
                badges,
                _sec(
                    "THREAT INTELLIGENCE",
                    html.Div(
                        [
                            _bar("VirusTotal", vt, 10),
                            _bar("AbuseIPDB", ab, 100),
                            html.P(f"MISP: {misp_txt}", style={"fontSize": "11px", "color": THEME["text_secondary"], "whiteSpace": "pre-wrap", "margin": "8px 0 0"}),
                        ]
                    ),
                ),
                _sec(
                    "NETWORK",
                    html.Div(
                        [
                            html.Div(
                                style={"display": "flex", "flexDirection": "column", "gap": "4px", "fontSize": "13px"},
                                children=[
                                    html.Div([html.Span("ASN ", style={"color": THEME["text_muted"]}), html.Span(str(r.get("asn", "") or "—"), style={"fontFamily": FONT_MONO})]),
                                    html.Div([html.Span("Org ", style={"color": THEME["text_muted"]}), str(r.get("asn_org", "") or "—")]),
                                    html.Div([html.Span(f"{flag} ", style={"color": THEME["text_muted"]}), country or "—"]),
                                    html.Div([html.Span("Ports ", style={"color": THEME["text_muted"]}), html.Span(str(r.get("shodan_ports", "") or "—"), style={"fontFamily": FONT_MONO})]),
                                ],
                            )
                        ]
                    ),
                ),
                _sec(
                    "ATTACK",
                    html.Div(
                        style={"display": "flex", "flexDirection": "column", "gap": "4px", "fontSize": "13px"},
                        children=[
                            html.Div([html.Span("Type ", style={"color": THEME["text_muted"]}), atk or "—"]),
                            html.Div([html.Span("TTP ", style={"color": THEME["text_muted"]}), html.Span(str(r.get("technique_id", "") or "—"), style={"fontFamily": FONT_MONO})]),
                            html.Div([html.Span("Beacon CoV ", style={"color": THEME["text_muted"]}), html.Span(f"{beacon:.2f} ({beacon_txt})", style={"fontFamily": FONT_MONO})]),
                        ],
                    ),
                ),
                html.Div(
                    style={"display": "flex", "gap": "16px", "marginTop": "18px", "paddingTop": "14px", "borderTop": f"1px solid {THEME['card_border']}"},
                    children=[
                        html.Span(nid, id="ioc-copy-text", style={"display": "none"}),
                        dcc.Clipboard(target_id="ioc-copy-text", title="Copy IOC", style={"color": THEME["primary"], "fontWeight": 600, "fontSize": "13px", "cursor": "pointer"}),
                        html.A("View in VT →", href=f"https://www.virustotal.com/gui/search/{nid}", target="_blank", rel="noreferrer", style={"color": THEME["primary"], "fontWeight": 600, "fontSize": "13px", "textDecoration": "none"}),
                    ],
                ),
            ]
        )
        return panel, no_update, _panel_shown

    return app


def main() -> None:
    import argparse

    cfg = load_cfg()
    dash_cfg = cfg.get("dashboard", {}) or {}

    default_artifacts = DEMO_ARTIFACTS_DIR if (ROOT / DEMO_ARTIFACTS_DIR).is_dir() else "output"
    parser = argparse.ArgumentParser(description="AttribIQ dashboard")
    parser.add_argument(
        "--artifacts",
        default=default_artifacts,
        help=f"Directory holding pipeline artifacts (default: {default_artifacts})",
    )
    parser.add_argument("--port", type=int, default=int(dash_cfg.get("port", 8050)))
    args = parser.parse_args()

    art_dir = ROOT / args.artifacts
    if not art_dir.is_dir():
        print(f"[!] Artifacts directory not found: {art_dir}")
        print("    Run the pipeline first, or pass --artifacts output")
        raise SystemExit(1)

    cfg = retarget_artifacts(cfg, args.artifacts)
    label = "SYNTHETIC DEMO DATA" if cfg["DEMO_MODE"] else "REAL CAPTURE DATA"
    print(f"[i] Serving artifacts from {args.artifacts}/  ({label})")

    app = build_app(cfg)
    host = str(dash_cfg.get("host", "127.0.0.1"))
    port = int(args.port)
    browse = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    print(f"[OK] Starting Dash - listening on {host}:{port}")
    print(f"[OK] Open in your browser (this PC): http://{browse}:{port}/")
    if host in ("0.0.0.0", "::"):
        print("[i] Do not use http://0.0.0.0 in the address bar — use http://127.0.0.1 above (or your machine's LAN IP from another device).")
    try:
        app.run(host=host, port=port, debug=False)
    except OSError as e:
        print(f"[!] Could not bind port {port}: {e}")
        print(f"[!] Another dashboard is probably already running. Stop it, or use --port {port + 1}.")
        raise SystemExit(1) from e


if __name__ == "__main__":
    main()
