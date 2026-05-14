# Post-Incident Attack Attribution and Campaign Analysis
**Group 17 | Somaiya Vidyavihar University | Dept. of Information Technology**

## Project Structure
```
attack_attribution/
├── config.yaml              ← DEMO_MODE, weights, clustering, paths, dashboard
├── data/                    ← CTU-13 `.binetflow` files
├── data/iot23/              ← IoT-23 Zeek `conn.log.labeled` and/or `.pcap`
├── data/demo/               ← Synthetic demo `.binetflow` + mock_ti_responses.json
├── data/converted/          ← PCAP → CICFlowMeter CSV (auto-created)
├── src/
│   ├── demo_data_generator.py
│   ├── 01_preprocess.py     ← Unified ingest (CTU-13 + IoT-23 + Zeek + PCAP)
│   ├── 02_features.py       ← Fingerprints, scan entropy, beacon CoV, classifier
│   ├── 03_clustering.py     ← K-Means / HDBSCAN + cross-dataset flags
│   ├── 04_threat_intel.py   ← VT, AbuseIPDB, WHOIS, Shodan (mock in DEMO_MODE)
│   ├── 05_dashboard.py      ← Dash multi-tab dashboard
│   ├── 06_attribution.py    ← C(k) confidence + temporal drift + FORMULA_REGISTRY
│   ├── 07_graph.py          ← NetworkX → attack_graph.json
│   ├── 08_misp.py           ← Optional MISP search → misp_matches.json
│   └── 09_iot_labels.py     ← IoT SubLabel → family + MITRE TTP merge
├── output/                  ← Parquet, CSV, JSON artifacts
├── run_all.py               ← Full pipeline + tqdm + dashboard spawn
├── setup_demo.sh / setup_demo.bat
└── requirements.txt
```

## Quick demo (one command)
- **Linux/macOS:** `bash setup_demo.sh`
- **Windows:** `setup_demo.bat`

Each script creates a `.venv`, installs dependencies, sets `DEMO_MODE: true` in `config.yaml`, runs `python run_all.py`, and prints **Dashboard at http://127.0.0.1:8050**.

## Setup (manual)
```bash
cd attack_attribution
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run Pipeline
From the `attack_attribution` directory:

```bash
python run_all.py
```

With **`DEMO_MODE: true`**, `run_all.py` runs `src/demo_data_generator.py` first (~40k synthetic flows), then phases **01 → 02 → 03 → 04 → 06 → 09 → 07 → 08 → 05**. The dashboard is started in the **background** after summaries so the terminal walkthrough still prints.

**If the dashboard does not appear:** wait a few seconds, then open **http://127.0.0.1:8050** manually. Check **`output/dashboard.log`** for import/bind errors (for example a missing `dash-cytoscape`). To run in the foreground with errors in the terminal: `python src/05_dashboard.py`. Ensure **`config.yaml`** `dashboard.port` is free (change the port if 8050 is already in use).

Or run steps manually (order matters for merged JSON):

```bash
python src/01_preprocess.py
python src/02_features.py
python src/03_clustering.py
python src/04_threat_intel.py
python src/06_attribution.py
python src/09_iot_labels.py
python src/07_graph.py
python src/08_misp.py
python src/05_dashboard.py
```

`run_all.py` reads `config.yaml`. When no real files match globs, preprocessing can use **`demo_paths`** synthetic data.

## Dataset Download
- **CTU-13**: https://www.stratosphereips.org/datasets-ctu13  
  Place scenario **`.binetflow`** files under `data/` (see `ctu13_paths` in `config.yaml`).
- **IoT-23**: https://www.stratosphereips.org/datasets-iot23  
  Recommended labeled scenarios for variety: **1, 3, 8, 20, 42**.  
  Place **`conn.log.labeled`** under `data/iot23/`. Raw **`.pcap`** is converted with **CICFlowMeter** (install `cicflowmeter`) into `data/converted/` then unified to the same schema as CTU-13.

## Formula reference (implemented)

| Name | Formula / rule | Module |
|------|----------------|--------|
| Scan entropy | \(H(\mathrm{dst}) = -\sum_i p(\mathrm{dst}_i)\log_2 p(\mathrm{dst}_i)\), \(p(\mathrm{dst}_i)\) = flows to dst / total | `02_features.py` |
| Beacon score | \(\mathrm{CoV} = \sigma(\Delta t) / \mu(\Delta t)\) on sorted inter-arrival times | `02_features.py` |
| Payload asymmetry | \(R = \mathrm{mean}(\mathrm{SrcBytes}) / \mathrm{mean}(\mathrm{DstBytes})\) | `02_features.py` |
| Port affinity | \(PA = \|\mathrm{flows\ to\ IoT\ ports}\| / \|\mathrm{flows}\|\) (ports from `config.yaml` `iot_ports`) | `02_features.py` |
| Horizontal scan | unique DstAddr count greater than 50 and unique Dport count less than 3 | `02_features.py` |
| Vertical scan | unique Dport count greater than 20 and unique DstAddr count less than 5 | `02_features.py` |
| Attack classifier | Ordered rules → `C2_Beaconing`, `Horizontal_PortScan`, … | `02_features.py` |
| Confidence | \(C(k) = w_1 B(k) + w_2 I(k) + w_3 T(k) + w_4 M(k)\) (weights in `config.yaml`) | `06_attribution.py` |
| Temporal drift | \(\mathrm{drift}(w,w{+}1) = 1 - \cos(\mathrm{centroid}_w, \mathrm{centroid}_{w+1})\) | `06_attribution.py` |

Full text of **`FORMULA_REGISTRY`** is printed when you run `06_attribution.py` and is embedded in PDF reports from the dashboard (Tab 5).

## Demo walkthrough (~10 min)
1. **Tab 1:** Campaign timeline / bars — red under 50%, yellow 50–75%, green above 75% confidence.  
2. **Tab 1:** KPI cards — total flows vs clustered campaigns.  
3. **Tab 2:** Select a campaign — gauge + B/I/T/M bars and drift context.  
4. **Tab 2:** Click an IP in Cytoscape — VT, AbuseIPDB, ASN, Shodan (mock in demo).  
5. **Tab 3:** Factor heatmap — which component drives confidence.  
6. **Tab 4:** Replay — play/pause and watch activity over time.  
7. **Tab 5:** Filters → **Export JSON** → **Generate Incident Report (PDF)** (multi-page, includes heatmap + formulas).  
8. **Tab 6:** IoT profiler — scan entropy vs beacon score scatter.

## API keys (optional; skipped with warning if missing)
Add to **`.env`** in project root:
- **VirusTotal**, **AbuseIPDB** — see `04_threat_intel.py`
- **SHODAN_API_KEY** — Shodan host view (cached in `output/shodan_cache.json`)
- **MISP_URL**, **MISP_KEY** — `08_misp.py` → `output/misp_matches.json`

When **`DEMO_MODE: true`**, threat intel reads **`data/demo/mock_ti_responses.json`** and does not call paid APIs.
