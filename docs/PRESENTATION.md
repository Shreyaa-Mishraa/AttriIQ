# Post-Incident Attack Attribution and Campaign Analysis

**Group 17 · Department of Information Technology · Somaiya Vidyavihar University**

Project codename: **AttribIQ** · Repository: <https://github.com/Shreyaa-Mishraa/AttriIQ>

> All quantitative results in this document come from a verified run on the real
> CTU-13 dataset completed on 2026-10-04 (6 scenarios, 3,107,498 flows). Numbers
> from the synthetic demo dataset are labelled as such wherever they appear.

---

## 1. Problem Definition

During and immediately after a security incident, defenders can usually answer
*"was this host compromised?"* but not *"which hosts were part of the same
operation?"*. Intrusion detection systems and SIEM rules raise alerts one host
at a time, so a single coordinated campaign appears as hundreds of unrelated
alerts. Analysts then reconstruct the campaign manually from raw flow logs,
which is slow, inconsistent between analysts, and effectively impossible at
capture sizes of millions of flows.

The problem is further complicated because:

- **Attribution evidence is multi-dimensional.** Behavioural similarity alone is
  not proof of a shared operator; shared infrastructure, synchronised timing and
  external threat-intelligence corroboration all contribute independently.
- **Analyst conclusions are rarely quantified.** Reports state "likely the same
  actor" without a reproducible score, so two analysts can disagree with no way
  to locate the disagreement.
- **Campaigns are not static.** An operator may pivot from reconnaissance to
  exfiltration mid-incident, so a single static profile per host misrepresents
  what happened.

### Problem statement

Given raw post-incident network flow records, **group source hosts into probable
coordinated attack campaigns without prior labels, and attach to every campaign
a reproducible, decomposable numerical confidence score together with the
evidence that produced it.**

### Scope

In scope: offline (post-incident) analysis of flow-level records, unsupervised
campaign discovery, quantified multi-factor attribution, MITRE ATT&CK technique
mapping, analyst-facing visualisation, and exportable incident reporting.

Out of scope: real-time/inline detection, packet payload inspection and deep
packet inspection, malware binary analysis, and legal-grade actor naming (the
system reports behavioural campaign attribution, never a named human adversary).

---

## 2. Functional and Non-Functional Requirements

### 2.1 Functional Requirements

| ID | Requirement | Status |
|----|-------------|--------|
| FR-01 | Ingest CTU-13 `.binetflow`, IoT-23 Zeek `conn.log.labeled`, generic CSV and PCAP (via CICFlowMeter) into one unified schema | Implemented |
| FR-02 | Normalise heterogeneous sources into a single 15-field flow schema with a dataset-provenance column | Implemented |
| FR-03 | Build a behavioural fingerprint per (source IP, 1-hour window) using 19 features | Implemented |
| FR-04 | Compute scan entropy, C2 beacon score, payload asymmetry, IoT port affinity and horizontal/vertical scan flags from published formulas | Implemented |
| FR-05 | Group fingerprints into campaigns without labels, selecting cluster count automatically | Implemented (K-means; HDBSCAN and Agglomerative selectable) |
| FR-06 | Validate clustering with silhouette and Davies–Bouldin indices | Implemented |
| FR-07 | Cross-check unsupervised campaigns against a supervised benign/malicious classifier | Implemented (Random Forest) |
| FR-08 | Enrich campaign member IPs from external threat intelligence (VirusTotal, AbuseIPDB, WHOIS/ASN, Shodan) | Implemented |
| FR-09 | Compute a decomposable confidence score C(k) from behavioural, infrastructure, timing and threat-intel evidence | Implemented |
| FR-10 | Detect temporal drift in campaign behaviour across time windows | Implemented |
| FR-11 | Map campaigns to MITRE ATT&CK techniques | Implemented |
| FR-12 | Build a navigable attack graph of IPs, campaigns, ASNs and malware families with centrality ranking | Implemented |
| FR-13 | Present results in an interactive multi-tab analyst dashboard | Implemented (6 tabs) |
| FR-14 | Replay the incident chronologically | Implemented |
| FR-15 | Export the full attribution payload as JSON | Implemented |
| FR-16 | Generate a multi-page PDF incident report including the factor heatmap and formula registry | Implemented |
| FR-17 | Correlate indicators against a MISP instance | Implemented, untested (no MISP instance available) |
| FR-18 | Map IoT-23 sub-labels to malware families and techniques | Implemented, inert (IoT-23 not yet ingested) |
| FR-19 | Run the full pipeline from a single command | Implemented (`run_all.py`) |
| FR-20 | Operate on synthetic data with no API keys or licensed dataset, for demonstration | Implemented (`DEMO_MODE`) |

### 2.2 Non-Functional Requirements

| ID | Category | Requirement | Evidence / Status |
|----|----------|-------------|-------------------|
| NFR-01 | Scalability | Process ≥ 3 million flows on a commodity laptop | Met: 3,107,498 flows end-to-end |
| NFR-02 | Performance | Feature extraction to complete within ~30 min at that scale | Met: 553,781 fingerprints in ≈20 min on 8 workers |
| NFR-03 | Performance | Dashboard first paint under 15 s | Met: 11.6 s on the demo artifact set |
| NFR-04 | Memory | Stay within 16 GB RAM | Met: the O(n·d) cohesion identity replaced an n×n matrix that needed ≈80 GB at 131k fingerprints |
| NFR-05 | Reproducibility | Identical inputs must give identical outputs | Met: `random_state=42` throughout; parallel output is byte-identical to serial (TC-14) |
| NFR-06 | Transparency | Every score must be traceable to its formula | Met: `FORMULA_REGISTRY` printed by phase 06 and embedded in the PDF |
| NFR-07 | Usability | An analyst reaches per-IP evidence in ≤ 3 clicks | Met: Overview → Inspector → node click |
| NFR-08 | Security | API credentials must never be committed | Met: `.env` git-ignored; verified untracked |
| NFR-09 | Resilience | Missing API keys or unreachable services must degrade gracefully, not crash | Met: each enrichment source is independently skipped with a warning |
| NFR-10 | Portability | Run on Windows, Linux and macOS | Met: pure Python; `setup_demo.bat` and `setup_demo.sh` provided |
| NFR-11 | Honesty | Synthetic results must be visually distinguishable from real results | Met: DEMO MODE badge in the UI and a data-source line in the PDF |
| NFR-12 | Maintainability | Core formulas must be unit-tested | Met: 38 automated tests, all passing |

---

## 3. Literature Survey

### 3.1 Clustering-based botnet and campaign detection

**BotMiner** (Gu et al., USENIX Security 2008) clusters hosts on C-plane
(communication) and A-plane (activity) features and cross-correlates the two to
find bots sharing both traffic patterns and malicious activity, independent of
protocol or payload. It established that behavioural clustering can find
coordinated hosts without signatures. **BotSniffer** (Gu et al., NDSS 2008)
targeted the narrower case of centralised HTTP/IRC C2, using spatial-temporal
correlation of response crowds. **Disclosure** (Bilge et al., ACSAC 2012) scaled
C2 detection to large-scale NetFlow using flow-size, client-access-pattern and
temporal features, demonstrating that flow-level metadata alone is sufficient
and that payload inspection is not required.

*Gap addressed by this project:* all three produce a binary or clustered
detection verdict. None attaches a graded, decomposable confidence value to the
resulting group, so an analyst cannot see *why* a grouping was proposed or how
strongly each piece of evidence contributed.

### 3.2 Attribution and campaign-analysis frameworks

The **Intrusion Kill Chain** (Hutchins, Cloppert & Amin, Lockheed Martin 2011)
introduced campaign-level analysis, arguing that indicators should be linked
across intrusions to reveal a persistent adversary rather than treated as
isolated events. The **Diamond Model of Intrusion Analysis** (Caltagirone,
Pendergast & Betz, 2013) formalised attribution around four linked vertices —
adversary, capability, infrastructure, victim — and explicitly introduced a
confidence value on analytic conclusions. **MITRE ATT&CK** (Strom et al., 2018)
supplies the standard technique taxonomy used for communicating adversary
behaviour.

*Gap addressed by this project:* these are analytic doctrines applied manually by
human analysts. They prescribe *that* confidence should be recorded, but not a
computable function for it. This project operationalises the Diamond Model's
infrastructure and capability vertices as the measurable terms I(k) and B(k) of
an explicit formula.

### 3.3 Benchmark datasets

**CTU-13** (García, Grill, Stiborek & Zunino, *Computers & Security* 2014)
provides 13 real botnet captures with per-flow ground-truth labels, and its
authors' comparison of detection methods established the evaluation conventions
this project follows. **IoT-23** (Parmisano, Garcia & Erquiaga, 2020) extends
labelled captures to IoT malware families including Mirai, Okiru and Torii.
**Understanding the Mirai Botnet** (Antonakakis et al., USENIX Security 2017)
documents Mirai's telnet-scanning behaviour and is the behavioural basis for the
synthetic scanner campaign in this project's demo generator.

*Gap addressed by this project:* published work on these datasets predominantly
reports per-flow or per-host classification accuracy. Campaign-level grouping
with quantified attribution confidence is comparatively unexplored.

### 3.4 Supporting methods

Cluster quality uses the **silhouette coefficient** (Rousseeuw, 1987) and the
**Davies–Bouldin index** (Davies & Bouldin, IEEE TPAMI 1979). **HDBSCAN**
(Campello, Moulavi & Sander, PAKDD 2013) is offered as a density-based
alternative that does not require a preset cluster count. Scan dispersion is
quantified with **Shannon entropy** (Shannon, 1948). The supervised cross-check
uses **Random Forests** (Breiman, 2001). Graph pivot sampling for betweenness
centrality follows **Brandes' algorithm** (Brandes, 2001), which makes
centrality tractable on a 353,690-node graph.

### 3.5 Summary of the research gap

| Prior work | Contribution | Limitation this project addresses |
|------------|--------------|-----------------------------------|
| BotMiner, BotSniffer | Protocol-independent behavioural clustering | Binary verdict; no graded confidence |
| Disclosure | Flow-level C2 detection at scale | Per-flow focus; no campaign grouping |
| Kill Chain, Diamond Model | Campaign-level analytic doctrine | Manual; confidence not computable |
| MITRE ATT&CK | Behaviour taxonomy | Descriptive only; no scoring |
| CTU-13 / IoT-23 papers | Labelled benchmarks | Evaluated on classification accuracy, not attribution |

**This project's contribution:** an end-to-end pipeline that discovers campaigns
without labels and scores each one with an explicit, decomposable four-factor
confidence function, with every factor traceable to the evidence that produced
it and exportable as an incident report.

---

## 4. Technologies Used

| Layer | Technology | Role in the project |
|-------|-----------|---------------------|
| Language | Python 3.13 | Entire analysis pipeline |
| Data processing | pandas, NumPy, PyArrow/Parquet | Flow ingest, 19-feature extraction, columnar storage |
| Machine learning | scikit-learn | K-means, Agglomerative, StandardScaler, silhouette, Davies–Bouldin, Random Forest |
| Clustering (alt.) | hdbscan | Density-based clustering option |
| Statistics | SciPy | Pearson correlation for the timing factor T(k) |
| Graph analysis | NetworkX | Attack graph, degree and pivot-sampled betweenness centrality |
| Dashboard | Dash, Plotly, dash-cytoscape | Six-tab analyst UI, interactive graph, WebGL scatter |
| Reporting | ReportLab, Matplotlib (Agg) | Multi-page PDF incident report with embedded factor heatmap |
| Threat intelligence | VirusTotal API v3, AbuseIPDB v2, ipwhois, Shodan, PyMISP | External corroboration for factor M(k) |
| Parallelism | concurrent.futures ProcessPoolExecutor | 8-worker feature extraction |
| Config & secrets | PyYAML, python-dotenv | `config.yaml` for parameters, `.env` for API keys |
| PCAP conversion | CICFlowMeter | Converts raw `.pcap` to flow CSV |
| Testing | pytest | 38 automated test cases |
| Web frontend | React 18, Vite 5, Tailwind CSS 3 | Standalone browser UI ("AttribIQ") |
| Frontend libraries | recharts, react-force-graph-2d, PapaParse, lucide-react, Web Workers | Charts, force-directed graph, in-browser CSV parsing and pipeline |
| Version control | Git, GitHub | <https://github.com/Shreyaa-Mishraa/AttriIQ> |
| Datasets | CTU-13, IoT-23 (Stratosphere Laboratory, CTU Prague) | Evaluation data |

---

## 5. Status of Work Completed (End of Semester VI → Current Date)

### 5.1 Baseline at end of Semester VI (15 May 2026)

Verified from Git history — commits `ee24349` and `5db3cdc`, both dated
15 May 2026:

- All nine pipeline phases existed and ran end-to-end.
- The six-tab Dash dashboard and the React frontend existed.
- The project ran on **synthetic demo data only** (40,000 generated flows).
- Confidence, drift and all feature formulas were implemented.
- No automated tests; no real-dataset validation.

### 5.2 Work completed since then (current: 4 October 2026)

| # | Work item | Outcome |
|---|-----------|---------|
| 1 | **Migrated from synthetic to real data** | Six bot-dense CTU-13 scenarios (4, 5, 7, 10, 11, 12) extracted and ingested: 3,107,498 real flows |
| 2 | **Fixed silent synthetic fallback** | The pipeline previously fell back to demo data when globs failed, with no warning; it now warns loudly. A second defect mixed 40,000 synthetic rows into the real run and was fixed with an explicit exclusion list |
| 3 | **Scaled the pipeline ~78× in data volume** | Four independent scalability defects found and fixed (detailed in §6.5) |
| 4 | **Parallelised feature extraction** | 8-worker sharding, ~4× faster, output verified byte-identical to serial |
| 5 | **Verified live threat-intelligence integration** | VirusTotal and AbuseIPDB confirmed returning live data; WHOIS resolved 47/50 IPs to real ASN owners |
| 6 | **Built the reporting subsystem** | Reports tab with JSON export and a multi-page PDF incident report (previously documented but absent) |
| 7 | **Built the IoT Profiler tab** | Scan-entropy vs beacon-score scatter with labelled-malicious overlay |
| 8 | **Separated demo and real artifact sets** | `--artifacts` / `--port` flags let a synthetic presentation dashboard and a real-data dashboard run concurrently |
| 9 | **Created the test suite** | 38 pytest cases covering ingest, all feature formulas, clustering, every confidence factor, drift, graph and reporting — all passing |
| 10 | **Found and fixed defects via testing** | A latent crash on datasets without a `Sport` column, an AbuseIPDB null-ISP crash, a threat-intel prioritisation defect that enriched the wrong IPs, and a frontend `NaN%` display bug |
| 11 | **Repository hygiene** | Dataset exclusion rules added; verified no credentials tracked |

### 5.3 Current completion status

| Component | Status |
|-----------|--------|
| Phases 01–07, 09 on real data | Complete and verified |
| Phase 08 (MISP) | Code complete, untested — requires a MISP instance |
| IoT-23 ingest | Loader implemented, data not yet ingested |
| Dashboard (6 tabs) | Complete |
| JSON + PDF reporting | Complete |
| Test suite | Complete (38 cases) |
| React frontend | Functional, independent of the Python pipeline |
| Research paper | See §8 |

---

## 6. Implementation Details, Results and Discussion

### 6.1 Architecture

A nine-phase pipeline; each phase reads the previous phase's artifact, so any
phase can be re-run independently.

```
Raw captures (CTU-13 .binetflow / IoT-23 Zeek / PCAP)
  → 01 Preprocess      unified 15-field schema        → unified_flows.parquet
  → 02 Features        19 features per (IP, 1h)       → features_iot_extended.parquet
  → 03 Clustering      K-means + silhouette + RF      → 03_campaigns.csv
  → 04 Threat Intel    VT / AbuseIPDB / WHOIS / Shodan→ 04_enriched.csv
  → 06 Attribution     C(k) confidence + drift        → attribution_scores.json
  → 09 IoT Labels      family + MITRE TTP mapping     → attribution_scores.json
  → 07 Graph           NetworkX + centrality          → attack_graph.json
  → 08 MISP (optional) indicator correlation          → misp_matches.json
  → 05 Dashboard       6-tab UI + JSON/PDF export
```

### 6.2 Behavioural fingerprinting (19 features)

Each source IP is profiled per 1-hour window across four groups:

- **Volume (4):** connection count, unique destination IPs, unique destination
  ports, protocol diversity
- **Size and shape (3):** average bytes, bytes per packet, average duration
- **Behavioural signatures (10):** scan score, scan entropy, horizontal and
  vertical scan flags, C2 beacon score, payload asymmetry, source-byte ratio,
  night ratio, burst score, protocol entropy
- **IoT-specific (2):** IoT port affinity, device role score

Key formulas, all implemented exactly as published in the formula registry:

- Scan entropy: $H(\mathrm{dst}) = -\sum_i p(\mathrm{dst}_i)\log_2 p(\mathrm{dst}_i)$
- Beacon score: $\mathrm{CoV} = \sigma(\Delta t)/\mu(\Delta t)$ over sorted inter-arrival times
- Payload asymmetry: $R = \mathrm{mean}(\mathrm{SrcBytes})/\mathrm{mean}(\mathrm{DstBytes})$
- Port affinity: $PA = |\{f : \mathrm{Dport}(f) \in \mathcal{P}_{IoT}\}| / |\mathrm{flows}|$
- Horizontal scan: unique destinations > 50 **and** unique ports < 3
- Vertical scan: unique ports > 20 **and** unique destinations < 5

### 6.3 Attribution confidence

$$C(k) = w_1 B(k) + w_2 I(k) + w_3 T(k) + w_4 M(k), \quad w = (0.35,\ 0.25,\ 0.20,\ 0.20)$$

| Factor | Meaning | Computation |
|--------|---------|-------------|
| B(k) | Behavioural cohesion | Mean pairwise cosine similarity of member fingerprints |
| I(k) | Infrastructure overlap | Fraction sharing the majority ASN or /24 |
| T(k) | Timing correlation | $\lvert \mathrm{Pearson}(\text{cluster hourly}, \text{global hourly}) \rvert$ |
| M(k) | Threat-intel corroboration | Fraction with VirusTotal malicious > 0 **or** AbuseIPDB > 25 |

Temporal drift: $\mathrm{drift}(w,w{+}1) = 1 - \cos(\mathrm{centroid}_w, \mathrm{centroid}_{w+1})$,
flagged above 0.15.

### 6.4 Results on real CTU-13 data

**Dataset (verified 2026-10-04)**

| Metric | Value |
|--------|-------|
| Scenarios | 6 (CTU-13 #4, 5, 7, 10, 11, 12) |
| Malware families | 4 (Rbot, Virut, Sogou, NSIS.ay) |
| Total flows | 3,107,498 |
| Labelled malicious | 120,228 (3.9%) |
| Benign | 2,987,270 |
| Unique source IPs | 353,674 |
| Unique destination IPs | 184,496 |
| Capture window | 2011-08-15 10:42 → 2011-08-19 11:45 |
| Behavioural fingerprints | 553,781 |

**Clustering**

| Metric | Value |
|--------|-------|
| Selected k | 2 (silhouette-optimal over k = 2…10) |
| Silhouette score | **0.7344** |
| Davies–Bouldin index | 0.9071 |
| Campaign 0 | 536,329 fingerprints — *Reconnaissance / Scanning* (scan score 0.955) |
| Campaign 1 | 17,452 fingerprints — *Benign / Unknown* (burst score 0.092) |

A silhouette of 0.73 indicates strong, well-separated structure; the clustering
cleanly isolates a high-scan-score population from a bursty low-scan population.

**Supervised cross-check (Random Forest)**

| Class | Precision | Recall | F1 | Support |
|-------|-----------|--------|----|---------|
| Benign | 1.00 | 1.00 | 1.00 | 110,741 |
| Malicious | 1.00 | 0.75 | **0.86** | 16 |

Perfect precision with 0.75 recall on an extreme 1:6921 class imbalance: every
host flagged malicious truly was, while one quarter of infected hosts were
missed. This is the expected trade-off at this imbalance and is reported honestly
rather than rebalanced to inflate the figure.

**Attribution**

| Campaign | B | I | T | M | C(k) | Top TTP |
|----------|------|--------|-------|------|--------|---------|
| 0 | 0.7872 | 0.0004 | 0.9970 | 0.00 | **47.50%** | T1046 |
| 1 | 0.7830 | 0.0085 | 0.9988 | 0.00 | **47.59%** | — |

**Threat intelligence** — 50 IPs enriched. WHOIS resolved 47/50 to real
organisations, including **AS2852 CESNET** (the Czech academic network where
CTU-13 was actually captured), China Unicom, AT&T and Chulalongkorn University.
This independently confirms the ASN pipeline is correct.

**Attack graph** — 353,690 nodes and 357,883 edges; betweenness approximated with
500 Brandes pivots.

### 6.5 Scalability engineering (3M-flow milestone)

Moving from 40,000 synthetic flows to 3.1 million real flows exposed four
defects that were individually fatal:

| Defect | Original cost | Fix | Result |
|--------|---------------|-----|--------|
| Behavioural cohesion built an n×n similarity matrix | ≈80 GB RAM at 131k fingerprints | Exact identity $\sum_{i,j} u_i\!\cdot\!u_j = \lVert\sum u_i\rVert^2$ on L2-normalised rows | O(n·d), exact to 1e-16 |
| `silhouette_score` called 9× in the k-sweep | O(n²) per call | Deterministic 20,000-point subsample | Phase 03 in ~135 s |
| Exact betweenness centrality | O(V·E) on 353k nodes | 500-pivot Brandes sampling | Phase 07 in ~5 min |
| Replay timeline shipped every unique timestamp to the browser | ≈100 MB `dcc.Store` | Downsample to 1,500 evenly spaced steps | Dashboard loads in 11.6 s |

Additionally, graph rendering caps display at 3,000 IP nodes per campaign by
degree centrality (6,016 nodes kept, 347,674 dropped), and feature extraction was
parallelised across 8 processes with byte-identical output.

### 6.6 Discussion

**The confidence score behaves correctly, and the reason it is low is itself the
finding.** Both campaigns score ≈47.5%, which the system correctly bands as LOW.
Decomposing the score shows exactly why, which is the central value of the
four-factor design:

- **B ≈ 0.79** — members genuinely behave alike. The behavioural evidence is strong.
- **T ≈ 1.00** — near-perfect timing correlation, but this factor is weak evidence
  here: with 536,329 of 553,781 fingerprints in one cluster, that cluster's
  hourly profile is necessarily the global profile. T(k) is close to tautological
  for a dominant cluster, and is a known limitation.
- **I ≈ 0.0004** — essentially zero infrastructure overlap. 353,674 source IPs
  spread across thousands of ASNs, so almost no pair shares an ASN or /24. On
  the synthetic demo set, where each campaign is generated inside one ASN, this
  factor is 1.00 — the contrast quantifies how much easier synthetic data is.
- **M = 0.00** — no threat-intel corroboration. **This is a genuine result, not a
  failure.** Both APIs were verified live during this run: a control probe
  returned 13 VirusTotal malicious engines and an AbuseIPDB score of 100 with 361
  reports. The CTU-13 hosts return zero because they are 2011 university-lab
  addresses with no present-day reputation. Reputation feeds are therefore
  near-useless for historical captures — a real methodological limitation of
  threat-intel-weighted attribution.

**The dominant limitation is single-flow fingerprints.** 491,917 of 553,781
fingerprints (**89%**) are built from a single flow. A one-flow window has no
computable inter-arrival time, no entropy and no burst behaviour, so it carries
almost no signal yet still participates in clustering. This is why k=2 collapses
to one giant cluster plus a small one. Filtering these out before clustering is
the single highest-value next step.

**Honest appraisal.** The pipeline demonstrably works end-to-end on real data at
scale, the formulas are implemented exactly as published, and the scores are
reproducible and decomposable. What it does *not* yet do is produce
sharply-separated campaigns on real traffic — real background traffic is far
messier than the synthetic demo, and the synthetic demo's 80–99% confidence
figures should be read as an upper bound achievable only on clean data.

---

## 7. Software Test Cases

Suite: `tests/test_pipeline.py` (+ `tests/conftest.py`) · Framework: pytest
Run with `python -m pytest tests -q` · **Result: 38 passed, 0 failed (14.3 s)**

### 7.1 Test case summary

| ID | Test case | Input | Expected result | Status |
|----|-----------|-------|-----------------|--------|
| TC-01 | CTU-13 parsed to unified schema | 2-row `.binetflow` | Unified columns present, source tagged CTU-13, timestamps parsed by `clean()` | Pass |
| TC-02 | Malicious labelling | `From-Botnet` + `Background` rows | Botnet row flagged 1, background 0 | Pass |
| TC-03 | Invalid rows dropped | Row with empty `SrcAddr` | Row removed during cleaning | Pass |
| TC-04 | Demo exclusion (regression) | Real + demo file, demo excluded | Only the real file selected | Pass |
| TC-05 | Scan entropy formula | 4 equiprobable destinations | H = 2.0 bits | Pass |
| TC-06 | Scan entropy lower bound | Single destination | H = 0.0 | Pass |
| TC-07 | Beacon score, periodic | Fixed 30 s intervals | CoV = 0 (strongest beacon) | Pass |
| TC-08 | Beacon score, irregular | Irregular gaps | CoV > 0.5 | Pass |
| TC-09 | Payload asymmetry | mean Src 1000 / mean Dst 100 | R = 10.0 | Pass |
| TC-10 | IoT port affinity | 2 of 4 flows on IoT ports | PA = 0.5 | Pass |
| TC-11 | Horizontal scan rule | 60 destinations, 1 port | Flag true; narrow case false | Pass |
| TC-12 | Vertical scan rule | 30 ports, 1 destination | Vertical true, horizontal false | Pass |
| TC-13 | Attack classifier precedence | Feature rows per branch | C2_Beaconing / Horizontal / Vertical / Exfiltration / Unknown | Pass |
| TC-14 | Parallel = serial (regression) | 480 flows, 12 IPs | 1-worker and 4-worker outputs byte-identical | Pass |
| TC-15 | Missing optional columns (regression) | Flows without `Sport`/`SrcBytes` | Extraction completes, values finite | Pass |
| TC-16 | Silhouette exactness | 2 separated blobs | Scalable silhouette = exact sklearn value | Pass |
| TC-17 | Optimal k recovery | 3 separated blobs | k = 3 selected | Pass |
| TC-18 | K-means separation | 2 distinct profiles | Each profile wholly in its own cluster | Pass |
| TC-19 | Cohesion identity (regression) | 120×8 random matrix | Matches sklearn pairwise mean to 1e-12 | Pass |
| TC-20 | Cohesion with zero rows | Zero + unit rows | Finite, within [0,1], no NaN | Pass |
| TC-21 | Infrastructure overlap I(k) | 3 of 4 IPs share ASN and /24 | I = 0.75 | Pass |
| TC-22 | Timing correlation T(k) | Campaign = whole population | T = 1.0 | Pass |
| TC-23 | Threat match M(k) | VT 3 / abuse 90 / abuse 10 / none | M = 0.5 (threshold 25 respected) | Pass |
| TC-24 | Confidence weighted sum | All factors 1, then 0 | C = 1.0 and 0.0; weights verified | Pass |
| TC-25 | Confidence reproduces real result | Measured CTU-13 factors | C = 47.5% (matches reported figure) | Pass |
| TC-26 | Drift detection | Orthogonal window centroids | drift = 1.0, flag raised | Pass |
| TC-27 | Drift suppression | Stable centroid | drift = 0.0, no flag | Pass |
| TC-28 | Graph construction | 2 IPs, 1 campaign, 1 ASN | Nodes and edges created with types | Pass |
| TC-29 | Centrality annotation | 6-IP graph | Every node has finite degree centrality | Pass |
| TC-30 | IoT sub-label mapping | `PartOfAHorizontalPortScan`, `C&C-Torii` | Scanner/T1046; Torii/T1573 | Pass |
| TC-31 | Unknown label not guessed | Unrecognised sub-label | Returns Unknown IoT, no false attribution | Pass |
| TC-32 | Artifact retargeting | Config with `output/` paths | Rewritten to `output_demo/`, DEMO_MODE set | Pass |
| TC-33 | Graph display cap | 3,050 IP nodes | Top 3,000 by centrality kept, edges pruned consistently | Pass |
| TC-34 | Replay downsampling | 4,500 timestamps | ≤ 1,500 ordered steps | Pass |
| TC-35 | Small capture fidelity | 25 timestamps | All 25 retained | Pass |
| TC-36 | Factor heatmap rendering | 2 campaigns | Valid PNG produced | Pass |
| TC-37 | PDF incident report | Full report payload | Valid multi-page PDF (`%PDF-`…`%%EOF`) | Pass |
| TC-38 | Empty selection | No campaigns | Returns nothing instead of erroring | Pass |

### 7.2 Coverage by phase

| Phase | Cases |
|-------|-------|
| 01 Preprocess | TC-01 … TC-04 |
| 02 Features | TC-05 … TC-15 |
| 03 Clustering | TC-16 … TC-18 |
| 06 Attribution | TC-19 … TC-27 |
| 07 Graph | TC-28, TC-29 |
| 09 IoT labels | TC-30, TC-31 |
| 05 Dashboard & reporting | TC-32 … TC-38 |

### 7.3 Defects found by testing

| Defect | Detected by | Severity | Status |
|--------|-------------|----------|--------|
| Feature extraction crashed (`AttributeError`) on any dataset lacking a `Sport` column — would have broken all Zeek/CICFlowMeter ingest | TC-15 | High | Fixed (`_numeric_col` helper) |
| Synthetic demo rows silently merged into real runs | TC-04 | High | Fixed (explicit exclusion) |
| Cohesion used an n×n matrix (≈80 GB at scale) | TC-19 | Critical | Fixed (exact O(n·d) identity) |
| AbuseIPDB null ISP wrote a `TypeError` string into the CSV | Manual run | Medium | Fixed |
| Threat intel enriched the first 25 IPs per campaign, missing the actual bots | Manual run | High | Fixed (prioritisation) |
| Frontend displayed `NaN%` confidence | Vite build warning | Low | Fixed (operator precedence) |

### 7.4 Integration and system testing performed

- Full pipeline executed end-to-end on 3,107,498 real flows; all phases produced
  artifacts without error.
- Live API integration verified against a control IP (VirusTotal: 13 malicious
  engines; AbuseIPDB: score 100, 361 reports).
- Dashboard verified in-browser: all six tabs render, campaign selection works,
  and both the JSON and PDF exports were exercised (PDF: 49 KB, 3 campaigns).
- Concurrent demo and real dashboards verified on separate ports.

### 7.5 Known untested areas

- Phase 08 (MISP) — requires a live MISP instance.
- Phase 09 IoT family mapping is unit-tested but has never run on real IoT-23 data.
- The React frontend has no automated tests.

---

## 8. Status of Research Paper

*To be completed by the team.* Suggested structure for this slide:

| Field | Detail |
|-------|--------|
| Paper title | *(to fill)* |
| Target venue / journal | *(to fill)* |
| Current stage | Draft / Submitted / Under review / Accepted *(to fill)* |
| Submission date | *(to fill)* |
| Manuscript link | *(to fill)* |

Results from this work that are strong enough to carry a paper:

1. A decomposable four-factor attribution confidence function, validated at
   3.1M-flow scale, where each factor is independently interpretable.
2. The empirical finding that **reputation-based threat intelligence contributes
   nothing to historical-capture attribution** (M = 0 across all 50 enriched
   hosts, with live API operation independently verified) — a concrete limitation
   of threat-intel-weighted attribution models.
3. The finding that **89% of 1-hour behavioural fingerprints in real CTU-13
   traffic are single-flow**, which dominates and degrades clustering — a
   measurement that argues for minimum-activity thresholds in flow-window
   fingerprinting.
4. The exact O(n·d) reformulation of mean pairwise cosine similarity that makes
   cohesion computable on 550k fingerprints instead of requiring ≈80 GB.

---

## 9. List of References

1. García, S., Grill, M., Stiborek, J., & Zunino, A. (2014). An empirical comparison of botnet detection methods. *Computers & Security*, 45, 100–123. (CTU-13 dataset)
2. Gu, G., Perdisci, R., Zhang, J., & Lee, W. (2008). BotMiner: Clustering analysis of network traffic for protocol- and structure-independent botnet detection. *USENIX Security Symposium*.
3. Gu, G., Zhang, J., & Lee, W. (2008). BotSniffer: Detecting botnet command and control channels in network traffic. *NDSS*.
4. Bilge, L., Balzarotti, D., Robertson, W., Kirda, E., & Kruegel, C. (2012). Disclosure: Detecting botnet command and control servers through large-scale NetFlow analysis. *ACSAC*.
5. Antonakakis, M., April, T., Bailey, M., Bernhard, M., Bursztein, E., Cochran, J., et al. (2017). Understanding the Mirai botnet. *USENIX Security Symposium*.
6. Parmisano, A., Garcia, S., & Erquiaga, M. J. (2020). *A labeled dataset with malicious and benign IoT network traffic*. Stratosphere Laboratory. (IoT-23 dataset)
7. Hutchins, E. M., Cloppert, M. J., & Amin, R. M. (2011). Intelligence-driven computer network defense informed by analysis of adversary campaigns and intrusion kill chains. *Leading Issues in Information Warfare & Security Research*.
8. Caltagirone, S., Pendergast, A., & Betz, C. (2013). *The Diamond Model of Intrusion Analysis*. Center for Cyber Intelligence Analysis and Threat Research.
9. Strom, B. E., Applebaum, A., Miller, D. P., Nickels, K. C., Pennington, A. G., & Thomas, C. B. (2018). *MITRE ATT&CK: Design and Philosophy*. MITRE Technical Report.
10. Rousseeuw, P. J. (1987). Silhouettes: A graphical aid to the interpretation and validation of cluster analysis. *Journal of Computational and Applied Mathematics*, 20, 53–65.
11. Davies, D. L., & Bouldin, D. W. (1979). A cluster separation measure. *IEEE Transactions on Pattern Analysis and Machine Intelligence*, 1(2), 224–227.
12. Campello, R. J. G. B., Moulavi, D., & Sander, J. (2013). Density-based clustering based on hierarchical density estimates. *PAKDD*. (HDBSCAN)
13. Breiman, L. (2001). Random forests. *Machine Learning*, 45(1), 5–32.
14. Brandes, U. (2001). A faster algorithm for betweenness centrality. *Journal of Mathematical Sociology*, 25(2), 163–177.
15. Shannon, C. E. (1948). A mathematical theory of communication. *Bell System Technical Journal*, 27(3), 379–423.
16. Lashkari, A. H., Draper-Gil, G., Mamun, M. S. I., & Ghorbani, A. A. (2017). Characterization of Tor traffic using time based features. *ICISSP*. (CICFlowMeter)
17. Pedregosa, F., et al. (2011). Scikit-learn: Machine learning in Python. *Journal of Machine Learning Research*, 12, 2825–2830.
18. Hagberg, A. A., Schult, D. A., & Swart, P. J. (2008). Exploring network structure, dynamics, and function using NetworkX. *Proceedings of the 7th Python in Science Conference (SciPy)*.

---

## 10. Supporting Links

| Resource | Link |
|----------|------|
| GitHub repository | <https://github.com/Shreyaa-Mishraa/AttriIQ> |
| Latest commit (real-data migration, reporting, tests) | <https://github.com/Shreyaa-Mishraa/AttriIQ/commit/eec916f> |
| Project README (setup, formulas, walkthrough) | <https://github.com/Shreyaa-Mishraa/AttriIQ/blob/main/README.md> |
| Test suite | <https://github.com/Shreyaa-Mishraa/AttriIQ/blob/main/tests/test_pipeline.py> |
| Formula registry (source) | <https://github.com/Shreyaa-Mishraa/AttriIQ/blob/main/src/06_attribution.py> |
| CTU-13 dataset | <https://www.stratosphereips.org/datasets-ctu13> |
| IoT-23 dataset | <https://www.stratosphereips.org/datasets-iot23> |
| MITRE ATT&CK | <https://attack.mitre.org/> |
| VirusTotal API | <https://developers.virustotal.com/reference/ip-info> |
| AbuseIPDB API | <https://docs.abuseipdb.com/> |
| SRS document | *(to add)* |
| Project report | *(to add)* |
| Demo video | *(to add)* |
| Research paper | *(to add — see §8)* |

---

## Appendix A — Live demonstration script (~10 minutes)

1. **Terminal** — `python run_all.py` on real CTU-13: show "3,107,498 flows,
   `DatasetSource: CTU-13`" proving real data.
2. **Tab 1 Overview** — campaign timeline and KPI cards.
3. **Tab 2 Inspector** — select a campaign; show the confidence gauge and the
   B/I/T/M bars; click an IP node to reveal **AS2852 CESNET**, the network where
   CTU-13 was captured.
4. **Tab 3 Heatmap** — show visually that I and M are the factors suppressing
   confidence, not B.
5. **Tab 4 Replay** — play the incident chronologically.
6. **Tab 5 Reports** — export JSON, then generate the PDF incident report.
7. **Tab 6 IoT Profiler** — scan entropy vs beacon score, with labelled bots
   overlaid in red.
8. **Terminal** — `python -m pytest tests -q` → **38 passed**.

## Appendix B — Reproducing the results

```bash
cd attack_attribution
python -m venv .venv && .venv\Scripts\activate   # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt

# Real CTU-13 run (DEMO_MODE: false in config.yaml)
python run_all.py

# Synthetic demo dashboard (no dataset or API keys required)
python src/05_dashboard.py --artifacts output_demo

# Real-data dashboard alongside the demo one
python src/05_dashboard.py --artifacts output --port 8051

# Tests
python -m pytest tests -q
```
