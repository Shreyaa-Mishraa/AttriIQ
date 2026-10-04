"""Unit tests for the attack-attribution pipeline.

Each test maps to a numbered test case (TC-xx) in the project report. Tests cover
the deterministic core: ingest schema, the published feature formulas, the C(k)
confidence factors, drift, and the dashboard/report helpers. Live threat-intel
lookups are not tested here because they depend on third-party availability.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest


# ─────────────────────────────── helpers ────────────────────────────────


def _flows(rows: list[dict]) -> pd.DataFrame:
    """Flow frame with the columns the feature functions read."""
    df = pd.DataFrame(rows)
    if "StartTime" in df.columns:
        df["StartTime"] = pd.to_datetime(df["StartTime"])
    return df


def _binetflow(tmp_path, rows: list[str]) -> str:
    header = "StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label"
    p = tmp_path / "capture.binetflow"
    p.write_text("\n".join([header, *rows]) + "\n", encoding="utf-8")
    return str(p)


# ───────────────────── Phase 01: ingest and cleaning ────────────────────


class TestIngest:
    def test_tc01_ctu13_parses_to_unified_schema(self, preprocess, tmp_path):
        """TC-01: a CTU-13 .binetflow is parsed into the unified schema."""
        path = _binetflow(
            tmp_path,
            [
                "2011/08/15 10:42:52.613,0.26,tcp,147.32.84.165,1043,->,10.0.0.5,23,INT,0,0,4,240,180,flow=From-Botnet-V42",
                "2011/08/15 10:42:53.001,1.10,udp,147.32.84.59,53,->,8.8.8.8,53,CON,0,0,2,120,60,flow=Background",
            ],
        )
        df = preprocess.auto_detect_load(path)

        assert len(df) == 2
        for col in ("StartTime", "SrcAddr", "DstAddr", "Dport", "Proto", "Label"):
            assert col in df.columns
        assert df["DatasetSource"].eq("CTU-13").all()
        # Timestamps are parsed in clean(), not in the loader.
        assert pd.api.types.is_datetime64_any_dtype(preprocess.clean(df)["StartTime"])

    def test_tc02_botnet_label_marked_malicious(self, preprocess, tmp_path):
        """TC-02: 'From-Botnet' is malicious and 'Background' is not."""
        path = _binetflow(
            tmp_path,
            [
                "2011/08/15 10:42:52.613,0.26,tcp,147.32.84.165,1043,->,10.0.0.5,23,INT,0,0,4,240,180,flow=From-Botnet-V42",
                "2011/08/15 10:42:53.001,1.10,udp,147.32.84.59,53,->,8.8.8.8,53,CON,0,0,2,120,60,flow=Background",
            ],
        )
        df = preprocess.clean(preprocess.auto_detect_load(path))

        by_ip = df.set_index("SrcAddr")["is_malicious"].to_dict()
        assert by_ip["147.32.84.165"] == 1
        assert by_ip["147.32.84.59"] == 0

    def test_tc03_clean_drops_rows_missing_key_fields(self, preprocess, tmp_path):
        """TC-03: rows with no source address are dropped during cleaning."""
        path = _binetflow(
            tmp_path,
            [
                "2011/08/15 10:42:52.613,0.26,tcp,147.32.84.165,1043,->,10.0.0.5,23,INT,0,0,4,240,180,flow=Background",
                "2011/08/15 10:42:54.613,0.26,tcp,,1043,->,10.0.0.6,23,INT,0,0,4,240,180,flow=Background",
            ],
        )
        cleaned = preprocess.clean(preprocess.auto_detect_load(path))
        assert len(cleaned) == 1
        assert cleaned["SrcAddr"].iloc[0] == "147.32.84.165"

    def test_tc04_expand_inputs_honours_exclude(self, preprocess, tmp_path):
        """TC-04: excluded demo files never enter the real-dataset file list.

        Regression test: without this the synthetic demo capture was silently
        concatenated onto the real CTU-13 run.
        """
        (tmp_path / "data").mkdir()
        real = tmp_path / "data" / "real.binetflow"
        demo = tmp_path / "data" / "synthetic_demo.binetflow"
        real.write_text("x", encoding="utf-8")
        demo.write_text("x", encoding="utf-8")

        found = preprocess.expand_inputs(["data/*.binetflow"], tmp_path)
        assert {p.name for p in found} == {"real.binetflow", "synthetic_demo.binetflow"}

        filtered = preprocess.expand_inputs(["data/*.binetflow"], tmp_path, exclude=[demo])
        assert {p.name for p in filtered} == {"real.binetflow"}


# ───────────────── Phase 02: behavioral feature formulas ────────────────


class TestFeatureFormulas:
    def test_tc05_scan_entropy_matches_shannon_formula(self, features):
        """TC-05: H(dst) = -sum p*log2(p); 4 equiprobable destinations give 2 bits."""
        df = _flows([{"DstAddr": f"10.0.0.{i}"} for i in range(1, 5)])
        assert features.compute_scan_entropy(df) == pytest.approx(2.0)

    def test_tc06_scan_entropy_zero_for_single_destination(self, features):
        """TC-06: a single destination carries no scanning information."""
        df = _flows([{"DstAddr": "10.0.0.1"} for _ in range(10)])
        assert features.compute_scan_entropy(df) == 0.0

    def test_tc07_beacon_score_zero_for_perfect_periodicity(self, features):
        """TC-07: fixed 30 s intervals give CoV = 0, the strongest beacon signal."""
        base = pd.Timestamp("2024-01-01 00:00:00")
        df = _flows([{"StartTime": base + pd.Timedelta(seconds=30 * i)} for i in range(20)])
        assert features.compute_beacon_score(df) == pytest.approx(0.0, abs=1e-9)

    def test_tc08_beacon_score_higher_for_irregular_traffic(self, features):
        """TC-08: irregular human-like gaps score well above a periodic beacon."""
        base = pd.Timestamp("2024-01-01 00:00:00")
        offsets = [0, 1, 2, 90, 91, 400, 401, 402, 1500]
        df = _flows([{"StartTime": base + pd.Timedelta(seconds=s)} for s in offsets])
        assert features.compute_beacon_score(df) > 0.5

    def test_tc09_payload_asymmetry_is_src_over_dst_mean(self, features):
        """TC-09: R = mean(SrcBytes)/mean(DstBytes) detects outbound-heavy flows."""
        df = _flows([{"SrcBytes": 900, "DstBytes": 100}, {"SrcBytes": 1100, "DstBytes": 100}])
        assert features.compute_payload_asymmetry(df) == pytest.approx(10.0)

    def test_tc10_port_affinity_counts_iot_ports_only(self, features):
        """TC-10: PA is the fraction of flows aimed at configured IoT ports."""
        df = _flows([{"Dport": p} for p in (23, 2323, 443, 80)])
        assert features.compute_port_affinity(df, {23, 2323}) == pytest.approx(0.5)

    def test_tc11_horizontal_scan_flag_rule(self, features):
        """TC-11: horizontal scan = >50 destinations on <3 ports."""
        wide = _flows([{"DstAddr": f"10.0.{i // 256}.{i % 256}", "Dport": 23} for i in range(60)])
        narrow = _flows([{"DstAddr": "10.0.0.1", "Dport": 23} for _ in range(60)])
        assert features.compute_horizontal_scan(wide) is True
        assert features.compute_horizontal_scan(narrow) is False

    def test_tc12_vertical_scan_flag_rule(self, features):
        """TC-12: vertical scan = >20 ports against <5 destinations."""
        deep = _flows([{"DstAddr": "10.0.0.1", "Dport": 1000 + i} for i in range(30)])
        assert features.compute_vertical_scan(deep) is True
        assert features.compute_horizontal_scan(deep) is False

    def test_tc13_attack_classifier_rule_precedence(self, features):
        """TC-13: the ordered rule set returns the documented attack labels."""
        assert features.classify_attack_type({"c2_beacon_score": 0.1, "payload_asymmetry": 0.2}) == "C2_Beaconing"
        assert (
            features.classify_attack_type(
                {"c2_beacon_score": 2.0, "scan_entropy": 5.0, "horizontal_scan_flag": 1}
            )
            == "Horizontal_PortScan"
        )
        assert features.classify_attack_type({"c2_beacon_score": 2.0, "vertical_scan_flag": 1}) == "Vertical_PortScan"
        assert features.classify_attack_type({"c2_beacon_score": 2.0, "payload_asymmetry": 50.0}) == "Data_Exfiltration"
        assert features.classify_attack_type({"c2_beacon_score": 2.0}) == "Unknown"

    def test_tc14_parallel_extraction_matches_serial(self, features):
        """TC-14: sharded multi-process extraction is identical to the serial path.

        Guards the phase-02 speed-up: correctness must not depend on worker count.
        """
        base = pd.Timestamp("2024-01-01 00:00:00")
        rows = []
        for ip in range(12):
            for j in range(40):
                rows.append(
                    {
                        "StartTime": base + pd.Timedelta(seconds=37 * j + ip),
                        "SrcAddr": f"192.168.1.{ip}",
                        "DstAddr": f"10.0.0.{j % 17}",
                        "Dport": (23 if j % 3 == 0 else 443),
                        "Proto": "tcp",
                        "Dur": 0.1,
                        "SrcBytes": 100 + j,
                        "DstBytes": 50 + j,
                        "TotPkts": 4,
                        "Label": 0,
                    }
                )
        df = _flows(rows)

        serial = features.extract_features(df.copy(), iot_ports={23}, jobs=1)
        parallel = features.extract_features(df.copy(), iot_ports={23}, jobs=4)
        pd.testing.assert_frame_equal(serial, parallel)

    def test_tc15_extraction_survives_missing_optional_columns(self, features):
        """TC-15: extraction works on sources lacking Sport/SrcBytes (Zeek, CICFlowMeter).

        Regression test: a missing column used to reach .fillna() on a bare int and
        crash phase 02 with AttributeError.
        """
        base = pd.Timestamp("2024-01-01 00:00:00")
        df = _flows(
            [
                {
                    "StartTime": base + pd.Timedelta(seconds=10 * j),
                    "SrcAddr": "10.0.0.1",
                    "DstAddr": f"10.0.1.{j}",
                    "Dport": 23,
                    "Proto": "tcp",
                    "Dur": 0.2,
                    "TotPkts": 3,
                }
                for j in range(8)
            ]
        )

        out = features.extract_features(df, iot_ports={23}, jobs=1)

        assert len(out) == 1
        assert out["conn_count"].iloc[0] == 8
        assert np.isfinite(out["device_role_score"].iloc[0])
        assert np.isfinite(out["src_bytes_ratio"].iloc[0])


# ──────────────── Phase 03: clustering and model selection ──────────────


class TestClustering:
    def test_tc16_silhouette_exact_below_sampling_cap(self, clustering):
        """TC-16: the scalable silhouette equals the exact score on small inputs."""
        from sklearn.metrics import silhouette_score

        rng = np.random.default_rng(0)
        X = np.vstack([rng.normal(0, 0.3, (60, 4)), rng.normal(6, 0.3, (60, 4))])
        labels = np.array([0] * 60 + [1] * 60)

        assert clustering.scalable_silhouette(X, labels) == pytest.approx(silhouette_score(X, labels))

    def test_tc17_optimal_k_recovers_known_cluster_count(self, clustering):
        """TC-17: on three well-separated blobs the k-sweep selects k=3."""
        rng = np.random.default_rng(1)
        X = np.vstack(
            [
                rng.normal(0, 0.25, (70, 5)),
                rng.normal(8, 0.25, (70, 5)),
                rng.normal(-8, 0.25, (70, 5)),
            ]
        )
        assert clustering.find_optimal_k(X, k_range=(2, 6)) == 3

    def test_tc18_kmeans_separates_scanner_from_beacon(self, clustering):
        """TC-18: clustering assigns distinct behaviour profiles to distinct campaigns."""
        rng = np.random.default_rng(2)
        X = np.vstack([rng.normal(0, 0.2, (40, 3)), rng.normal(5, 0.2, (40, 3))])
        labels = clustering.run_clustering(X, k=2, method="kmeans")

        assert len(set(labels)) == 2
        assert len(set(labels[:40])) == 1
        assert len(set(labels[40:])) == 1
        assert labels[0] != labels[-1]


# ───────────── Phase 06: confidence factors and temporal drift ──────────


class TestAttribution:
    def test_tc19_cohesion_matches_sklearn_cosine_similarity(self, attribution):
        """TC-19: the O(n*d) cohesion identity reproduces the pairwise mean exactly.

        Regression test: the naive n x n matrix needed ~80 GB at 131k fingerprints.
        """
        from sklearn.metrics.pairwise import cosine_similarity

        rng = np.random.default_rng(3)
        X = rng.normal(size=(120, 8))
        S = cosine_similarity(X)
        n = len(X)
        expected = (S.sum() - np.trace(S)) / (n * (n - 1))

        assert attribution.behavioral_cohesion(X) == pytest.approx(expected, abs=1e-12)

    def test_tc20_cohesion_handles_zero_rows(self, attribution):
        """TC-20: all-zero fingerprints do not produce NaN cohesion."""
        X = np.vstack([np.zeros((5, 4)), np.ones((5, 4))])
        val = attribution.behavioral_cohesion(X)
        assert np.isfinite(val)
        assert 0.0 <= val <= 1.0

    def test_tc21_infrastructure_overlap_fraction(self, attribution):
        """TC-21: I(k) is the fraction sharing the majority ASN or /24."""
        ips = ["10.1.1.1", "10.1.1.2", "10.1.1.3", "203.0.113.9"]
        asn = {"10.1.1.1": "AS100", "10.1.1.2": "AS100", "10.1.1.3": "AS100", "203.0.113.9": "AS999"}
        assert attribution.infrastructure_overlap(ips, asn) == pytest.approx(0.75)

    def test_tc22_timing_correlation_perfect_for_whole_population(self, attribution):
        """TC-22: T(k) = 1 when the campaign's hourly profile is the global profile."""
        base = pd.Timestamp("2024-01-01 00:00:00")
        rows = []
        for h, count in enumerate([5, 9, 2, 14, 7]):
            for _ in range(count):
                rows.append({"StartTime": base + pd.Timedelta(hours=h), "SrcAddr": "10.0.0.1"})
        flows = _flows(rows)

        assert attribution.timing_correlation(flows, ["10.0.0.1"]) == pytest.approx(1.0)

    def test_tc23_threat_match_fraction_thresholds(self, attribution):
        """TC-23: M(k) counts VirusTotal > 0 or AbuseIPDB > 25."""
        enriched = pd.DataFrame(
            {
                "vt_malicious": [3, 0, 0, 0],
                "abuse_score": [0, 90, 10, 0],
            }
        )
        assert attribution.threat_match_fraction(enriched) == pytest.approx(0.5)

    def test_tc24_confidence_is_weighted_sum_and_bounded(self, attribution):
        """TC-24: C(k) = 0.35B + 0.25I + 0.20T + 0.20M, bounded by [0,1]."""
        w = {"w1": 0.35, "w2": 0.25, "w3": 0.20, "w4": 0.20}
        assert attribution.confidence_score(1, 1, 1, 1, w) == pytest.approx(1.0)
        assert attribution.confidence_score(0, 0, 0, 0, w) == pytest.approx(0.0)
        assert attribution.confidence_score(0.8, 0.0, 1.0, 0.0, w) == pytest.approx(0.35 * 0.8 + 0.20)

    def test_tc25_confidence_reproduces_real_campaign_score(self, attribution):
        """TC-25: the measured CTU-13 factors reproduce the reported 47.5%."""
        w = {"w1": 0.35, "w2": 0.25, "w3": 0.20, "w4": 0.20}
        pct = attribution.confidence_score(0.7872, 0.0004, 0.9970, 0.0, w) * 100
        assert pct == pytest.approx(47.5, abs=0.1)

    def test_tc26_drift_flags_behaviour_change(self, attribution):
        """TC-26: drift = 1 - cos(centroid_w, centroid_w+1) flags orthogonal windows."""
        feat_cols = ["scan_entropy", "c2_beacon_score"]
        camps = pd.DataFrame(
            {
                "campaign_id": [0, 0, 0, 0],
                "time_window": pd.to_datetime(
                    ["2024-01-01 00:00", "2024-01-01 01:00", "2024-01-01 12:00", "2024-01-01 13:00"]
                ),
                "scan_entropy": [5.0, 5.0, 0.0, 0.0],
                "c2_beacon_score": [0.0, 0.0, 5.0, 5.0],
            }
        )
        series, flags = attribution.compute_drift(camps, feat_cols, window="6h", threshold=0.15)

        assert flags[0] is True
        assert series[0][0]["drift"] == pytest.approx(1.0, abs=1e-6)

    def test_tc27_drift_silent_for_stable_behaviour(self, attribution):
        """TC-27: an unchanged centroid produces zero drift and no flag."""
        feat_cols = ["scan_entropy", "c2_beacon_score"]
        camps = pd.DataFrame(
            {
                "campaign_id": [1, 1, 1, 1],
                "time_window": pd.to_datetime(
                    ["2024-01-01 00:00", "2024-01-01 01:00", "2024-01-01 12:00", "2024-01-01 13:00"]
                ),
                "scan_entropy": [4.0, 4.0, 4.0, 4.0],
                "c2_beacon_score": [0.2, 0.2, 0.2, 0.2],
            }
        )
        series, flags = attribution.compute_drift(camps, feat_cols, window="6h", threshold=0.15)

        assert flags[1] is False
        assert series[1][0]["drift"] == pytest.approx(0.0, abs=1e-9)


# ───────────────── Phase 07/09: graph and IoT label mapping ─────────────


class TestGraphAndLabels:
    def test_tc28_graph_links_ips_to_campaigns(self, graph):
        """TC-28: the attack graph contains campaign, IP and ASN nodes."""
        camps = pd.DataFrame(
            {
                "SrcAddr": ["10.0.0.1", "10.0.0.2"],
                "campaign_id": [0, 0],
                "campaign_type": ["Reconnaissance / Scanning"] * 2,
            }
        )
        enr = pd.DataFrame(
            {
                "ip": ["10.0.0.1", "10.0.0.2"],
                "campaign_id": [0, 0],
                "asn": ["AS100", "AS100"],
                "country": ["CZ", "CZ"],
            }
        )
        G = graph.build_graph(camps, enr)

        assert G.number_of_nodes() > 0
        assert G.number_of_edges() > 0
        types = {str(d.get("type")) for _, d in G.nodes(data=True)}
        assert "ip" in types

    def test_tc29_centrality_annotated_on_every_node(self, graph):
        """TC-29: degree and betweenness centrality are attached to all nodes."""
        camps = pd.DataFrame(
            {
                "SrcAddr": [f"10.0.0.{i}" for i in range(6)],
                "campaign_id": [0] * 6,
                "campaign_type": ["Reconnaissance / Scanning"] * 6,
            }
        )
        enr = pd.DataFrame(
            {
                "ip": [f"10.0.0.{i}" for i in range(6)],
                "campaign_id": [0] * 6,
                "asn": ["AS100"] * 6,
                "country": ["CZ"] * 6,
            }
        )
        G = graph.build_graph(camps, enr)
        graph.annotate_centralities(G)

        for _, data in G.nodes(data=True):
            assert "degree_centrality" in data
            assert np.isfinite(float(data["degree_centrality"]))

    def test_tc30_iot_sublabel_maps_to_family_and_ttp(self, iot_labels):
        """TC-30: IoT-23 sub-labels map to a malware family and MITRE techniques."""
        assert iot_labels.map_sublabel("PartOfAHorizontalPortScan") == ("Scanner", ["T1046"])
        family, ttps = iot_labels.map_sublabel("C&C-Torii")
        assert family == "Torii"
        assert "T1573" in ttps
        assert iot_labels.map_sublabel("") == ("Unknown IoT", [])

    def test_tc31_unknown_sublabel_is_not_guessed(self, iot_labels):
        """TC-31: an unrecognised sub-label stays Unknown rather than mis-attributed."""
        assert iot_labels.map_sublabel("SomeBrandNewThing") == ("Unknown IoT", [])


# ─────────────── Phase 05: dashboard, scaling and reporting ─────────────


class TestDashboardAndReport:
    def test_tc32_retarget_artifacts_switches_directory(self, dashboard):
        """TC-32: --artifacts rewrites output/ paths so demo and real data coexist."""
        cfg = {"paths": {"flows": "output/unified_flows.parquet", "other": "data/demo/x.csv"}}
        out = dashboard.retarget_artifacts(cfg, "output_demo")

        assert out["paths"]["flows"] == "output_demo/unified_flows.parquet"
        assert out["paths"]["other"] == "data/demo/x.csv"
        assert out["DEMO_MODE"] is True
        assert dashboard.retarget_artifacts(cfg, "output")["DEMO_MODE"] is False

    def test_tc33_graph_display_cap_keeps_most_central_ips(self, dashboard):
        """TC-33: the display cap keeps the highest-centrality IPs and drops the rest.

        Without this a 353k-node real graph is unrenderable in the browser.
        """
        cap = dashboard.MAX_IP_NODES_PER_CAMPAIGN
        nodes = [{"id": "c0", "type": "campaign"}]
        nodes += [
            {"id": f"ip{i}", "type": "ip", "campaign_id": 0, "degree_centrality": i / (cap + 50)}
            for i in range(cap + 50)
        ]
        links = [{"source": f"ip{i}", "target": "c0"} for i in range(cap + 50)]

        trimmed = dashboard._cap_ip_nodes({"nodes": nodes, "links": links})
        kept_ips = [n for n in trimmed["nodes"] if n.get("type") == "ip"]

        assert len(kept_ips) == cap
        assert {n["id"] for n in trimmed["nodes"] if n["type"] == "campaign"} == {"c0"}
        # The 50 least-central IPs are the ones removed.
        assert "ip0" not in {n["id"] for n in kept_ips}
        assert f"ip{cap + 49}" in {n["id"] for n in kept_ips}
        assert all(
            e["source"] in {n["id"] for n in trimmed["nodes"]} for e in trimmed["links"]
        )

    def test_tc34_replay_timeline_downsampled(self, dashboard):
        """TC-34: the replay slider is capped so the browser store stays small."""
        base = pd.Timestamp("2024-01-01")
        n = dashboard.REPLAY_MAX_STEPS * 3
        flows = _flows([{"StartTime": base + pd.Timedelta(seconds=i)} for i in range(n)])

        timeline = dashboard._replay_timeline(flows)

        assert 0 < len(timeline) <= dashboard.REPLAY_MAX_STEPS
        assert timeline == sorted(timeline)
        assert timeline[0] == base

    def test_tc35_small_capture_timeline_not_downsampled(self, dashboard):
        """TC-35: a short capture keeps every timestamp, so no fidelity is lost."""
        base = pd.Timestamp("2024-01-01")
        flows = _flows([{"StartTime": base + pd.Timedelta(seconds=i)} for i in range(25)])
        assert len(dashboard._replay_timeline(flows)) == 25

    def test_tc36_factor_heatmap_renders_png(self, dashboard):
        """TC-36: the B/I/T/M heatmap embedded in the PDF renders as a PNG."""
        campaigns = [
            {"campaign_id": 0, "contributing_factors": {"B": 0.79, "I": 0.0, "T": 1.0, "M": 0.0}},
            {"campaign_id": 1, "contributing_factors": {"B": 0.78, "I": 0.01, "T": 1.0, "M": 0.0}},
        ]
        png = dashboard._factor_heatmap_png(campaigns)

        assert png is not None
        assert png[:8] == b"\x89PNG\r\n\x1a\n"

    def test_tc37_incident_pdf_is_valid_multipage_document(self, dashboard):
        """TC-37: Generate Incident Report produces a valid multi-page PDF."""
        payload = {
            "report": {
                "generated_at": "2026-10-04T00:00:00+00:00",
                "demo_mode": False,
                "filters": {"campaigns": None, "min_confidence_pct": 0},
            },
            "dataset": {
                "total_flows": 3_107_498,
                "unique_source_ips": 353_674,
                "fingerprints": 553_781,
                "campaigns_total": 2,
                "campaigns_selected": 2,
                "enriched_ips": 50,
            },
            "formula_registry": {"confidence_score": {"formula": "C(k) = w1*B + w2*I + w3*T + w4*M"}},
            "campaigns": [
                {
                    "campaign_id": 0,
                    "confidence_pct": 47.5,
                    "confidence_band": "LOW",
                    "ip_count": 336_000,
                    "attack_type": "Reconnaissance / Scanning",
                    "top_ttps": ["T1046"],
                    "drift_detected": False,
                    "cross_dataset": False,
                    "contributing_factors": {"B": 0.7872, "I": 0.0004, "T": 0.997, "M": 0.0},
                    "indicators": [
                        {"ip": "147.32.84.165", "vt_malicious": 0, "abuse_score": 0, "asn": "AS2852"}
                    ],
                    "drift_series": [],
                }
            ],
            "misp_matches": [],
        }
        pdf = dashboard._build_incident_pdf(payload)

        assert pdf[:5] == b"%PDF-"
        assert pdf.rstrip()[-5:] == b"%%EOF"
        assert pdf.count(b"/Type /Page") >= 2
        assert len(pdf) > 10_000

    def test_tc38_empty_selection_reports_nothing(self, dashboard):
        """TC-38: filtering out every campaign yields no heatmap rather than an error."""
        assert dashboard._factor_heatmap_png([]) is None
