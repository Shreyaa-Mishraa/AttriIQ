"""
PHASE 4: ML-Based Campaign Discovery  →  Cₖ = cluster(B₁, B₂, …, Bₙ)
-----------------------------------------------------------------------
Clustering on extended IoT-aware fingerprints (Parquet input by default).
One-hot encodes dataset_source; exports cluster_summary.json with dataset mix stats.
che
Usage:
    python src/03_clustering.py
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import yaml
from datetime import datetime, timezone

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.cluster import AgglomerativeClustering, KMeans
from sklearn.decomposition import PCA
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    davies_bouldin_score,
    silhouette_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

try:
    from xgboost import XGBClassifier  # noqa: F401

    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    print("[!] XGBoost not installed. Skipping campaign type classifier.")

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

CAMPAIGN_TYPE_NAMES = {
    0: "Reconnaissance / Scanning",
    1: "Botnet C2 Communication",
    2: "DDoS / Flood",
    3: "Data Exfiltration",
    4: "Benign Traffic",
}


def read_features(path: str) -> pd.DataFrame:
    if path.lower().endswith(".parquet"):
        return pd.read_parquet(path)
    return pd.read_csv(path)


def build_clustering_matrix(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """One-hot dataset_source and return (design matrix, feature column names)."""
    df0 = df.drop(columns=[c for c in ["attack_type"] if c in df.columns], errors="ignore")
    dummies = pd.get_dummies(df0["dataset_source"].astype(str), prefix="ds")
    df2 = pd.concat([df0.reset_index(drop=True), dummies.reset_index(drop=True)], axis=1)
    dummy_cols = list(dummies.columns)
    feat_cols = [c for c in BASE_FEATURE_COLS + IOT_FEATURE_COLS if c in df2.columns]
    feat_cols = feat_cols + dummy_cols
    return df2, feat_cols


# silhouette_score builds an n x n distance matrix; subsample above this size.
SILHOUETTE_SAMPLE_CAP = 20_000


def scalable_silhouette(X: np.ndarray, labels: np.ndarray) -> float:
    n = len(labels)
    if n > SILHOUETTE_SAMPLE_CAP:
        return float(
            silhouette_score(X, labels, sample_size=SILHOUETTE_SAMPLE_CAP, random_state=42)
        )
    return float(silhouette_score(X, labels))


def find_optimal_k(X: np.ndarray, k_range: tuple[int, int] = (2, 10)) -> int:
    lo, hi = k_range
    n = len(X)
    hi = min(hi, max(lo + 1, n - 1))
    if hi < lo:
        return lo
    print("[+] Finding optimal number of clusters...")
    scores: dict[int, float] = {}
    for k in range(lo, hi + 1):
        if k >= n:
            break
        km = KMeans(n_clusters=k, random_state=42, n_init=10)
        labels = km.fit_predict(X)
        if len(set(labels)) < 2:
            continue
        score = scalable_silhouette(X, labels)
        scores[k] = score
        print(f"    k={k:2d}  silhouette={score:.4f}")

    if not scores:
        return min(2, max(1, n // 2))

    best_k = max(scores, key=scores.get)
    print(f"[✓] Optimal k = {best_k} (silhouette={scores[best_k]:.4f})")

    plt.figure(figsize=(8, 4))
    plt.plot(list(scores.keys()), list(scores.values()), "o-", color="#c0392b")
    plt.axvline(best_k, linestyle="--", color="gray", label=f"Best k={best_k}")
    plt.xlabel("Number of Clusters (k)")
    plt.ylabel("Silhouette Score")
    plt.title("Silhouette Score vs Number of Campaigns")
    plt.legend()
    plt.tight_layout()
    plt.savefig("output/silhouette_plot.png", dpi=150)
    plt.close()
    print("    Saved → output/silhouette_plot.png")
    return best_k


def run_clustering(X: np.ndarray, k: int, method: str = "kmeans", hdb_cfg: dict | None = None) -> np.ndarray:
    print(f"\n[+] Running {method} clustering (k={k})...")
    if method == "hdbscan":
        try:
            import hdbscan  # type: ignore

            hdb_cfg = hdb_cfg or {}
            min_cluster_size = int(hdb_cfg.get("min_cluster_size", 5))
            min_samples = int(hdb_cfg.get("min_samples", 3))
            clusterer = hdbscan.HDBSCAN(
                min_cluster_size=min_cluster_size,
                min_samples=min_samples,
            )
            labels = clusterer.fit_predict(X)
            noise = int((labels == -1).sum())
            if noise > 0:
                print(f"    [i] HDBSCAN noise points: {noise:,} (relabelled to singleton clusters)")
                nxt = int(labels.max()) + 1
                for i in range(len(labels)):
                    if labels[i] == -1:
                        labels[i] = nxt
                        nxt += 1
            uniq = sorted(set(labels.tolist()))
            for c in uniq:
                print(f"    Campaign {c}: {(labels == c).sum():,} fingerprints")
            return labels
        except Exception as e:
            print(f"[!] HDBSCAN failed ({e}); falling back to k-means.")
            method = "kmeans"

    if method == "kmeans":
        model = KMeans(n_clusters=k, random_state=42, n_init=10)
    else:
        model = AgglomerativeClustering(n_clusters=k, linkage="ward")
    labels = model.fit_predict(X)
    for c in range(k):
        print(f"    Campaign {c}: {(labels == c).sum():,} fingerprints")
    return labels


def characterize_campaigns(df: pd.DataFrame, labels: np.ndarray, feat_cols: list[str]) -> pd.DataFrame:
    df = df.copy()
    df["campaign_id"] = labels
    num_cols = [c for c in feat_cols if c in df.columns and pd.api.types.is_numeric_dtype(df[c])]
    summary = df.groupby("campaign_id")[num_cols].mean().round(4)
    summary["ip_count"] = df.groupby("campaign_id")["SrcAddr"].count()

    def infer_type(row):
        if row.get("scan_score", 0) > 0.5:
            return "Reconnaissance / Scanning"
        if row.get("burst_score", 0) > 0.6:
            return "Botnet C2 Communication"
        if row.get("conn_count", 0) > 0.7 and row.get("avg_bytes", 0) < 0.3:
            return "DDoS / Flood"
        if row.get("src_bytes_ratio", 0) > 0.7:
            return "Data Exfiltration"
        return "Benign / Unknown"

    summary["campaign_type"] = summary.apply(infer_type, axis=1)
    summary = summary.reset_index()
    print("\n── Campaign Summary ─────────────────────────────────────")
    show_cols = [c for c in ["ip_count", "scan_score", "burst_score", "conn_count", "campaign_type"]
                 if c in summary.columns]
    print(summary[show_cols].to_string())
    return summary


def train_classifier(df: pd.DataFrame, feat_cols: list[str]):
    if "label" not in df.columns or df["label"].nunique() < 2:
        print("[!] No labels found. Skipping supervised classification.")
        return None

    print("\n[+] Training Random Forest (benign vs malicious)...")
    X = df[feat_cols].fillna(0).values
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    print("\n── Classification Report ────────────────────────────────")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))

    importances = pd.Series(clf.feature_importances_, index=feat_cols)
    importances = importances.sort_values(ascending=True)
    plt.figure(figsize=(8, 5))
    importances.plot(kind="barh", color="#c0392b")
    plt.title("Feature Importance (Random Forest)")
    plt.xlabel("Importance")
    plt.tight_layout()
    plt.savefig("output/feature_importance.png", dpi=150)
    plt.close()
    print("    Saved → output/feature_importance.png")

    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(5, 4))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Reds",
        xticklabels=["Benign", "Malicious"],
        yticklabels=["Benign", "Malicious"],
    )
    plt.title("Confusion Matrix")
    plt.tight_layout()
    plt.savefig("output/confusion_matrix.png", dpi=150)
    plt.close()
    print("    Saved → output/confusion_matrix.png")

    return clf


def visualize_clusters(df: pd.DataFrame, labels: np.ndarray, feat_cols: list[str]):
    X = df[feat_cols].fillna(0).values
    pca = PCA(n_components=2, random_state=42)
    X2 = pca.fit_transform(X)

    plt.figure(figsize=(10, 7))
    colors = plt.cm.tab10(np.linspace(0, 1, len(np.unique(labels))))
    for k, color in zip(np.unique(labels), colors):
        mask = labels == k
        plt.scatter(X2[mask, 0], X2[mask, 1], s=30, alpha=0.6, color=color, label=f"Campaign {k}")
    plt.xlabel(f"PC1 ({pca.explained_variance_ratio_[0]*100:.1f}% variance)")
    plt.ylabel(f"PC2 ({pca.explained_variance_ratio_[1]*100:.1f}% variance)")
    plt.title("Attack Campaigns — PCA Projection")
    plt.legend(bbox_to_anchor=(1.05, 1), loc="upper left")
    plt.tight_layout()
    plt.savefig("output/campaign_clusters.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("    Saved → output/campaign_clusters.png")


def build_cluster_summary(df: pd.DataFrame) -> list[dict]:
    rows: list[dict] = []
    for cid in sorted(df["campaign_id"].unique()):
        sub = df[df["campaign_id"] == cid]
        n = len(sub)
        ds = sub["dataset_source"].astype(str)
        n_iot = int((ds == "IoT-23").sum())
        n_ctu = int((ds == "CTU-13").sum())
        n_mix = int((ds == "Mixed").sum())
        iot_pct = 100.0 * n_iot / n if n else 0.0
        ctu_pct = 100.0 * n_ctu / n if n else 0.0
        cross_dataset = bool((n_iot > 0 and n_ctu > 0) or n_mix > 0)

        def mean_col(c: str) -> float:
            if c not in sub.columns:
                return 0.0
            return float(pd.to_numeric(sub[c], errors="coerce").fillna(0).mean())

        rows.append(
            {
                "campaign_id": int(cid),
                "ip_count": int(n),
                "iot_pct": round(iot_pct, 2),
                "ctu_pct": round(ctu_pct, 2),
                "cross_dataset": cross_dataset,
                "mean_device_role_score": round(mean_col("device_role_score"), 4),
                "mean_c2_beacon_score": round(mean_col("c2_beacon_score"), 4),
                "pct_horizontal_scan": round(100.0 * mean_col("horizontal_scan_flag"), 2),
            }
        )
    return rows


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    default_in = root / "output" / "features_iot_extended.parquet"
    fallback_in = root / "output" / "02_features.csv"

    parser = argparse.ArgumentParser(description="Campaign discovery via clustering")
    parser.add_argument("--input", type=str, default=None)
    parser.add_argument("--output", type=str, default=str(root / "output" / "03_campaigns.csv"))
    parser.add_argument("--method", type=str, default=None)
    parser.add_argument("--k", type=int, default=None)
    args = parser.parse_args()

    cfg: dict = {}
    cfg_path = root / "config.yaml"
    if cfg_path.is_file():
        with open(cfg_path, encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    clust_cfg = cfg.get("clustering") or {}
    method = args.method or clust_cfg.get("method", "kmeans")

    in_path = Path(args.input) if args.input else None
    if in_path is None or not in_path.is_file():
        in_path = default_in if default_in.is_file() else fallback_in
    if not in_path.is_file():
        raise FileNotFoundError(f"Features not found: {in_path}. Run 02_features.py first.")

    (root / "output").mkdir(parents=True, exist_ok=True)
    os.chdir(root)

    raw_df = read_features(str(in_path))
    df_x, feat_cols = build_clustering_matrix(raw_df)

    X = df_x[feat_cols].fillna(0).values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    hdb_cfg = clust_cfg.get("hdbscan") or {}
    km_cfg = clust_cfg.get("kmeans") or {}

    if method == "hdbscan":
        labels = run_clustering(X_scaled, k=0, method="hdbscan", hdb_cfg=hdb_cfg)
        k_eff = int(len(np.unique(labels)))
    else:
        k_lo = int(km_cfg.get("k_min", 2))
        k_hi = int(km_cfg.get("k_max", 10))
        k = args.k if args.k else find_optimal_k(X_scaled, k_range=(k_lo, k_hi))
        labels = run_clustering(X_scaled, k, method=method, hdb_cfg=hdb_cfg)
        k_eff = int(len(np.unique(labels)))

    sil = float("nan")
    db = float("nan")
    try:
        if len(np.unique(labels)) > 1:
            sil = scalable_silhouette(X_scaled, labels)
            db = float(davies_bouldin_score(X_scaled, labels))
        print(f"[i] Silhouette={sil:.4f} | Davies-Bouldin={db:.4f}")
    except Exception as e:
        print(f"[!] Clustering metrics: {e}")

    campaign_summary = characterize_campaigns(df_x, labels, feat_cols)

    out_summary_csv = root / "output" / "03_campaign_summary.csv"
    campaign_summary.to_csv(out_summary_csv, index=False)
    print(f"\n[✓] Saved campaign summary → {out_summary_csv}")

    visualize_clusters(df_x, labels, feat_cols)
    try:
        train_classifier(df_x, feat_cols)
    except Exception as e:
        print(f"[!] Classifier skipped: {e}")

    df_x["campaign_id"] = labels
    df_x.to_csv(args.output, index=False)
    print(f"[✓] Saved clustered data → {args.output}")

    cluster_summary = build_cluster_summary(df_x)
    summary_path = root / "output" / "cluster_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "clusters": cluster_summary,
                "silhouette": sil,
                "davies_bouldin": db,
            },
            f,
            indent=2,
        )
    print(f"[✓] Saved cluster summary → {summary_path}")
