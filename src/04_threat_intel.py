"""
PHASE 5: Threat Intelligence Enrichment
-----------------------------------------
VirusTotal, AbuseIPDB, WHOIS/ASN (ipwhois), optional Shodan, offline MITRE map.

**VirusTotal** uses the **v3** REST API (not legacy ``vtapi/v2``): IP reports are
``GET https://www.virustotal.com/api/v3/ip_addresses/{ip}`` with header
``x-apikey: <key>``. Reference: https://docs.virustotal.com/reference/ip-info

In DEMO_MODE, reads ``data/demo/mock_ti_responses.json`` and skips live APIs.

Usage:
    python src/04_threat_intel.py
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from pathlib import Path

import pandas as pd
import requests
import yaml
from dotenv import load_dotenv

random.seed(42)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

load_dotenv()

# v3 auth: ``x-apikey`` only. Also accept ``VT_API_KEY`` as an alias for convenience.
VIRUSTOTAL_KEY = (os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("VT_API_KEY") or "").strip()
ABUSEIPDB_KEY = (os.getenv("ABUSEIPDB_API_KEY") or "").strip()
SHODAN_KEY = (os.getenv("SHODAN_API_KEY") or "").strip()


def _cfg(root: Path) -> dict:
    p = root / "config.yaml"
    if not p.is_file():
        return {}
    with open(p, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _load_json(path: Path) -> dict:
    if not path.is_file():
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _save_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


def query_virustotal(ip: str, timeout: int) -> dict:
    """Query VT v3 IP report. Auth: ``x-apikey`` header only (not query ``apikey``)."""
    if not VIRUSTOTAL_KEY:
        return {
            "vt_malicious": -1,
            "vt_suspicious": -1,
            "vt_reputation": -1,
            "vt_categories": "API_KEY_NOT_SET",
        }
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_KEY}
    max_429_retries = 3
    for attempt in range(max_429_retries + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) or {}
                cats = data.get("data", {}).get("attributes", {}).get("categories", {}) or {}
                rep = data.get("data", {}).get("attributes", {}).get("reputation", 0)
                return {
                    "vt_malicious": int(stats.get("malicious", 0)),
                    "vt_suspicious": int(stats.get("suspicious", 0)),
                    "vt_reputation": rep,
                    "vt_categories": ", ".join(set(cats.values()))[:100] if cats else "",
                }
            if resp.status_code == 429 and attempt < max_429_retries:
                time.sleep(60)
                continue
            err = ""
            try:
                err = (resp.json().get("error", {}) or {}).get("message", "")[:120]
            except Exception:
                err = resp.text[:120] if resp.text else ""
            return {
                "vt_malicious": -1,
                "vt_suspicious": -1,
                "vt_reputation": -1,
                "vt_categories": f"HTTP_{resp.status_code}:{err}"[:160],
            }
        except Exception as e:
            return {"vt_malicious": -1, "vt_suspicious": -1, "vt_reputation": -1, "vt_categories": str(e)}
    return {"vt_malicious": -1, "vt_suspicious": -1, "vt_reputation": -1, "vt_categories": "HTTP_429_exhausted"}


def query_abuseipdb(ip: str, timeout: int) -> dict:
    if not ABUSEIPDB_KEY:
        return {"abuse_score": -1, "abuse_reports": -1, "abuse_isp": "API_KEY_NOT_SET", "abuse_usage_type": ""}
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=timeout)
        if resp.status_code == 200:
            d = resp.json().get("data", {})
            return {
                "abuse_score": d.get("abuseConfidenceScore", 0),
                "abuse_reports": d.get("totalReports", 0),
                "abuse_isp": d.get("isp", "")[:80],
                "abuse_usage_type": d.get("usageType", ""),
            }
        return {"abuse_score": -1, "abuse_reports": -1, "abuse_isp": f"HTTP_{resp.status_code}", "abuse_usage_type": ""}
    except Exception as e:
        return {"abuse_score": -1, "abuse_reports": -1, "abuse_isp": str(e), "abuse_usage_type": ""}


def query_whois(ip: str, cache: dict, cache_path: Path, timeout: int) -> dict:
    if ip in cache:
        return cache[ip]
    out = {"asn": "", "asn_org": "", "country": "", "cidr": "", "org": ""}
    try:
        from ipwhois import IPWhois  # type: ignore

        obj = IPWhois(ip)
        r = obj.lookup_whois(retry_count=0, get_referral=True)
        asn = r.get("asn") or ""
        out["asn"] = f"AS{asn}" if str(asn).isdigit() else str(asn)
        out["asn_org"] = str(r.get("asn_description", "") or "")[:120]
        out["country"] = str(r.get("asn_country_code", "") or r.get("network", {}).get("country", "") or "")
        nets = r.get("nets", []) or []
        if nets:
            out["cidr"] = str(nets[0].get("cidr", ""))
            out["org"] = str(nets[0].get("description", ""))[:120]
    except Exception as e:
        out["asn_org"] = f"whois_error:{e}"
    cache[ip] = out
    _save_json(cache_path, cache)
    return out


def query_shodan(ip: str, cache: dict, cache_path: Path, timeout: int) -> dict:
    if not SHODAN_KEY:
        return {"shodan_ports": "", "shodan_tags": ""}
    if ip in cache:
        return cache[ip]
    out = {"shodan_ports": "", "shodan_tags": ""}
    try:
        resp = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}",
            timeout=timeout,
        )
        if resp.status_code == 200:
            d = resp.json()
            ports = d.get("ports") or []
            tags = d.get("tags") or []
            out["shodan_ports"] = ",".join(str(p) for p in ports)[:200]
            out["shodan_tags"] = ",".join(str(t) for t in tags)[:200]
    except Exception:
        pass
    cache[ip] = out
    _save_json(cache_path, cache)
    return out


MITRE_CAMPAIGN_MAP = {
    "Reconnaissance / Scanning": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "mitre_url": "https://attack.mitre.org/techniques/T1046/",
    },
    "Botnet C2 Communication": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol (C2)",
        "tactic": "Command and Control",
        "mitre_url": "https://attack.mitre.org/techniques/T1071/",
    },
    "DDoS / Flood": {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "mitre_url": "https://attack.mitre.org/techniques/T1499/",
    },
    "Data Exfiltration": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "mitre_url": "https://attack.mitre.org/techniques/T1041/",
    },
    "Benign / Unknown": {
        "technique_id": "N/A",
        "technique_name": "N/A",
        "tactic": "N/A",
        "mitre_url": "N/A",
    },
}


def _compute_threat_level(vt: dict, abuse: dict) -> str:
    score = 0
    if vt.get("vt_malicious", 0) > 3:
        score += 2
    if vt.get("vt_suspicious", 0) > 0:
        score += 1
    if abuse.get("abuse_score", 0) > 50:
        score += 2
    if abuse.get("abuse_score", 0) > 20:
        score += 1
    if score >= 4:
        return "CRITICAL"
    if score >= 2:
        return "HIGH"
    if score >= 1:
        return "MEDIUM"
    return "LOW"


def enrich_ip(
    ip: str,
    campaign_id: int,
    campaign_type: str,
    demo_mode: bool,
    mock: dict,
    whois_cache: dict,
    shodan_cache: dict,
    whois_path: Path,
    shodan_path: Path,
    timeout: int,
) -> dict:
    mitre = MITRE_CAMPAIGN_MAP.get(campaign_type, MITRE_CAMPAIGN_MAP["Benign / Unknown"])
    if demo_mode:
        m = mock.get(ip, {})
        vt = {
            "vt_malicious": int(m.get("vt_malicious", 0)),
            "vt_suspicious": 0,
            "vt_reputation": 0,
            "vt_categories": "DEMO",
        }
        abuse = {
            "abuse_score": int(m.get("abuse_score", 0)),
            "abuse_reports": 0,
            "abuse_isp": "DEMO_ISP",
            "abuse_usage_type": "",
        }
        who = {
            "asn": str(m.get("asn", "")),
            "asn_org": "DEMO_ASN_ORG",
            "country": str(m.get("country", "")),
            "cidr": "",
            "org": "",
        }
        sh = {
            "shodan_ports": str(m.get("shodan_ports", "")),
            "shodan_tags": str(m.get("shodan_tags", "")),
        }
    else:
        vt = query_virustotal(ip, timeout)
        abuse = query_abuseipdb(ip, timeout)
        who = query_whois(ip, whois_cache, whois_path, timeout)
        sh = query_shodan(ip, shodan_cache, shodan_path, timeout)

    threat = _compute_threat_level(vt, abuse)
    return {
        "campaign_id": campaign_id,
        "campaign_type": campaign_type,
        "ip": ip,
        "threat_level": threat,
        **vt,
        **abuse,
        **who,
        **sh,
        **mitre,
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    cfg = _cfg(root)
    demo_mode = bool(cfg.get("DEMO_MODE", False))
    paths = cfg.get("paths") or {}
    timeout = int(cfg.get("api_timeouts_sec", 15))

    mock_path = root / (paths.get("mock_ti") or "data/demo/mock_ti_responses.json")
    whois_path = root / (paths.get("whois_cache") or "output/whois_cache.json")
    shodan_path = root / (paths.get("shodan_cache") or "output/shodan_cache.json")

    parser = argparse.ArgumentParser(description="Threat intelligence enrichment")
    parser.add_argument("--input", type=str, default=str(root / "output" / "03_campaigns.csv"))
    parser.add_argument("--summary", type=str, default=str(root / "output" / "03_campaign_summary.csv"))
    parser.add_argument("--output", type=str, default=str(root / "output" / "04_enriched.csv"))
    parser.add_argument("--max-ips", type=int, default=25)
    args = parser.parse_args()

    mock = _load_json(mock_path) if demo_mode else {}
    whois_cache = _load_json(whois_path)
    shodan_cache = _load_json(shodan_path)

    print(f"[+] DEMO_MODE={demo_mode} | mock file={mock_path.name if demo_mode else 'n/a'}")

    df = pd.read_csv(args.input, low_memory=False)
    summary = pd.read_csv(args.summary, low_memory=False)
    if "campaign_type" not in summary.columns:
        summary["campaign_type"] = "Benign / Unknown"

    all_records: list[dict] = []
    for _, row in summary.iterrows():
        c_id = int(row["campaign_id"])
        c_type = str(row.get("campaign_type", "Benign / Unknown"))
        ips = df[df["campaign_id"] == c_id]["SrcAddr"].astype(str).unique().tolist()
        if not ips:
            continue
        for ip in ips[: args.max_ips]:
            rec = enrich_ip(
                ip,
                c_id,
                c_type,
                demo_mode,
                mock,
                whois_cache,
                shodan_cache,
                whois_path,
                shodan_path,
                timeout,
            )
            all_records.append(rec)
            if not demo_mode and (VIRUSTOTAL_KEY or ABUSEIPDB_KEY):
                time.sleep(2)

    out = pd.DataFrame(all_records)
    outp = Path(args.output)
    outp.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(outp, index=False)
    print(f"\n[OK] Saved enriched intelligence -> {outp} ({len(out)} rows)")


if __name__ == "__main__":
    main()
