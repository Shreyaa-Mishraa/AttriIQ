import { shannonEntropy, cov, minMaxNorm, parseDate, floorToWindow, simplifyLabel } from './utils.js';

export const FEATURE_NAMES = [
  'proto_entropy','scan_entropy','c2_beacon_score','payload_asymmetry',
  'burst_score','night_ratio','scan_score','flow_count','avg_duration',
  'avg_bytes','avg_pkts','tcp_ratio','udp_ratio','unique_dst_ports',
  'unique_dst_ips','avg_sport_entropy','state_entropy','bytes_per_pkt','pkts_per_flow',
];

/**
 * Preprocess raw parsed rows:
 *  - parse StartTime → JS Date
 *  - derive DstBytes
 *  - drop rows with null SrcAddr / DstAddr
 */
export function preprocessRows(rawRows) {
  const out = [];
  for (const r of rawRows) {
    if (!r.SrcAddr || !r.DstAddr) continue;
    const ts = parseDate(r.StartTime);
    if (!ts) continue;
    const totPkts = parseFloat(r.TotPkts) || 1;
    const totBytes = parseFloat(r.TotBytes) || 0;
    const srcBytes = parseFloat(r.SrcBytes) || 0;
    const dstBytes = Math.max(0, totBytes - srcBytes);
    out.push({
      ...r,
      _ts: ts,
      _hour: floorToWindow(ts, 1).getTime(),
      SrcAddr: String(r.SrcAddr).trim(),
      DstAddr: String(r.DstAddr).trim(),
      Proto: String(r.Proto || '').toLowerCase(),
      Sport: String(r.Sport || ''),
      Dport: String(r.Dport || ''),
      State: String(r.State || ''),
      Label: String(r.Label || ''),
      Dur: parseFloat(r.Dur) || 0,
      TotPkts: totPkts,
      TotBytes: totBytes,
      SrcBytes: srcBytes,
      DstBytes: dstBytes,
    });
  }
  return out;
}

/**
 * Extract 19 per-IP features across ALL hours (aggregate).
 * Returns array of { ip, label, hourKey, features: number[19], raw: {...} }
 */
export function extractFeatures(rows) {
  // Group by SrcAddr
  const byIp = {};
  for (const r of rows) {
    (byIp[r.SrcAddr] ??= []).push(r);
  }

  const allHours = rows.map(r => r._hour);
  const globalHourCounts = {};
  for (const h of allHours) globalHourCounts[h] = (globalHourCounts[h] || 0) + 1;

  const result = [];

  for (const [ip, ipRows] of Object.entries(byIp)) {
    const feat = computeIPFeatures(ip, ipRows, globalHourCounts);
    // Most common label — simplify CTU-13 flow= prefix
    const labelCounts = {};
    for (const r of ipRows) {
      const simplified = simplifyLabel(r.Label);
      labelCounts[simplified] = (labelCounts[simplified] || 0) + 1;
    }
    const label = Object.entries(labelCounts).sort((a, b) => b[1] - a[1])[0]?.[0] ?? '';
    result.push({ ip, label, features: feat.vec, raw: feat.raw });
  }

  // Min-max normalise each of the 19 dimensions
  const n = result.length;
  if (n === 0) return [];

  const mins = new Array(19).fill(Infinity);
  const maxs = new Array(19).fill(-Infinity);
  for (const item of result) {
    for (let d = 0; d < 19; d++) {
      if (item.features[d] < mins[d]) mins[d] = item.features[d];
      if (item.features[d] > maxs[d]) maxs[d] = item.features[d];
    }
  }

  for (const item of result) {
    item.normFeatures = item.features.map((v, d) => {
      const range = maxs[d] - mins[d];
      return range === 0 ? 0 : (v - mins[d]) / range;
    });
  }

  return result;
}

function computeIPFeatures(ip, rows, globalHourCounts) {
  const n = rows.length;

  // Protocol entropy
  const protos = rows.map(r => r.Proto);
  const proto_entropy = shannonEntropy(protos);

  // Scan entropy (destination IP diversity)
  const dstAddrs = rows.map(r => r.DstAddr);
  const scan_entropy = shannonEntropy(dstAddrs);

  // C2 beacon score — 1/(1+CoV) of inter-flow gaps
  const timestamps = rows.map(r => r._ts.getTime()).sort((a, b) => a - b);
  let c2_beacon_score = 0;
  if (timestamps.length >= 2) {
    const gaps = [];
    for (let i = 1; i < timestamps.length; i++) {
      gaps.push((timestamps[i] - timestamps[i - 1]) / 1000); // seconds
    }
    const cv = cov(gaps.filter(g => g >= 0));
    c2_beacon_score = 1 / (1 + cv);
  }

  // Payload asymmetry
  const srcB = rows.map(r => r.SrcBytes);
  const dstB = rows.map(r => r.DstBytes);
  const meanSrc = srcB.reduce((a, b) => a + b, 0) / n;
  const meanDst = dstB.reduce((a, b) => a + b, 0) / n;
  const payload_asymmetry = meanSrc / (meanDst + 1);

  // Burst score — flows in top-10% busiest hour / total
  const hourCounts = {};
  for (const r of rows) hourCounts[r._hour] = (hourCounts[r._hour] || 0) + 1;
  const hourVals = Object.values(hourCounts).sort((a, b) => b - a);
  const topN = Math.max(1, Math.ceil(hourVals.length * 0.1));
  const topFlows = hourVals.slice(0, topN).reduce((a, b) => a + b, 0);
  const burst_score = topFlows / n;

  // Night ratio (22:00–06:00)
  const nightFlows = rows.filter(r => {
    const h = r._ts.getHours();
    return h >= 22 || h < 6;
  }).length;
  const night_ratio = nightFlows / n;

  // Scan score — unique dst / total pkts (capped at 1)
  const uniqueDst = new Set(dstAddrs).size;
  const totalPkts = rows.reduce((a, r) => a + r.TotPkts, 0);
  const scan_score = Math.min(1, uniqueDst / (totalPkts || 1));

  // Basic stats
  const flow_count = n;
  const avg_duration = rows.reduce((a, r) => a + r.Dur, 0) / n;
  const avg_bytes = rows.reduce((a, r) => a + r.TotBytes, 0) / n;
  const avg_pkts = rows.reduce((a, r) => a + r.TotPkts, 0) / n;

  // Protocol ratios
  const tcpCount = rows.filter(r => r.Proto === 'tcp').length;
  const udpCount = rows.filter(r => r.Proto === 'udp').length;
  const tcp_ratio = tcpCount / n;
  const udp_ratio = udpCount / n;

  // Unique destination ports and IPs
  const unique_dst_ports = new Set(rows.map(r => r.Dport)).size;
  const unique_dst_ips = uniqueDst;

  // Source port entropy
  const sports = rows.map(r => r.Sport);
  const avg_sport_entropy = shannonEntropy(sports);

  // State entropy
  const states = rows.map(r => r.State);
  const state_entropy = shannonEntropy(states);

  // Bytes per packet
  const bytes_per_pkt = rows.reduce((a, r) => a + (r.TotBytes / (r.TotPkts || 1)), 0) / n;

  // Packets per flow
  const pkts_per_flow = avg_pkts;

  const vec = [
    proto_entropy, scan_entropy, c2_beacon_score, payload_asymmetry,
    burst_score, night_ratio, scan_score, flow_count, avg_duration,
    avg_bytes, avg_pkts, tcp_ratio, udp_ratio, unique_dst_ports,
    unique_dst_ips, avg_sport_entropy, state_entropy, bytes_per_pkt, pkts_per_flow,
  ];

  return {
    vec,
    raw: {
      proto_entropy, scan_entropy, c2_beacon_score, payload_asymmetry,
      burst_score, night_ratio, scan_score, flow_count, avg_duration,
      avg_bytes, avg_pkts, tcp_ratio, udp_ratio, unique_dst_ports,
      unique_dst_ips, avg_sport_entropy, state_entropy, bytes_per_pkt, pkts_per_flow,
    },
  };
}
