import { cosineSim, pearsonR, subnet24, isMalicious } from './utils.js';

const WEIGHTS = { w1: 0.35, w2: 0.25, w3: 0.20, w4: 0.20 };

/**
 * B(k) — mean pairwise cosine similarity of normalised feature vectors.
 * Uses centroid approximation for large clusters (>50 IPs).
 */
function behavioralCohesion(normVecs) {
  if (normVecs.length < 2) return 0;
  // For speed, use sample of 50 pairs per cluster
  const n = normVecs.length;
  const pairs = [];
  if (n <= 10) {
    for (let i = 0; i < n; i++)
      for (let j = i + 1; j < n; j++)
        pairs.push([i, j]);
  } else {
    const tries = 200;
    for (let t = 0; t < tries; t++) {
      const i = Math.floor(Math.random() * n);
      let j = Math.floor(Math.random() * (n - 1));
      if (j >= i) j++;
      pairs.push([i, j]);
    }
  }
  const sims = pairs.map(([i, j]) => cosineSim(normVecs[i], normVecs[j]));
  return sims.reduce((a, b) => a + b, 0) / sims.length;
}

/**
 * I(k) — fraction of IPs sharing the majority /24 subnet.
 */
function infrastructureOverlap(ips) {
  if (ips.length === 0) return 0;
  const subnetCounts = {};
  for (const ip of ips) {
    const s = subnet24(ip);
    subnetCounts[s] = (subnetCounts[s] || 0) + 1;
  }
  const majCount = Math.max(...Object.values(subnetCounts));
  return majCount / ips.length;
}

/**
 * T(k) — |Pearson r| between cluster's hourly flow counts and global hourly counts.
 */
function timingCorrelation(clusterRows, allRows) {
  if (clusterRows.length < 3 || allRows.length < 3) return 0;

  const globalHours = {};
  for (const r of allRows) globalHours[r._hour] = (globalHours[r._hour] || 0) + 1;

  const clusterHours = {};
  for (const r of clusterRows) clusterHours[r._hour] = (clusterHours[r._hour] || 0) + 1;

  const allHourKeys = [...new Set([...Object.keys(globalHours), ...Object.keys(clusterHours)])].sort();
  if (allHourKeys.length < 3) return 0;

  const xs = allHourKeys.map(h => globalHours[h] || 0);
  const ys = allHourKeys.map(h => clusterHours[h] || 0);

  return Math.abs(pearsonR(xs, ys));
}

/**
 * M(k) — fraction of IPs with a "Botnet" or "Malicious" label.
 */
function threatMatchFraction(ips, ipLabelMap) {
  if (ips.length === 0) return 0;
  const malCount = ips.filter(ip => isMalicious(ipLabelMap[ip] || '')).length;
  return malCount / ips.length;
}

/**
 * Compute full attribution for all clusters.
 *
 * @param {object[]} ipFeatures  — output of extractFeatures()
 * @param {number[]}  labels     — cluster assignment per IP (same order)
 * @param {object[][]} allRows   — preprocessed rows (for T(k))
 * @returns {object[]} campaigns array
 */
export function computeAttribution(ipFeatures, labels, allRows) {
  const k = Math.max(...labels) + 1;

  // Build ipLabel map
  const ipLabelMap = {};
  for (const f of ipFeatures) ipLabelMap[f.ip] = f.label;

  // Group rows by cluster
  const rowsByIp = {};
  for (const r of allRows) (rowsByIp[r.SrcAddr] ??= []).push(r);

  const campaigns = [];

  for (let c = 0; c < k; c++) {
    const indices = labels.map((l, i) => l === c ? i : -1).filter(i => i >= 0);
    const clusterFeats = indices.map(i => ipFeatures[i]);
    const clusterIPs = clusterFeats.map(f => f.ip);
    const normVecs = clusterFeats.map(f => f.normFeatures);

    const clusterRows = clusterIPs.flatMap(ip => rowsByIp[ip] || []);

    const B = behavioralCohesion(normVecs);
    const I = infrastructureOverlap(clusterIPs);
    const T = timingCorrelation(clusterRows, allRows);
    const M = threatMatchFraction(clusterIPs, ipLabelMap);

    const confidence = WEIGHTS.w1 * B + WEIGHTS.w2 * I + WEIGHTS.w3 * T + WEIGHTS.w4 * M;

    // Dominant /24 subnet
    const subnetCounts = {};
    for (const ip of clusterIPs) {
      const s = subnet24(ip);
      subnetCounts[s] = (subnetCounts[s] || 0) + 1;
    }
    const dominantSubnet = Object.entries(subnetCounts).sort((a, b) => b[1] - a[1])[0]?.[0] ?? '';

    // Top attack type from labels
    const labelCounts = {};
    for (const ip of clusterIPs) {
      const lbl = ipLabelMap[ip] || 'Unknown';
      labelCounts[lbl] = (labelCounts[lbl] || 0) + 1;
    }
    const topLabel = Object.entries(labelCounts).sort((a, b) => b[1] - a[1])[0]?.[0] ?? 'Unknown';

    campaigns.push({
      id: c,
      ipCount: clusterIPs.length,
      ips: clusterIPs,
      confidence: Math.min(1, Math.max(0, confidence)),
      factors: { B: +B.toFixed(4), I: +I.toFixed(4), T: +T.toFixed(4), M: +M.toFixed(4) },
      dominantSubnet,
      topLabel,
      drifting: false, // filled in by drift analysis
    });
  }

  return campaigns;
}
