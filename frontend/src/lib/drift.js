import { cosineSim, floorToWindow } from './utils.js';

const DRIFT_THRESHOLD = 0.15;
const WINDOW_HOURS = 6;

/**
 * Compute temporal drift per campaign.
 * Returns { campaignId: { windows: [{t, drift}], drifting: bool } }
 */
export function computeDrift(ipFeatures, labels, allRows) {
  const k = Math.max(...labels) + 1;
  const ipToLabel = {};
  ipFeatures.forEach((f, i) => { ipToLabel[f.ip] = labels[i]; });

  // For each campaign, group rows by 6h window and compute centroid
  const result = {};

  for (let c = 0; c < k; c++) {
    const campaignIPs = new Set(
      ipFeatures.filter((_, i) => labels[i] === c).map(f => f.ip)
    );
    const campaignRows = allRows.filter(r => campaignIPs.has(r.SrcAddr));

    // Group by 6h window
    const windowGroups = {};
    for (const r of campaignRows) {
      const wb = floorToWindow(r._ts, WINDOW_HOURS).getTime();
      (windowGroups[wb] ??= []).push(r);
    }

    const sortedWindows = Object.keys(windowGroups).map(Number).sort();
    if (sortedWindows.length < 2) {
      result[c] = { windows: [], drifting: false };
      continue;
    }

    // Build centroid per window using IP norm features
    // Map ip → normFeatures
    const ipNorm = {};
    ipFeatures.forEach((f, i) => { if (labels[i] === c) ipNorm[f.ip] = f.normFeatures; });

    const centroids = sortedWindows.map(wb => {
      const rows = windowGroups[wb];
      const ipSet = new Set(rows.map(r => r.SrcAddr));
      const vecs = [...ipSet].map(ip => ipNorm[ip]).filter(Boolean);
      if (vecs.length === 0) return null;
      const dim = vecs[0].length;
      const centroid = new Array(dim).fill(0);
      for (const v of vecs)
        for (let d = 0; d < dim; d++) centroid[d] += v[d];
      for (let d = 0; d < dim; d++) centroid[d] /= vecs.length;
      return centroid;
    });

    const windows = [];
    let drifting = false;
    for (let i = 0; i < centroids.length - 1; i++) {
      const a = centroids[i], b = centroids[i + 1];
      if (!a || !b) continue;
      const drift = 1 - cosineSim(a, b);
      const flagged = drift > DRIFT_THRESHOLD;
      if (flagged) drifting = true;
      windows.push({
        t: new Date(sortedWindows[i]).toISOString(),
        drift: +drift.toFixed(4),
        flagged,
      });
    }

    result[c] = { windows, drifting };
  }

  return result;
}
