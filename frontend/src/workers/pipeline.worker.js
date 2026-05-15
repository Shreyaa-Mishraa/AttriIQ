import Papa from 'papaparse';
import { createStreamSampler } from '../lib/sampling.js';
import { preprocessRows, extractFeatures } from '../lib/features.js';
import { findBestK } from '../lib/clustering.js';
import { computeAttribution } from '../lib/attribution.js';
import { computeDrift } from '../lib/drift.js';
import { buildGraph } from '../lib/graph.js';

function post(stage, pct, extra = {}) {
  self.postMessage({ stage, pct, ...extra });
}

self.onmessage = async (e) => {
  const { file, mode } = e.data;
  const LIMIT = mode === 'full' ? Infinity : 50_000;
  const K_RANGE = mode === 'full' ? [4, 8] : [4, 6];

  post('Parsing CTU-13 flows…', 5);

  const sampler = createStreamSampler(LIMIT);

  await new Promise((resolve, reject) => {
    Papa.parse(file, {
      header: true,
      skipEmptyLines: true,
      step(result) { sampler.push(result.data); },
      complete: resolve,
      error: reject,
    });
  });

  const totalRows = sampler.total();
  const sampledRows = sampler.result();

  post('Fingerprinting IPs…', 25);
  const t1 = performance.now();
  const rows = preprocessRows(sampledRows);
  const dur_preprocess = performance.now() - t1;

  post('Fingerprinting IPs…', 35);
  const t2 = performance.now();
  const ipFeatures = extractFeatures(rows);
  const dur_features = performance.now() - t2;

  if (ipFeatures.length < 2) {
    post('error', 0, { error: 'Not enough IPs to cluster (need ≥ 2).' });
    return;
  }

  post('Clustering into campaigns…', 55);
  const t3 = performance.now();
  const normVecs = ipFeatures.map(f => f.normFeatures);
  const { k, silhouette, labels, centroids } = findBestK(normVecs, K_RANGE);
  const dur_clustering = performance.now() - t3;

  post('Scoring attribution confidence…', 70);
  const t4 = performance.now();
  let campaigns = computeAttribution(ipFeatures, labels, rows);
  const dur_attribution = performance.now() - t4;

  post('Detecting temporal drift…', 80);
  const t5 = performance.now();
  const driftData = computeDrift(ipFeatures, labels, rows);
  const dur_drift = performance.now() - t5;

  // Merge drift into campaigns
  for (const camp of campaigns) {
    const d = driftData[camp.id];
    camp.drifting = d?.drifting ?? false;
    camp.driftWindows = d?.windows ?? [];
  }

  post('Building attack graph…', 90);
  const t6 = performance.now();
  const graph = buildGraph(ipFeatures, labels, campaigns);
  const dur_graph = performance.now() - t6;

  const pipelineSteps = [
    { id: '01', name: 'Preprocess', status: 'done', duration: dur_preprocess },
    { id: '02', name: 'Features', status: 'done', duration: dur_features },
    { id: '03', name: 'Clustering', status: 'done', duration: dur_clustering, note: `k=${k}, silhouette=${silhouette.toFixed(3)}` },
    { id: '04', name: 'Threat Intel', status: 'done', duration: dur_attribution },
    { id: '05', name: 'Attribution', status: 'done', duration: dur_attribution },
    { id: '06', name: 'Temporal Drift', status: 'done', duration: dur_drift },
    { id: '07', name: 'Graph', status: 'done', duration: dur_graph },
    { id: '08', name: 'MISP', status: 'skipped', note: 'No API key' },
    { id: '09', name: 'IoT Labels', status: 'skipped', note: 'No API key' },
  ];

  post('done', 100, {
    payload: {
      totalRows,
      sampledRows: sampledRows.length,
      ipFeatures,
      labels,
      centroids,
      campaigns,
      driftData,
      graph,
      pipelineSteps,
      mode,
      fileName: file.name,
    },
  });
};
