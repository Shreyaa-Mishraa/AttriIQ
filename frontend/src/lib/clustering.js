import { euclidean } from './utils.js';

const MAX_ITER = 100;
const CONVERGENCE_THRESHOLD = 0.001;

/** k-means++ initialisation. Returns k centroids chosen from `data`. */
function kMeansPlusPlusInit(data, k) {
  const n = data.length;
  const centroids = [];

  // First centroid: random
  centroids.push(data[Math.floor(Math.random() * n)]);

  for (let c = 1; c < k; c++) {
    // D² distances from each point to nearest centroid
    const d2 = data.map(point => {
      let minDist = Infinity;
      for (const cent of centroids) {
        const d = euclidean(point, cent);
        if (d < minDist) minDist = d;
      }
      return minDist ** 2;
    });

    // Sample with probability proportional to D²
    const total = d2.reduce((a, b) => a + b, 0);
    let r = Math.random() * total;
    let chosen = n - 1;
    for (let i = 0; i < n; i++) {
      r -= d2[i];
      if (r <= 0) { chosen = i; break; }
    }
    centroids.push(data[chosen]);
  }

  return centroids;
}

/** Run k-means on normalised feature vectors. Returns { labels, centroids }. */
export function kmeans(data, k) {
  if (data.length < k) k = Math.max(1, data.length);
  const dim = data[0].length;
  let centroids = kMeansPlusPlusInit(data, k);
  let labels = new Array(data.length).fill(0);

  for (let iter = 0; iter < MAX_ITER; iter++) {
    // Assignment step
    const newLabels = data.map(point => {
      let minDist = Infinity, best = 0;
      for (let c = 0; c < k; c++) {
        const d = euclidean(point, centroids[c]);
        if (d < minDist) { minDist = d; best = c; }
      }
      return best;
    });

    // Update step — recompute centroids
    const newCentroids = Array.from({ length: k }, () => new Array(dim).fill(0));
    const counts = new Array(k).fill(0);
    for (let i = 0; i < data.length; i++) {
      const c = newLabels[i];
      counts[c]++;
      for (let d = 0; d < dim; d++) newCentroids[c][d] += data[i][d];
    }
    for (let c = 0; c < k; c++) {
      if (counts[c] === 0) {
        // Empty cluster — re-init to random point
        newCentroids[c] = data[Math.floor(Math.random() * data.length)];
      } else {
        for (let d = 0; d < dim; d++) newCentroids[c][d] /= counts[c];
      }
    }

    // Convergence check
    let maxShift = 0;
    for (let c = 0; c < k; c++) {
      maxShift = Math.max(maxShift, euclidean(centroids[c], newCentroids[c]));
    }

    centroids = newCentroids;
    labels = newLabels;

    if (maxShift < CONVERGENCE_THRESHOLD) break;
  }

  return { labels, centroids };
}

/**
 * Approximate Silhouette Score using centroid distances.
 * O(n*k) — suitable for large datasets.
 */
export function silhouetteScore(data, labels, centroids) {
  const n = data.length;
  const k = centroids.length;
  if (n < 2 || k < 2) return 0;

  let total = 0;
  for (let i = 0; i < n; i++) {
    const ci = labels[i];
    const a = euclidean(data[i], centroids[ci]);

    let b = Infinity;
    for (let c = 0; c < k; c++) {
      if (c === ci) continue;
      const d = euclidean(data[i], centroids[c]);
      if (d < b) b = d;
    }

    const s = (b - a) / Math.max(a, b);
    total += isNaN(s) ? 0 : s;
  }
  return total / n;
}

/**
 * Run k-means for a range of k values, return the best (highest silhouette).
 * kRange is [kMin, kMax] inclusive.
 */
export function findBestK(data, kRange = [4, 6]) {
  const [lo, hi] = kRange;
  let bestK = lo, bestScore = -Infinity, bestResult = null;

  for (let k = lo; k <= hi; k++) {
    const result = kmeans(data, k);
    const score = silhouetteScore(data, result.labels, result.centroids);
    if (score > bestScore) {
      bestScore = score;
      bestK = k;
      bestResult = result;
    }
  }

  return { k: bestK, silhouette: bestScore, ...bestResult };
}
