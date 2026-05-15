/** Shannon entropy in bits over an array of values. */
export function shannonEntropy(values) {
  if (!values || values.length === 0) return 0;
  const freq = {};
  for (const v of values) freq[v] = (freq[v] || 0) + 1;
  const n = values.length;
  let h = 0;
  for (const c of Object.values(freq)) {
    const p = c / n;
    if (p > 0) h -= p * Math.log2(p);
  }
  return h;
}

/** Min-max normalise a column of numbers; returns array in [0,1]. */
export function minMaxNorm(arr) {
  const mn = Math.min(...arr);
  const mx = Math.max(...arr);
  const range = mx - mn || 1;
  return arr.map(v => (v - mn) / range);
}

/** Pearson correlation between two equal-length arrays. */
export function pearsonR(xs, ys) {
  const n = xs.length;
  if (n < 3) return 0;
  const xm = xs.reduce((a, b) => a + b, 0) / n;
  const ym = ys.reduce((a, b) => a + b, 0) / n;
  let num = 0, dx2 = 0, dy2 = 0;
  for (let i = 0; i < n; i++) {
    const dx = xs[i] - xm, dy = ys[i] - ym;
    num += dx * dy; dx2 += dx * dx; dy2 += dy * dy;
  }
  const denom = Math.sqrt(dx2 * dy2);
  return denom === 0 ? 0 : num / denom;
}

/** Cosine similarity between two numeric arrays. */
export function cosineSim(a, b) {
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i];
  }
  const denom = Math.sqrt(na) * Math.sqrt(nb);
  return denom === 0 ? 0 : dot / denom;
}

/** Euclidean distance between two arrays. */
export function euclidean(a, b) {
  let s = 0;
  for (let i = 0; i < a.length; i++) s += (a[i] - b[i]) ** 2;
  return Math.sqrt(s);
}

/** Coefficient of variation (stddev / mean) for an array. Returns 0 if mean=0. */
export function cov(arr) {
  if (!arr || arr.length === 0) return 0;
  const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
  if (mean === 0) return 0;
  const variance = arr.reduce((s, v) => s + (v - mean) ** 2, 0) / arr.length;
  return Math.sqrt(variance) / mean;
}

/** Parse a date string to a JS Date; return null on failure. */
export function parseDate(s) {
  if (!s) return null;
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}

/** Floor a Date to the given hour window (in hours). */
export function floorToWindow(date, windowHours = 1) {
  const ms = windowHours * 3_600_000;
  return new Date(Math.floor(date.getTime() / ms) * ms);
}

/** Extract /24 subnet from an IPv4 string, e.g. "192.168.1.0" */
export function subnet24(ip) {
  if (!ip) return '';
  const parts = String(ip).split('.');
  if (parts.length >= 3) return parts.slice(0, 3).join('.');
  return ip;
}

/**
 * Detect malicious traffic from CTU-13 / generic label strings.
 * CTU-13 labels look like: "flow=To-Botnet-V42-UDP-SPAM", "flow=From-Botnet-..."
 * Generic: "Botnet", "Malicious", "Attack"
 */
export function isMalicious(label) {
  if (!label) return false;
  const l = String(label).toLowerCase();
  return l.includes('botnet') || l.includes('malicious') || l.includes('attack');
}

/**
 * Simplify a raw CTU-13 label into a short human-readable string.
 * e.g. "flow=To-Botnet-V42-UDP-SPAM" → "Botnet (UDP-SPAM)"
 */
export function simplifyLabel(raw) {
  if (!raw) return 'Unknown';
  const s = String(raw);
  // CTU-13 flow= prefix
  const m = s.match(/flow=(?:To-|From-)?(\w+?)(?:-V\d+)?(?:-([\w-]+))?$/);
  if (m) {
    const type = m[1];
    const detail = m[2] ? ` (${m[2]})` : '';
    return `${type}${detail}`;
  }
  return s.length > 32 ? s.slice(0, 32) + '…' : s;
}

/** Format milliseconds as "1.23s" or "456ms". */
export function fmtMs(ms) {
  return ms >= 1000 ? `${(ms / 1000).toFixed(2)}s` : `${Math.round(ms)}ms`;
}

/** Format a number with thousand separators. */
export function fmtNum(n) {
  return n?.toLocaleString?.() ?? String(n);
}

/** Severity tier from confidence score. */
export function severityTier(c) {
  if (c >= 0.8) return 'high';
  if (c >= 0.5) return 'medium';
  return 'low';
}

export const SEVERITY_COLORS = {
  high:   { bg: 'bg-red-100',   text: 'text-red-700',   bar: '#EF4444', hex: '#EF4444' },
  medium: { bg: 'bg-amber-100', text: 'text-amber-700', bar: '#F59E0B', hex: '#F59E0B' },
  low:    { bg: 'bg-green-100', text: 'text-green-700', bar: '#22C55E', hex: '#22C55E' },
};

export const CAMPAIGN_PALETTE = [
  '#3B82F6','#EF4444','#F59E0B','#22C55E','#8B5CF6',
  '#EC4899','#06B6D4','#F97316','#84CC16','#6366F1',
];
