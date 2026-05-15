/**
 * Reservoir sampling — Algorithm R.
 * Guarantees uniform random sample of `limit` rows regardless of input size.
 */
export function reservoirSample(rows, limit = 50_000) {
  if (rows.length <= limit) return rows;
  const sample = rows.slice(0, limit);
  for (let i = limit; i < rows.length; i++) {
    const j = Math.floor(Math.random() * (i + 1));
    if (j < limit) sample[j] = rows[i];
  }
  return sample;
}

/**
 * Stream-compatible reservoir sampler.
 * Call `push(row)` for each row; call `result()` when done.
 */
export function createStreamSampler(limit = 50_000) {
  const sample = [];
  let count = 0;
  return {
    push(row) {
      if (count < limit) {
        sample.push(row);
      } else {
        const j = Math.floor(Math.random() * (count + 1));
        if (j < limit) sample[j] = row;
      }
      count++;
    },
    result() { return sample; },
    total() { return count; },
  };
}
