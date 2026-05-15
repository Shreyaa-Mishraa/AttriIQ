import { severityTier, SEVERITY_COLORS } from '../lib/utils.js';

export default function ConfidenceBadge({ value }) {
  const tier = severityTier(value);
  const { bg, text } = SEVERITY_COLORS[tier];
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold ${bg} ${text}`}>
      {(value * 100).toFixed(0)}%
    </span>
  );
}
