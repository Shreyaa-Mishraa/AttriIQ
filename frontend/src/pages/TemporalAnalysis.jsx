import { useState, useMemo } from 'react';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, ReferenceLine, Legend,
} from 'recharts';
import { useAttribIQ } from '../context/AttribIQContext.jsx';
import { CAMPAIGN_PALETTE } from '../lib/utils.js';

export default function TemporalAnalysis() {
  const { status, campaigns, driftData } = useAttribIQ();
  const [visible, setVisible] = useState(() =>
    Object.fromEntries((campaigns ?? []).map(c => [c.id, true]))
  );

  const chartData = useMemo(() => {
    if (!campaigns?.length) return [];
    const drift = driftData || {};

    // Collect all drift windows and their values per campaign
    const rows = {};
    for (const c of campaigns) {
      const d = drift[c.id];
      if (!d?.windows?.length) continue;
      for (const w of d.windows) {
        const key = w.t;
        if (!rows[key]) rows[key] = { t: key };
        rows[key][`c${c.id}`] = w.drift;
        rows[key][`flag_${c.id}`] = w.flagged;
      }
    }
    return Object.values(rows).sort((a, b) => a.t.localeCompare(b.t));
  }, [campaigns, driftData]);

  const driftThreshold = 0.15;

  if (status !== 'ready') {
    return <div className="flex items-center justify-center h-64 text-slate-400 text-sm">No data loaded.</div>;
  }

  if (!chartData.length) {
    return (
      <div className="bg-white rounded-xl border border-slate-100 shadow-sm p-10 text-center">
        <p className="text-slate-500 text-sm">Not enough time windows in this sample to compute drift.</p>
        <p className="text-slate-400 text-xs mt-1">Try loading a larger dataset.</p>
      </div>
    );
  }

  const tickFmt = (t) => {
    try { return new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); }
    catch { return t; }
  };

  return (
    <div className="space-y-6">
      {/* Campaign toggles */}
      <div className="bg-white rounded-xl border border-slate-100 shadow-sm px-5 py-4">
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">Campaigns</p>
        <div className="flex flex-wrap gap-2">
          {campaigns.map((c, i) => (
            <button
              key={c.id}
              onClick={() => setVisible(v => ({ ...v, [c.id]: !v[c.id] }))}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-semibold border transition-colors
                          ${visible[c.id] ? 'border-transparent text-white' : 'bg-white border-slate-200 text-slate-500'}`}
              style={visible[c.id] ? { background: CAMPAIGN_PALETTE[i % CAMPAIGN_PALETTE.length] } : {}}
            >
              <span className="w-2 h-2 rounded-full" style={{ background: CAMPAIGN_PALETTE[i % CAMPAIGN_PALETTE.length] }} />
              Campaign {c.id}
              {c.drifting && <span className="opacity-80">(drift)</span>}
            </button>
          ))}
        </div>
      </div>

      {/* Chart */}
      <div className="bg-white rounded-xl border border-slate-100 shadow-sm p-6">
        <h2 className="font-semibold text-slate-900 mb-1">Temporal Drift Score per Campaign</h2>
        <p className="text-xs text-slate-400 mb-5">
          drift(w, w+1) = 1 − cos(centroid_w, centroid_w+1) · Red dashed line = threshold 0.15
        </p>
        <ResponsiveContainer width="100%" height={320}>
          <LineChart data={chartData} margin={{ top: 10, right: 20, bottom: 10, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#F1F5F9" />
            <XAxis dataKey="t" tickFormatter={tickFmt} tick={{ fontSize: 11, fill: '#94A3B8' }} axisLine={false} tickLine={false} />
            <YAxis domain={[0, 0.5]} tick={{ fontSize: 11, fill: '#94A3B8' }} axisLine={false} tickLine={false} />
            <Tooltip
              labelFormatter={tickFmt}
              formatter={(v) => v.toFixed(4)}
              contentStyle={{ border: '1px solid #E2E8F0', borderRadius: '8px', fontSize: '12px' }}
            />
            <ReferenceLine
              y={driftThreshold}
              stroke="#EF4444"
              strokeDasharray="6 3"
              label={{ value: 'Threshold 0.15', position: 'right', fill: '#EF4444', fontSize: 11 }}
            />
            {campaigns.map((c, i) =>
              visible[c.id] ? (
                <Line
                  key={c.id}
                  type="monotone"
                  dataKey={`c${c.id}`}
                  name={`Campaign ${c.id}`}
                  stroke={CAMPAIGN_PALETTE[i % CAMPAIGN_PALETTE.length]}
                  strokeWidth={2}
                  dot={(props) => {
                    const { cx, cy, payload } = props;
                    if (!payload[`flag_${c.id}`]) return null;
                    return (
                      <g key={cx}>
                        <circle cx={cx} cy={cy} r={5} fill="#EF4444" stroke="white" strokeWidth={2} />
                        <text x={cx} y={cy - 10} fill="#EF4444" fontSize="9" textAnchor="middle">Tactic Shift</text>
                      </g>
                    );
                  }}
                  connectNulls={false}
                />
              ) : null
            )}
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
