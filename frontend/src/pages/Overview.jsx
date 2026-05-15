import { useState } from 'react';
import { X, Network, Users, AlertTriangle, Clock } from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell, ResponsiveContainer,
} from 'recharts';
import { useAttribIQ } from '../context/AttribIQContext.jsx';
import DropZone from '../components/DropZone.jsx';
import StatCard from '../components/StatCard.jsx';
import { fmtNum, severityTier, SEVERITY_COLORS } from '../lib/utils.js';

export default function Overview() {
  const { status, campaigns, totalRows, sampledRows, pipelineSteps, runPipeline } = useAttribIQ();
  const [dismissAlert, setDismissAlert] = useState(false);

  if (status === 'idle' || status === 'error') {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-8">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-slate-900 mb-2">AttribIQ</h1>
          <p className="text-slate-500 text-sm">Network Attack Attribution — CTU-13 Dataset</p>
        </div>
        <DropZone onFile={(f) => runPipeline(f, 'sample')} />
      </div>
    );
  }

  if (status === 'loading') return null;

  const highConf = campaigns.filter(c => c.confidence >= 0.8);
  const lastStep = pipelineSteps.find(s => s.status === 'done');
  const lastRun = lastStep ? new Date().toLocaleTimeString() : '—';

  const barData = campaigns.map(c => ({
    name: `C${c.id}`,
    confidence: +(c.confidence * 100).toFixed(1),
    tier: severityTier(c.confidence),
  }));

  const CustomTooltip = ({ active, payload }) => {
    if (!active || !payload?.length) return null;
    const d = payload[0].payload;
    const camp = campaigns[parseInt(d.name.replace('C', ''))];
    return (
      <div className="bg-white border border-slate-200 rounded-lg shadow-lg p-3 text-xs">
        <p className="font-bold text-slate-900 mb-1">{d.name} — {d.confidence.toFixed(1)}%</p>
        <p className="text-slate-600">{camp?.topLabel}</p>
        <p className="text-slate-500">{camp?.ipCount} IPs · {camp?.dominantSubnet}</p>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* High-confidence alert */}
      {!dismissAlert && highConf.length > 0 && (
        <div className="flex items-center gap-3 bg-red-50 border border-red-200 rounded-xl px-4 py-3">
          <AlertTriangle size={16} className="text-red-500 shrink-0" />
          <p className="text-sm font-medium text-red-800 flex-1">
            {highConf.length} campaign{highConf.length > 1 ? 's' : ''} with high-confidence attribution (C(k) &gt; 80%) detected.
            Immediate review recommended.
          </p>
          <button onClick={() => setDismissAlert(true)} className="p-1 hover:bg-red-100 rounded transition-colors">
            <X size={14} className="text-red-400" />
          </button>
        </div>
      )}

      {/* KPI cards */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard
          label="Total IPs Analyzed"
          value={fmtNum(campaigns.reduce((a, c) => a + c.ipCount, 0))}
          sub={`from ${fmtNum(sampledRows)} flows`}
          accent="blue"
          icon={Users}
        />
        <StatCard
          label="Campaigns Discovered"
          value={campaigns.length}
          sub="via k-means++ clustering"
          accent="slate"
          icon={Network}
        />
        <StatCard
          label="High-Conf Alerts"
          value={highConf.length}
          sub="C(k) > 80%"
          accent={highConf.length > 0 ? 'red' : 'green'}
          icon={AlertTriangle}
        />
        <StatCard
          label="Last Pipeline Run"
          value={lastRun}
          sub={`${fmtNum(totalRows)} total rows`}
          accent="slate"
          icon={Clock}
        />
      </div>

      {/* Bar chart */}
      <div className="bg-white rounded-xl border border-slate-100 shadow-sm p-6">
        <h2 className="font-semibold text-slate-900 mb-1">Attribution Confidence per Campaign</h2>
        <p className="text-xs text-slate-500 mb-5">C(k) = 0.35·B + 0.25·I + 0.20·T + 0.20·M</p>
        <ResponsiveContainer width="100%" height={260}>
          <BarChart data={barData} barSize={36}>
            <CartesianGrid strokeDasharray="3 3" stroke="#F1F5F9" vertical={false} />
            <XAxis dataKey="name" tick={{ fontSize: 12, fill: '#64748B' }} axisLine={false} tickLine={false} />
            <YAxis domain={[0, 100]} tickFormatter={v => `${v}%`} tick={{ fontSize: 12, fill: '#94A3B8' }} axisLine={false} tickLine={false} />
            <Tooltip content={<CustomTooltip />} />
            <Bar dataKey="confidence" radius={[6, 6, 0, 0]}>
              {barData.map((entry, i) => (
                <Cell key={i} fill={SEVERITY_COLORS[entry.tier].hex} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
        {/* Legend */}
        <div className="flex items-center gap-4 mt-4 justify-center">
          {[['high','≥ 80% — High','#EF4444'],['medium','50–79% — Medium','#F59E0B'],['low','< 50% — Low','#22C55E']].map(([,lbl,col]) => (
            <span key={lbl} className="flex items-center gap-1.5 text-xs text-slate-500">
              <span className="w-2.5 h-2.5 rounded-full" style={{ background: col }} />
              {lbl}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
