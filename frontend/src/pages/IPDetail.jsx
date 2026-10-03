import { useState, useMemo } from 'react';
import { Search } from 'lucide-react';
import {
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, ResponsiveContainer, Tooltip,
} from 'recharts';
import { useAttribIQ } from '../context/AttribIQContext.jsx';
import { FEATURE_NAMES } from '../lib/features.js';

const FEATURE_LABELS = {
  proto_entropy: 'Protocol Entropy',
  scan_entropy: 'Scan Entropy',
  c2_beacon_score: 'C2 Beacon Score',
  payload_asymmetry: 'Payload Asymmetry',
  burst_score: 'Burst Score',
  night_ratio: 'Night Ratio',
  scan_score: 'Scan Score',
  flow_count: 'Flow Count',
  avg_duration: 'Avg Duration',
  avg_bytes: 'Avg Bytes',
  avg_pkts: 'Avg Packets',
  tcp_ratio: 'TCP Ratio',
  udp_ratio: 'UDP Ratio',
  unique_dst_ports: 'Unique Dst Ports',
  unique_dst_ips: 'Unique Dst IPs',
  avg_sport_entropy: 'Src Port Entropy',
  state_entropy: 'State Entropy',
  bytes_per_pkt: 'Bytes / Packet',
  pkts_per_flow: 'Pkts / Flow',
};

export default function IPDetail() {
  const { status, ipFeatures, labels, campaigns } = useAttribIQ();
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState(null);
  const [showSuggestions, setShowSuggestions] = useState(false);

  const allIPs = useMemo(() => ipFeatures.map(f => f.ip), [ipFeatures]);

  const suggestions = useMemo(() => {
    if (!query || query.length < 2) return [];
    return allIPs.filter(ip => ip.includes(query)).slice(0, 12);
  }, [allIPs, query]);

  const selectIP = (ip) => {
    const feat = ipFeatures.find(f => f.ip === ip);
    if (!feat) return;
    const idx = ipFeatures.indexOf(feat);
    const cid = labels[idx];
    setSelected({ ...feat, campaignId: cid, campaign: campaigns[cid] });
    setQuery(ip);
    setShowSuggestions(false);
  };

  if (status !== 'ready') {
    return <div className="flex items-center justify-center h-64 text-slate-400 text-sm">No data loaded.</div>;
  }

  const radarData = selected
    ? FEATURE_NAMES.map((k, i) => ({
        feature: FEATURE_LABELS[k] ?? k,
        value: +(selected.normFeatures[i] ?? 0).toFixed(3),
      }))
    : [];

  return (
    <div className="space-y-6">
      {/* Search */}
      <div className="bg-white rounded-xl border border-slate-100 shadow-sm p-5 relative">
        <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">
          Search IP Address
        </label>
        <div className="relative">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            value={query}
            onChange={e => { setQuery(e.target.value); setShowSuggestions(true); }}
            onFocus={() => setShowSuggestions(true)}
            placeholder="Type an IP address…"
            className="w-full pl-9 pr-4 py-2.5 border border-slate-200 rounded-lg text-sm font-mono outline-none focus:border-red-400 transition-colors"
          />
        </div>
        {showSuggestions && suggestions.length > 0 && (
          <div className="absolute left-5 right-5 top-full mt-1 bg-white border border-slate-200 rounded-lg shadow-lg z-20 max-h-48 overflow-y-auto">
            {suggestions.map(ip => (
              <button
                key={ip}
                className="w-full text-left px-4 py-2 text-sm font-mono text-slate-700 hover:bg-red-50 hover:text-red-700 transition-colors"
                onClick={() => selectIP(ip)}
              >
                {ip}
              </button>
            ))}
          </div>
        )}
      </div>

      {selected && (
        <div className="grid grid-cols-2 gap-6">
          {/* Radar chart */}
          <div className="bg-white rounded-xl border border-slate-100 shadow-sm p-6">
            <h3 className="font-semibold text-slate-900 mb-1">Feature Profile</h3>
            <p className="text-xs text-slate-400 mb-4">All 19 normalised features (0–1)</p>
            <ResponsiveContainer width="100%" height={300}>
              <RadarChart data={radarData}>
                <PolarGrid stroke="#F1F5F9" />
                <PolarAngleAxis dataKey="feature" tick={{ fontSize: 8, fill: '#94A3B8' }} />
                <PolarRadiusAxis domain={[0, 1]} tick={false} axisLine={false} />
                <Radar dataKey="value" fill="#EF4444" fillOpacity={0.25} stroke="#EF4444" strokeWidth={2} />
                <Tooltip formatter={(v) => v.toFixed(3)} />
              </RadarChart>
            </ResponsiveContainer>
          </div>

          {/* Stats */}
          <div className="space-y-4">
            <div className="bg-white rounded-xl border border-slate-100 shadow-sm p-5">
              <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">IP Summary</p>
              <div className="space-y-2 text-sm">
                {[
                  ['IP Address', selected.ip, true],
                  ['Label', selected.label || 'Unknown', false],
                  ['Campaign', `C${selected.campaignId}`, false],
                  ['Confidence', `${((selected.campaign?.confidence ?? 0) * 100).toFixed(1)}%`, false],
                  ['Flow Count', selected.raw.flow_count?.toLocaleString(), false],
                  ['Avg Bytes', selected.raw.avg_bytes?.toFixed(0), false],
                  ['Avg Packets', selected.raw.avg_pkts?.toFixed(1), false],
                ].map(([lbl, val, mono]) => (
                  <div key={lbl} className="flex justify-between items-center py-1.5 border-b border-slate-50">
                    <span className="text-slate-500">{lbl}</span>
                    <span className={`font-medium text-slate-900 ${mono ? 'font-mono' : ''}`}>{val}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Feature table — full width */}
          <div className="col-span-2 bg-white rounded-xl border border-slate-100 shadow-sm overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-100">
              <h3 className="font-semibold text-slate-900">Full Feature Vector</h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-slate-50">
                  <tr>
                    {['Feature', 'Raw Value', 'Normalised'].map(h => (
                      <th key={h} className="px-4 py-2.5 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-50">
                  {FEATURE_NAMES.map((k, i) => (
                    <tr key={k} className="hover:bg-slate-50">
                      <td className="px-4 py-2 text-slate-700">{FEATURE_LABELS[k]}</td>
                      <td className="px-4 py-2 font-mono text-xs text-slate-600">{(selected.features[i] ?? 0).toFixed(4)}</td>
                      <td className="px-4 py-2">
                        <div className="flex items-center gap-2">
                          <div className="flex-1 h-1.5 bg-slate-100 rounded-full overflow-hidden">
                            <div className="h-full bg-red-400 rounded-full" style={{ width: `${(selected.normFeatures[i] ?? 0) * 100}%` }} />
                          </div>
                          <span className="font-mono text-xs text-slate-500 w-10 text-right">{(selected.normFeatures[i] ?? 0).toFixed(3)}</span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
