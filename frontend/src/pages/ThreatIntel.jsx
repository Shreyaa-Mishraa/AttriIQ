import { useMemo } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell, ResponsiveContainer,
} from 'recharts';
import { useAttribIQ } from '../context/AttribIQContext.jsx';
import { isMalicious, subnet24, fmtNum } from '../lib/utils.js';
import ConfidenceBadge from '../components/ConfidenceBadge.jsx';

export default function ThreatIntel() {
  const { status, ipFeatures, labels, campaigns } = useAttribIQ();

  const { maliciousIPs, subnetChart, labelChart } = useMemo(() => {
    if (!ipFeatures?.length) return { maliciousIPs: [], subnetChart: [], labelChart: [] };

    const ipCampMap = {};
    ipFeatures.forEach((f, i) => { ipCampMap[f.ip] = labels[i]; });

    const maliciousIPs = ipFeatures
      .filter(f => isMalicious(f.label))
      .map(f => ({
        ip: f.ip,
        label: f.label,
        subnet: subnet24(f.ip),
        campaignId: ipCampMap[f.ip],
        campaign: campaigns[ipCampMap[f.ip]],
        flowCount: f.raw.flow_count ?? 0,
        payloadAsymmetry: f.raw.payload_asymmetry ?? 0,
      }))
      .sort((a, b) => b.flowCount - a.flowCount);

    // Top 10 subnets by malicious IP count
    const subnetCounts = {};
    for (const ip of maliciousIPs) {
      subnetCounts[ip.subnet] = (subnetCounts[ip.subnet] || 0) + 1;
    }
    const subnetChart = Object.entries(subnetCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([subnet, count]) => ({ subnet, count }));

    // Attack type distribution from all labels
    const labelCounts = {};
    for (const f of ipFeatures) {
      const lbl = f.label || 'Unknown';
      labelCounts[lbl] = (labelCounts[lbl] || 0) + 1;
    }
    const labelChart = Object.entries(labelCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 12)
      .map(([label, count]) => ({ label: label.length > 24 ? label.slice(0, 24) + '…' : label, count }));

    return { maliciousIPs, subnetChart, labelChart };
  }, [ipFeatures, labels, campaigns]);

  if (status !== 'ready') {
    return <div className="flex items-center justify-center h-64 text-slate-400 text-sm">No data loaded.</div>;
  }

  return (
    <div className="space-y-6">
      {/* Summary */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-white rounded-xl border border-slate-100 shadow-sm p-5 border-l-4 border-red-500">
          <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Malicious IPs</p>
          <p className="text-3xl font-bold text-slate-900 mt-1">{fmtNum(maliciousIPs.length)}</p>
        </div>
        <div className="bg-white rounded-xl border border-slate-100 shadow-sm p-5 border-l-4 border-amber-500">
          <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Unique Subnets</p>
          <p className="text-3xl font-bold text-slate-900 mt-1">{fmtNum(new Set(maliciousIPs.map(i => i.subnet)).size)}</p>
        </div>
        <div className="bg-white rounded-xl border border-slate-100 shadow-sm p-5 border-l-4 border-slate-300">
          <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Total IPs</p>
          <p className="text-3xl font-bold text-slate-900 mt-1">{fmtNum(ipFeatures.length)}</p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Subnet chart */}
        <div className="bg-white rounded-xl border border-slate-100 shadow-sm p-6">
          <h3 className="font-semibold text-slate-900 mb-4">Top 10 Subnets by Malicious IP Count</h3>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={subnetChart} layout="vertical" barSize={16}>
              <CartesianGrid horizontal={false} strokeDasharray="3 3" stroke="#F1F5F9" />
              <XAxis type="number" tick={{ fontSize: 11, fill: '#94A3B8' }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="subnet" tick={{ fontSize: 10, fill: '#64748B', fontFamily: 'monospace' }} width={100} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ border: '1px solid #E2E8F0', borderRadius: '8px', fontSize: '12px' }} />
              <Bar dataKey="count" fill="#EF4444" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Label distribution */}
        <div className="bg-white rounded-xl border border-slate-100 shadow-sm p-6">
          <h3 className="font-semibold text-slate-900 mb-4">Attack Type Distribution</h3>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={labelChart} layout="vertical" barSize={16}>
              <CartesianGrid horizontal={false} strokeDasharray="3 3" stroke="#F1F5F9" />
              <XAxis type="number" tick={{ fontSize: 11, fill: '#94A3B8' }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="label" width={130} tick={{ fontSize: 10, fill: '#64748B' }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ border: '1px solid #E2E8F0', borderRadius: '8px', fontSize: '12px' }} />
              <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                {labelChart.map((e, i) => (
                  <Cell key={i} fill={isMalicious(e.label) ? '#EF4444' : '#94A3B8'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Malicious IP table */}
      <div className="bg-white rounded-xl border border-slate-100 shadow-sm overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
          <h3 className="font-semibold text-slate-900">Malicious IPs</h3>
          <span className="text-xs text-slate-400">{maliciousIPs.length} entries</span>
        </div>
        <div className="overflow-x-auto max-h-96">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 sticky top-0">
              <tr>
                {['IP', 'Label', 'Subnet /24', 'Campaign', 'Flow Count', 'Payload Asymmetry'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-50">
              {maliciousIPs.slice(0, 200).map(ip => (
                <tr key={ip.ip} className="hover:bg-red-50 transition-colors">
                  <td className="px-4 py-2.5 font-mono text-xs text-slate-900">{ip.ip}</td>
                  <td className="px-4 py-2.5 text-xs text-slate-700">{ip.label}</td>
                  <td className="px-4 py-2.5 font-mono text-xs text-slate-600">{ip.subnet}</td>
                  <td className="px-4 py-2.5">
                    {ip.campaign && <ConfidenceBadge value={ip.campaign.confidence} />}
                    <span className="ml-1 text-xs text-slate-500">C{ip.campaignId}</span>
                  </td>
                  <td className="px-4 py-2.5 text-slate-700">{ip.flowCount.toLocaleString()}</td>
                  <td className="px-4 py-2.5 font-mono text-xs text-slate-600">{ip.payloadAsymmetry.toFixed(3)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
