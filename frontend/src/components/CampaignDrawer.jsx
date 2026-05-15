import { X } from 'lucide-react';
import ConfidenceBadge from './ConfidenceBadge.jsx';

const FACTOR_META = {
  B: { label: 'Behavioral Cohesion', desc: 'Mean pairwise cosine similarity of IP feature vectors — how similarly the IPs behave.' },
  I: { label: 'Infrastructure Overlap', desc: 'Fraction of IPs sharing the majority /24 subnet — shared hosting footprint.' },
  T: { label: 'Timing Correlation', desc: '|Pearson r| between cluster and global hourly flow counts — coordinated activity.' },
  M: { label: 'Threat Match', desc: 'Fraction of IPs labeled Botnet/Malicious in the dataset.' },
};

export default function CampaignDrawer({ campaign, onClose }) {
  if (!campaign) return null;

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 z-30 bg-black/10" onClick={onClose} />

      {/* Drawer */}
      <div className="fixed right-0 top-0 h-screen w-[400px] bg-white border-l border-slate-200 z-40 flex flex-col shadow-xl overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-100">
          <div>
            <h2 className="font-bold text-slate-900">Campaign {campaign.id}</h2>
            <p className="text-xs text-slate-500 mt-0.5">{campaign.topLabel}</p>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-slate-100 rounded-lg transition-colors">
            <X size={16} className="text-slate-500" />
          </button>
        </div>

        <div className="flex-1 p-6 space-y-6">
          {/* Confidence */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-semibold text-slate-700">Attribution Confidence</span>
              <ConfidenceBadge value={campaign.confidence} />
            </div>
            <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
              <div
                className="h-full rounded-full bg-gradient-to-r from-red-500 via-amber-400 to-green-500"
                style={{ width: `${campaign.confidence * 100}%` }}
              />
            </div>
          </div>

          {/* Factor bars */}
          <div>
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
              Factor Contributions
            </p>
            <div className="space-y-3">
              {Object.entries(campaign.factors).map(([key, val]) => {
                const meta = FACTOR_META[key];
                return (
                  <div key={key}>
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-1 group relative">
                        <span className="text-sm text-slate-700">{meta.label}</span>
                        <span className="w-3.5 h-3.5 rounded-full bg-slate-200 text-slate-500 text-[9px] font-bold flex items-center justify-center cursor-help">?</span>
                        <div className="absolute left-full ml-2 top-0 w-56 bg-slate-900 text-white text-xs rounded-lg p-2.5 opacity-0 group-hover:opacity-100 pointer-events-none z-50 leading-relaxed shadow-lg">
                          {meta.desc}
                        </div>
                      </div>
                      <span className="text-xs font-mono font-bold text-slate-700">{val.toFixed(3)}</span>
                    </div>
                    <div className="h-1.5 bg-slate-100 rounded-full overflow-hidden">
                      <div className="h-full bg-red-400 rounded-full" style={{ width: `${val * 100}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Info */}
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-slate-50 rounded-lg p-3">
              <p className="text-xs text-slate-500">IPs</p>
              <p className="font-bold text-slate-900 text-lg">{campaign.ipCount}</p>
            </div>
            <div className="bg-slate-50 rounded-lg p-3">
              <p className="text-xs text-slate-500">Subnet</p>
              <p className="font-bold text-slate-900 text-sm font-mono">{campaign.dominantSubnet}</p>
            </div>
          </div>

          {campaign.drifting && (
            <div className="flex items-center gap-2 px-3 py-2 bg-amber-50 border border-amber-200 rounded-lg text-xs font-medium text-amber-700">
              <span className="w-2 h-2 rounded-full bg-amber-400" />
              Tactic drift detected across time windows
            </div>
          )}

          {/* IP list */}
          <div>
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">
              IPs in this campaign ({campaign.ips.length})
            </p>
            <div className="bg-slate-50 rounded-lg p-3 max-h-48 overflow-y-auto space-y-1">
              {campaign.ips.slice(0, 100).map(ip => (
                <p key={ip} className="text-xs font-mono text-slate-700">{ip}</p>
              ))}
              {campaign.ips.length > 100 && (
                <p className="text-xs text-slate-400 pt-1">…and {campaign.ips.length - 100} more</p>
              )}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
