import { useState, useMemo } from 'react';
import { ChevronUp, ChevronDown, Search } from 'lucide-react';
import { useAttribIQ } from '../context/AttribIQContext.jsx';
import ConfidenceBadge from '../components/ConfidenceBadge.jsx';
import CampaignDrawer from '../components/CampaignDrawer.jsx';

function SortHeader({ col, current, onSort, children }) {
  const active = current.col === col;
  return (
    <th
      className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide cursor-pointer select-none hover:text-slate-800 transition-colors"
      onClick={() => onSort(col)}
    >
      <span className="flex items-center gap-1">
        {children}
        {active
          ? (current.dir === 'asc' ? <ChevronUp size={12} /> : <ChevronDown size={12} />)
          : <ChevronDown size={12} className="opacity-30" />}
      </span>
    </th>
  );
}

export default function CampaignExplorer() {
  const { status, campaigns } = useAttribIQ();
  const [sort, setSort] = useState({ col: 'confidence', dir: 'desc' });
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState(null);

  const onSort = (col) => {
    setSort(s => s.col === col ? { col, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { col, dir: 'desc' });
  };

  const sorted = useMemo(() => {
    let rows = [...campaigns];
    if (query) {
      const q = query.toLowerCase();
      rows = rows.filter(c =>
        String(c.id).includes(q) ||
        c.dominantSubnet.includes(q) ||
        c.topLabel.toLowerCase().includes(q)
      );
    }
    rows.sort((a, b) => {
      let av = a[sort.col], bv = b[sort.col];
      if (typeof av === 'string') av = av.toLowerCase(), bv = bv.toLowerCase();
      return sort.dir === 'asc' ? (av > bv ? 1 : -1) : (av < bv ? 1 : -1);
    });
    return rows;
  }, [campaigns, sort, query]);

  if (status !== 'ready') {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 text-sm">
        No data — drop a CTU-13 file on the Overview page.
      </div>
    );
  }

  return (
    <>
      <div className="space-y-4">
        {/* Filter bar */}
        <div className="bg-white rounded-xl border border-slate-100 shadow-sm px-4 py-3 flex items-center gap-3">
          <Search size={15} className="text-slate-400" />
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Filter by ID, subnet, or attack type…"
            className="flex-1 text-sm outline-none text-slate-700 placeholder:text-slate-400"
          />
          <span className="text-xs text-slate-400">{sorted.length} campaigns</span>
        </div>

        {/* Table */}
        <div className="bg-white rounded-xl border border-slate-100 shadow-sm overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-50 border-b border-slate-100">
                <tr>
                  <SortHeader col="id" current={sort} onSort={onSort}>Campaign ID</SortHeader>
                  <SortHeader col="ipCount" current={sort} onSort={onSort}># IPs</SortHeader>
                  <SortHeader col="confidence" current={sort} onSort={onSort}>C(k)</SortHeader>
                  <SortHeader col="dominantSubnet" current={sort} onSort={onSort}>Dominant /24</SortHeader>
                  <SortHeader col="topLabel" current={sort} onSort={onSort}>Top Attack Type</SortHeader>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide">Drift</th>
                  <th className="px-4 py-3" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-50">
                {sorted.map(c => (
                  <tr
                    key={c.id}
                    className="hover:bg-slate-50 cursor-pointer transition-colors"
                    onClick={() => setSelected(c)}
                  >
                    <td className="px-4 py-3 font-semibold text-slate-900">Campaign {c.id}</td>
                    <td className="px-4 py-3 text-slate-700">{c.ipCount.toLocaleString()}</td>
                    <td className="px-4 py-3"><ConfidenceBadge value={c.confidence} /></td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-600">{c.dominantSubnet}</td>
                    <td className="px-4 py-3">
                      <span className="inline-flex px-2 py-0.5 bg-slate-100 text-slate-700 rounded text-xs font-medium">
                        {c.topLabel}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {c.drifting && (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-amber-100 text-amber-700 rounded-full text-xs font-semibold">
                          <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                          Drift Detected
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <span className="text-xs text-red-500 font-medium hover:text-red-700">View →</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <CampaignDrawer campaign={selected} onClose={() => setSelected(null)} />
    </>
  );
}
