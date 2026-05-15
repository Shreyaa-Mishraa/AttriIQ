export default function StatCard({ label, value, sub, accent = 'slate', icon: Icon }) {
  const accents = {
    red:   'border-red-500',
    amber: 'border-amber-500',
    green: 'border-green-500',
    slate: 'border-slate-300',
    blue:  'border-blue-500',
  };

  return (
    <div className={`bg-white rounded-xl border border-slate-100 shadow-sm p-5 border-l-4 ${accents[accent]}`}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-1">{label}</p>
          <p className="text-3xl font-bold text-slate-900">{value}</p>
          {sub && <p className="text-xs text-slate-400 mt-1">{sub}</p>}
        </div>
        {Icon && (
          <div className="p-2 bg-slate-50 rounded-lg">
            <Icon size={18} className="text-slate-400" />
          </div>
        )}
      </div>
    </div>
  );
}
