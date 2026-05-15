import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard, Network, Share2, Search,
  Clock, Shield, Activity, ShieldAlert,
} from 'lucide-react';

const NAV = [
  { to: '/',          icon: LayoutDashboard, label: 'Overview' },
  { to: '/campaigns', icon: Network,          label: 'Campaign Explorer' },
  { to: '/graph',     icon: Share2,           label: 'Attack Graph' },
  { to: '/ip',        icon: Search,           label: 'IP Detail' },
  { to: '/temporal',  icon: Clock,            label: 'Temporal Analysis' },
  { to: '/threats',   icon: Shield,           label: 'Threat Intel' },
  { to: '/pipeline',  icon: Activity,         label: 'Pipeline Status' },
];

export default function Sidebar() {
  return (
    <aside className="fixed left-0 top-0 h-screen w-60 bg-white border-r border-slate-200 flex flex-col z-30">
      {/* Logo */}
      <div className="h-[60px] flex items-center gap-2 px-5 border-b border-slate-100">
        <ShieldAlert className="text-red-500" size={22} strokeWidth={2.5} />
        <span className="font-bold text-slate-900 tracking-tight text-lg">AttribIQ</span>
      </div>

      {/* Nav */}
      <nav className="flex-1 py-4 overflow-y-auto">
        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-4 py-2.5 mx-2 rounded-lg text-sm font-medium transition-colors
               ${isActive
                 ? 'bg-red-50 text-red-600 border-l-[3px] border-red-500 pl-[13px]'
                 : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
               }`
            }
          >
            <Icon size={17} strokeWidth={2} />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="px-5 py-4 border-t border-slate-100">
        <p className="text-xs text-slate-400 leading-relaxed">
          CTU-13 network flow attribution pipeline
        </p>
      </div>
    </aside>
  );
}
