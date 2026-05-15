import { useAttribIQ } from '../context/AttribIQContext.jsx';

export default function LoadingOverlay() {
  const { status, loadingStage, loadingPct } = useAttribIQ();
  if (status !== 'loading') return null;

  return (
    <div className="fixed inset-0 z-50 bg-white/90 backdrop-blur-sm flex flex-col items-center justify-center gap-6">
      {/* Spinner */}
      <div className="relative w-16 h-16">
        <div className="absolute inset-0 rounded-full border-4 border-slate-100" />
        <div className="absolute inset-0 rounded-full border-4 border-t-red-500 animate-spin" />
      </div>

      <div className="text-center">
        <p className="font-semibold text-slate-900 text-lg mb-1">{loadingStage}</p>
        <p className="text-sm text-slate-500">{Math.round(loadingPct)}% complete</p>
      </div>

      {/* Progress bar */}
      <div className="w-64 h-2 bg-slate-100 rounded-full overflow-hidden">
        <div
          className="h-full bg-red-500 rounded-full transition-all duration-300"
          style={{ width: `${loadingPct}%` }}
        />
      </div>

      <div className="text-xs text-slate-400 text-center max-w-xs">
        Running in background thread — the page remains responsive
      </div>
    </div>
  );
}
