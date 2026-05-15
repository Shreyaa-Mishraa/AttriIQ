import { useLocation } from 'react-router-dom';
import { RefreshCw, Zap, FileText } from 'lucide-react';
import { useState } from 'react';
import { useAttribIQ } from '../context/AttribIQContext.jsx';
import { fmtNum } from '../lib/utils.js';

const PAGE_TITLES = {
  '/':          'Overview',
  '/campaigns': 'Campaign Explorer',
  '/graph':     'Attack Graph',
  '/ip':        'IP Detail',
  '/temporal':  'Temporal Analysis',
  '/threats':   'Threat Intel',
  '/pipeline':  'Pipeline Status',
};

export default function TopBar({ onFullDataset }) {
  const { pathname } = useLocation();
  const { status, fileName, totalRows, sampledRows, mode, reset } = useAttribIQ();
  const [showModal, setShowModal] = useState(false);

  const title = PAGE_TITLES[pathname] ?? 'AttribIQ';
  const hasData = status === 'ready';

  const handleFullDataset = () => {
    setShowModal(false);
    onFullDataset?.();
  };

  return (
    <>
      <header className="fixed top-0 left-60 right-0 h-[60px] bg-white border-b border-slate-200 z-20 flex items-center justify-between px-6">
        {/* Breadcrumb */}
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400 font-medium">AttribIQ</span>
          <span className="text-slate-300">/</span>
          <span className="text-sm font-semibold text-slate-900">{title}</span>
        </div>

        {/* Right side */}
        <div className="flex items-center gap-3">
          {hasData && fileName && (
            <span className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-100 rounded-md text-xs font-medium text-slate-600">
              <FileText size={12} />
              {fileName}
            </span>
          )}

          {hasData ? (
            <span className="flex items-center gap-1.5 px-2.5 py-1 bg-green-50 border border-green-200 rounded-md text-xs font-semibold text-green-700">
              <span className="w-1.5 h-1.5 rounded-full bg-green-500 inline-block" />
              LIVE CTU-13
            </span>
          ) : (
            <span className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-100 rounded-md text-xs font-medium text-slate-500">
              NO DATA
            </span>
          )}

          <button
            disabled={!hasData || mode === 'full'}
            onClick={() => setShowModal(true)}
            className="flex items-center gap-2 px-3 py-1.5 bg-red-500 text-white text-xs font-semibold rounded-lg
                       disabled:opacity-40 disabled:cursor-not-allowed hover:bg-red-600 transition-colors"
          >
            <Zap size={13} />
            Run Full Dataset
          </button>

          {hasData && (
            <button
              onClick={reset}
              title="Reset / load new file"
              className="p-2 text-slate-400 hover:text-slate-700 hover:bg-slate-100 rounded-lg transition-colors"
            >
              <RefreshCw size={15} />
            </button>
          )}
        </div>
      </header>

      {/* Sampled mode banner */}
      {hasData && mode === 'sample' && (
        <div className="fixed top-[60px] left-60 right-0 z-10 bg-amber-50 border-b border-amber-200 px-6 py-2 text-xs font-medium text-amber-700 flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-amber-400 inline-block" />
          Sampled mode: showing results for {fmtNum(sampledRows)} of {fmtNum(totalRows)} total flows.
          <button onClick={() => setShowModal(true)} className="underline hover:no-underline ml-1">
            Run full dataset
          </button>
        </div>
      )}

      {/* Confirmation modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/20 backdrop-blur-sm">
          <div className="bg-white rounded-xl shadow-lg border border-slate-200 p-6 max-w-sm w-full mx-4">
            <h3 className="font-bold text-slate-900 mb-2">Run Full Dataset?</h3>
            <p className="text-sm text-slate-600 mb-5 leading-relaxed">
              This will process all {fmtNum(totalRows)} rows and may take 30–60 seconds.
              All computation runs in a background thread.
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => setShowModal(false)}
                className="flex-1 px-4 py-2 border border-slate-200 rounded-lg text-sm font-medium text-slate-700 hover:bg-slate-50 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleFullDataset}
                className="flex-1 px-4 py-2 bg-red-500 text-white rounded-lg text-sm font-semibold hover:bg-red-600 transition-colors"
              >
                Continue
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
