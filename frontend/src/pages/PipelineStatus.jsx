import { CheckCircle, Circle, SkipForward, Loader } from 'lucide-react';
import { useAttribIQ } from '../context/AttribIQContext.jsx';
import { fmtMs } from '../lib/utils.js';

const STEP_DESCRIPTIONS = {
  '01': 'Parse raw binetflow CSV, derive DstBytes, drop incomplete rows.',
  '02': 'Compute 19 behavioral features per source IP per 1-hour window.',
  '03': 'k-means++ clustering with silhouette-optimal k selection (k=4–8).',
  '04': 'Map IPs to threat labels from dataset ground truth.',
  '05': 'C(k) = 0.35·B + 0.25·I + 0.20·T + 0.20·M attribution confidence.',
  '06': 'drift(w,w+1) = 1 − cos(centroid_w, centroid_w+1) per 6h window.',
  '07': 'Build IP → Subnet → AttackType graph for visual exploration.',
  '08': 'Cross-reference IPs against MISP threat sharing platform.',
  '09': 'Assign IoT device family labels (Mirai, Torii, etc.) to clusters.',
};

export default function PipelineStatus() {
  const { status, pipelineSteps } = useAttribIQ();

  if (status !== 'ready') {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 text-sm">
        No pipeline run yet — drop a CTU-13 file on the Overview page.
      </div>
    );
  }

  return (
    <div className="max-w-2xl space-y-4">
      <div className="bg-white rounded-xl border border-slate-100 shadow-sm overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-100">
          <h2 className="font-bold text-slate-900">Pipeline Execution</h2>
          <p className="text-xs text-slate-500 mt-0.5">9-step attack attribution pipeline</p>
        </div>

        <div className="divide-y divide-slate-50">
          {pipelineSteps.map((step, i) => {
            const isSkipped = step.status === 'skipped';
            const isDone = step.status === 'done';
            const isRunning = step.status === 'running';

            return (
              <div key={step.id} className={`flex items-start gap-4 px-6 py-4 ${isSkipped ? 'opacity-60' : ''}`}>
                {/* Status icon */}
                <div className="mt-0.5 shrink-0">
                  {isDone && <CheckCircle size={18} className="text-green-500" />}
                  {isSkipped && <SkipForward size={18} className="text-slate-400" />}
                  {isRunning && <Loader size={18} className="text-red-500 animate-spin" />}
                  {!isDone && !isSkipped && !isRunning && <Circle size={18} className="text-slate-200" />}
                </div>

                {/* Line connector */}
                <div className="flex flex-col flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <span className={`font-semibold text-sm ${isDone ? 'text-slate-900' : isSkipped ? 'text-slate-400' : 'text-slate-400'}`}>
                      <span className="font-mono text-xs text-slate-400 mr-2">{step.id}</span>
                      {step.name}
                    </span>
                    <div className="flex items-center gap-2 shrink-0 ml-4">
                      {step.duration != null && isDone && (
                        <span className="text-xs text-green-600 font-mono">{fmtMs(step.duration)}</span>
                      )}
                      {isSkipped && (
                        <span className="text-xs text-slate-400 italic">{step.note || 'Skipped'}</span>
                      )}
                    </div>
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5 leading-relaxed">
                    {STEP_DESCRIPTIONS[step.id]}
                  </p>
                  {step.note && isDone && (
                    <span className="text-xs font-mono text-slate-500 mt-0.5">{step.note}</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
