import { createContext, useContext, useReducer, useCallback, useRef } from 'react';

const AttribIQContext = createContext(null);

const INITIAL = {
  status: 'idle',           // 'idle' | 'loading' | 'ready' | 'error'
  loadingStage: '',
  loadingPct: 0,
  mode: 'sample',           // 'sample' | 'full'
  fileName: '',
  totalRows: 0,
  sampledRows: 0,
  // Pipeline results
  ipFeatures: [],           // { ip, label, normFeatures, raw, features }[]
  labels: [],               // cluster assignment per IP
  centroids: [],
  campaigns: [],            // { id, ipCount, ips, confidence, factors, ... }[]
  driftData: {},            // { [campaignId]: { windows, drifting } }
  graph: { nodes: [], links: [] },
  pipelineSteps: [],
  error: null,
};

function reducer(state, action) {
  switch (action.type) {
    case 'LOADING_START':
      return { ...state, status: 'loading', loadingStage: action.stage, loadingPct: action.pct, error: null };
    case 'LOADING_PROGRESS':
      return { ...state, loadingStage: action.stage, loadingPct: action.pct };
    case 'LOADING_DONE':
      return { ...state, status: 'ready', loadingStage: '', loadingPct: 100, ...action.payload };
    case 'LOADING_ERROR':
      return { ...state, status: 'error', loadingStage: '', error: action.error };
    case 'RESET':
      return { ...INITIAL };
    default:
      return state;
  }
}

export function AttribIQProvider({ children }) {
  const [state, dispatch] = useReducer(reducer, INITIAL);
  const workerRef = useRef(null);

  const runPipeline = useCallback((file, mode = 'sample') => {
    if (workerRef.current) workerRef.current.terminate();

    dispatch({ type: 'LOADING_START', stage: 'Parsing CTU-13 flows…', pct: 5 });

    const worker = new Worker(
      new URL('../workers/pipeline.worker.js', import.meta.url),
      { type: 'module' }
    );
    workerRef.current = worker;

    worker.onmessage = (e) => {
      const { stage, pct, payload, error } = e.data;
      if (stage === 'done') {
        dispatch({ type: 'LOADING_DONE', payload });
        worker.terminate();
      } else if (stage === 'error') {
        dispatch({ type: 'LOADING_ERROR', error });
        worker.terminate();
      } else {
        dispatch({ type: 'LOADING_PROGRESS', stage, pct });
      }
    };

    worker.onerror = (err) => {
      dispatch({ type: 'LOADING_ERROR', error: err.message || 'Worker error' });
      worker.terminate();
    };

    worker.postMessage({ file, mode });
  }, []);

  const reset = useCallback(() => {
    workerRef.current?.terminate();
    dispatch({ type: 'RESET' });
  }, []);

  return (
    <AttribIQContext.Provider value={{ ...state, runPipeline, reset }}>
      {children}
    </AttribIQContext.Provider>
  );
}

export const useAttribIQ = () => {
  const ctx = useContext(AttribIQContext);
  if (!ctx) throw new Error('useAttribIQ must be used within AttribIQProvider');
  return ctx;
};
