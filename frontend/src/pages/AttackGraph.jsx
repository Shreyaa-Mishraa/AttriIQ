import { useRef, useState, useCallback } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { useAttribIQ } from '../context/AttribIQContext.jsx';
import { SEVERITY_COLORS, severityTier } from '../lib/utils.js';

function nodeColor(node) {
  if (node.type === 'subnet') return '#94A3B8';
  if (node.type === 'attacktype') return '#F59E0B';
  if (node.malicious) return '#EF4444';
  return '#3B82F6';
}

function nodeSize(node) {
  if (node.type === 'subnet') return 8;
  if (node.type === 'attacktype') return 10;
  return Math.max(4, Math.min(14, 4 + Math.log1p(node.flowCount || 1) * 1.2));
}

export default function AttackGraph() {
  const { status, graph, campaigns } = useAttribIQ();
  const fgRef = useRef(null);
  const [hovered, setHovered] = useState(null);

  const nodeCanvasObject = useCallback((node, ctx, globalScale) => {
    const size = nodeSize(node);
    const col = nodeColor(node);
    ctx.save();

    if (node.type === 'subnet') {
      ctx.fillStyle = '#F1F5F9';
      ctx.strokeStyle = '#94A3B8';
      ctx.lineWidth = 1.5 / globalScale;
      ctx.beginPath();
      ctx.rect(node.x - size, node.y - size / 1.8, size * 2, size * 1.4);
      ctx.fill(); ctx.stroke();
    } else if (node.type === 'attacktype') {
      ctx.fillStyle = '#FEF3C7';
      ctx.strokeStyle = '#F59E0B';
      ctx.lineWidth = 1.5 / globalScale;
      ctx.beginPath();
      ctx.moveTo(node.x, node.y - size);
      ctx.lineTo(node.x + size, node.y);
      ctx.lineTo(node.x, node.y + size);
      ctx.lineTo(node.x - size, node.y);
      ctx.closePath();
      ctx.fill(); ctx.stroke();
    } else {
      ctx.fillStyle = node.malicious ? '#FEE2E2' : '#DBEAFE';
      ctx.strokeStyle = col;
      ctx.lineWidth = (hovered?.id === node.id ? 2.5 : 1.5) / globalScale;
      ctx.beginPath();
      ctx.arc(node.x, node.y, size, 0, 2 * Math.PI);
      ctx.fill(); ctx.stroke();
    }

    ctx.restore();

    // Label at scale > 2
    if (globalScale > 2 && node.type !== 'attacktype') {
      const label = node.type === 'subnet' ? node.id : (node.id.split('.').slice(-2).join('.'));
      ctx.font = `${9 / globalScale}px monospace`;
      ctx.textAlign = 'center';
      ctx.fillStyle = '#334155';
      ctx.fillText(label, node.x, node.y + size + 8 / globalScale);
    }
  }, [hovered]);

  if (status !== 'ready') {
    return <div className="flex items-center justify-center h-64 text-slate-400 text-sm">No data loaded.</div>;
  }

  const campByIp = {};
  if (campaigns) {
    for (const c of campaigns)
      for (const ip of c.ips) campByIp[ip] = c;
  }

  return (
    <div className="flex gap-4 h-[calc(100vh-160px)]">
      {/* Graph */}
      <div className="flex-1 bg-white rounded-xl border border-slate-100 shadow-sm overflow-hidden relative">
        <div className="absolute top-4 left-4 z-10 text-xs text-slate-400 font-medium">
          {graph.nodes.length} nodes · {graph.links.length} edges
        </div>
        <ForceGraph2D
          ref={fgRef}
          graphData={graph}
          nodeCanvasObject={nodeCanvasObject}
          nodeCanvasObjectMode={() => 'replace'}
          linkColor={() => '#E2E8F0'}
          linkWidth={1}
          backgroundColor="#F8FAFC"
          onNodeHover={setHovered}
          onNodeClick={setHovered}
          cooldownTicks={200}
        />
      </div>

      {/* Node detail panel */}
      <div className="w-64 bg-white rounded-xl border border-slate-100 shadow-sm p-5 space-y-4 overflow-y-auto">
        {/* Legend */}
        <div>
          <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">Node Types</p>
          <div className="space-y-2">
            {[
              ['circle','#DBEAFE','#3B82F6', 'IP (benign)'],
              ['circle','#FEE2E2','#EF4444', 'IP (malicious)'],
              ['rect','#F1F5F9','#94A3B8', 'Subnet /24'],
              ['diamond','#FEF3C7','#F59E0B', 'Attack Type'],
            ].map(([shape, bg, border, lbl]) => (
              <div key={lbl} className="flex items-center gap-2 text-xs text-slate-600">
                <svg width="16" height="16">
                  {shape === 'circle' && <circle cx="8" cy="8" r="6" fill={bg} stroke={border} strokeWidth="1.5" />}
                  {shape === 'rect' && <rect x="2" y="4" width="12" height="8" fill={bg} stroke={border} strokeWidth="1.5" />}
                  {shape === 'diamond' && <polygon points="8,2 14,8 8,14 2,8" fill={bg} stroke={border} strokeWidth="1.5" />}
                </svg>
                {lbl}
              </div>
            ))}
          </div>
        </div>

        <hr className="border-slate-100" />

        {hovered ? (
          <div className="space-y-3">
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Selected Node</p>
            <p className="font-mono text-sm text-slate-900 break-all">{hovered.id}</p>
            <div className="space-y-1.5 text-xs text-slate-600">
              <div className="flex justify-between">
                <span>Type</span>
                <span className="font-medium capitalize">{hovered.type}</span>
              </div>
              {hovered.flowCount != null && (
                <div className="flex justify-between">
                  <span>Flow count</span>
                  <span className="font-medium">{hovered.flowCount.toLocaleString()}</span>
                </div>
              )}
              {hovered.label && (
                <div className="flex justify-between">
                  <span>Label</span>
                  <span className="font-medium">{hovered.label}</span>
                </div>
              )}
              {hovered.campaignId != null && (
                <div className="flex justify-between">
                  <span>Campaign</span>
                  <span className="font-medium">C{hovered.campaignId}</span>
                </div>
              )}
              {hovered.confidence != null && (
                <div className="flex justify-between">
                  <span>Confidence</span>
                  <span className="font-bold text-red-600">{(hovered.confidence * 100).toFixed(1)}%</span>
                </div>
              )}
            </div>
          </div>
        ) : (
          <p className="text-xs text-slate-400">Click a node to see details</p>
        )}
      </div>
    </div>
  );
}
