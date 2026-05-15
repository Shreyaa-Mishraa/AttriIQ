import { subnet24, isMalicious } from './utils.js';

/**
 * Build the attack graph data from processed results.
 * Nodes: IP, /24 Subnet, AttackType
 * Edges: IP→Subnet (belongs_to), IP→AttackType (classified_as)
 *
 * Capped at top 300 IPs by flow count to keep graph readable.
 */
export function buildGraph(ipFeatures, labels, campaigns) {
  const MAX_IPS = 300;

  // Sort IPs by flow count descending
  const sorted = [...ipFeatures].sort((a, b) => (b.raw.flow_count ?? 0) - (a.raw.flow_count ?? 0));
  const topIPs = sorted.slice(0, MAX_IPS);

  const nodes = [];
  const links = [];
  const nodeIds = new Set();

  const addNode = (id, type, extra = {}) => {
    if (nodeIds.has(id)) return;
    nodeIds.add(id);
    nodes.push({ id, type, ...extra });
  };

  const ipIndex = {};
  ipFeatures.forEach((f, i) => { ipIndex[f.ip] = i; });

  for (const feat of topIPs) {
    const cid = labels[ipIndex[feat.ip]] ?? 0;
    const campaign = campaigns[cid];
    const conf = campaign?.confidence ?? 0;

    addNode(feat.ip, 'ip', {
      flowCount: feat.raw.flow_count ?? 0,
      label: feat.label,
      campaignId: cid,
      confidence: conf,
      malicious: isMalicious(feat.label),
    });

    // Subnet node
    const sub = subnet24(feat.ip) + '.0';
    addNode(sub, 'subnet', { campaignId: cid });
    links.push({ source: feat.ip, target: sub, type: 'belongs_to' });

    // Attack type node
    const atk = feat.label || 'Unknown';
    const atkId = `atk_${atk}`;
    addNode(atkId, 'attacktype', { label: atk });
    links.push({ source: feat.ip, target: atkId, type: 'classified_as' });
  }

  return { nodes, links };
}
