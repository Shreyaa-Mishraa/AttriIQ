import { Routes, Route } from 'react-router-dom';
import { useAttribIQ } from './context/AttribIQContext.jsx';
import Sidebar from './components/Sidebar.jsx';
import TopBar from './components/TopBar.jsx';
import LoadingOverlay from './components/LoadingOverlay.jsx';
import Overview from './pages/Overview.jsx';
import CampaignExplorer from './pages/CampaignExplorer.jsx';
import AttackGraph from './pages/AttackGraph.jsx';
import IPDetail from './pages/IPDetail.jsx';
import TemporalAnalysis from './pages/TemporalAnalysis.jsx';
import ThreatIntel from './pages/ThreatIntel.jsx';
import PipelineStatus from './pages/PipelineStatus.jsx';

export default function App() {
  const { runPipeline, mode, fileName } = useAttribIQ();

  const handleFullDataset = () => {
    // Re-run with same file in full mode — user needs to re-drop the file
    // We signal by showing the drop zone again (reset)
    // A real app would store the File ref; for now inform user
    alert('Re-drop your file on the Overview page to run full dataset mode.');
  };

  return (
    <div className="min-h-screen bg-slate-50">
      <Sidebar />
      <TopBar onFullDataset={handleFullDataset} />
      <LoadingOverlay />

      <main className="ml-60 mt-[60px] p-6 min-h-[calc(100vh-60px)]">
        {/* Amber banner offset when visible */}
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/campaigns" element={<CampaignExplorer />} />
          <Route path="/graph" element={<AttackGraph />} />
          <Route path="/ip" element={<IPDetail />} />
          <Route path="/temporal" element={<TemporalAnalysis />} />
          <Route path="/threats" element={<ThreatIntel />} />
          <Route path="/pipeline" element={<PipelineStatus />} />
        </Routes>
      </main>
    </div>
  );
}
