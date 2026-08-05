import { useScan } from '../context/ScanContext';
import ForceGraph2D, { type ForceGraphMethods } from 'react-force-graph-2d';
import { useRef, useEffect, useState } from 'react';

const GraphExplorer = () => {
  const { scanData } = useScan();
  const fgRef = useRef<ForceGraphMethods>();
  const [windowSize, setWindowSize] = useState({ width: window.innerWidth, height: window.innerHeight });

  // Handle resizing
  useEffect(() => {
    const handleResize = () => setWindowSize({ width: window.innerWidth, height: window.innerHeight });
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  // --- PHYSICS ENGINE TUNING ---
  useEffect(() => {
    if (fgRef.current) {
      // Increase the distance between connected nodes
      fgRef.current.d3Force('link')!.distance(150);
      // Increase repulsion (charge) so nodes stay far apart
      fgRef.current.d3Force('charge')!.strength(-300);
      // Add some centering force
      fgRef.current.d3Force('center')!.strength(0.05);
    }
  }, [scanData]);

  if (!scanData) return <div className="text-white p-10">Loading Graph Engine...</div>;

  const gData = {
    nodes: scanData.graph_data.nodes.map(n => ({
      id: n.node_id,
      name: n.label,
      type: n.type,
      risk: n.risk_level,
      color: n.risk_level === 'CRITICAL' ? '#ef4444' : 
             n.risk_level === 'HIGH' ? '#f97316' : 
             n.risk_level === 'MEDIUM' ? '#eab308' : '#10b981',
      // INCREASED BASE SIZE
      size: n.risk_level === 'CRITICAL' ? 12 : 8
    })),
    links: scanData.graph_data.edges.map(e => ({
      source: e.source,
      target: e.target,
      label: e.label
    }))
  };

  return (
    <div className="space-y-6 h-full flex flex-col">
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">IAM Relationship Map</h1>
        <p className="text-slate-400">
          Clustered View: Connected entities represent potential <span className="text-red-400">Privilege Escalation paths</span>.
        </p>
      </div>

      <div className="flex-1 bg-slate-950 rounded-xl border border-slate-800 overflow-hidden relative shadow-2xl min-h-[700px]">
        {/* Legend Overlay */}
        <div className="absolute top-4 left-4 z-10 bg-slate-900/90 backdrop-blur-md p-5 rounded-lg border border-slate-700 space-y-3">
            <div className="flex items-center gap-3 text-sm text-slate-200">
                <div className="w-4 h-4 bg-red-500 rounded-full shadow-[0_0_10px_#ef4444]" /> Critical Risk
            </div>
            <div className="flex items-center gap-3 text-sm text-slate-200">
                <div className="w-4 h-4 bg-orange-500 rounded-full" /> High Risk
            </div>
            <div className="flex items-center gap-3 text-sm text-slate-200">
                <div className="w-4 h-4 bg-emerald-500 rounded-full" /> Safe Entity
            </div>
            <div className="pt-2 border-t border-slate-800">
                <p className="text-[11px] text-slate-500 italic">Drag nodes to explore connections</p>
                <p className="text-[11px] text-slate-500 italic">Scroll to zoom in/out</p>
            </div>
        </div>

        <ForceGraph2D
          ref={fgRef}
          graphData={gData}
          width={windowSize.width - 320}
          height={700}
          backgroundColor="#020617"
          nodeRelSize={8}
          linkDirectionalArrowLength={6}
          linkDirectionalArrowRelPos={1}
          linkCurvature={0.2}
          linkColor={() => '#475569'}
          linkWidth={2}
          
          // --- IMPROVED NODE DRAWING ---
          nodeCanvasObject={(node, ctx, globalScale) => {
            const label = node.name;
            const fontSize = 14 / globalScale; // Larger font
            ctx.font = `${fontSize}px "Inter", sans-serif`;
            
            // Draw Node Circle
            ctx.beginPath();
            ctx.arc(node.x!, node.y!, node.size, 0, 2 * Math.PI, false);
            ctx.fillStyle = node.color;
            ctx.fill();

            // Add a border to the node
            ctx.strokeStyle = '#fff';
            ctx.lineWidth = 1 / globalScale;
            ctx.stroke();
            
            // Text Styling
            const textWidth = ctx.measureText(label).width;
            const bckgDimensions = [textWidth, fontSize].map(n => n + fontSize * 0.2); 
            
            // Draw label background for readability
            ctx.fillStyle = 'rgba(2, 6, 23, 0.8)';
            ctx.fillRect(node.x! - bckgDimensions[0] / 2, node.y! + node.size + 2, bckgDimensions[0], bckgDimensions[1]);

            ctx.textAlign = 'center';
            ctx.textBaseline = 'top';
            ctx.fillStyle = node.risk === 'CRITICAL' ? '#fca5a5' : '#e2e8f0';
            ctx.fillText(label, node.x!, node.y! + node.size + 3);
            
            // Red Glow for Critical Nodes
            if (node.risk === 'CRITICAL') {
                ctx.shadowColor = node.color;
                ctx.shadowBlur = 20;
            } else {
                ctx.shadowBlur = 0;
            }
          }}
          
          cooldownTicks={100}
          onEngineStop={() => fgRef.current!.zoomToFit(400, 100)}
        />
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
        <h2 className="text-lg font-semibold text-white mb-2">Security Analysis</h2>
        <p className="text-sm text-slate-400 leading-relaxed">
          The map uses a force-directed layout where <span className="text-cyan-400">relationships</span> exert pull. 
          Clusters containing <span className="text-red-400 font-bold">Red Nodes</span> indicate high-value targets or 
          exposed entry points that are connected to other parts of your infrastructure. 
          Isolated nodes are generally lower risk as they lack lateral movement paths.
        </p>
      </div>
    </div>
  );
};

export default GraphExplorer;