// ============================================================
// API PANEL — Live JSON API Response Viewer
// ============================================================

import React, { useState } from 'react';
import { Code, ChevronDown, ChevronUp } from 'lucide-react';

interface APIPanelProps {
  apiResponse: object | null;
  endpoint: string;
}

export const APIPanel: React.FC<APIPanelProps> = ({ apiResponse, endpoint }) => {
  const [expanded, setExpanded] = useState(false);

  const json = apiResponse
    ? JSON.stringify(apiResponse, null, 2)
    : '// Awaiting data stream…';

  return (
    <div className="bg-slate-900/60 rounded-xl border border-slate-700/50">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-slate-700/50 hover:bg-slate-800/30 transition-colors rounded-t-xl"
      >
        <div className="flex items-center gap-2">
          <Code className="w-4 h-4 text-violet-400" />
          <span className="text-sm font-semibold text-slate-300 uppercase tracking-wider">API Response</span>
          <span className="text-xs font-mono text-violet-400 bg-violet-900/30 px-2 py-0.5 rounded border border-violet-500/30">
            GET {endpoint}
          </span>
        </div>
        {expanded ? (
          <ChevronUp className="w-4 h-4 text-slate-500" />
        ) : (
          <ChevronDown className="w-4 h-4 text-slate-500" />
        )}
      </button>

      {expanded && (
        <div className="p-4">
          <pre className="text-xs font-mono text-green-300 bg-black/60 rounded-lg p-4 overflow-x-auto overflow-y-auto border border-slate-800"
            style={{ maxHeight: 400 }}>
            {json
              .replace(/"riskScore":\s*(\d+)/g, (_, n) => `"riskScore": ${n}`)
              .split('\n')
              .map((line, i) => {
                // Syntax highlighting
                let colored = line
                  .replace(/("[\w]+")/g, '<span style="color:#93c5fd">$1</span>')
                  .replace(/: (true|false)/g, ': <span style="color:#f472b6">$1</span>')
                  .replace(/: (\d+\.?\d*)/g, ': <span style="color:#34d399">$1</span>')
                  .replace(/: "([^"]+)"/g, ': <span style="color:#fbbf24">"$1"</span>');
                return `<span key="${i}">${colored}</span>`;
              })
              .join('\n')}
          </pre>
        </div>
      )}
    </div>
  );
};
