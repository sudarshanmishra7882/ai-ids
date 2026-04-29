import React from 'react';
import { AlertLevel } from '../types/ids';
import { Brain, AlertTriangle, Info, CheckCircle, Shield } from 'lucide-react';

interface Props {
  explanation: string;
  reasons: string[];
  alert: AlertLevel;
  isolationScore: number;
  correlationScore: number;
  falsePositiveReduced: boolean;
  confidence: number;
  threatCategory: string;
  alternativeInterpretation: string;
  temporalContext: string;
  executiveSummary: string;
}

const COLORS: Record<AlertLevel, string> = {
  CRITICAL: 'border-purple-500/30 text-purple-400 bg-purple-900/10',
  HIGH: 'border-red-500/30 text-red-400 bg-red-900/10',
  MEDIUM: 'border-amber-500/30 text-amber-400 bg-amber-900/10',
  LOW: 'border-green-500/30 text-green-400 bg-green-900/10',
};

export const ExplanationPanel: React.FC<Props> = (props) => {
  const cfg = COLORS[props.alert];
  const filteredReasons = props.reasons.filter(r => !r.includes('FP') && !r.includes('adjusted'));
  const fpReasons = props.reasons.filter(r => r.includes('adjusted') || r.includes('Batch') || r.includes('hours'));

  return (
    <div className={"rounded-xl border p-5 space-y-4 " + cfg}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-black/30 border">
            <Brain className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">AI Explanation Engine</h3>
            <p className="text-xs text-slate-500">Behavioral analysis and correlation reasoning</p>
          </div>
        </div>
        {props.falsePositiveReduced && (
          <span className="px-2 py-1 bg-blue-900/40 border border-blue-500/40 rounded-lg text-xs text-blue-300 font-medium">FP Reduced</span>
        )}
      </div>

      <div className="flex items-center justify-between bg-black/30 rounded-lg p-3 border border-slate-800">
        <div className="px-3 py-1.5 rounded-lg border font-bold text-xs uppercase tracking-wider bg-slate-800/50 border-slate-600/50 text-slate-300">
          {props.threatCategory}
        </div>
        <div className="text-right">
          <div className="text-2xl font-bold font-mono text-blue-400">{(props.confidence * 100).toFixed(0)}%</div>
          <div className="text-xs text-slate-500 font-mono">CONFIDENCE</div>
        </div>
      </div>

      {props.temporalContext && (
        <div className="space-y-2">
          <h4 className="text-xs font-semibold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
            <Info className="w-3 h-3" /> Temporal Context
          </h4>
          <div className="bg-black/20 rounded-lg p-3 border border-slate-800/50">
            <p className="text-xs font-mono text-cyan-400/80 leading-relaxed">{props.temporalContext}</p>
          </div>
        </div>
      )}

      {props.alternativeInterpretation && (
        <div className="space-y-2">
          <h4 className="text-xs font-semibold text-indigo-400 uppercase tracking-wider flex items-center gap-1.5">
            <Info className="w-3 h-3" /> Alternative Interpretation
          </h4>
          <div className="bg-black/20 rounded-lg p-3 border border-slate-800/50">
            <p className="text-xs font-mono text-indigo-400/70 leading-relaxed">{props.alternativeInterpretation}</p>
          </div>
        </div>
      )}

      <div className="bg-black/30 rounded-lg p-4 border border-slate-800">
        <div className="text-xs font-mono leading-relaxed text-slate-300 opacity-90">
          {props.explanation || 'Initializing analysis engine...'}
        </div>
      </div>

      {filteredReasons.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Detected Signals</h4>
          <div className="space-y-1.5">
            {filteredReasons.map((reason, i) => (
              <div key={i} className="flex items-start gap-2">
                {props.alert === 'HIGH' || props.alert === 'CRITICAL' ? (
                  <AlertTriangle className="w-3.5 h-3.5 text-red-400 mt-0.5 shrink-0" />
                ) : props.alert === 'MEDIUM' ? (
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400 mt-0.5 shrink-0" />
                ) : (
                  <CheckCircle className="w-3.5 h-3.5 text-green-400 mt-0.5 shrink-0" />
                )}
                <span className="text-xs text-slate-400 font-mono leading-relaxed">{reason}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {fpReasons.length > 0 && (
        <div className="space-y-1.5">
          <h4 className="text-xs font-semibold text-blue-400 uppercase tracking-wider">False Positive Mitigation</h4>
          <div className="space-y-1.5">
            {fpReasons.map((reason, i) => (
              <div key={i} className="flex items-start gap-2">
                <CheckCircle className="w-3.5 h-3.5 text-blue-400 mt-0.5 shrink-0" />
                <span className="text-xs text-blue-400/70 font-mono leading-relaxed">{reason}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {props.executiveSummary && (
        <div className="bg-black/40 rounded-lg p-4 border border-slate-700/50">
          <div className="flex items-start gap-2">
            <Shield className="w-4 h-4 text-blue-400 mt-0.5 shrink-0" />
            <p className="text-xs font-bold font-mono text-slate-300 leading-relaxed">{props.executiveSummary}</p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 pt-2 border-t border-slate-800">
        <div className="bg-black/30 rounded-lg p-3 border border-slate-800">
          <div className="text-xs text-slate-500 font-mono mb-1">Isolation Forest Score</div>
          <div className="flex items-center gap-2">
            <div className="flex-1 bg-slate-800 rounded-full h-2">
              <div className="h-2 rounded-full bg-violet-500 transition-all duration-700" style={{ width: `${props.isolationScore * 100}%` }} />
            </div>
            <span className="text-xs font-mono text-violet-400">{(props.isolationScore * 100).toFixed(0)}%</span>
          </div>
        </div>
        <div className="bg-black/30 rounded-lg p-3 border border-slate-800">
          <div className="text-xs text-slate-500 font-mono mb-1">Correlation Score</div>
          <div className="flex items-center gap-2">
            <div className="flex-1 bg-slate-800 rounded-full h-2">
              <div className="h-2 rounded-full bg-cyan-500 transition-all duration-700" style={{ width: `${Math.min(props.correlationScore, 100)}%` }} />
            </div>
            <span className="text-xs font-mono text-cyan-400">{props.correlationScore}</span>
          </div>
        </div>
      </div>
    </div>
  );
};
