import React from 'react';
import { AttackPhase, SystemMode } from '../types/ids';
import { Play, RotateCcw, Zap } from 'lucide-react';

interface AttackScenarioProps {
  mode: SystemMode;
  attackPhase: AttackPhase;
  onTriggerAttack: () => void;
  onReset: () => void;
  isRunning: boolean;
  onToggleRunning: () => void;
}

export const AttackScenario: React.FC<AttackScenarioProps> = ({
  mode,
  attackPhase: _attackPhase,
  onTriggerAttack,
  onReset,
  isRunning,
  onToggleRunning,
}) => {
  return (
    <div className="bg-slate-900/60 rounded-xl border border-slate-700/50 p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
          <Zap className="w-4 h-4 text-amber-400" />
          Controls
        </h3>
        <div
          className={`px-2 py-1 rounded text-xs font-bold font-mono border ${
            mode === 'attack'
              ? 'bg-red-900/40 border-red-500/50 text-red-400'
              : 'bg-green-900/30 border-green-500/40 text-green-400'
          }`}
        >
          {mode.toUpperCase()}
        </div>
      </div>

      <div className="grid grid-cols-3 gap-2">
        <button
          onClick={onToggleRunning}
          className={`col-span-1 flex items-center justify-center gap-1.5 px-3 py-2.5 rounded-lg text-xs font-bold font-mono border transition-all ${
            isRunning
              ? 'bg-slate-800 border-slate-600 text-slate-400 hover:bg-slate-700'
              : 'bg-green-900/40 border-green-500/50 text-green-400 hover:bg-green-900/60'
          }`}
        >
          <Play className="w-3 h-3" />
          {isRunning ? 'PAUSE' : 'START'}
        </button>

        <button
          onClick={onTriggerAttack}
          disabled={mode === 'attack'}
          className={`col-span-1 flex items-center justify-center gap-1.5 px-3 py-2.5 rounded-lg text-xs font-bold font-mono border transition-all ${
            mode === 'attack'
              ? 'bg-slate-800 border-slate-700 text-slate-600 cursor-not-allowed'
              : 'bg-red-900/40 border-red-500/50 text-red-400 hover:bg-red-900/60'
          }`}
        >
          <Zap className="w-3 h-3" />
          ATTACK
        </button>

        <button
          onClick={onReset}
          className="col-span-1 flex items-center justify-center gap-1.5 px-3 py-2.5 rounded-lg text-xs font-bold font-mono border bg-slate-800/60 border-slate-600/50 text-slate-400 hover:bg-slate-700/60 transition-all"
        >
          <RotateCcw className="w-3 h-3" />
          RESET
        </button>
      </div>
    </div>
  );
};
