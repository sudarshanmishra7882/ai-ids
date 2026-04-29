// ============================================================
// useIDSEngine — React Hook for Streaming IDS Pipeline
// ============================================================

import { useState, useEffect, useCallback, useRef } from 'react';
import { APIResponse, DetectionResult, SystemState, WindowStats } from '../types/ids';
import {
  createInitialState,
  processLog,
  triggerAttack,
  resetToNormal,
} from '../engine/idsEngine';
import { computeWindowStats } from '../engine/baselineEngine';

const TICK_INTERVAL_MS = 1000; // 1 second streaming

interface IDSEngineReturn {
  state: SystemState;
  latestResult: DetectionResult | null;
  windowStats: WindowStats | null;
  apiResponse: APIResponse | null;
  isRunning: boolean;
  handleTriggerAttack: () => void;
  handleReset: () => void;
  handleToggleRunning: () => void;
}

export function useIDSEngine(): IDSEngineReturn {
  const [state, setState] = useState<SystemState>(() => createInitialState());
  const [latestResult, setLatestResult] = useState<DetectionResult | null>(null);
  const [windowStats, setWindowStats] = useState<WindowStats | null>(null);
  const [apiResponse, setApiResponse] = useState<APIResponse | null>(null);
  const [isRunning, setIsRunning] = useState(false);

  const stateRef = useRef(state);
  stateRef.current = state;

  // ─── Streaming tick ────────────────────────────────────────
  useEffect(() => {
    if (!isRunning) return;

    const interval = setInterval(() => {
      const timestamp = Date.now();
      const { newState, result } = processLog(stateRef.current, timestamp);

      setState(newState);
      setLatestResult(result);

      // Compute window stats for UI
      const stats = computeWindowStats(newState.slidingWindow, timestamp);
      setWindowStats(stats);

      // Build API response
      const apiResp = {
        log: result.log,
        riskScore: result.riskScore,
        alert: result.alert,
        confidence: result.confidence,
        reasons: result.reasons,
        explanation: result.explanation,
        threatCategory: result.threatCategory,
        alternativeInterpretation: result.alternativeInterpretation,
        temporalContext: result.temporalContext,
        executiveSummary: result.executiveSummary,
        signals: result.signals,
        timestamp,
        agentBreakdown: result.agentBreakdown,
        attackClassification: result.attackClassification,
        correlationChain: result.correlationChain,
      };
      setApiResponse(apiResp);
    }, TICK_INTERVAL_MS);

    return () => clearInterval(interval);
  }, [isRunning]);

  // ─── Handlers ─────────────────────────────────────────────
  const handleTriggerAttack = useCallback(() => {
    setState(prev => triggerAttack(prev));
    setIsRunning(true);
  }, []);

  const handleReset = useCallback(() => {
    setState(prev => resetToNormal(prev));
    setLatestResult(null);
    setWindowStats(null);
    setApiResponse(null);
  }, []);

  const handleToggleRunning = useCallback(() => {
    setIsRunning(prev => !prev);
  }, []);

  return {
    state,
    latestResult,
    windowStats,
    apiResponse,
    isRunning,
    handleTriggerAttack,
    handleReset,
    handleToggleRunning,
  };
}
