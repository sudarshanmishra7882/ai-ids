# TODO: Sentinels of the Network — AI-Driven IDS v4.0 Upgrade

## Phase 1: Kill Fake AI (CRITICAL) ✅ COMPLETE
- [x] `src/engine/riskEngine.ts` — Removed random jitter, added deterministic noise
- [x] Reduced ESCALATION_CAP from 20 → 8
- [x] Added warm-up multiplier for gradual escalation (0.35x → 1.0x)
- [x] Added computeSignalEntropy() for deterministic noise based on CV
- [x] Improved confidence calculation with 4 factors


## Phase 2: Correlation Engine Overhaul (CRITICAL)
- [ ] `src/engine/correlationEngine.ts` — Multi-signal fusion rules
- [ ] Weighted confidence propagation
- [ ] Temporal correlation window

## Phase 3: Add Response Agent (HIGH)
- [ ] `src/engine/agents/responseAgent.ts` — NEW file
- [ ] SOC decision logic, mitigation recommendations

## Phase 4: Multi-Agent Data Enrichment (HIGH)
- [ ] `src/engine/idsEngine.ts` — Agent-to-agent data passing
- [ ] `src/engine/agents/*.ts` — Cross-agent feature passing

## Phase 5: SOC-Style Explanations (MEDIUM)
- [ ] `src/engine/correlationEngine.ts` — Enhanced reasoning chains
- [ ] Reference actual agent signals in explanations

## Phase 6: UI Updates (LOW)
- [ ] `src/components/ExplanationPanel.tsx` — Display correlation chain
- [ ] `src/types/ids.ts` — ResponseAgent types if needed
