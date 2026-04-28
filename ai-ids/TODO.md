# Implementation TODO

## ✅ Completed

- [x] 1. Update types (`src/types/ids.ts`) — Added threatCategory, alternativeInterpretation, executiveSummary, temporalContext
- [x] 2. Enhance correlation engine (`src/engine/correlationEngine.ts`) — Generates all 4 new fields + temporal language + confidence capped at 0.99
- [x] 3. Upgrade ExplanationPanel (`src/components/ExplanationPanel.tsx`) — Threat badge, confidence, temporal context, alternative interpretation, executive summary
- [x] 4. Fix auto scroll (`src/components/LiveLogFeed.tsx`) — Removed forced scroll-to-bottom behavior
- [x] 5. App.tsx — Passes new props to both ExplanationPanel call sites
- [x] 6. useIDSEngine.ts — API response includes new fields

## Features Delivered

1. **UNCERTAINTY / CONFIDENCE** — Large "87%" display in ExplanationPanel header, capped at 99% in engine
2. **ALTERNATIVE INTERPRETATION** — Analyst-level reasoning about benign alternatives (e.g. batch processing vs C2)
3. **TEMPORAL LANGUAGE** — "Over the last 60 seconds…", "Pattern persisted across multiple intervals…"
4. **THREAT CATEGORY LABEL** — Badge: "Possible C2 Beaconing", "Privileged Data Exfiltration", etc.
5. **FINAL EXECUTIVE SUMMARY** — Bold summary at bottom of ExplanationPanel
6. **AUTO-SCROLL FIX** — LiveLogFeed allows free up/down scrolling
