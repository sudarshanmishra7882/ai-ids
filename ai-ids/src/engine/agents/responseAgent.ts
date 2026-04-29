// ============================================================
// RESPONSE AGENT v4.0 — SOC Decision & Mitigation Engine
// Final agent in pipeline: Packet → Flow → Behavior → Correlation → Response
// Outputs: Action recommendations, containment decisions, analyst guidance
// ============================================================

import { AgentSignal, AlertLevel, RiskState, AttackClassification } from '../../types/ids';

export interface ResponseRecommendation {
  action: string;
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  target: string;
  reasoning: string;
  autoExecutable: boolean;
}

export interface ResponseDecision {
  containmentRecommended: boolean;
  isolationTarget: string | null;
  alertSOC: boolean;
  escalateToTier2: boolean;
  recommendations: ResponseRecommendation[];
  analystGuidance: string;
  playBookTrigger: string | null;
}

// ─── Generate Recommendations Based on Alert Level ────────────
function generateRecommendations(
  alert: AlertLevel,
  attackClassification: string,
  _riskState: RiskState,
  sourceIP: string,
  destIP: string,
  userId: string
): ResponseRecommendation[] {
  const recommendations: ResponseRecommendation[] = [];

  if (alert === 'LOW') {
    recommendations.push({
      action: 'Continue monitoring',
      priority: 'LOW',
      target: 'Network',
      reasoning: 'Low risk score — maintain observation',
      autoExecutable: true,
    });
    return recommendations;
  }

  if (alert === 'MEDIUM') {
    recommendations.push({
      action: `Increase logging granularity for ${sourceIP}`,
      priority: 'MEDIUM',
      target: sourceIP,
      reasoning: 'Elevated risk requires deeper inspection',
      autoExecutable: false,
    });
    recommendations.push({
      action: 'Capture PCAP for flow analysis',
      priority: 'MEDIUM',
      target: `${sourceIP} → ${destIP}`,
      reasoning: 'Need packet-level evidence for confirmation',
      autoExecutable: true,
    });
    return recommendations;
  }

  // HIGH or CRITICAL
  recommendations.push({
    action: `Throttle connections from ${sourceIP}`,
    priority: 'HIGH',
    target: sourceIP,
    reasoning: 'High risk — reduce potential data exfiltration rate',
    autoExecutable: true,
  });

  recommendations.push({
    action: `Force re-auth for user ${userId}`,
    priority: 'HIGH',
    target: userId,
    reasoning: 'Privileged account may be compromised',
    autoExecutable: true,
  });

  if (attackClassification === 'C2_BEACONING') {
    recommendations.push({
      action: 'Sinkhole DNS for beacon domain',
      priority: 'CRITICAL',
      target: destIP,
      reasoning: 'C2 beaconing detected — disrupt command channel',
      autoExecutable: false,
    });
  }

  if (attackClassification === 'DATA_EXFILTRATION') {
    recommendations.push({
      action: 'Block outbound to unknown external IPs',
      priority: 'CRITICAL',
      target: destIP,
      reasoning: 'Data exfiltration pattern — stop data loss',
      autoExecutable: true,
    });
  }

  return recommendations;
}

// ─── Generate Analyst Guidance ────────────────────────────────
function generateAnalystGuidance(
  alert: AlertLevel,
  attackClassification: string,
  riskState: RiskState,
  agentBreakdown: Record<string, { score: number; confidence: number; detected: boolean }>
): string {
  if (alert === 'LOW') {
    return 'No action required. Continue baseline monitoring.';
  }

  const detectedAgents = Object.entries(agentBreakdown)
    .filter(([, v]) => v.detected)
    .map(([k]) => k);

  let guidance = `SOC Analyst: ${detectedAgents.join(' + ')} agents triggered. `;

  if (alert === 'MEDIUM') {
    guidance += 'Investigate within 15 minutes. Check if this is a scheduled maintenance window.';
  } else if (alert === 'HIGH') {
    guidance += 'Immediate investigation required. Consider isolating the source host.';
  } else {
    guidance += 'CRITICAL: Initiate incident response procedure. Contact on-call security lead.';
  }

  if (attackClassification !== 'NONE') {
    guidance += ` Suspected ${attackClassification.replace('_', ' ')}.`;
  }

  guidance += ` Risk accumulation: ${riskState.accumulatedRisk.toFixed(1)}/100.`;

  return guidance;
}

// ─── Determine Playbook Trigger ───────────────────────────────
function determinePlaybook(attackClassification: string): string | null {
  switch (attackClassification) {
    case 'C2_BEACONING':
      return 'C2_RESPONSE_PLAYBOOK';
    case 'DATA_EXFILTRATION':
      return 'DLP_INCIDENT_PLAYBOOK';
    case 'LATERAL_MOVEMENT':
      return 'LATERAL_CONTAINMENT_PLAYBOOK';
    case 'PRIVILEGED_ABUSE':
      return 'PRIVILEGED_ACCOUNT_RESPONSE';
    case 'RECONNAISSANCE':
      return 'RECON_MONITORING_PLAYBOOK';
    default:
      return null;
  }
}

// ─── Main Response Agent Entry Point ──────────────────────────
export function runResponseAgent(
  alert: AlertLevel,
  attackClassification: AttackClassification,
  riskState: RiskState,
  sourceIP: string,
  destIP: string,
  userId: string,
  agentBreakdown: Record<string, { score: number; confidence: number; detected: boolean }>
): AgentSignal {
  const recommendations = generateRecommendations(
    alert,
    attackClassification,
    riskState,
    sourceIP,
    destIP,
    userId
  );

  const analystGuidance = generateAnalystGuidance(alert, attackClassification, riskState, agentBreakdown);
  const playBookTrigger = determinePlaybook(attackClassification);

  const hasCritical = recommendations.some(r => r.priority === 'CRITICAL');
  const shouldContain = alert === 'HIGH' || alert === 'CRITICAL' || hasCritical;
  const shouldEscalate = alert === 'CRITICAL' || hasCritical;

  const responseScore = alert === 'CRITICAL' ? 1.0 : alert === 'HIGH' ? 0.85 : alert === 'MEDIUM' ? 0.5 : 0.1;

  const reasoningParts = [
    `RESPONSE AGENT: Alert=${alert}, Classification=${attackClassification}`,
    `Containment: ${shouldContain ? 'RECOMMENDED' : 'Not required'}`,
    `Escalation: ${shouldEscalate ? 'TIER-2 SOC' : 'Tier-1 handling'}`,
    `${recommendations.length} action(s) queued`,
  ];

  if (playBookTrigger) {
    reasoningParts.push(`Playbook triggered: ${playBookTrigger}`);
  }
  reasoningParts.push(analystGuidance);

  return {
    agent: 'RESPONSE',
    signalType: alert === 'LOW' ? 'NO_ACTION' : 'RESPONSE_TRIGGERED',
    score: responseScore,
    confidence: riskState.confidence,
    detected: alert !== 'LOW',
    features: {
      containmentRecommended: shouldContain ? 1 : 0,
      escalationToTier2: shouldEscalate ? 1 : 0,
      recommendationCount: recommendations.length,
      criticalActions: recommendations.filter(r => r.priority === 'CRITICAL').length,
      playbookTriggered: playBookTrigger ? 1 : 0,
    },
    reasoning: reasoningParts.join(' | '),
  };
}
