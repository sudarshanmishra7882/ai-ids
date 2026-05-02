import { NetworkLog } from '../types/ids';

interface SignatureRule {
  id: string;
  title: string;
  matches: (log: NetworkLog) => boolean;
}

export const SIGNATURE_RULES: SignatureRule[] = [
  {
    id: 'ET-MALWARE-SWIFT-JA3-BEACON',
    title: 'Suspicious JA3 beacon on SWIFT subnet',
    matches: log =>
      log.networkSegment === 'SWIFT_SUBNET' &&
      log.isExternalIP &&
      log.connectionInterval <= 1100 &&
      log.packetSize <= 140 &&
      !!log.signatureTag,
  },
  {
    id: 'CVE-2023-4966-STYLE-SESSION-HIJACK',
    title: 'Session hijack style access into banking services',
    matches: log =>
      !!log.signatureTag &&
      log.signatureTag.includes('CVE-2023-4966') &&
      log.isPrivileged,
  },
  {
    id: 'WIN-PRIV-DBA-BURST',
    title: 'Privileged DBA burst against core banking',
    matches: log =>
      log.applicationLabel.includes('Pumori') &&
      log.isPrivileged &&
      log.queryFrequency >= 180 &&
      log.sessionDuration <= 120,
  },
  {
    id: 'ET-DLP-BULK-EXFIL',
    title: 'Bulk encrypted data exfiltration',
    matches: log =>
      log.isExternalIP &&
      log.packetSize >= 1300 &&
      log.flowDuration >= 8000,
  },
];

export function matchSignatureRules(log: NetworkLog): string[] {
  const matches = SIGNATURE_RULES
    .filter(rule => rule.matches(log))
    .map(rule => `${rule.id}: ${rule.title}`);

  if (log.signatureTag && !matches.some(match => match.includes(log.signatureTag ?? ''))) {
    matches.push(log.signatureTag);
  }

  return matches;
}
