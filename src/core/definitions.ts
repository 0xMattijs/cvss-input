import type { CvssVersion, MetricDef, MetricGroup, MetricValueDef, VersionDef } from './types';

type ValueTuple = [code: string, name: string];

function metric(
  key: string,
  name: string,
  group: MetricGroup,
  values: ValueTuple[],
): MetricDef {
  return {
    key,
    name,
    group,
    values: values.map(([code, n]): MetricValueDef => ({ code, name: n })),
    required: group === 'base',
  };
}

const ND: ValueTuple = ['ND', 'Not Defined'];
const X: ValueTuple = ['X', 'Not Defined'];

const v2Metrics: MetricDef[] = [
  metric('AV', 'Access Vector', 'base', [['L', 'Local'], ['A', 'Adjacent Network'], ['N', 'Network']]),
  metric('AC', 'Access Complexity', 'base', [['H', 'High'], ['M', 'Medium'], ['L', 'Low']]),
  metric('Au', 'Authentication', 'base', [['M', 'Multiple'], ['S', 'Single'], ['N', 'None']]),
  metric('C', 'Confidentiality Impact', 'base', [['N', 'None'], ['P', 'Partial'], ['C', 'Complete']]),
  metric('I', 'Integrity Impact', 'base', [['N', 'None'], ['P', 'Partial'], ['C', 'Complete']]),
  metric('A', 'Availability Impact', 'base', [['N', 'None'], ['P', 'Partial'], ['C', 'Complete']]),
  metric('E', 'Exploitability', 'temporal', [
    ['U', 'Unproven'], ['POC', 'Proof-of-Concept'], ['F', 'Functional'], ['H', 'High'], ND,
  ]),
  metric('RL', 'Remediation Level', 'temporal', [
    ['OF', 'Official Fix'], ['TF', 'Temporary Fix'], ['W', 'Workaround'], ['U', 'Unavailable'], ND,
  ]),
  metric('RC', 'Report Confidence', 'temporal', [
    ['UC', 'Unconfirmed'], ['UR', 'Uncorroborated'], ['C', 'Confirmed'], ND,
  ]),
  metric('CDP', 'Collateral Damage Potential', 'environmental', [
    ['N', 'None'], ['L', 'Low'], ['LM', 'Low-Medium'], ['MH', 'Medium-High'], ['H', 'High'], ND,
  ]),
  metric('TD', 'Target Distribution', 'environmental', [
    ['N', 'None'], ['L', 'Low'], ['M', 'Medium'], ['H', 'High'], ND,
  ]),
  metric('CR', 'Confidentiality Requirement', 'environmental', [['L', 'Low'], ['M', 'Medium'], ['H', 'High'], ND]),
  metric('IR', 'Integrity Requirement', 'environmental', [['L', 'Low'], ['M', 'Medium'], ['H', 'High'], ND]),
  metric('AR', 'Availability Requirement', 'environmental', [['L', 'Low'], ['M', 'Medium'], ['H', 'High'], ND]),
];

const AV3: ValueTuple[] = [['N', 'Network'], ['A', 'Adjacent'], ['L', 'Local'], ['P', 'Physical']];
const AC3: ValueTuple[] = [['L', 'Low'], ['H', 'High']];
const PR3: ValueTuple[] = [['N', 'None'], ['L', 'Low'], ['H', 'High']];
const UI3: ValueTuple[] = [['N', 'None'], ['R', 'Required']];
const S3: ValueTuple[] = [['U', 'Unchanged'], ['C', 'Changed']];
const CIA3: ValueTuple[] = [['H', 'High'], ['L', 'Low'], ['N', 'None']];
const REQ: ValueTuple[] = [X, ['H', 'High'], ['M', 'Medium'], ['L', 'Low']];

const v3Metrics: MetricDef[] = [
  metric('AV', 'Attack Vector', 'base', AV3),
  metric('AC', 'Attack Complexity', 'base', AC3),
  metric('PR', 'Privileges Required', 'base', PR3),
  metric('UI', 'User Interaction', 'base', UI3),
  metric('S', 'Scope', 'base', S3),
  metric('C', 'Confidentiality', 'base', CIA3),
  metric('I', 'Integrity', 'base', CIA3),
  metric('A', 'Availability', 'base', CIA3),
  metric('E', 'Exploit Code Maturity', 'temporal', [
    X, ['H', 'High'], ['F', 'Functional'], ['P', 'Proof-of-Concept'], ['U', 'Unproven'],
  ]),
  metric('RL', 'Remediation Level', 'temporal', [
    X, ['U', 'Unavailable'], ['W', 'Workaround'], ['T', 'Temporary Fix'], ['O', 'Official Fix'],
  ]),
  metric('RC', 'Report Confidence', 'temporal', [X, ['C', 'Confirmed'], ['R', 'Reasonable'], ['U', 'Unknown']]),
  metric('CR', 'Confidentiality Requirement', 'environmental', REQ),
  metric('IR', 'Integrity Requirement', 'environmental', REQ),
  metric('AR', 'Availability Requirement', 'environmental', REQ),
  metric('MAV', 'Modified Attack Vector', 'environmental', [X, ...AV3]),
  metric('MAC', 'Modified Attack Complexity', 'environmental', [X, ...AC3]),
  metric('MPR', 'Modified Privileges Required', 'environmental', [X, ...PR3]),
  metric('MUI', 'Modified User Interaction', 'environmental', [X, ...UI3]),
  metric('MS', 'Modified Scope', 'environmental', [X, ...S3]),
  metric('MC', 'Modified Confidentiality', 'environmental', [X, ...CIA3]),
  metric('MI', 'Modified Integrity', 'environmental', [X, ...CIA3]),
  metric('MA', 'Modified Availability', 'environmental', [X, ...CIA3]),
];

const AV4: ValueTuple[] = [['N', 'Network'], ['A', 'Adjacent'], ['L', 'Local'], ['P', 'Physical']];
const AC4: ValueTuple[] = [['L', 'Low'], ['H', 'High']];
const AT4: ValueTuple[] = [['N', 'None'], ['P', 'Present']];
const PR4: ValueTuple[] = [['N', 'None'], ['L', 'Low'], ['H', 'High']];
const UI4: ValueTuple[] = [['N', 'None'], ['P', 'Passive'], ['A', 'Active']];
const HLN: ValueTuple[] = [['H', 'High'], ['L', 'Low'], ['N', 'None']];
const SHLN: ValueTuple[] = [['S', 'Safety'], ...HLN];

const v4Metrics: MetricDef[] = [
  metric('AV', 'Attack Vector', 'base', AV4),
  metric('AC', 'Attack Complexity', 'base', AC4),
  metric('AT', 'Attack Requirements', 'base', AT4),
  metric('PR', 'Privileges Required', 'base', PR4),
  metric('UI', 'User Interaction', 'base', UI4),
  metric('VC', 'Vulnerable System Confidentiality', 'base', HLN),
  metric('VI', 'Vulnerable System Integrity', 'base', HLN),
  metric('VA', 'Vulnerable System Availability', 'base', HLN),
  metric('SC', 'Subsequent System Confidentiality', 'base', HLN),
  metric('SI', 'Subsequent System Integrity', 'base', HLN),
  metric('SA', 'Subsequent System Availability', 'base', HLN),
  metric('E', 'Exploit Maturity', 'threat', [X, ['A', 'Attacked'], ['P', 'POC'], ['U', 'Unreported']]),
  metric('CR', 'Confidentiality Requirement', 'environmental', REQ),
  metric('IR', 'Integrity Requirement', 'environmental', REQ),
  metric('AR', 'Availability Requirement', 'environmental', REQ),
  metric('MAV', 'Modified Attack Vector', 'environmental', [X, ...AV4]),
  metric('MAC', 'Modified Attack Complexity', 'environmental', [X, ...AC4]),
  metric('MAT', 'Modified Attack Requirements', 'environmental', [X, ...AT4]),
  metric('MPR', 'Modified Privileges Required', 'environmental', [X, ...PR4]),
  metric('MUI', 'Modified User Interaction', 'environmental', [X, ...UI4]),
  metric('MVC', 'Modified Vulnerable System Confidentiality', 'environmental', [X, ...HLN]),
  metric('MVI', 'Modified Vulnerable System Integrity', 'environmental', [X, ...HLN]),
  metric('MVA', 'Modified Vulnerable System Availability', 'environmental', [X, ...HLN]),
  metric('MSC', 'Modified Subsequent System Confidentiality', 'environmental', [X, ...HLN]),
  metric('MSI', 'Modified Subsequent System Integrity', 'environmental', [X, ...SHLN]),
  metric('MSA', 'Modified Subsequent System Availability', 'environmental', [X, ...SHLN]),
  metric('S', 'Safety', 'supplemental', [X, ['N', 'Negligible'], ['P', 'Present']]),
  metric('AU', 'Automatable', 'supplemental', [X, ['N', 'No'], ['Y', 'Yes']]),
  metric('R', 'Recovery', 'supplemental', [X, ['A', 'Automatic'], ['U', 'User'], ['I', 'Irrecoverable']]),
  metric('V', 'Value Density', 'supplemental', [X, ['D', 'Diffuse'], ['C', 'Concentrated']]),
  metric('RE', 'Vulnerability Response Effort', 'supplemental', [X, ['L', 'Low'], ['M', 'Moderate'], ['H', 'High']]),
  metric('U', 'Provider Urgency', 'supplemental', [
    X, ['Clear', 'Clear'], ['Green', 'Green'], ['Amber', 'Amber'], ['Red', 'Red'],
  ]),
];

export const VERSIONS: Record<CvssVersion, VersionDef> = {
  '2.0': { version: '2.0', prefix: null, notDefined: 'ND', metrics: v2Metrics },
  '3.0': { version: '3.0', prefix: 'CVSS:3.0', notDefined: 'X', metrics: v3Metrics },
  '3.1': { version: '3.1', prefix: 'CVSS:3.1', notDefined: 'X', metrics: v3Metrics },
  '4.0': { version: '4.0', prefix: 'CVSS:4.0', notDefined: 'X', metrics: v4Metrics },
};

export const ALL_VERSIONS: CvssVersion[] = ['2.0', '3.0', '3.1', '4.0'];

export function getMetricDef(version: CvssVersion, key: string): MetricDef | undefined {
  return VERSIONS[version].metrics.find((m) => m.key === key);
}

export const GROUP_LABELS: Record<MetricGroup, string> = {
  base: 'Base',
  temporal: 'Temporal',
  threat: 'Threat',
  environmental: 'Environmental',
  supplemental: 'Supplemental',
};
