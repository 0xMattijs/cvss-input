import type { CvssVersion, MetricDef, MetricGroup, MetricValueDef, ValueOrder, VersionDef } from './types';

type ValueTuple = [code: string, name: string];

function metric(
  key: string,
  name: string,
  group: MetricGroup,
  values: ValueTuple[],
  severity: 'ascending' | 'descending',
): MetricDef {
  return {
    key,
    name,
    group,
    values: values.map(([code, n]): MetricValueDef => ({ code, name: n })),
    severity,
    required: group === 'base',
  };
}

const ASC = 'ascending';
const DESC = 'descending';

const ND: ValueTuple = ['ND', 'Not Defined'];
const X: ValueTuple = ['X', 'Not Defined'];

// Value order follows NVD's CVSS 2.0 calculator (FIRST doesn't host one).
const v2Metrics: MetricDef[] = [
  metric('AV', 'Access Vector', 'base', [['L', 'Local'], ['A', 'Adjacent Network'], ['N', 'Network']], ASC),
  metric('AC', 'Access Complexity', 'base', [['H', 'High'], ['M', 'Medium'], ['L', 'Low']], ASC),
  metric('Au', 'Authentication', 'base', [['M', 'Multiple'], ['S', 'Single'], ['N', 'None']], ASC),
  metric('C', 'Confidentiality Impact', 'base', [['N', 'None'], ['P', 'Partial'], ['C', 'Complete']], ASC),
  metric('I', 'Integrity Impact', 'base', [['N', 'None'], ['P', 'Partial'], ['C', 'Complete']], ASC),
  metric('A', 'Availability Impact', 'base', [['N', 'None'], ['P', 'Partial'], ['C', 'Complete']], ASC),
  metric('E', 'Exploitability', 'temporal', [
    ND, ['U', 'Unproven'], ['POC', 'Proof-of-Concept'], ['F', 'Functional'], ['H', 'High'],
  ], ASC),
  metric('RL', 'Remediation Level', 'temporal', [
    ND, ['OF', 'Official Fix'], ['TF', 'Temporary Fix'], ['W', 'Workaround'], ['U', 'Unavailable'],
  ], ASC),
  metric('RC', 'Report Confidence', 'temporal', [
    ND, ['UC', 'Unconfirmed'], ['UR', 'Uncorroborated'], ['C', 'Confirmed'],
  ], ASC),
  metric('CDP', 'Collateral Damage Potential', 'environmental', [
    ND, ['N', 'None'], ['L', 'Low'], ['LM', 'Low-Medium'], ['MH', 'Medium-High'], ['H', 'High'],
  ], ASC),
  metric('TD', 'Target Distribution', 'environmental', [
    ND, ['N', 'None'], ['L', 'Low'], ['M', 'Medium'], ['H', 'High'],
  ], ASC),
  metric('CR', 'Confidentiality Requirement', 'environmental', [ND, ['L', 'Low'], ['M', 'Medium'], ['H', 'High']], ASC),
  metric('IR', 'Integrity Requirement', 'environmental', [ND, ['L', 'Low'], ['M', 'Medium'], ['H', 'High']], ASC),
  metric('AR', 'Availability Requirement', 'environmental', [ND, ['L', 'Low'], ['M', 'Medium'], ['H', 'High']], ASC),
];

// Value order follows FIRST's CVSS 3.0 and 3.1 calculators, which agree.
const AV3: ValueTuple[] = [['N', 'Network'], ['A', 'Adjacent'], ['L', 'Local'], ['P', 'Physical']];
const AC3: ValueTuple[] = [['L', 'Low'], ['H', 'High']];
const PR3: ValueTuple[] = [['N', 'None'], ['L', 'Low'], ['H', 'High']];
const UI3: ValueTuple[] = [['N', 'None'], ['R', 'Required']];
const S3: ValueTuple[] = [['U', 'Unchanged'], ['C', 'Changed']];
const CIA3: ValueTuple[] = [['N', 'None'], ['L', 'Low'], ['H', 'High']];
const REQ3: ValueTuple[] = [X, ['L', 'Low'], ['M', 'Medium'], ['H', 'High']];

const v3Metrics: MetricDef[] = [
  metric('AV', 'Attack Vector', 'base', AV3, DESC),
  metric('AC', 'Attack Complexity', 'base', AC3, DESC),
  metric('PR', 'Privileges Required', 'base', PR3, DESC),
  metric('UI', 'User Interaction', 'base', UI3, DESC),
  metric('S', 'Scope', 'base', S3, ASC),
  metric('C', 'Confidentiality', 'base', CIA3, ASC),
  metric('I', 'Integrity', 'base', CIA3, ASC),
  metric('A', 'Availability', 'base', CIA3, ASC),
  metric('E', 'Exploit Code Maturity', 'temporal', [
    X, ['U', 'Unproven'], ['P', 'Proof-of-Concept'], ['F', 'Functional'], ['H', 'High'],
  ], ASC),
  metric('RL', 'Remediation Level', 'temporal', [
    X, ['O', 'Official Fix'], ['T', 'Temporary Fix'], ['W', 'Workaround'], ['U', 'Unavailable'],
  ], ASC),
  metric('RC', 'Report Confidence', 'temporal', [X, ['U', 'Unknown'], ['R', 'Reasonable'], ['C', 'Confirmed']], ASC),
  metric('CR', 'Confidentiality Requirement', 'environmental', REQ3, ASC),
  metric('IR', 'Integrity Requirement', 'environmental', REQ3, ASC),
  metric('AR', 'Availability Requirement', 'environmental', REQ3, ASC),
  metric('MAV', 'Modified Attack Vector', 'environmental', [X, ...AV3], DESC),
  metric('MAC', 'Modified Attack Complexity', 'environmental', [X, ...AC3], DESC),
  metric('MPR', 'Modified Privileges Required', 'environmental', [X, ...PR3], DESC),
  metric('MUI', 'Modified User Interaction', 'environmental', [X, ...UI3], DESC),
  metric('MS', 'Modified Scope', 'environmental', [X, ...S3], ASC),
  metric('MC', 'Modified Confidentiality', 'environmental', [X, ...CIA3], ASC),
  metric('MI', 'Modified Integrity', 'environmental', [X, ...CIA3], ASC),
  metric('MA', 'Modified Availability', 'environmental', [X, ...CIA3], ASC),
];

// Value order follows FIRST's CVSS 4.0 calculator.
const AV4: ValueTuple[] = [['N', 'Network'], ['A', 'Adjacent'], ['L', 'Local'], ['P', 'Physical']];
const AC4: ValueTuple[] = [['L', 'Low'], ['H', 'High']];
const AT4: ValueTuple[] = [['N', 'None'], ['P', 'Present']];
const PR4: ValueTuple[] = [['N', 'None'], ['L', 'Low'], ['H', 'High']];
const UI4: ValueTuple[] = [['N', 'None'], ['P', 'Passive'], ['A', 'Active']];
const HLN: ValueTuple[] = [['H', 'High'], ['L', 'Low'], ['N', 'None']];
const SHLN: ValueTuple[] = [['S', 'Safety'], ...HLN];
const REQ4: ValueTuple[] = [X, ['H', 'High'], ['M', 'Medium'], ['L', 'Low']];

const v4Metrics: MetricDef[] = [
  metric('AV', 'Attack Vector', 'base', AV4, DESC),
  metric('AC', 'Attack Complexity', 'base', AC4, DESC),
  metric('AT', 'Attack Requirements', 'base', AT4, DESC),
  metric('PR', 'Privileges Required', 'base', PR4, DESC),
  metric('UI', 'User Interaction', 'base', UI4, DESC),
  metric('VC', 'Vulnerable System Confidentiality', 'base', HLN, DESC),
  metric('VI', 'Vulnerable System Integrity', 'base', HLN, DESC),
  metric('VA', 'Vulnerable System Availability', 'base', HLN, DESC),
  metric('SC', 'Subsequent System Confidentiality', 'base', HLN, DESC),
  metric('SI', 'Subsequent System Integrity', 'base', HLN, DESC),
  metric('SA', 'Subsequent System Availability', 'base', HLN, DESC),
  metric('E', 'Exploit Maturity', 'threat', [X, ['A', 'Attacked'], ['P', 'POC'], ['U', 'Unreported']], DESC),
  metric('CR', 'Confidentiality Requirement', 'environmental', REQ4, DESC),
  metric('IR', 'Integrity Requirement', 'environmental', REQ4, DESC),
  metric('AR', 'Availability Requirement', 'environmental', REQ4, DESC),
  metric('MAV', 'Modified Attack Vector', 'environmental', [X, ...AV4], DESC),
  metric('MAC', 'Modified Attack Complexity', 'environmental', [X, ...AC4], DESC),
  metric('MAT', 'Modified Attack Requirements', 'environmental', [X, ...AT4], DESC),
  metric('MPR', 'Modified Privileges Required', 'environmental', [X, ...PR4], DESC),
  metric('MUI', 'Modified User Interaction', 'environmental', [X, ...UI4], DESC),
  metric('MVC', 'Modified Vulnerable System Confidentiality', 'environmental', [X, ...HLN], DESC),
  metric('MVI', 'Modified Vulnerable System Integrity', 'environmental', [X, ...HLN], DESC),
  metric('MVA', 'Modified Vulnerable System Availability', 'environmental', [X, ...HLN], DESC),
  metric('MSC', 'Modified Subsequent System Confidentiality', 'environmental', [X, ...HLN], DESC),
  metric('MSI', 'Modified Subsequent System Integrity', 'environmental', [X, ...SHLN], DESC),
  metric('MSA', 'Modified Subsequent System Availability', 'environmental', [X, ...SHLN], DESC),
  // Supplemental metrics don't change the score; "ascending" here means the
  // value that calls for more attention comes last, as in FIRST's order.
  metric('S', 'Safety', 'supplemental', [X, ['N', 'Negligible'], ['P', 'Present']], ASC),
  metric('AU', 'Automatable', 'supplemental', [X, ['N', 'No'], ['Y', 'Yes']], ASC),
  metric('R', 'Recovery', 'supplemental', [X, ['A', 'Automatic'], ['U', 'User'], ['I', 'Irrecoverable']], ASC),
  metric('V', 'Value Density', 'supplemental', [X, ['D', 'Diffuse'], ['C', 'Concentrated']], ASC),
  metric('RE', 'Vulnerability Response Effort', 'supplemental', [X, ['L', 'Low'], ['M', 'Moderate'], ['H', 'High']], ASC),
  metric('U', 'Provider Urgency', 'supplemental', [
    X, ['Clear', 'Clear'], ['Green', 'Green'], ['Amber', 'Amber'], ['Red', 'Red'],
  ], ASC),
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

/**
 * A metric's values in the given order. "Not defined" always comes first.
 * `first` keeps the official calculator's order.
 */
export function orderedValues(def: MetricDef, order: ValueOrder = 'first'): MetricValueDef[] {
  if (order === 'first' || order === def.severity) return def.values;
  const notDefined = def.required ? [] : def.values.slice(0, 1);
  return [...notDefined, ...def.values.slice(notDefined.length).reverse()];
}
