import type { ClassicScores, Severity } from './types';

type Metrics = Record<string, string>;

/** Rounds to one decimal, half up, with a tolerance for floating-point noise. */
function round1(x: number): number {
  return Math.round(x * 10 + 1e-9) / 10;
}

export function severityV2(score: number): Severity {
  // CVSS 2.0 has no official qualitative scale; these are the NVD bands.
  if (score < 4) return 'Low';
  if (score < 7) return 'Medium';
  return 'High';
}

export function severityV3(score: number): Severity {
  if (score === 0) return 'None';
  if (score < 4) return 'Low';
  if (score < 7) return 'Medium';
  if (score < 9) return 'High';
  return 'Critical';
}

// ---------------------------------------------------------------------------
// CVSS 2.0
// ---------------------------------------------------------------------------

const V2 = {
  AV: { L: 0.395, A: 0.646, N: 1.0 },
  AC: { H: 0.35, M: 0.61, L: 0.71 },
  Au: { M: 0.45, S: 0.56, N: 0.704 },
  CIA: { N: 0.0, P: 0.275, C: 0.66 },
  E: { U: 0.85, POC: 0.9, F: 0.95, H: 1.0, ND: 1.0 },
  RL: { OF: 0.87, TF: 0.9, W: 0.95, U: 1.0, ND: 1.0 },
  RC: { UC: 0.9, UR: 0.95, C: 1.0, ND: 1.0 },
  CDP: { N: 0, L: 0.1, LM: 0.3, MH: 0.4, H: 0.5, ND: 0 },
  TD: { N: 0, L: 0.25, M: 0.75, H: 1.0, ND: 1.0 },
  REQ: { L: 0.5, M: 1.0, H: 1.51, ND: 1.0 },
} as const;

const get = <T extends Record<string, number>>(table: T, value: string | undefined, fallback: keyof T) =>
  table[(value ?? fallback) as keyof T] ?? table[fallback];

export function scoreV2(m: Metrics): ClassicScores {
  const c = get(V2.CIA, m.C, 'N');
  const i = get(V2.CIA, m.I, 'N');
  const a = get(V2.CIA, m.A, 'N');
  const exploitability = 20 * get(V2.AV, m.AV, 'N') * get(V2.AC, m.AC, 'L') * get(V2.Au, m.Au, 'N');

  const baseEquation = (impact: number) => {
    const f = impact === 0 ? 0 : 1.176;
    return round1((0.6 * impact + 0.4 * exploitability - 1.5) * f);
  };
  const temporalMultiplier = (base: number) =>
    round1(base * get(V2.E, m.E, 'ND') * get(V2.RL, m.RL, 'ND') * get(V2.RC, m.RC, 'ND'));

  const impact = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a));
  const base = baseEquation(impact);
  const temporal = temporalMultiplier(base);

  const adjustedImpact = Math.min(
    10,
    10.41 *
      (1 -
        (1 - c * get(V2.REQ, m.CR, 'ND')) *
          (1 - i * get(V2.REQ, m.IR, 'ND')) *
          (1 - a * get(V2.REQ, m.AR, 'ND'))),
  );
  const adjustedTemporal = temporalMultiplier(baseEquation(adjustedImpact));
  const cdp = get(V2.CDP, m.CDP, 'ND');
  const environmental = round1((adjustedTemporal + (10 - adjustedTemporal) * cdp) * get(V2.TD, m.TD, 'ND'));

  return {
    kind: 'classic',
    version: '2.0',
    base: { score: base, severity: severityV2(base) },
    temporal: { score: temporal, severity: severityV2(temporal) },
    environmental: { score: environmental, severity: severityV2(environmental) },
    temporalDefined: isDefined(m, ['E', 'RL', 'RC'], 'ND'),
    environmentalDefined: isDefined(m, ['CDP', 'TD', 'CR', 'IR', 'AR'], 'ND'),
    impact: round1(impact),
    exploitability: round1(exploitability),
  };
}

// ---------------------------------------------------------------------------
// CVSS 3.0 and 3.1
// ---------------------------------------------------------------------------

const V3 = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR_U: { N: 0.85, L: 0.62, H: 0.27 },
  PR_C: { N: 0.85, L: 0.68, H: 0.5 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
  E: { X: 1, H: 1, F: 0.97, P: 0.94, U: 0.91 },
  RL: { X: 1, U: 1, W: 0.97, T: 0.96, O: 0.95 },
  RC: { X: 1, C: 1, R: 0.96, U: 0.92 },
  REQ: { X: 1, H: 1.5, M: 1, L: 0.5 },
} as const;

/** CVSS 3.1 Roundup: avoids floating-point artifacts (spec Appendix A). */
function roundup31(x: number): number {
  const intInput = Math.round(x * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

/** CVSS 3.0 Roundup: plain ceiling to one decimal. */
function roundup30(x: number): number {
  return Math.ceil(x * 10) / 10;
}

function isDefined(m: Metrics, keys: string[], notDefined: string): boolean {
  return keys.some((k) => m[k] !== undefined && m[k] !== notDefined);
}

export function scoreV3(m: Metrics, version: '3.0' | '3.1'): ClassicScores {
  const roundup = version === '3.1' ? roundup31 : roundup30;

  // Modified metric if set (and not X), otherwise the base metric.
  const mod = (key: string) => {
    const v = m['M' + key];
    return v !== undefined && v !== 'X' ? v : m[key];
  };

  // Base
  const changed = m.S === 'C';
  const iss = 1 - (1 - get(V3.CIA, m.C, 'N')) * (1 - get(V3.CIA, m.I, 'N')) * (1 - get(V3.CIA, m.A, 'N'));
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const exploitability =
    8.22 *
    get(V3.AV, m.AV, 'N') *
    get(V3.AC, m.AC, 'L') *
    get(changed ? V3.PR_C : V3.PR_U, m.PR, 'N') *
    get(V3.UI, m.UI, 'N');
  const base =
    impact <= 0 ? 0 : roundup(Math.min((changed ? 1.08 : 1) * (impact + exploitability), 10));

  // Temporal
  const temporalFactor = get(V3.E, m.E, 'X') * get(V3.RL, m.RL, 'X') * get(V3.RC, m.RC, 'X');
  const temporal = roundup(base * temporalFactor);

  // Environmental
  const mChanged = mod('S') === 'C';
  const miss = Math.min(
    1 -
      (1 - get(V3.REQ, m.CR, 'X') * get(V3.CIA, mod('C'), 'N')) *
        (1 - get(V3.REQ, m.IR, 'X') * get(V3.CIA, mod('I'), 'N')) *
        (1 - get(V3.REQ, m.AR, 'X') * get(V3.CIA, mod('A'), 'N')),
    0.915,
  );
  let modifiedImpact: number;
  if (!mChanged) {
    modifiedImpact = 6.42 * miss;
  } else if (version === '3.1') {
    modifiedImpact = 7.52 * (miss - 0.029) - 3.25 * Math.pow(miss * 0.9731 - 0.02, 13);
  } else {
    modifiedImpact = 7.52 * (miss - 0.029) - 3.25 * Math.pow(miss - 0.02, 15);
  }
  const modifiedExploitability =
    8.22 *
    get(V3.AV, mod('AV'), 'N') *
    get(V3.AC, mod('AC'), 'L') *
    get(mChanged ? V3.PR_C : V3.PR_U, mod('PR'), 'N') *
    get(V3.UI, mod('UI'), 'N');
  const environmental =
    modifiedImpact <= 0
      ? 0
      : roundup(
          roundup(Math.min((mChanged ? 1.08 : 1) * (modifiedImpact + modifiedExploitability), 10)) *
            temporalFactor,
        );

  return {
    kind: 'classic',
    version,
    base: { score: base, severity: severityV3(base) },
    temporal: { score: temporal, severity: severityV3(temporal) },
    environmental: { score: environmental, severity: severityV3(environmental) },
    temporalDefined: isDefined(m, ['E', 'RL', 'RC'], 'X'),
    environmentalDefined: isDefined(
      m,
      ['CR', 'IR', 'AR', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA'],
      'X',
    ),
    impact: round1(Math.max(0, impact)),
    exploitability: round1(exploitability),
  };
}
