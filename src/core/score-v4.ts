// CVSS v4.0 scoring, ported from the FIRST reference implementation:
// https://github.com/FIRSTdotorg/cvss-v4-calculator (cvss_score.js, max_composed.js, max_severity.js)
// Copyright FIRST, Red Hat, and contributors. SPDX-License-Identifier: BSD-2-Clause

import { severityV3 } from './score-classic';
import type { V4Nomenclature, V4Scores } from './types';
import { V4_LOOKUP } from './v4-lookup';

type Metrics = Record<string, string>;

const MAX_COMPOSED = {
  eq1: { 0: ['AV:N/PR:N/UI:N/'], 1: ['AV:A/PR:N/UI:N/', 'AV:N/PR:L/UI:N/', 'AV:N/PR:N/UI:P/'], 2: ['AV:P/PR:N/UI:N/', 'AV:A/PR:L/UI:P/'] },
  eq2: { 0: ['AC:L/AT:N/'], 1: ['AC:H/AT:N/', 'AC:L/AT:P/'] },
  eq3: {
    0: { 0: ['VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/'], 1: ['VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/', 'VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/'] },
    1: {
      0: ['VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/', 'VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/'],
      1: [
        'VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/',
        'VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/',
        'VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/',
        'VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/',
        'VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/',
      ],
    },
    2: { 1: ['VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/'] },
  },
  eq4: { 0: ['SC:H/SI:S/SA:S/'], 1: ['SC:H/SI:H/SA:H/'], 2: ['SC:L/SI:L/SA:L/'] },
  eq5: { 0: ['E:A/'], 1: ['E:P/'], 2: ['E:U/'] },
} as const;

const MAX_SEVERITY = {
  eq1: [1, 4, 5],
  eq2: [1, 2],
  eq3eq6: [
    [7, 6],
    [8, 8],
    [NaN, 10],
  ],
  eq4: [6, 5, 4],
};

const LEVELS: Record<string, Record<string, number>> = {
  AV: { N: 0.0, A: 0.1, L: 0.2, P: 0.3 },
  PR: { N: 0.0, L: 0.1, H: 0.2 },
  UI: { N: 0.0, P: 0.1, A: 0.2 },
  AC: { L: 0.0, H: 0.1 },
  AT: { N: 0.0, P: 0.1 },
  VC: { H: 0.0, L: 0.1, N: 0.2 },
  VI: { H: 0.0, L: 0.1, N: 0.2 },
  VA: { H: 0.0, L: 0.1, N: 0.2 },
  SC: { H: 0.1, L: 0.2, N: 0.3 },
  SI: { S: 0.0, H: 0.1, L: 0.2, N: 0.3 },
  SA: { S: 0.0, H: 0.1, L: 0.2, N: 0.3 },
  CR: { H: 0.0, M: 0.1, L: 0.2 },
  IR: { H: 0.0, M: 0.1, L: 0.2 },
  AR: { H: 0.0, M: 0.1, L: 0.2 },
};

/** Effective value of a metric: applies X defaults and environmental overrides. */
function effective(m: Metrics, key: string): string {
  const v = m[key] ?? 'X';
  if (key === 'E' && v === 'X') return 'A';
  if ((key === 'CR' || key === 'IR' || key === 'AR') && v === 'X') return 'H';
  const modified = m['M' + key];
  if (modified !== undefined && modified !== 'X') return modified;
  return v;
}

export function macroVector(m: Metrics): string {
  const e = (k: string) => effective(m, k);

  let eq1: number;
  if (e('AV') === 'N' && e('PR') === 'N' && e('UI') === 'N') eq1 = 0;
  else if ((e('AV') === 'N' || e('PR') === 'N' || e('UI') === 'N') && e('AV') !== 'P') eq1 = 1;
  else eq1 = 2;

  const eq2 = e('AC') === 'L' && e('AT') === 'N' ? 0 : 1;

  let eq3: number;
  if (e('VC') === 'H' && e('VI') === 'H') eq3 = 0;
  else if (e('VC') === 'H' || e('VI') === 'H' || e('VA') === 'H') eq3 = 1;
  else eq3 = 2;

  let eq4: number;
  if (e('MSI') === 'S' || e('MSA') === 'S') eq4 = 0;
  else if (e('SC') === 'H' || e('SI') === 'H' || e('SA') === 'H') eq4 = 1;
  else eq4 = 2;

  const eq5 = { A: 0, P: 1, U: 2 }[e('E')] ?? 0;

  const eq6 =
    (e('CR') === 'H' && e('VC') === 'H') ||
    (e('IR') === 'H' && e('VI') === 'H') ||
    (e('AR') === 'H' && e('VA') === 'H')
      ? 0
      : 1;

  return `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6}`;
}

function valueIn(fragment: string, key: string): string {
  const match = new RegExp(`(?:^|/)${key}:([^/]+)`).exec(fragment);
  return match ? match[1] : '';
}

export function scoreV4Value(m: Metrics): { score: number; macroVector: string } {
  const mv = macroVector(m);
  const e = (k: string) => effective(m, k);

  if (['VC', 'VI', 'VA', 'SC', 'SI', 'SA'].every((k) => e(k) === 'N')) {
    return { score: 0, macroVector: mv };
  }

  const [eq1, eq2, eq3, eq4, eq5, eq6] = mv.split('').map(Number);
  const lookup = (a: number, b: number, c: number, d: number, f: number, g: number) =>
    V4_LOOKUP[`${a}${b}${c}${d}${f}${g}`] ?? NaN;

  const value = V4_LOOKUP[mv];

  const scoreEq1Lower = lookup(eq1 + 1, eq2, eq3, eq4, eq5, eq6);
  const scoreEq2Lower = lookup(eq1, eq2 + 1, eq3, eq4, eq5, eq6);
  let scoreEq3Eq6Lower: number;
  if (eq3 === 0 && eq6 === 0) {
    const left = lookup(eq1, eq2, eq3, eq4, eq5, eq6 + 1);
    const right = lookup(eq1, eq2, eq3 + 1, eq4, eq5, eq6);
    // The reference picks `left` only when it is strictly greater.
    scoreEq3Eq6Lower = left > right ? left : right;
  } else if (eq3 === 1 && eq6 === 0) {
    scoreEq3Eq6Lower = lookup(eq1, eq2, eq3, eq4, eq5, eq6 + 1);
  } else if ((eq3 === 0 || eq3 === 1) && eq6 === 1) {
    scoreEq3Eq6Lower = lookup(eq1, eq2, eq3 + 1, eq4, eq5, eq6);
  } else {
    scoreEq3Eq6Lower = lookup(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1);
  }
  const scoreEq4Lower = lookup(eq1, eq2, eq3, eq4 + 1, eq5, eq6);
  const scoreEq5Lower = lookup(eq1, eq2, eq3, eq4, eq5 + 1, eq6);

  // Highest-severity vectors in this MacroVector.
  const eq1Maxes = MAX_COMPOSED.eq1[eq1 as 0 | 1 | 2];
  const eq2Maxes = MAX_COMPOSED.eq2[eq2 as 0 | 1];
  const eq3Eq6Maxes = (MAX_COMPOSED.eq3 as Record<number, Record<number, readonly string[]>>)[eq3][eq6];
  const eq4Maxes = MAX_COMPOSED.eq4[eq4 as 0 | 1 | 2];
  const eq5Maxes = MAX_COMPOSED.eq5[eq5 as 0 | 1 | 2];

  const maxVectors: string[] = [];
  for (const a of eq1Maxes)
    for (const b of eq2Maxes)
      for (const c of eq3Eq6Maxes)
        for (const d of eq4Maxes) for (const f of eq5Maxes) maxVectors.push(a + b + c + d + f);

  const keys = ['AV', 'PR', 'UI', 'AC', 'AT', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA', 'CR', 'IR', 'AR'];
  let distances: Record<string, number> = {};
  // The reference keeps the last candidate's distances if none qualifies.
  for (const maxVector of maxVectors) {
    distances = {};
    for (const k of keys) distances[k] = LEVELS[k][e(k)] - LEVELS[k][valueIn(maxVector, k)];
    if (!keys.some((k) => distances[k] < 0)) break;
  }

  const d = distances;
  const current = {
    eq1: d.AV + d.PR + d.UI,
    eq2: d.AC + d.AT,
    eq3eq6: d.VC + d.VI + d.VA + d.CR + d.IR + d.AR,
    eq4: d.SC + d.SI + d.SA,
  };

  const step = 0.1;
  const maxSev = {
    eq1: MAX_SEVERITY.eq1[eq1] * step,
    eq2: MAX_SEVERITY.eq2[eq2] * step,
    eq3eq6: MAX_SEVERITY.eq3eq6[eq3][eq6] * step,
    eq4: MAX_SEVERITY.eq4[eq4] * step,
  };

  const parts: Array<[available: number, normalized: () => number]> = [
    [value - scoreEq1Lower, () => (value - scoreEq1Lower) * (current.eq1 / maxSev.eq1)],
    [value - scoreEq2Lower, () => (value - scoreEq2Lower) * (current.eq2 / maxSev.eq2)],
    [value - scoreEq3Eq6Lower, () => (value - scoreEq3Eq6Lower) * (current.eq3eq6 / maxSev.eq3eq6)],
    [value - scoreEq4Lower, () => (value - scoreEq4Lower) * (current.eq4 / maxSev.eq4)],
    [value - scoreEq5Lower, () => 0],
  ];

  let existing = 0;
  let sum = 0;
  for (const [available, normalized] of parts) {
    if (!Number.isNaN(available)) {
      existing++;
      sum += normalized();
    }
  }
  const meanDistance = existing === 0 ? 0 : sum / existing;

  let score = value - meanDistance;
  score = Math.min(10, Math.max(0, score));
  // Like the current FIRST calculator, add an epsilon so that values such as
  // 5.6499999999999995 (5.65 in exact arithmetic) round up.
  return { score: Math.round((score + 1e-6) * 10) / 10, macroVector: mv };
}

export function scoreV4(m: Metrics): V4Scores {
  const { score, macroVector: mv } = scoreV4Value(m);
  const defined = (keys: string[]) => keys.some((k) => m[k] !== undefined && m[k] !== 'X');
  const threat = defined(['E']);
  const env = defined([
    'CR', 'IR', 'AR', 'MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC', 'MVI', 'MVA', 'MSC', 'MSI', 'MSA',
  ]);
  const nomenclature: V4Nomenclature = threat
    ? env
      ? 'CVSS-BTE'
      : 'CVSS-BT'
    : env
      ? 'CVSS-BE'
      : 'CVSS-B';
  const value = { score, severity: severityV3(score) };
  const group = env ? 'environmental' : threat ? 'threat' : 'base';
  return {
    kind: 'v4',
    version: '4.0',
    overall: { ...value, group },
    score: value,
    nomenclature,
    macroVector: mv,
  };
}
