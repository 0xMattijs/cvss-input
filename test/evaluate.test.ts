import { describe, expect, it } from 'vitest';
import { detectVersion, evaluate, evaluateLayers } from '../src/core';
import type { ClassicScores, IssueCode, V4Scores } from '../src/core';

const codes = (input: string, opts = {}) => evaluate(input, opts).issues.map((i) => i.code);
const classic = (input: string, opts = {}) => evaluate(input, opts).scores as ClassicScores;
const v4 = (input: string, opts = {}) => evaluate(input, opts).scores as V4Scores;

describe('known scores', () => {
  it.each([
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8, 'Critical'],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1, 'Medium'],
    ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8, 'Critical'],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0, 'None'],
    ['AV:N/AC:L/Au:N/C:P/I:P/A:P', 7.5, 'High'],
    ['AV:N/AC:L/Au:N/C:C/I:C/A:C', 10, 'High'],
  ])('%s → %s', (vector, score, severity) => {
    expect(classic(vector).base).toEqual({ score, severity });
  });

  it('scores CVSS 4.0 with nomenclature', () => {
    const base = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
    expect(v4(base)).toMatchObject({ score: { score: 9.3, severity: 'Critical' }, nomenclature: 'CVSS-B' });
    expect(v4(base + '/E:P')).toMatchObject({ score: { score: 8.9 }, nomenclature: 'CVSS-BT' });
    expect(v4(base + '/CR:L')).toMatchObject({ nomenclature: 'CVSS-BE' });
    expect(v4(base + '/E:U/CR:L')).toMatchObject({ nomenclature: 'CVSS-BTE' });
    // X values and supplemental metrics don't change the nomenclature.
    expect(v4(base + '/E:X/S:P/U:Red')).toMatchObject({ score: { score: 9.3 }, nomenclature: 'CVSS-B' });
  });

  describe('2.0 temporal and environmental methods', () => {
    const full = 'AV:N/AC:L/Au:N/C:P/I:P/A:P/E:F/RL:OF/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H';

    it('uses the NVD method by default', () => {
      const s = classic(full);
      // AdjustedBase 8.8166 (not rounded) × 0.95 × 0.87 = 7.2869; 7.2869 + 2.7131 × 0.5 = 8.643 → 8.6
      expect([s.base.score, s.temporal.score, s.environmental.score]).toEqual([7.5, 6.2, 8.6]);
      expect(s.temporalDefined && s.environmentalDefined).toBe(true);
    });

    it('follows the spec with v2Method: spec', () => {
      const s = classic(full, { v2Method: 'spec' });
      // AdjustedBase 8.8 → AdjustedTemporal 7.27 → 7.3; (7.3 + 2.7 × 0.5) × 1 = 8.65 → 8.7
      expect([s.base.score, s.temporal.score, s.environmental.score]).toEqual([7.5, 6.2, 8.7]);
    });

    // Hand-checked cases where the methods differ.
    it.each([
      // NVD: AdjustedBase 2.0905 (Exploitability 3.9) × 0.9 = 1.8815; 1.8815 + 8.1185 × 0.5 = 5.941 → 5.9
      // Spec: Temporal 2.1 × 0.9 = 1.89 → 1.9; 1.9 + 8.1 × 0.5 = 5.95 → 6.0
      ['AV:N/AC:H/Au:S/C:N/I:N/A:P/E:H/RC:UC/CDP:H/CR:L', 5.9, 6.0],
      // NVD: AdjustedBase 2.8228 × 0.9 = 2.5405; (2.5405 + 7.4595 × 0.1) × 0.75 = 2.465 → 2.5
      // Spec: AdjustedBase 2.8 → AdjustedTemporal 2.52 → 2.5; (2.5 + 7.5 × 0.1) × 0.75 = 2.4375 → 2.4
      ['AV:L/AC:L/Au:N/C:P/I:P/A:N/E:ND/RC:UC/CDP:L/TD:M/CR:ND/IR:L', 2.5, 2.4],
      // NVD: AdjustedBase 4.9467 × 0.87 = 4.3036 → 4.3
      // Spec: AdjustedBase 5.0 × 0.87 = 4.35 → 4.4
      ['AV:L/AC:L/Au:M/C:C/I:P/A:N/E:H/RL:OF/CDP:N/TD:H/CR:M', 4.3, 4.4],
    ])('%s → NVD %s, spec %s', (vector, nvd, spec) => {
      expect(classic(vector).environmental.score).toBe(nvd);
      expect(classic(vector, { v2Method: 'spec' }).environmental.score).toBe(spec);
    });

    it('uses the Temporal score as Environmental when no environmental metric is set', () => {
      const s = classic('AV:N/AC:L/Au:N/C:P/I:P/A:P/E:F/RL:OF');
      expect(s.environmentalDefined).toBe(false);
      expect(s.environmental.score).toBe(s.temporal.score);
    });

    it('passes the method through layers', () => {
      const layers = [{ id: 'asset', vector: 'CDP:H/TD:H/CR:H/IR:H/AR:H' }];
      const base = 'AV:N/AC:L/Au:N/C:P/I:P/A:P/E:F/RL:OF/RC:C';
      const env = (o = {}) => (evaluateLayers(base, layers, o).scores as ClassicScores).environmental.score;
      expect([env(), env({ v2Method: 'spec' })]).toEqual([8.6, 8.7]);
    });
  });

  it('marks temporal and environmental groups as not defined', () => {
    const s = classic('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:X');
    expect(s.temporalDefined).toBe(false);
    expect(s.environmentalDefined).toBe(false);
    expect(s.temporal.score).toBe(9.8);
  });
});

describe('final score', () => {
  const V31 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
  const V40 = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
  const overall = (v: string, o = {}) => evaluate(v, o).scores!.overall;

  it.each([
    [V31, { score: 9.8, severity: 'Critical', group: 'base' }],
    [V31 + '/E:X/CR:X', { score: 9.8, severity: 'Critical', group: 'base' }],
    [V31 + '/E:U', { score: 9.0, severity: 'Critical', group: 'temporal' }],
    // Environmental wins even when no temporal metric is set.
    [V31 + '/MAV:L', { score: 8.4, severity: 'High', group: 'environmental' }],
    [V31 + '/E:U/MAV:L', { score: 7.7, severity: 'High', group: 'environmental' }],
    // 7.5 × 0.95 = 7.125 → 7.1
    ['AV:N/AC:L/Au:N/C:P/I:P/A:P/E:F', { score: 7.1, severity: 'High', group: 'temporal' }],
    ['AV:N/AC:L/Au:N/C:P/I:P/A:P/E:F/CDP:H', { group: 'environmental' }],
  ])('%s → %o', (vector, expected) => {
    expect(overall(vector)).toMatchObject(expected);
  });

  it('matches the group score it was taken from', () => {
    const s = evaluate(V31 + '/E:U/MAV:L').scores as ClassicScores;
    expect(s.overall.score).toBe(s.environmental.score);
  });

  it.each([
    [V40, 'base'],
    [V40 + '/E:P', 'threat'],
    [V40 + '/CR:L', 'environmental'],
    [V40 + '/E:P/CR:L', 'environmental'],
    [V40 + '/S:P', 'base'],
  ])('CVSS 4.0 %s → %s', (vector, group) => {
    const s = evaluate(vector).scores as V4Scores;
    expect(s.overall).toEqual({ ...s.score, group });
  });
});

describe('version detection', () => {
  it.each([
    ['CVSS:3.1/AV:N', '3.1'],
    ['CVSS:3.0/AV:N', '3.0'],
    ['CVSS:4.0/AV:N', '4.0'],
    ['AV:N/AC:L/Au:N/C:P/I:P/A:P', '2.0'],
    ['(AV:N/AC:L/Au:N/C:P/I:P/A:P)', '2.0'],
    ['CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P', '2.0'],
    ['AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', '4.0'],
    ['AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', '3.x'],
    ['E:F/RL:O', null],
  ])('%s → %s', (vector, expected) => {
    expect(detectVersion(vector)).toBe(expected);
  });

  it('refuses to guess between 3.0 and 3.1', () => {
    const r = evaluate('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(r.valid).toBe(false);
    expect(r.issues.map((i) => i.code)).toEqual(['AMBIGUOUS_VERSION']);
  });

  it('accepts a prefixless 2.0 vector wrapped in parentheses', () => {
    const r = evaluate(' (AV:N/AC:L/Au:N/C:P/I:P/A:P) ');
    expect(r.valid).toBe(true);
    expect(r.normalized).toBe('AV:N/AC:L/Au:N/C:P/I:P/A:P');
  });
});

describe('forced version', () => {
  it('reports a prefix that conflicts with the forced version', () => {
    expect(codes('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', { version: '4.0' })).toContain(
      'VERSION_MISMATCH',
    );
  });

  it('adds a missing prefix in lenient mode', () => {
    const r = evaluate('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', { version: '3.0' });
    expect(r.valid).toBe(true);
    expect(r.issues).toMatchObject([{ code: 'MISSING_PREFIX', severity: 'warning' }]);
    expect(r.normalized).toBe('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  });

  it('rejects a missing prefix in strict mode', () => {
    const r = evaluate('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', { version: '3.1', strict: true });
    expect(r.valid).toBe(false);
    expect(r.issues).toMatchObject([{ code: 'MISSING_PREFIX', severity: 'error' }]);
  });

  it('validates against the forced version', () => {
    expect(codes('AV:N/AC:L/Au:N/C:P/I:P/A:P', { version: '3.1' })).toEqual(
      expect.arrayContaining(['UNKNOWN_METRIC', 'MISSING_METRIC']),
    );
  });
});

describe('validation', () => {
  const base31 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';

  it.each<[string, IssueCode]>([
    ['', 'EMPTY'],
    ['CVSS:5.0/AV:N', 'UNKNOWN_PREFIX'],
    [base31 + '/XX:Y', 'UNKNOWN_METRIC'],
    [base31 + '/E:Q', 'INVALID_VALUE'],
    [base31 + '/E:F/E:H', 'DUPLICATE_METRIC'],
    [base31 + '/garbage', 'MALFORMED_SEGMENT'],
    ['CVSS:3.1/AV:N//AC:L', 'MALFORMED_SEGMENT'],
    ['CVSS:3.1/AV:N/AC:L', 'MISSING_METRIC'],
    ['E:F/RL:O', 'UNDETECTABLE_VERSION'],
  ])('%j → %s', (input, code) => {
    expect(codes(input)).toContain(code);
  });

  it('reports character ranges for bad segments', () => {
    const input = base31 + '/E:Q';
    const issue = evaluate(input).issues[0];
    expect(input.slice(issue.start, issue.end)).toBe('E:Q');
  });

  it('is case sensitive', () => {
    expect(codes('CVSS:3.1/av:n/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toContain('UNKNOWN_METRIC');
  });

  it('tolerates a trailing slash', () => {
    expect(evaluate(base31 + '/').valid).toBe(true);
  });

  it('reorders metrics in lenient mode', () => {
    const r = evaluate('CVSS:3.1/E:F/A:H/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H');
    expect(r.valid).toBe(true);
    expect(r.issues).toMatchObject([{ code: 'METRIC_ORDER', severity: 'warning' }]);
    expect(r.normalized).toBe(base31 + '/E:F');
  });

  it('rejects out-of-order metrics in strict mode', () => {
    const r = evaluate('CVSS:3.1/E:F/A:H/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H', { strict: true });
    expect(r.valid).toBe(false);
    expect(r.issues).toMatchObject([{ code: 'METRIC_ORDER', severity: 'error' }]);
  });

  it('flags the nonstandard CVSS2# prefix and drops it on normalization', () => {
    const r = evaluate('CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
    expect(r.issues).toMatchObject([{ code: 'NONSTANDARD_PREFIX', severity: 'warning' }]);
    expect(r.normalized).toBe('AV:N/AC:L/Au:N/C:P/I:P/A:P');
  });

  it('returns no scores for an invalid vector', () => {
    expect(evaluate('CVSS:3.1/AV:N').scores).toBeNull();
  });
});

describe('overlay on a base vector', () => {
  const base31 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
  const base40 = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';

  it('combines temporal metrics with the base vector', () => {
    const r = evaluate('E:P/RL:O/RC:C', { baseVector: base31 });
    expect(r.valid).toBe(true);
    expect(r.version).toBe('3.1');
    expect(r.normalized).toBe('E:P/RL:O/RC:C');
    expect(r.combined).toBe(base31 + '/E:P/RL:O/RC:C');
    expect((r.scores as ClassicScores).temporal.score).toBe(8.8);
  });

  it('accepts a prefix that matches the base vector', () => {
    expect(evaluate('CVSS:3.1/E:P', { baseVector: base31 }).valid).toBe(true);
  });

  it('rejects a prefix that conflicts with the base vector', () => {
    expect(codes('CVSS:3.0/E:P', { baseVector: base31 })).toContain('VERSION_MISMATCH');
  });

  it('rejects base metrics in the overlay', () => {
    expect(codes('AV:L/E:P', { baseVector: base31 })).toContain('BASE_METRIC_IN_OVERLAY');
  });

  it('scores CVSS 4.0 threat overlays as CVSS-BT', () => {
    const r = evaluate('E:P', { baseVector: base40 });
    expect(r.scores).toMatchObject({ score: { score: 8.9 }, nomenclature: 'CVSS-BT' });
  });

  it('treats an empty overlay as the base vector', () => {
    const r = evaluate('', { baseVector: base31 });
    expect(r.valid).toBe(true);
    expect(r.combined).toBe(base31);
  });

  it('reports an invalid base vector', () => {
    expect(codes('E:P', { baseVector: 'CVSS:3.1/AV:N' })).toEqual(['INVALID_BASE_VECTOR']);
  });

  it('applies a forced version to the base vector', () => {
    expect(codes('E:P', { baseVector: base31, version: '4.0' })).toEqual(['INVALID_BASE_VECTOR']);
  });

  it('reorders overlay metrics', () => {
    expect(evaluate('RC:C/E:P', { baseVector: base31 }).normalized).toBe('E:P/RC:C');
  });
});
