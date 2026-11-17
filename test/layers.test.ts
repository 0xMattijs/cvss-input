import { describe, expect, it } from 'vitest';
import { evaluate, evaluateLayers } from '../src/core';
import type { ClassicScores, CvssLayer, V4Scores } from '../src/core';

const V31 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
const V40 = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
const V20 = 'AV:N/AC:L/Au:N/C:P/I:P/A:P';

const asset: CvssLayer = {
  id: 'asset',
  label: 'Asset',
  requirements: { C: 'H', I: 'M', A: 'L' },
  vector: { '3.x': 'MAV:L', '4.0': 'MAV:L/MSI:S' },
  groups: ['environmental'],
};

const codes = (r: { issues: { code: string }[] }) => r.issues.map((i) => i.code);

describe('evaluateLayers', () => {
  it('combines base, threat feed, and asset layers', () => {
    const r = evaluateLayers(V31, [{ id: 'feed', vector: 'E:F/RL:O' }, asset]);
    expect(r.valid).toBe(true);
    expect(r.combined).toBe(V31 + '/E:F/RL:O/CR:H/IR:M/AR:L/MAV:L');
    expect(r.provenance).toMatchObject({ AV: 'base', E: 'feed', RL: 'feed', CR: 'asset', MAV: 'asset' });
    // Same scores as scoring the combined vector directly.
    expect(r.scores).toEqual(evaluate(r.combined!).scores);
    expect((r.scores as ClassicScores).environmental.score).toBeLessThan(
      (r.scores as ClassicScores).temporal.score,
    );
  });

  it('applies version-neutral requirements to every version', () => {
    expect(evaluateLayers(V20, [{ id: 'asset', requirements: { C: 'H' } }]).combined).toBe(V20 + '/CR:H');
    expect(evaluateLayers(V40, [{ id: 'asset', requirements: { C: 'L', A: 'X' } }]).combined).toBe(
      V40 + '/CR:L',
    );
  });

  it('picks the layer vector for the base version family', () => {
    const r = evaluateLayers(V40, [asset]);
    expect(r.combined).toBe(V40 + '/CR:H/IR:M/AR:L/MAV:L/MSI:S');
    expect((r.scores as V4Scores).nomenclature).toBe('CVSS-BE');
    expect(evaluateLayers('CVSS:3.0' + V31.slice(8), [asset]).effectiveMetrics.MAV).toBe('L');
  });

  it('warns when a layer has no vector for the base version, and still applies requirements', () => {
    const r = evaluateLayers(V20, [asset]);
    expect(r.valid).toBe(true);
    expect(r.issues).toMatchObject([{ code: 'MISSING_LAYER_VECTOR', severity: 'warning', layer: 'asset' }]);
    expect(r.combined).toBe(V20 + '/CR:H/IR:M/AR:L');
  });

  it('treats the base vector\'s own temporal metrics as the first layer', () => {
    const r = evaluateLayers(V31 + '/E:U', [{ id: 'feed', vector: 'E:H' }], { conflict: 'last' });
    expect(r.effectiveMetrics.E).toBe('H');
    expect(r.overrides).toEqual([
      { metric: 'E', winner: { layer: 'feed', value: 'H' }, overridden: [{ layer: 'base', value: 'U' }] },
    ]);
  });

  describe('conflict rules', () => {
    const layers: CvssLayer[] = [
      { id: 'vendor', vector: 'E:P' },
      { id: 'feed', vector: 'E:H' },
    ];

    it('reports conflicts by default', () => {
      const r = evaluateLayers(V31, layers);
      expect(r.valid).toBe(false);
      expect(r.scores).toBeNull();
      expect(r.issues).toMatchObject([{ code: 'METRIC_CONFLICT', metric: 'E' }]);
    });

    it('picks by layer order with first and last', () => {
      expect(evaluateLayers(V31, layers, { conflict: 'first' }).effectiveMetrics.E).toBe('P');
      expect(evaluateLayers(V31, layers, { conflict: 'last' }).effectiveMetrics.E).toBe('H');
    });

    it('accepts a custom rule', () => {
      // Pessimistic: take the highest exploit maturity.
      const rank = ['U', 'P', 'F', 'H'];
      const r = evaluateLayers(V31, layers, {
        conflict: (_, c) => c.map((x) => x.value).sort((a, b) => rank.indexOf(b) - rank.indexOf(a))[0],
      });
      expect(r.effectiveMetrics.E).toBe('H');
      expect(r.provenance.E).toBe('feed');
    });

    it('rejects a custom rule that returns a value no layer set', () => {
      expect(codes(evaluateLayers(V31, layers, { conflict: () => 'F' }))).toContain(
        'INVALID_CONFLICT_RESOLUTION',
      );
    });

    it('ignores equal values and not-defined values', () => {
      const r = evaluateLayers(V31, [
        { id: 'a', vector: 'E:F/RL:X' },
        { id: 'b', vector: 'E:F/RL:O' },
      ]);
      expect(r.valid).toBe(true);
      expect(r.provenance).toMatchObject({ E: 'a', RL: 'b' });
      expect(r.overrides).toEqual([]);
    });
  });

  describe('validation', () => {
    it('rejects metrics outside a layer\'s groups', () => {
      const r = evaluateLayers(V31, [{ ...asset, vector: 'E:F/MAV:L' }]);
      expect(r.issues).toMatchObject([{ code: 'METRIC_NOT_ALLOWED_IN_LAYER', metric: 'E', layer: 'asset' }]);
    });

    it('rejects base metrics in a layer', () => {
      expect(codes(evaluateLayers(V31, [{ id: 'x', vector: 'AV:L' }]))).toContain('BASE_METRIC_IN_OVERLAY');
    });

    it('rejects a metric set by both the vector and the requirements of one layer', () => {
      const r = evaluateLayers(V31, [{ id: 'asset', vector: 'CR:L', requirements: { C: 'H' } }]);
      expect(r.issues).toMatchObject([{ code: 'METRIC_CONFLICT', metric: 'CR', layer: 'asset' }]);
    });

    it('rejects duplicate and reserved layer IDs', () => {
      expect(codes(evaluateLayers(V31, [{ id: 'a' }, { id: 'a' }]))).toEqual(['DUPLICATE_LAYER_ID']);
      expect(codes(evaluateLayers(V31, [{ id: 'base' }]))).toEqual(['DUPLICATE_LAYER_ID']);
    });

    it('rejects invalid requirement levels', () => {
      const r = evaluateLayers(V31, [{ id: 'a', requirements: { C: 'Q' as 'H' } }]);
      expect(codes(r)).toEqual(['INVALID_REQUIREMENTS']);
    });

    it('reports an invalid base vector', () => {
      const r = evaluateLayers('CVSS:3.1/AV:N', [asset]);
      expect(r.valid).toBe(false);
      expect(codes(r)).toContain('INVALID_BASE_VECTOR');
    });

    it('tags layer issues with character ranges in the layer vector', () => {
      const r = evaluateLayers(V31, [{ id: 'feed', vector: 'E:F/RL:Q' }]);
      const issue = r.issues.find((i) => i.code === 'INVALID_VALUE')!;
      expect(issue.layer).toBe('feed');
      expect('E:F/RL:Q'.slice(issue.start, issue.end)).toBe('RL:Q');
    });

    it('applies the forced version to the base vector', () => {
      expect(codes(evaluateLayers(V31, [], { version: '4.0' }))).toContain('VERSION_MISMATCH');
    });
  });
});
