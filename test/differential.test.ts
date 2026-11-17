// Compares our scores with an independent implementation (ae-cvss-calculator)
// on random vectors that set every metric.
import { Cvss2, Cvss3P0, Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator';
import { describe, expect, it } from 'vitest';
import { VERSIONS, evaluate, serialize } from '../src/core';
import type { ClassicScores, CvssVersion, V4Scores } from '../src/core';

function rng(seed: number) {
  return () => {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    return seed / 2 ** 32;
  };
}

function randomVector(version: CvssVersion, rand: () => number): string {
  const metrics: Record<string, string> = {};
  for (const m of VERSIONS[version].metrics) {
    // Skip some optional metrics so "not set" paths are covered too.
    if (!m.required && rand() < 0.3) continue;
    metrics[m.key] = m.values[Math.floor(rand() * m.values.length)].code;
  }
  return serialize(version, metrics);
}

const N = 5000;

describe('differential: classic versions', () => {
  const cases: Array<[CvssVersion, new (v: string) => { calculateScores(): object }]> = [
    ['2.0', Cvss2],
    ['3.0', Cvss3P0],
    ['3.1', Cvss3P1],
  ];
  for (const [version, Ref] of cases) {
    it(`CVSS ${version} matches reference on ${N} random vectors`, () => {
      const rand = rng(42 + Number(version.replace('.', '')));
      const mismatches: string[] = [];
      for (let n = 0; n < N; n++) {
        const vector = randomVector(version, rand);
        const ours = evaluate(vector).scores as ClassicScores;
        const ref = new Ref(vector).calculateScores() as unknown as Record<string, number | undefined>;
        // For 2.0, the reference skips the spec's rounding of AdjustedTemporal and
        // lets floating-point noise decide x.x5 boundaries, so allow ±0.1 there.
        // test/evaluate.test.ts pins those boundary cases with hand-checked values.
        const check = (name: string, a: number, b: number | undefined) => {
          const tolerance = version === '2.0' && name !== 'base' ? 0.1 + 1e-9 : 0;
          if (b !== undefined && Math.abs(a - b) > tolerance) {
            mismatches.push(`${vector} ${name}: ours=${a} ref=${b}`);
          }
        };
        check('base', ours.base.score, ref.base);
        check('temporal', ours.temporal.score, ref.temporal);
        check('environmental', ours.environmental.score, ref.environmental);
      }
      expect(mismatches.slice(0, 10)).toEqual([]);
    });
  }
});

describe('differential: CVSS 4.0', () => {
  it(`matches reference on ${N} random vectors`, () => {
    const rand = rng(4040);
    const mismatches: string[] = [];
    for (let n = 0; n < N; n++) {
      const vector = randomVector('4.0', rand);
      const ours = evaluate(vector).scores as V4Scores;
      const ref = new Cvss4P0(vector).calculateScores() as { overall: number };
      if (ours.score.score !== ref.overall) {
        mismatches.push(`${vector}: ours=${ours.score.score} ref=${ref.overall}`);
      }
    }
    expect(mismatches.slice(0, 10)).toEqual([]);
  }, 60_000);
});
