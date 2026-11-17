// @vitest-environment node
// Checks our scores against official scores from the NVD CVE API, calculated by
// NVD or by the CNA that reported the CVE. Regenerate the fixture with
// `node scripts/fetch-nvd-fixtures.mjs`.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { evaluate } from '../src/core';
import type { CvssVersion } from '../src/core';

type Row = [version: CvssVersion, vector: string, baseScore: number, exampleCve: string];

const { rows } = JSON.parse(readFileSync(new URL('./fixtures/nvd-scores.json', import.meta.url), 'utf8')) as {
  rows: Row[];
};

describe('NVD published scores', () => {
  it('has a sample for every version', () => {
    const counts = Object.fromEntries(['2.0', '3.0', '3.1', '4.0'].map((v) => [v, rows.filter((r) => r[0] === v).length]));
    for (const n of Object.values(counts)) expect(n).toBeGreaterThan(100);
  });

  for (const version of ['2.0', '3.0', '3.1', '4.0'] as const) {
    it(`matches every CVSS ${version} score`, () => {
      const mismatches: string[] = [];
      for (const [v, vector, expected, cve] of rows) {
        if (v !== version) continue;
        const r = evaluate(vector, { version });
        if (!r.valid || !r.scores) {
          mismatches.push(`${cve} ${vector}: invalid (${r.issues.map((i) => i.code).join(', ')})`);
          continue;
        }
        // NVD's 4.0 baseScore is the score of the whole vector, including threat metrics.
        const actual = r.scores.kind === 'v4' ? r.scores.score.score : r.scores.base.score;
        if (actual !== expected) mismatches.push(`${cve} ${vector}: ours ${actual}, NVD ${expected}`);
      }
      expect(mismatches).toEqual([]);
    });
  }
});
