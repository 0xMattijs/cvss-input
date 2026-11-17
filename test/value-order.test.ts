// @vitest-environment node
// Pins the value order of each metric to the official calculators:
// FIRST's 3.0, 3.1 (https://www.first.org/cvss/calculator/3.1) and 4.0
// (github.com/FIRSTdotorg/cvss-v4-calculator, cvss_config.js), and NVD's 2.0
// (https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator). Checked 2026-11-17.
import { describe, expect, it } from 'vitest';
import { VERSIONS, orderedValues } from '../src/core';
import type { CvssVersion, ValueOrder } from '../src/core';

const V3 =
  'AV:N,A,L,P AC:L,H PR:N,L,H UI:N,R S:U,C C:N,L,H I:N,L,H A:N,L,H E:X,U,P,F,H RL:X,O,T,W,U RC:X,U,R,C ' +
  'CR:X,L,M,H IR:X,L,M,H AR:X,L,M,H MAV:X,N,A,L,P MAC:X,L,H MPR:X,N,L,H MUI:X,N,R MS:X,U,C ' +
  'MC:X,N,L,H MI:X,N,L,H MA:X,N,L,H';

const REFERENCE: Record<CvssVersion, string> = {
  '2.0':
    'AV:L,A,N AC:H,M,L Au:M,S,N C:N,P,C I:N,P,C A:N,P,C E:ND,U,POC,F,H RL:ND,OF,TF,W,U ' +
    'RC:ND,UC,UR,C CDP:ND,N,L,LM,MH,H TD:ND,N,L,M,H CR:ND,L,M,H IR:ND,L,M,H AR:ND,L,M,H',
  '3.0': V3,
  '3.1': V3,
  '4.0':
    'AV:N,A,L,P AC:L,H AT:N,P PR:N,L,H UI:N,P,A VC:H,L,N VI:H,L,N VA:H,L,N SC:H,L,N SI:H,L,N SA:H,L,N ' +
    'E:X,A,P,U CR:X,H,M,L IR:X,H,M,L AR:X,H,M,L MAV:X,N,A,L,P MAC:X,L,H MAT:X,N,P MPR:X,N,L,H MUI:X,N,P,A ' +
    'MVC:X,H,L,N MVI:X,H,L,N MVA:X,H,L,N MSC:X,H,L,N MSI:X,S,H,L,N MSA:X,S,H,L,N ' +
    'S:X,N,P AU:X,N,Y R:X,A,U,I V:X,D,C RE:X,L,M,H U:X,Clear,Green,Amber,Red',
};

const order = (version: CvssVersion, valueOrder: ValueOrder) =>
  VERSIONS[version].metrics
    .map((m) => `${m.key}:${orderedValues(m, valueOrder).map((v) => v.code).join(',')}`)
    .join(' ');

describe('value order', () => {
  it.each(Object.keys(REFERENCE) as CvssVersion[])('CVSS %s follows the official calculator', (version) => {
    expect(order(version, 'first')).toBe(REFERENCE[version]);
  });

  it('puts the least severe value first in ascending order', () => {
    const asc = order('3.1', 'ascending');
    expect(asc).toContain('AV:P,L,A,N ');
    expect(asc).toContain('PR:H,L,N ');
    expect(asc).toContain('C:N,L,H ');
    expect(asc).toContain('E:X,U,P,F,H ');
    expect(order('4.0', 'ascending')).toContain('VC:N,L,H ');
    expect(order('4.0', 'ascending')).toContain('MSI:X,N,L,H,S ');
    expect(order('4.0', 'ascending')).toContain('E:X,U,P,A ');
    expect(order('2.0', 'ascending')).toContain('E:ND,U,POC,F,H ');
  });

  it('puts the most severe value first in descending order, after Not Defined', () => {
    const desc = order('3.1', 'descending');
    expect(desc).toContain('AV:N,A,L,P ');
    expect(desc).toContain('C:H,L,N ');
    expect(desc).toContain('E:X,H,F,P,U ');
    expect(desc).toContain('CR:X,H,M,L ');
    expect(order('2.0', 'descending')).toContain('AV:N,A,L ');
    expect(order('2.0', 'descending')).toContain('CDP:ND,H,MH,LM,L,N ');
  });

  it('reverses exactly the metrics whose official order runs the other way', () => {
    for (const version of Object.keys(REFERENCE) as CvssVersion[]) {
      for (const m of VERSIONS[version].metrics) {
        const asc = orderedValues(m, 'ascending').map((v) => v.code);
        const desc = orderedValues(m, 'descending').map((v) => v.code);
        const skip = m.required ? 0 : 1;
        expect(asc.slice(0, skip)).toEqual(desc.slice(0, skip));
        expect(asc.slice(skip)).toEqual([...desc.slice(skip)].reverse());
        expect(orderedValues(m, m.severity)).toBe(m.values);
      }
    }
  });
});
