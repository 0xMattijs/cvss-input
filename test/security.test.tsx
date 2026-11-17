import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import {
  ALL_VERSIONS,
  CvssCombined,
  CvssInput,
  DEFAULT_MAX_LENGTH,
  MAX_ISSUES,
  VERSIONS,
  detectVersion,
  evaluate,
  evaluateLayers,
  serialize,
} from '../src';

afterEach(cleanup);

const V31 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';

describe('length limit', () => {
  it('leaves room for the longest valid vector of every version', () => {
    for (const version of ALL_VERSIONS) {
      const metrics: Record<string, string> = {};
      for (const m of VERSIONS[version].metrics) {
        metrics[m.key] = m.values.reduce((a, b) => (b.code.length > a.code.length ? b : a)).code;
      }
      const longest = serialize(version, metrics);
      expect(evaluate(longest).valid).toBe(true);
      expect(longest.length).toBeLessThan(DEFAULT_MAX_LENGTH / 3);
    }
  });

  it('rejects oversized input with one error, without parsing it', () => {
    const r = evaluate(V31 + '/' + 'x/'.repeat(1e6));
    expect(r.issues).toEqual([expect.objectContaining({ code: 'TOO_LONG', severity: 'error' })]);
    expect(r.metrics).toEqual({});
  });

  it('accepts input exactly at the limit', () => {
    const padded = V31 + ' '.repeat(DEFAULT_MAX_LENGTH - V31.length);
    expect(evaluate(padded).valid).toBe(true);
    expect(evaluate(padded + ' ').issues[0].code).toBe('TOO_LONG');
  });

  it('takes a custom limit', () => {
    expect(evaluate(V31, { maxLength: 20 }).issues[0].code).toBe('TOO_LONG');
  });

  it('applies to base vectors and layer vectors', () => {
    const huge = 'E:F/'.repeat(1e5);
    expect(evaluate(huge, { baseVector: V31 }).issues.map((i) => i.code)).toContain('TOO_LONG');
    expect(evaluate('E:F', { baseVector: huge }).issues.map((i) => i.code)).toEqual(['INVALID_BASE_VECTOR']);
    const r = evaluateLayers(V31, [{ id: 'feed', vector: huge }]);
    expect(r.issues).toMatchObject([{ code: 'TOO_LONG', layer: 'feed' }]);
  });

  it('makes detectVersion return null for oversized input', () => {
    expect(detectVersion('CVSS:3.1/' + 'x'.repeat(DEFAULT_MAX_LENGTH))).toBeNull();
  });
});

describe('issue cap', () => {
  it(`reports at most ${MAX_ISSUES} issues plus a summary`, () => {
    const r = evaluate(V31 + '/' + 'x/'.repeat(100));
    expect(r.issues).toHaveLength(MAX_ISSUES + 1);
    expect(r.issues.at(-1)).toMatchObject({ code: 'TOO_MANY_ISSUES', severity: 'error', message: '…and 80 more problems.' });
    expect(r.valid).toBe(false);
  });

  it("doesn't add a summary at or under the cap", () => {
    const r = evaluate(V31 + '/' + 'x/'.repeat(MAX_ISSUES));
    expect(r.issues).toHaveLength(MAX_ISSUES);
    expect(r.issues.some((i) => i.code === 'TOO_MANY_ISSUES')).toBe(false);
  });
});

describe('output encoding', () => {
  const payloads = [
    '<img src=x onerror=alert(1)>',
    'CVSS:3.1/AV:<script>alert(1)</script>',
    'CVSS:3.1/"><svg onload=alert(1)>:N',
    'CVSS:<b>x</b>/AV:N',
  ];

  it.each(payloads)('renders %s as text', (payload) => {
    const { container } = render(<CvssInput defaultValue={payload} />);
    expect(container.querySelector('img, script, svg, b')).toBeNull();
  });

  it('renders hostile layer labels and vectors as text', () => {
    const { container } = render(
      <CvssCombined baseVector={V31} layers={[{ id: 'x', label: '<img src=x onerror=alert(1)>', vector: 'E:<img src=x>' }]} />,
    );
    expect(container.querySelector('img')).toBeNull();
    expect(screen.getAllByText(/<img src=x onerror=alert\(1\)>/).length).toBeGreaterThan(0);
  });

  it('never puts unknown tokens in the normalized vector', () => {
    expect(evaluate(V31 + '/<x>:1').normalized).toBeNull();
    expect(evaluate('CVSS:3.1/__proto__:x/AV:N').issues[0].code).toBe('UNKNOWN_METRIC');
    expect(({} as Record<string, unknown>).x).toBeUndefined();
  });
});

describe('component limits', () => {
  it('sets maxLength on the text field', () => {
    render(<CvssInput defaultValue={V31} />);
    expect((screen.getByRole('textbox') as HTMLInputElement).maxLength).toBe(DEFAULT_MAX_LENGTH);
  });

  it('shows one error for an oversized controlled value', () => {
    render(<CvssInput value={'x/'.repeat(5000)} onChange={() => {}} />);
    expect(screen.getAllByRole('listitem')).toHaveLength(1);
    expect(screen.getByText(/The vector is 10000 characters long/)).toBeTruthy();
  });
});
