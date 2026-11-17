import { cleanup, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import {
  CvssCombined,
  CvssInput,
  CvssMessagesProvider,
  VERSIONS,
  en,
  evaluate,
  evaluateLayers,
  formatIssue,
  nl,
  resolveMessages,
  statusMessage,
} from '../src';
import type { CvssIssue, CvssMessages, CvssVersion, IssueCode } from '../src';

afterEach(cleanup);

const V31 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
const FAMILY = { '2.0': '2.0', '3.0': '3.x', '3.1': '3.x', '4.0': '4.0' } as const;

/** Vectors and layer setups that between them produce every issue code. */
function everyIssue(): CvssIssue[] {
  const issues: CvssIssue[] = [];
  const add = (r: { issues: CvssIssue[] }) => issues.push(...r.issues);
  add(evaluate(''));
  add(evaluate('CVSS:9.9/AV:N'));
  add(evaluate('CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'));
  add(evaluate('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', { version: '3.1' }));
  add(evaluate('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'));
  add(evaluate('XX:1'));
  add(evaluate(V31.replace('CVSS:3.1', 'CVSS:4.0'), { version: '3.1' }));
  add(evaluate('CVSS:3.1/AV:N//AC:L/bad/PR:N/XX:1/UI:Q/UI:N/C:H/I:H/A:H/AV:N'));
  add(evaluate('CVSS:3.1/AC:L/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H', { strict: true }));
  add(evaluate('E:P/AV:N', { baseVector: V31 }));
  add(evaluate('CVSS:4.0/E:P', { baseVector: V31 }));
  add(evaluate('E:P', { baseVector: 'CVSS:3.1/AV:Q' }));
  add(evaluate('x'.repeat(2000)));
  add(evaluate('CVSS:3.1/' + Array.from({ length: 30 }, (_, n) => `Q${n}:1`).join('/')));
  add(evaluateLayers('nonsense', []));
  add(
    evaluateLayers(V31 + '/E:U', [
      { id: 'feed', label: 'Threat feed', vector: 'E:H' },
      { id: 'feed', vector: 'E:F' },
      { id: 'base', vector: 'E:P' },
      { id: 'v4only', vector: { '4.0': 'E:A' }, requirements: { C: 'H' } },
      { id: 'asset', label: 'Database', vector: 'CR:L/RL:O', requirements: { C: 'H' }, groups: ['environmental'] },
      { id: 'bad', requirements: { C: 'Q' as 'H' } },
      { id: 'temporal', requirements: { C: 'H' }, groups: ['temporal'] },
    ]),
  );
  add(evaluateLayers(V31, [{ id: 'a', vector: 'E:H' }, { id: 'b', vector: 'E:U' }], { conflict: () => 'Z' }));
  return issues;
}

describe('message catalogs', () => {
  it('produces every issue code in the tests, each with parameters', () => {
    const issues = everyIssue();
    const codes = new Set(issues.map((i) => i.code));
    expect([...codes].sort()).toEqual(Object.keys(en.issues).sort());
    expect(issues.filter((i) => !i.params)).toEqual([]);
  });

  it('keeps English issue messages identical to formatIssue with en', () => {
    for (const issue of everyIssue()) {
      expect(formatIssue(issue, en)).toBe(issue.message);
    }
  });

  it('translates every issue into Dutch', () => {
    const untranslated = everyIssue()
      .map((i) => [i.code, formatIssue(i, nl)])
      .filter(([, text]) => /\b(isn't|the|is missing|vector has)\b/.test(text));
    expect(untranslated).toEqual([]);
  });

  it.each(['2.0', '3.1', '4.0'] as CvssVersion[])('nl names every CVSS %s metric and value', (version) => {
    const def = VERSIONS[version];
    const names = nl.metrics[FAMILY[version]];
    const expected = Object.fromEntries(
      def.metrics.map((m) => [m.key, m.values.map((v) => v.code).filter((c) => c !== def.notDefined).sort()]),
    );
    const actual = Object.fromEntries(Object.entries(names).map(([k, m]) => [k, Object.keys(m.values).sort()]));
    expect(actual).toEqual(expected);
  });

  it('formats issues with translated metric names, layer labels, and numbers', () => {
    const [invalid] = evaluate('CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').issues;
    expect(formatIssue(invalid, nl)).toBe('"Q" is geen geldige waarde voor AV (Aanvalsvector). Geldige waarden: N, A, L, P.');
    const [tooLong] = evaluate('x'.repeat(10_000)).issues;
    expect(formatIssue(tooLong, nl)).toBe('De vector is 10.000 tekens lang; het maximum is 1.024.');
    expect(tooLong.message).toBe('The vector is 10,000 characters long; the maximum is 1,024.');
    const layered = evaluateLayers(V31 + '/E:U', [{ id: 'feed', label: 'Dreigingsfeed', vector: 'E:H' }]);
    const conflict = layered.issues.find((i) => i.code === 'METRIC_CONFLICT')!;
    expect(conflict.message).toBe('E is set to different values: Base vector E:U, Dreigingsfeed E:H.');
    expect(formatIssue(conflict, nl)).toBe('E heeft verschillende waarden: Basisvector E:U, Dreigingsfeed E:H.');
  });

  it('translates the base vector errors quoted in an overlay error', () => {
    const [issue] = evaluate('E:P', { baseVector: 'CVSS:3.1/AV:Q' }).issues;
    expect(formatIssue(issue, nl)).toMatch(/^De basisvector is ongeldig: "Q" is geen geldige waarde voor AV/);
  });

  it('fills in a partial catalog from English', () => {
    const m = resolveMessages({ ui: { vectorLabel: 'Vector' }, metrics: { '3.x': { AV: { name: 'Vector' } } } });
    expect(m.ui.vectorLabel).toBe('Vector');
    expect(m.ui.baseVector).toBe('Base vector');
    expect(m.metrics['3.x'].AV).toEqual({ name: 'Vector', values: en.metrics['3.x'].AV.values });
    expect(m.issues.EMPTY).toBe(en.issues.EMPTY);
  });

  it('writes the screen reader summary in Dutch', () => {
    const scores = evaluate(V31 + '/E:P/CR:L').scores;
    expect(statusMessage(scores, [], nl)).toBe(
      'Eindscore 9,0 Kritiek (Omgeving). Basis 9,8 Kritiek, Temporaal 9,3 Kritiek, Omgeving 9,0 Kritiek.',
    );
    const { issues } = evaluate('CVSS:3.1/AV:Q');
    expect(statusMessage(null, issues, nl)).toMatch(/^\d+ problemen\. "Q" is geen geldige waarde/);
  });

  it('types every issue function', () => {
    // A compile-time check: a catalog must cover every issue code.
    const codes: IssueCode[] = Object.keys(nl.issues) as IssueCode[];
    const catalog: CvssMessages = nl;
    expect(codes.length).toBe(Object.keys(catalog.issues).length);
  });
});

describe('components in Dutch', () => {
  it('shows CvssInput in Dutch with Dutch numbers', () => {
    const { container } = render(<CvssInput defaultValue={V31} messages={nl} />);
    expect(container.querySelector('.cvss')!.getAttribute('lang')).toBe('nl');
    expect(screen.getByLabelText('CVSS-vector')).toBeTruthy();
    expect(screen.getByRole('group', { name: /^Aanvalsvector AV$/ })).toBeTruthy();
    expect(within(screen.getByRole('group', { name: /^Aanvalsvector AV$/ })).getByRole('radio', { name: 'Netwerk' })).toBeTruthy();
    const base = container.querySelector('.cvss-score')!;
    expect(base.textContent).toContain('9,8');
    expect(base.textContent).toContain('Kritiek');
    expect(base.textContent).toContain('Eindscore');
  });

  it('translates issues and the go-to button', () => {
    render(<CvssInput defaultValue="CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" messages={nl} />);
    expect(screen.getByText(/is geen geldige waarde voor AV \(Aanvalsvector\)/)).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Ga naar positie 10' })).toBeTruthy();
    expect(screen.getAllByText('Fout').length).toBeGreaterThan(0);
  });

  it('takes the language from a provider, and a prop overrides parts of it', () => {
    render(
      <CvssMessagesProvider messages={nl}>
        <CvssInput defaultValue={V31} messages={{ ui: { vectorLabel: 'Vector van de kwetsbaarheid' } }} />
      </CvssMessagesProvider>,
    );
    expect(screen.getByLabelText('Vector van de kwetsbaarheid')).toBeTruthy();
    expect(screen.getByRole('group', { name: /^Aanvalsvector AV$/ })).toBeTruthy();
  });

  it('shows CvssCombined in Dutch', () => {
    render(
      <CvssCombined
        baseVector={V31 + '/E:U'}
        layers={[{ id: 'feed', label: 'Dreigingsfeed', vector: 'E:H' }]}
        conflict="last"
        messages={nl}
      />,
    );
    const table = screen.getByRole('table', { name: 'Herkomst van de metrics' });
    const row = within(table).getByText('Volwassenheid van exploitcode').closest('tr')!;
    expect(row.textContent).toContain('Hoog');
    expect(row.textContent).toContain('Overschreven: Basisvector: U');
  });
});
