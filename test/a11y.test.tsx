import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import axe from 'axe-core';
import type { ReactElement } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { CvssCombined, CvssInput, MAX_ISSUES, evaluate, nl } from '../src';
import { statusMessage } from '../src/react/CvssInput';
import type { CvssLayer } from '../src';

afterEach(cleanup);

const V31 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
const V40 = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
const asset: CvssLayer = {
  id: 'asset',
  label: 'Database server',
  requirements: { C: 'H', I: 'H', A: 'L' },
  vector: { '3.x': 'MAV:L' },
  groups: ['environmental'],
};

/** Runs axe on the rendered element. jsdom has no layout, so color contrast is tested separately. */
async function violations(ui: ReactElement) {
  const { container } = render(<main>{ui}</main>);
  const result = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
  return result.violations.map((v) => `${v.id}: ${v.help} (${v.nodes.map((n) => n.target.join(' ')).join(', ')})`);
}

describe('axe', () => {
  const cases: Array<[string, ReactElement]> = [
    ['empty', <CvssInput />],
    ['valid 3.1', <CvssInput defaultValue={V31 + '/E:P'} />],
    ['valid 4.0', <CvssInput defaultValue={V40} />],
    ['valid 2.0', <CvssInput defaultValue="AV:N/AC:L/Au:N/C:P/I:P/A:P" />],
    ['errors', <CvssInput defaultValue="CVSS:3.1/AV:Q/XX:1/garbage" />],
    ['ambiguous version', <CvssInput defaultValue="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" />],
    ['forced mismatch', <CvssInput defaultValue={V31} version="4.0" />],
    ['text only', <CvssInput defaultValue={V31} mode="text" />],
    ['picker only', <CvssInput defaultValue={V31} mode="picker" />],
    ['read-only', <CvssInput defaultValue={V31} readOnly />],
    ['disabled', <CvssInput defaultValue={V31} disabled />],
    ['overlay', <CvssInput baseVector={V31} defaultValue="E:F" />],
    ['layers', <CvssInput baseVector={V31} layers={[asset]} layerId="feed" defaultValue="E:F" />],
    [
      'layer conflict',
      <CvssInput baseVector={V31} layers={[{ id: 'feed', vector: 'E:H' }]} defaultValue="E:U" conflict="first" />,
    ],
    ['two inputs on one page', (
      <>
        <CvssInput defaultValue={V31} />
        <CvssInput defaultValue={V40} />
      </>
    )],
    ['combined', <CvssCombined baseVector={V31 + '/E:U'} layers={[{ id: 'feed', vector: 'E:H' }, asset]} conflict="last" />],
    ['combined with conflict', <CvssCombined baseVector={V31 + '/E:U'} layers={[{ id: 'feed', vector: 'E:H' }]} />],
    ['Dutch', <CvssInput defaultValue="CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" messages={nl} />],
    [
      'Dutch combined',
      <CvssCombined baseVector={V31 + '/E:U'} layers={[{ id: 'feed', vector: 'E:H' }, asset]} conflict="last" messages={nl} />,
    ],
  ];

  it.each(cases)('%s has no violations', async (_, ui) => {
    expect(await violations(ui)).toEqual([]);
  });
});

describe('screen reader support', () => {
  it('announces a summary only after typing pauses', async () => {
    vi.useFakeTimers();
    try {
      render(<CvssInput defaultValue="" />);
      const status = screen.getByRole('status');
      const input = screen.getByRole('textbox');
      fireEvent.change(input, { target: { value: 'CVSS:3.1/AV:N' } });
      fireEvent.change(input, { target: { value: V31 } });
      expect(status.textContent).toBe('');
      await act(() => vi.advanceTimersByTimeAsync(800));
      expect(status.textContent).toBe('Final 9.8 Critical (Base).');
      fireEvent.change(input, { target: { value: V31 + '/E:Q' } });
      await act(() => vi.advanceTimersByTimeAsync(800));
      expect(status.textContent).toMatch(/^1 problem\. "Q" isn't a valid value for E/);
    } finally {
      vi.useRealTimers();
    }
  });

  it('summarizes defined groups and CVSS 4.0 scores', () => {
    const scores = (v: string) => evaluate(v).scores;
    // Environmental: 6.42 × 0.8606 + 3.887 = 9.41 → 9.5; 9.5 × 0.94 = 8.93 → 9.0
    expect(statusMessage(scores(V31 + '/E:P/CR:L'), [])).toBe(
      'Final 9.0 Critical (Environmental). Base 9.8 Critical, Temporal 9.3 Critical, Environmental 9.0 Critical.',
    );
    expect(statusMessage(scores(V40), [])).toBe('CVSS-B 9.3 Critical.');
  });

  it('counts every listed error when some issues were left out', () => {
    const capped = evaluate(V31 + '/' + 'x/'.repeat(100)).issues;
    const other = evaluate('CVSS:3.1/AV:Q').issues;
    const errors = [...capped, ...other].filter((i) => i.severity === 'error' && i.code !== 'TOO_MANY_ISSUES');
    expect(errors.length).toBeGreaterThan(MAX_ISSUES);
    expect(statusMessage(null, [...capped, ...other])).toMatch(new RegExp(`^More than ${errors.length} problems\\. `));
  });

  it('describes picker radio groups with notes from other layers', () => {
    render(<CvssInput baseVector={V31} layers={[asset]} layerId="feed" />);
    const group = screen.getByRole('group', { name: /^Confidentiality Requirement/ });
    expect(group.getAttribute('aria-describedby')).toBeTruthy();
    expect(document.getElementById(group.getAttribute('aria-describedby')!)?.textContent).toBe(
      'Database server: High (applied)',
    );
  });

  it('marks overridden values for screen readers', () => {
    render(<CvssCombined baseVector={V31 + '/E:U'} layers={[{ id: 'feed', vector: 'E:H' }]} conflict="last" />);
    expect(screen.getByText('Overridden:', { exact: false, selector: '.cvss-sr-only' })).toBeTruthy();
  });

  it('keeps the issue list out of live regions', () => {
    render(<CvssInput defaultValue="CVSS:3.1/AV:Q" />);
    expect(document.querySelector('.cvss-issues')?.getAttribute('aria-live')).toBeNull();
  });
});
