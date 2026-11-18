import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { CvssCombined, CvssInput, evaluate } from '../src';
import { markSegments } from '../src/react/CvssInput';
import type { CvssLayer } from '../src';

afterEach(cleanup);

const V31 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
const V40 = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';

const textbox = () => screen.getByRole('textbox') as HTMLInputElement;
const scoreCell = (title: string) =>
  screen.getByText(title, { selector: '.cvss-score-title' }).closest('.cvss-score') as HTMLElement;
const metricGroup = (name: string) => screen.getByRole('group', { name: new RegExp(`^${name}\\b`) });

describe('CvssInput', () => {
  it('shows Base, Temporal, and Environmental scores for a 3.1 vector', () => {
    render(<CvssInput defaultValue={V31 + '/E:P'} />);
    expect(within(scoreCell('Base')).getByText('9.8')).toBeTruthy();
    expect(within(scoreCell('Temporal')).getByText('9.3')).toBeTruthy();
    expect(within(scoreCell('Environmental')).getByText('No environmental metrics set')).toBeTruthy();
    expect(screen.getByText('CVSS 3.1')).toBeTruthy();
    expect(screen.getByText('detected')).toBeTruthy();
  });

  it('marks the cell with the final score', () => {
    const { rerender } = render(<CvssInput value={V31} onChange={() => {}} />);
    const finalCell = () => document.querySelector('.cvss-score[data-final]')!;
    expect(finalCell().textContent).toMatch(/^BaseFinal/);
    rerender(<CvssInput value={V31 + '/E:U'} onChange={() => {}} />);
    expect(finalCell().textContent).toMatch(/^TemporalFinal/);
    rerender(<CvssInput value={V31 + '/MAV:L'} onChange={() => {}} />);
    expect(finalCell().textContent).toMatch(/^EnvironmentalFinal8\.4/);
    expect(document.querySelectorAll('.cvss-final-badge')).toHaveLength(1);
  });

  it("doesn't add a Final label to the single 4.0 score", () => {
    render(<CvssInput defaultValue={V40} />);
    expect(document.querySelector('.cvss-final-badge')).toBeNull();
  });

  it('shows one labeled score for a 4.0 vector', () => {
    render(<CvssInput defaultValue={V40 + '/E:P'} />);
    expect(within(scoreCell('CVSS-BT')).getByText('8.9')).toBeTruthy();
    expect(screen.queryByText('Temporal', { selector: '.cvss-score-title' })).toBeNull();
  });

  it('updates the vector in canonical order when you pick a metric', () => {
    const onChange = vi.fn();
    render(<CvssInput defaultValue={V31} onChange={onChange} />);
    fireEvent.click(within(metricGroup('Report Confidence')).getByLabelText('Confirmed'));
    fireEvent.click(within(metricGroup('Exploit Code Maturity')).getByLabelText('Functional'));
    expect(textbox().value).toBe(V31 + '/E:F/RC:C');
    expect(onChange).toHaveBeenLastCalledWith(V31 + '/E:F/RC:C', expect.objectContaining({ valid: true }), null);
  });

  it('removes a metric when you pick Not Defined', () => {
    render(<CvssInput defaultValue={V31 + '/E:F'} />);
    fireEvent.click(within(metricGroup('Exploit Code Maturity')).getByLabelText('Not Defined'));
    expect(textbox().value).toBe(V31);
  });

  it('reorders the vector on blur in lenient mode', () => {
    render(<CvssInput defaultValue="CVSS:3.1/E:F/A:H/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H" />);
    expect(screen.getByText(/reordered on normalization/)).toBeTruthy();
    fireEvent.blur(textbox());
    expect(textbox().value).toBe(V31 + '/E:F');
  });

  it('keeps the order and reports an error in strict mode', () => {
    const messy = 'CVSS:3.1/E:F/A:H/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H';
    render(<CvssInput defaultValue={messy} strict />);
    fireEvent.blur(textbox());
    expect(textbox().value).toBe(messy);
    expect(textbox().getAttribute('aria-invalid')).toBe('true');
  });

  it('blocks the picker when a forced version conflicts with the vector', () => {
    render(<CvssInput defaultValue={V31} version="4.0" />);
    expect(screen.getByText(/CVSS 4.0 is required/)).toBeTruthy();
    expect(screen.getByText(/Fix the errors/)).toBeTruthy();
    expect((metricGroup('Attack Vector') as HTMLFieldSetElement).disabled).toBe(true);
  });

  it('builds a vector from scratch with the chosen version', () => {
    render(<CvssInput />);
    fireEvent.change(screen.getByLabelText('Version'), { target: { value: '3.1' } });
    fireEvent.click(within(metricGroup('Attack Vector')).getByLabelText('Network'));
    expect(textbox().value).toBe('CVSS:3.1/AV:N');
    expect(screen.getByText('AC (Attack Complexity) is missing.')).toBeTruthy();
  });

  it('offers to add a 3.x prefix to an ambiguous vector', () => {
    render(<CvssInput defaultValue="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" />);
    fireEvent.click(screen.getByRole('button', { name: 'Treat as CVSS 3.1' }));
    expect(textbox().value).toBe(V31);
  });

  it('works as a controlled component', () => {
    const onChange = vi.fn();
    const { rerender } = render(<CvssInput value={V31} onChange={onChange} />);
    fireEvent.change(textbox(), { target: { value: V31 + '/E:U' } });
    expect(onChange).toHaveBeenCalledWith(V31 + '/E:U', expect.anything(), null);
    expect(textbox().value).toBe(V31); // parent didn't update value
    rerender(<CvssInput value={V31 + '/E:U'} onChange={onChange} />);
    expect(within(scoreCell('Temporal')).getByText('9.0')).toBeTruthy(); // 9.8 × 0.91 = 8.92 → 9.0
  });

  describe('with a base vector', () => {
    it('edits only the overlay and scores the combined vector', () => {
      const onChange = vi.fn();
      render(<CvssInput baseVector={V31} onChange={onChange} />);
      expect(screen.getByText('from base vector', { selector: '.cvss-version-how' })).toBeTruthy();
      expect((metricGroup('Attack Vector') as HTMLFieldSetElement).disabled).toBe(true);

      fireEvent.click(within(metricGroup('Exploit Code Maturity')).getByLabelText('Proof-of-Concept'));
      expect(textbox().value).toBe('E:P');
      expect(onChange).toHaveBeenLastCalledWith(
        'E:P',
        expect.objectContaining({ combined: V31 + '/E:P', valid: true }),
        expect.objectContaining({ combined: V31 + '/E:P', valid: true }),
      );
      expect(within(scoreCell('Temporal')).getByText('9.3')).toBeTruthy(); // 9.8 × 0.94 = 9.21 → 9.3
    });

    it('rejects base metrics typed into the overlay', () => {
      render(<CvssInput baseVector={V31} defaultValue="AV:L/E:P" />);
      expect(screen.getByText(/is a base metric/)).toBeTruthy();
    });

    it('shows a CVSS-BT score for a 4.0 threat overlay', () => {
      render(<CvssInput baseVector={V40} defaultValue="E:U" />);
      expect(screen.getByText('CVSS-BT')).toBeTruthy();
    });
  });

  it('renders only the text field in text mode', () => {
    render(<CvssInput defaultValue={V31} mode="text" />);
    expect(screen.queryByRole('group', { name: /Attack Vector/ })).toBeNull();
  });

  it('renders only the picker in picker mode', () => {
    render(<CvssInput defaultValue={V31} mode="picker" />);
    expect(screen.queryByRole('textbox')).toBeNull();
  });
});

describe('layers', () => {
  const asset: CvssLayer = {
    id: 'asset',
    label: 'Database server',
    requirements: { C: 'H', I: 'H', A: 'L' },
    vector: { '3.x': 'MAV:L' },
    groups: ['environmental'],
  };

  it('edits a threat layer with the asset layer as context', () => {
    const onChange = vi.fn();
    render(<CvssInput baseVector={V31} layers={[asset]} layerId="feed" onChange={onChange} />);
    expect(screen.getByText('Database server', { selector: '.cvss-layer-chip' })).toBeTruthy();
    // The asset's MAV:L already lowers the environmental score.
    expect(within(scoreCell('Environmental')).getByText('8.4')).toBeTruthy();
    fireEvent.click(within(metricGroup('Exploit Code Maturity')).getByLabelText('Unproven'));
    expect(textbox().value).toBe('E:U');
    const layered = onChange.mock.calls.at(-1)![2];
    expect(layered.combined).toBe(V31 + '/E:U/CR:H/IR:H/AR:L/MAV:L');
    expect(layered.provenance).toMatchObject({ E: 'feed', CR: 'asset' });
  });

  it('shows what other layers set for a metric', () => {
    render(<CvssInput baseVector={V31} layers={[asset]} layerId="feed" />);
    // CR and IR are both High.
    expect(screen.getAllByText('Database server: High (applied)')).toHaveLength(2);
    expect(screen.getByText('Database server: Low (applied)')).toBeTruthy();
  });

  it('limits the picker to the edited layer\'s groups', () => {
    render(<CvssInput baseVector={V31} layers={[{ ...asset, vector: undefined }]} layerId="asset" defaultValue="MAV:L" />);
    expect(screen.queryByRole('group', { name: /^Exploit Code Maturity/ })).toBeNull();
    expect(metricGroup('Modified Attack Vector')).toBeTruthy();
    expect(textbox().value).toBe('MAV:L');
  });

  it('reports a conflict with the default rule and resolves it with "last"', () => {
    const feed: CvssLayer = { id: 'feed', label: 'Threat feed', vector: 'E:H' };
    const { rerender } = render(<CvssInput baseVector={V31} layers={[feed]} defaultValue="E:U" />);
    expect(screen.getByText(/E is set to different values/)).toBeTruthy();
    expect(screen.getByText('Conflicts with another layer.')).toBeTruthy();
    rerender(<CvssInput baseVector={V31} layers={[feed]} defaultValue="E:U" conflict="last" />);
    expect(within(scoreCell('Temporal')).getByText('9.0')).toBeTruthy();
    rerender(<CvssInput baseVector={V31} layers={[feed]} defaultValue="E:U" conflict="first" />);
    expect(screen.getByText('Overridden by Threat feed.')).toBeTruthy();
  });

  it('edits the base vector with layers applied on top', () => {
    render(<CvssInput defaultValue={V31} layers={[asset]} />);
    expect(within(scoreCell('Base')).getByText('9.8')).toBeTruthy();
    expect(within(scoreCell('Environmental')).getByText('8.4')).toBeTruthy();
    expect(screen.getByText(V31 + '/CR:H/IR:H/AR:L/MAV:L')).toBeTruthy();
  });

  it('shows the combined score and metric sources', () => {
    render(
      <CvssCombined
        baseVector={V31 + '/E:U'}
        layers={[{ id: 'feed', label: 'Threat feed', vector: 'E:H' }, asset]}
        conflict="last"
      />,
    );
    const table = screen.getByRole('table', { name: 'Metric sources' });
    const row = within(table).getByText('Exploit Code Maturity').closest('tr')!;
    expect(within(row).getByText('Threat feed')).toBeTruthy();
    expect(row.querySelector('del')?.textContent).toBe('Overridden: Base vector: U');
    expect(within(table).getByText('Modified Attack Vector').closest('tr')!.textContent).toContain('Database server');
  });
});

describe('issue marks in the text field', () => {
  const marks = () => [...document.querySelectorAll('.cvss-mark')].map((m) => [m.getAttribute('data-severity'), m.textContent]);

  it('splits text into runs by the most severe covering issue', () => {
    const issue = (severity: 'error' | 'warning', start: number, end: number) =>
      ({ severity, start, end, code: 'INVALID_VALUE', message: '' }) as const;
    expect(markSegments('abcdefgh', [issue('warning', 1, 5), issue('error', 3, 6)])).toEqual([
      { text: 'a', start: 0, severity: null },
      { text: 'bc', start: 1, severity: 'warning' },
      { text: 'def', start: 3, severity: 'error' },
      { text: 'gh', start: 6, severity: null },
    ]);
    expect(markSegments('abc', [])).toEqual([{ text: 'abc', start: 0, severity: null }]);
  });

  it('marks the ranges of errors in the vector', () => {
    const vector = 'CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/XX:1';
    render(<CvssInput defaultValue={vector} />);
    const ranged = evaluate(vector).issues.filter((i) => i.start !== undefined);
    expect(ranged.length).toBe(2);
    expect(marks()).toEqual(ranged.map((i) => ['error', vector.slice(i.start, i.end)]));
    // The copy behind the input holds the full text, so the marks line up with it.
    expect(document.querySelector('.cvss-text-marks')!.textContent).toBe(vector + ' ');
  });

  it('marks warnings with a range, such as a nonstandard prefix', () => {
    render(<CvssInput defaultValue="CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" />);
    expect(marks()).toEqual([['warning', 'CVSS2#']]);
    cleanup();
    render(<CvssInput defaultValue="CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P" />);
    expect(marks()).toEqual([['warning', 'CVSS:2.0']]);
  });

  it('has no marks for a valid vector', () => {
    render(<CvssInput defaultValue={V31} />);
    expect(marks()).toEqual([]);
  });

  it('selects the bad part of the vector from the issue list', () => {
    const vector = 'CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
    render(<CvssInput defaultValue={vector} />);
    fireEvent.click(screen.getByRole('button', { name: 'Go to position 10' }));
    const input = textbox();
    expect(document.activeElement).toBe(input);
    expect(vector.slice(input.selectionStart!, input.selectionEnd!)).toBe('AV:Q');
  });

  it('shows the position as text when the field is disabled', () => {
    render(<CvssInput defaultValue="CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" disabled />);
    expect(screen.queryByRole('button', { name: /^Go to position/ })).toBeNull();
    expect(screen.getByText('(position 10)')).toBeTruthy();
  });
});

describe('value order in the picker', () => {
  const options = (name: RegExp) =>
    within(screen.getByRole('group', { name })).getAllByRole('radio').map((r) => (r as HTMLInputElement).value);

  it('follows the FIRST calculator by default', () => {
    render(<CvssInput defaultValue={V31} />);
    expect(options(/^Attack Vector/)).toEqual(['N', 'A', 'L', 'P']);
    expect(options(/^Confidentiality C$/)).toEqual(['N', 'L', 'H']);
  });

  it('can put the least or most severe value first', () => {
    render(<CvssInput defaultValue={V31} valueOrder="ascending" />);
    expect(options(/^Attack Vector/)).toEqual(['P', 'L', 'A', 'N']);
    expect(options(/^Confidentiality C$/)).toEqual(['N', 'L', 'H']);
    cleanup();
    render(<CvssInput defaultValue={V31} valueOrder="descending" />);
    expect(options(/^Attack Vector/)).toEqual(['N', 'A', 'L', 'P']);
    expect(options(/^Confidentiality C$/)).toEqual(['H', 'L', 'N']);
  });
});

describe('metric groups', () => {
  const group = (title: string) =>
    screen.getByText(title, { selector: '.cvss-group > summary' }).closest('details') as HTMLDetailsElement;

  it('scrolls a group the user opens into view', async () => {
    const scroll = vi.fn();
    const original = Element.prototype.scrollIntoView;
    Element.prototype.scrollIntoView = scroll;
    try {
      render(<CvssInput defaultValue={V31} version="3.1" />);
      const temporal = group('Temporal');
      expect(temporal.open).toBe(false);
      fireEvent.click(temporal.querySelector('summary')!);
      temporal.open = true;
      fireEvent(temporal, new Event('toggle'));
      expect(scroll).toHaveBeenCalledTimes(1);
      expect(scroll.mock.contexts[0]).toBe(temporal);
      expect(scroll).toHaveBeenCalledWith(expect.objectContaining({ block: 'nearest' }));
    } finally {
      Element.prototype.scrollIntoView = original;
    }
  });

  it("doesn't scroll a group that starts open or that the user closes", () => {
    const scroll = vi.fn();
    const original = Element.prototype.scrollIntoView;
    Element.prototype.scrollIntoView = scroll;
    try {
      render(<CvssInput defaultValue={V31} version="3.1" />);
      const base = group('Base');
      fireEvent(base, new Event('toggle'));
      fireEvent.click(base.querySelector('summary')!);
      base.open = false;
      fireEvent(base, new Event('toggle'));
      expect(scroll).not.toHaveBeenCalled();
    } finally {
      Element.prototype.scrollIntoView = original;
    }
  });
});
