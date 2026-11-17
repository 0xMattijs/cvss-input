import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { CvssInput } from '../src';

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
    expect(onChange).toHaveBeenLastCalledWith(V31 + '/E:F/RC:C', expect.objectContaining({ valid: true }));
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
    expect(onChange).toHaveBeenCalledWith(V31 + '/E:U', expect.anything());
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
