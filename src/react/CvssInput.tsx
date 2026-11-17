import { useCallback, useId, useMemo, useState } from 'react';
import { ALL_VERSIONS, GROUP_LABELS, VERSIONS } from '../core/definitions';
import { evaluate, serialize } from '../core/evaluate';
import type {
  CvssIssue,
  CvssResult,
  CvssScores,
  CvssVersion,
  IssueCode,
  MetricGroup,
  ScoreValue,
  VersionMode,
} from '../core/types';
import { useCvss } from './useCvss';

export interface CvssInputProps {
  /** Vector string (controlled). */
  value?: string;
  /** Initial vector string (uncontrolled). */
  defaultValue?: string;
  /** Called with the new vector and its evaluation on every edit. */
  onChange?: (value: string, result: CvssResult) => void;
  /** `auto` (default) detects the version; any other value forces and validates it. */
  version?: VersionMode;
  /**
   * A complete vector that supplies the base metrics. The input then holds only
   * temporal, threat, environmental, and supplemental metrics.
   */
  baseVector?: string;
  /** Treat non-canonical order and a missing 3.x/4.0 prefix as errors. Default: false. */
  strict?: boolean;
  /** Rewrite the vector in canonical form when the text field loses focus. Default: `!strict`. */
  normalizeOnBlur?: boolean;
  /** Which editors to show. Default: `both`. */
  mode?: 'text' | 'picker' | 'both';
  /** Version the picker uses for an empty vector in auto mode. Default: `4.0`. */
  defaultPickerVersion?: CvssVersion;
  readOnly?: boolean;
  disabled?: boolean;
  /** Label for the text field. */
  label?: string;
  className?: string;
}

/** Issue codes that mean the text can't be mapped to picker state safely. */
const STRUCTURAL: IssueCode[] = [
  'UNKNOWN_PREFIX',
  'AMBIGUOUS_VERSION',
  'UNDETECTABLE_VERSION',
  'VERSION_MISMATCH',
  'MALFORMED_SEGMENT',
  'UNKNOWN_METRIC',
  'INVALID_VALUE',
  'DUPLICATE_METRIC',
  'BASE_METRIC_IN_OVERLAY',
  'INVALID_BASE_VECTOR',
];

export function CvssInput({
  value,
  defaultValue = '',
  onChange,
  version = 'auto',
  baseVector,
  strict = false,
  normalizeOnBlur = !strict,
  mode = 'both',
  defaultPickerVersion = '4.0',
  readOnly = false,
  disabled = false,
  label,
  className,
}: CvssInputProps) {
  const [internal, setInternal] = useState(defaultValue);
  const controlled = value !== undefined;
  const text = controlled ? value : internal;

  const result = useCvss(text, { version, strict, baseVector });
  const base = useCvss(baseVector ?? '', { version, strict });
  const overlay = baseVector !== undefined;

  const emit = useCallback(
    (next: string) => {
      if (!controlled) setInternal(next);
      onChange?.(next, evaluate(next, { version, strict, baseVector }));
    },
    [controlled, onChange, version, strict, baseVector],
  );

  const [emptyVersion, setEmptyVersion] = useState<CvssVersion>(defaultPickerVersion);
  const isEmpty = text.trim() === '';
  const pickerVersion: CvssVersion | null =
    result.version ?? (overlay ? null : version !== 'auto' ? version : isEmpty ? emptyVersion : null);
  const structural = result.issues.filter((i) => STRUCTURAL.includes(i.code));
  const pickerBlocked = !isEmpty && structural.length > 0;

  const setMetric = (key: string, code: string) => {
    if (!pickerVersion) return;
    const def = VERSIONS[pickerVersion];
    const metrics = { ...result.metrics };
    if (code === def.notDefined) delete metrics[key];
    else metrics[key] = code;
    emit(
      overlay
        ? serialize(pickerVersion, metrics, { prefix: false, groups: 'nonBase' })
        : serialize(pickerVersion, metrics),
    );
  };

  const handleBlur = () => {
    if (normalizeOnBlur && !readOnly && result.valid && result.normalized !== null && result.normalized !== text) {
      emit(result.normalized);
    }
  };

  const id = useId();
  const inputId = `${id}-vector`;
  const issuesId = `${id}-issues`;
  const errors = result.issues.filter((i) => i.severity === 'error');
  const showIssues = !isEmpty || overlay;

  return (
    <div className={['cvss', className].filter(Boolean).join(' ')} data-disabled={disabled || undefined}>
      {mode !== 'picker' && (
        <div className="cvss-field">
          <label className="cvss-label" htmlFor={inputId}>
            {label ?? (overlay ? 'Temporal and environmental metrics' : 'CVSS vector')}
          </label>
          <input
            id={inputId}
            className="cvss-text"
            type="text"
            value={text}
            spellCheck={false}
            autoComplete="off"
            autoCapitalize="off"
            readOnly={readOnly}
            disabled={disabled}
            placeholder={placeholderFor(pickerVersion ?? defaultPickerVersion, overlay)}
            aria-invalid={showIssues && errors.length > 0}
            aria-describedby={issuesId}
            onChange={(e) => emit(e.target.value)}
            onBlur={handleBlur}
          />
        </div>
      )}

      <VersionLine result={result} mode={version} overlay={overlay} baseResult={overlay ? base : null} />

      <ul id={issuesId} className="cvss-issues" aria-live="polite">
        {showIssues &&
          result.issues.map((issue, n) => <IssueItem key={n} issue={issue} input={text} />)}
      </ul>

      {!readOnly && !disabled && result.issues.some((i) => i.code === 'AMBIGUOUS_VERSION') && (
        <div className="cvss-fixes">
          {(['3.1', '3.0'] as const).map((v) => (
            <button key={v} type="button" className="cvss-fix" onClick={() => emit(`CVSS:${v}/${text.trim()}`)}>
              Treat as CVSS {v}
            </button>
          ))}
        </div>
      )}

      <ScorePanel scores={result.scores} />

      {mode !== 'text' && (
        <MetricPicker
          version={pickerVersion}
          metrics={result.metrics}
          baseMetrics={overlay ? base.metrics : null}
          blocked={pickerBlocked}
          disabled={disabled || readOnly}
          onSelect={setMetric}
          versionChoice={
            !overlay && version === 'auto' && isEmpty
              ? { value: emptyVersion, onChange: setEmptyVersion }
              : null
          }
        />
      )}
    </div>
  );
}

function placeholderFor(version: CvssVersion, overlay: boolean): string {
  if (overlay) {
    return { '2.0': 'E:F/RL:OF/RC:C', '3.0': 'E:F/RL:O/RC:C', '3.1': 'E:F/RL:O/RC:C', '4.0': 'E:P' }[version];
  }
  return {
    '2.0': 'AV:N/AC:L/Au:N/C:P/I:P/A:P',
    '3.0': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    '3.1': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    '4.0': 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
  }[version];
}

// ---------------------------------------------------------------------------

function VersionLine({
  result,
  mode,
  overlay,
  baseResult,
}: {
  result: CvssResult;
  mode: VersionMode;
  overlay: boolean;
  baseResult: CvssResult | null;
}) {
  const v = result.version ?? baseResult?.version ?? null;
  let how: string;
  if (overlay) how = 'from base vector';
  else if (mode === 'auto') how = 'detected';
  else how = 'required';
  return (
    <div className="cvss-meta">
      <span className="cvss-version" data-empty={!v || undefined}>
        {v ? `CVSS ${v}` : 'Version unknown'}
      </span>
      {v && <span className="cvss-version-how">{how}</span>}
      {overlay && baseResult?.normalized && (
        <code className="cvss-base-vector" title="Base vector">
          {baseResult.normalized}
        </code>
      )}
    </div>
  );
}

function IssueItem({ issue, input }: { issue: CvssIssue; input: string }) {
  const excerpt = issue.start !== undefined && issue.end !== undefined ? input.slice(issue.start, issue.end) : null;
  return (
    <li className="cvss-issue" data-severity={issue.severity}>
      <span className="cvss-issue-kind">{issue.severity === 'error' ? 'Error' : 'Note'}</span>
      <span>
        {issue.message}
        {excerpt && issue.start !== undefined && (
          <>
            {' '}
            <span className="cvss-issue-pos">(position {issue.start + 1})</span>
          </>
        )}
      </span>
    </li>
  );
}

// ---------------------------------------------------------------------------

export function ScorePanel({ scores }: { scores: CvssScores | null }) {
  if (!scores) {
    return (
      <div className="cvss-scores" data-empty>
        <ScoreCell title="Score" value={null} />
      </div>
    );
  }
  if (scores.kind === 'v4') {
    return (
      <div className="cvss-scores">
        <ScoreCell
          title={scores.nomenclature}
          value={scores.score}
          detail={`MacroVector ${scores.macroVector}`}
        />
      </div>
    );
  }
  return (
    <div className="cvss-scores">
      <ScoreCell
        title="Base"
        value={scores.base}
        detail={`Impact ${scores.impact.toFixed(1)} · Exploitability ${scores.exploitability.toFixed(1)}`}
      />
      <ScoreCell
        title="Temporal"
        value={scores.temporal}
        muted={!scores.temporalDefined}
        detail={scores.temporalDefined ? undefined : 'No temporal metrics set'}
      />
      <ScoreCell
        title="Environmental"
        value={scores.environmental}
        muted={!scores.environmentalDefined}
        detail={scores.environmentalDefined ? undefined : 'No environmental metrics set'}
      />
    </div>
  );
}

function ScoreCell({
  title,
  value,
  detail,
  muted,
}: {
  title: string;
  value: ScoreValue | null;
  detail?: string;
  muted?: boolean;
}) {
  return (
    <div className="cvss-score" data-muted={muted || undefined}>
      <div className="cvss-score-title">{title}</div>
      <div className="cvss-score-row">
        <span className="cvss-score-number">{value ? value.score.toFixed(1) : '—'}</span>
        {value && (
          <span className="cvss-severity" data-severity={value.severity.toLowerCase()}>
            {value.severity}
          </span>
        )}
      </div>
      {detail && <div className="cvss-score-detail">{detail}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------------

const GROUP_ORDER: MetricGroup[] = ['base', 'temporal', 'threat', 'environmental', 'supplemental'];

export function MetricPicker({
  version,
  metrics,
  baseMetrics,
  blocked,
  disabled,
  onSelect,
  versionChoice,
}: {
  version: CvssVersion | null;
  metrics: Record<string, string>;
  /** In overlay mode, the base vector's metrics, shown read-only. */
  baseMetrics: Record<string, string> | null;
  blocked: boolean;
  disabled: boolean;
  onSelect: (key: string, code: string) => void;
  versionChoice: { value: CvssVersion; onChange: (v: CvssVersion) => void } | null;
}) {
  const id = useId();
  const groups = useMemo(() => {
    if (!version) return [];
    const def = VERSIONS[version];
    return GROUP_ORDER.map((g) => ({ group: g, metrics: def.metrics.filter((m) => m.group === g) })).filter(
      (g) => g.metrics.length > 0,
    );
  }, [version]);

  if (!version) {
    return (
      <div className="cvss-picker" data-blocked>
        <p className="cvss-picker-note">Enter a valid vector or set a version to use the metric picker.</p>
      </div>
    );
  }

  const def = VERSIONS[version];

  return (
    <div className="cvss-picker" data-blocked={blocked || undefined}>
      {versionChoice && (
        <div className="cvss-picker-version">
          <label htmlFor={`${id}-version`}>Version</label>
          <select
            id={`${id}-version`}
            value={versionChoice.value}
            disabled={disabled}
            onChange={(e) => versionChoice.onChange(e.target.value as CvssVersion)}
          >
            {ALL_VERSIONS.map((v) => (
              <option key={v} value={v}>
                CVSS {v}
              </option>
            ))}
          </select>
        </div>
      )}
      {blocked && (
        <p className="cvss-picker-note">Fix the errors in the vector to edit it with the picker.</p>
      )}
      {groups.map(({ group, metrics: groupMetrics }) => {
        const readOnlyGroup = baseMetrics !== null && group === 'base';
        const source = readOnlyGroup ? baseMetrics : metrics;
        const anySet = groupMetrics.some((m) => source[m.key] !== undefined && source[m.key] !== def.notDefined);
        return (
          <details
            key={group}
            className="cvss-group"
            open={!readOnlyGroup && (group === 'base' || anySet) ? true : undefined}
          >
            <summary>
              {GROUP_LABELS[group]}
              {readOnlyGroup && <span className="cvss-group-note">from base vector</span>}
            </summary>
            <div className="cvss-metrics">
              {groupMetrics.map((m) => {
                const current = source[m.key] ?? (m.required ? undefined : def.notDefined ?? undefined);
                return (
                  <fieldset
                    key={m.key}
                    className="cvss-metric"
                    disabled={disabled || blocked || readOnlyGroup}
                  >
                    <legend>
                      {m.name} <abbr className="cvss-metric-key">{m.key}</abbr>
                    </legend>
                    <div className="cvss-options">
                      {m.values.map((v) => (
                        <label key={v.code} className="cvss-option" title={`${m.key}:${v.code}`}>
                          <input
                            type="radio"
                            name={`${id}-${m.key}`}
                            value={v.code}
                            checked={current === v.code}
                            onChange={() => onSelect(m.key, v.code)}
                          />
                          <span>{v.name}</span>
                        </label>
                      ))}
                    </div>
                  </fieldset>
                );
              })}
            </div>
          </details>
        );
      })}
    </div>
  );
}
