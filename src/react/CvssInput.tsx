import { useCallback, useEffect, useId, useMemo, useState } from 'react';
import { ALL_VERSIONS, GROUP_LABELS, VERSIONS } from '../core/definitions';
import { DEFAULT_MAX_LENGTH, evaluate, serialize } from '../core/evaluate';
import { evaluateLayers } from '../core/layers';
import type {
  ConflictRule,
  CvssIssue,
  CvssLayer,
  CvssResult,
  CvssScores,
  CvssVersion,
  IssueCode,
  LayeredResult,
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
  /**
   * Called on every edit with the new vector, its own evaluation, and, when
   * `baseVector` or `layers` is set, the combined evaluation.
   */
  onChange?: (value: string, result: CvssResult, layered: LayeredResult | null) => void;
  /** `auto` (default) detects the version; any other value forces and validates it. */
  version?: VersionMode;
  /**
   * A complete vector that supplies the base metrics. The input then edits one
   * layer (see `layerId`) instead of the base vector.
   */
  baseVector?: string;
  /**
   * Other layers, such as a threat feed or an asset, shown as read-only context
   * and included in the score. Without `baseVector`, the input edits the base
   * vector and these layers apply on top of it.
   */
  layers?: CvssLayer[];
  /**
   * ID of the layer the input edits when `baseVector` is set. If `layers` has an
   * entry with this ID, the input supplies its vector and the entry supplies its
   * position, label, groups, and requirements. Otherwise the input is the last
   * layer. Default: `input`.
   */
  layerId?: string;
  /** How to resolve layers that set the same metric. Default: `error`. */
  conflict?: ConflictRule;
  /** Treat non-canonical order and a missing 3.x/4.0 prefix as errors. Default: false. */
  strict?: boolean;
  /**
   * Maximum vector length. The text field won't accept more, and longer values
   * (for example from `value`) are rejected unparsed. Default: 1024.
   */
  maxLength?: number;
  /** CVSS 2.0 temporal and environmental method: `nvd` (default) or `spec`. */
  v2Method?: 'nvd' | 'spec';
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

/** Layer issues that `evaluate` alone doesn't produce for the edited layer. */
const LAYER_ONLY: IssueCode[] = ['METRIC_NOT_ALLOWED_IN_LAYER', 'METRIC_CONFLICT', 'DUPLICATE_LAYER_ID'];

interface Evaluation {
  own: CvssResult;
  layered: LayeredResult | null;
}

function buildLayers(
  text: string,
  baseVector: string | undefined,
  layers: CvssLayer[] | undefined,
  layerId: string,
): { base: string; layers: CvssLayer[] } | null {
  if (baseVector === undefined && layers === undefined) return null;
  if (baseVector === undefined) return { base: text, layers: layers ?? [] };
  const list = layers ?? [];
  const index = list.findIndex((l) => l.id === layerId);
  const own: CvssLayer =
    index >= 0 ? { ...list[index], vector: text } : { id: layerId, label: 'This input', vector: text };
  return {
    base: baseVector,
    layers: index >= 0 ? list.map((l, n) => (n === index ? own : l)) : [...list, own],
  };
}

function evaluateAll(
  text: string,
  opts: {
    version: VersionMode;
    strict: boolean;
    baseVector?: string;
    layers?: CvssLayer[];
    layerId: string;
    conflict?: ConflictRule;
    maxLength: number;
    v2Method?: 'nvd' | 'spec';
  },
): Evaluation {
  const own = evaluate(text, {
    version: opts.version,
    strict: opts.strict,
    baseVector: opts.baseVector,
    maxLength: opts.maxLength,
    v2Method: opts.v2Method,
  });
  const built = buildLayers(text, opts.baseVector, opts.layers, opts.layerId);
  const layered = built
    ? evaluateLayers(built.base, built.layers, {
        version: opts.version,
        strict: opts.strict,
        conflict: opts.conflict,
        maxLength: opts.maxLength,
        v2Method: opts.v2Method,
      })
    : null;
  return { own, layered };
}

export function CvssInput({
  value,
  defaultValue = '',
  onChange,
  version = 'auto',
  baseVector,
  layers,
  layerId = 'input',
  conflict,
  strict = false,
  maxLength = DEFAULT_MAX_LENGTH,
  v2Method,
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

  const overlay = baseVector !== undefined;
  const layersKey = JSON.stringify(layers ?? null);
  const evalOpts = { version, strict, baseVector, layers, layerId, conflict, maxLength, v2Method };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const { own: result, layered } = useMemo(() => evaluateAll(text, evalOpts), [text, version, strict, baseVector, layersKey, layerId, conflict, maxLength, v2Method]);
  const base = useCvss(baseVector ?? '', { version, strict, maxLength, v2Method });

  const emit = useCallback(
    (next: string) => {
      if (!controlled) setInternal(next);
      if (onChange) {
        const e = evaluateAll(next, evalOpts);
        onChange(next, e.own, e.layered);
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [controlled, onChange, version, strict, baseVector, layersKey, layerId, conflict, maxLength, v2Method],
  );

  const [emptyVersion, setEmptyVersion] = useState<CvssVersion>(defaultPickerVersion);
  const isEmpty = text.trim() === '';
  const pickerVersion: CvssVersion | null =
    result.version ?? (overlay ? null : version !== 'auto' ? version : isEmpty ? emptyVersion : null);
  const structural = result.issues.filter((i) => STRUCTURAL.includes(i.code));
  const pickerBlocked = !isEmpty && structural.length > 0;

  // The layer config for the edited layer, if any.
  const ownLayerId = overlay ? layerId : 'base';
  const ownLayer = overlay ? layers?.find((l) => l.id === layerId) : undefined;

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

  // Issues: the input's own, plus layer issues from the combination.
  const labels = useMemo(() => {
    const map: Record<string, string> = { base: 'Base vector' };
    for (const l of layered?.layers ?? []) map[l.id] = l.label;
    return map;
  }, [layered]);
  const shownIssues: CvssIssue[] = [...result.issues];
  if (layered) {
    for (const issue of layered.issues) {
      if (issue.code === 'INVALID_BASE_VECTOR') continue;
      if (issue.layer === 'base') continue;
      if (issue.layer === ownLayerId && !LAYER_ONLY.includes(issue.code)) continue;
      shownIssues.push(issue);
    }
  }

  const id = useId();
  const inputId = `${id}-vector`;
  const issuesId = `${id}-issues`;
  // Only the input's own problems mark the field invalid, not other layers' conflicts.
  const errors = shownIssues.filter(
    (i) => i.severity === 'error' && (result.issues.includes(i) || i.layer === ownLayerId),
  );
  const showIssues = !isEmpty || overlay;

  // Picker context: values other layers set for each metric.
  const context = useMemo(() => {
    if (!layered) return null;
    const map: Record<string, PickerContext[]> = {};
    for (const l of layered.layers.filter((o) => o.id !== ownLayerId)) {
      for (const [key, v] of Object.entries(l.metrics)) {
        (map[key] ??= []).push({ label: l.label, value: v, applied: layered.provenance[key] === l.id });
      }
    }
    if (overlay) {
      // The base vector's own non-base metrics.
      for (const [key, v] of Object.entries(layered.base.metrics)) {
        const group = VERSIONS[layered.base.version!]?.metrics.find((m) => m.key === key)?.group;
        if (group === 'base' || v === VERSIONS[layered.base.version!].notDefined) continue;
        (map[key] ??= []).push({ label: 'Base vector', value: v, applied: layered.provenance[key] === 'base' });
      }
    }
    const labelOf = (layer: string) => (layer === 'base' ? 'Base vector' : labels[layer] ?? layer);
    return { map, ownId: ownLayerId, provenance: layered.provenance, labelOf };
  }, [layered, overlay, ownLayerId, labels]);

  const scores = layered ? layered.scores : result.scores;
  const contextLayers = layered ? layered.layers.filter((l) => l.id !== ownLayerId) : [];

  return (
    <div className={['cvss', className].filter(Boolean).join(' ')} data-disabled={disabled || undefined}>
      {mode !== 'picker' && (
        <div className="cvss-field">
          <label className="cvss-label" htmlFor={inputId}>
            {label ?? (overlay ? (ownLayer?.label ?? 'Temporal and environmental metrics') : 'CVSS vector')}
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
            maxLength={maxLength}
            placeholder={placeholderFor(pickerVersion ?? defaultPickerVersion, overlay)}
            aria-invalid={showIssues && errors.length > 0}
            aria-describedby={issuesId}
            onChange={(e) => emit(e.target.value)}
            onBlur={handleBlur}
          />
        </div>
      )}

      <VersionLine result={result} mode={version} overlay={overlay} baseResult={overlay ? base : null} />

      {contextLayers.length > 0 && (
        <div className="cvss-meta">
          <span>Also applied:</span>
          {contextLayers.map((l) => (
            <span key={l.id} className="cvss-layer-chip">
              {l.label}
            </span>
          ))}
        </div>
      )}

      {/* Not a live region: it changes on every keystroke. The status below summarizes instead. */}
      <ul id={issuesId} className="cvss-issues">
        {showIssues &&
          shownIssues.map((issue, n) => (
            <IssueItem
              key={n}
              issue={issue}
              input={text}
              layerLabel={issue.layer && issue.layer !== ownLayerId ? labels[issue.layer] : undefined}
            />
          ))}
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

      <ScorePanel scores={scores} />
      <Announcer message={isEmpty && !overlay ? '' : statusMessage(scores, shownIssues)} />

      {layered?.combined && contextLayers.length > 0 && (
        <div className="cvss-meta">
          <span>Combined</span>
          <code className="cvss-base-vector">{layered.combined}</code>
        </div>
      )}

      {mode !== 'text' && (
        <MetricPicker
          version={pickerVersion}
          metrics={result.metrics}
          baseMetrics={overlay ? base.metrics : null}
          blocked={pickerBlocked}
          disabled={disabled || readOnly}
          onSelect={setMetric}
          allowedGroups={ownLayer?.groups ?? null}
          context={context}
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

function IssueItem({ issue, input, layerLabel }: { issue: CvssIssue; input: string; layerLabel?: string }) {
  const hasRange = !layerLabel && issue.start !== undefined && issue.end !== undefined && input.length >= issue.end;
  return (
    <li className="cvss-issue" data-severity={issue.severity}>
      <span className="cvss-issue-kind">{issue.severity === 'error' ? 'Error' : 'Note'}</span>
      <span>
        {layerLabel && <strong>{layerLabel}: </strong>}
        {issue.message}
        {hasRange && (
          <>
            {' '}
            <span className="cvss-issue-pos">(position {issue.start! + 1})</span>
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
  const final = scores.overall.group;
  return (
    <div className="cvss-scores">
      <ScoreCell
        title="Base"
        value={scores.base}
        final={final === 'base'}
        detail={`Impact ${scores.impact.toFixed(1)} · Exploitability ${scores.exploitability.toFixed(1)}`}
      />
      <ScoreCell
        title="Temporal"
        value={scores.temporal}
        final={final === 'temporal'}
        muted={!scores.temporalDefined}
        detail={scores.temporalDefined ? undefined : 'No temporal metrics set'}
      />
      <ScoreCell
        title="Environmental"
        value={scores.environmental}
        final={final === 'environmental'}
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
  final,
}: {
  title: string;
  value: ScoreValue | null;
  detail?: string;
  muted?: boolean;
  /** Marks the cell holding the final score, when several scores are shown. */
  final?: boolean;
}) {
  return (
    <div className="cvss-score" data-muted={muted || undefined} data-final={final || undefined}>
      <div className="cvss-score-title">
        {title}
        {final && <span className="cvss-final-badge">Final</span>}
      </div>
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

export interface PickerContext {
  label: string;
  value: string;
  /** True if this layer's value is the one in the combined vector. */
  applied: boolean;
}

const GROUP_ORDER: MetricGroup[] = ['base', 'temporal', 'threat', 'environmental', 'supplemental'];

export function MetricPicker({
  version,
  metrics,
  baseMetrics,
  blocked,
  disabled,
  onSelect,
  versionChoice,
  allowedGroups = null,
  context = null,
}: {
  version: CvssVersion | null;
  metrics: Record<string, string>;
  /** In overlay mode, the base vector's metrics, shown read-only. */
  baseMetrics: Record<string, string> | null;
  blocked: boolean;
  disabled: boolean;
  onSelect: (key: string, code: string) => void;
  versionChoice: { value: CvssVersion; onChange: (v: CvssVersion) => void } | null;
  /** Groups the edited layer may set; others are hidden. Null shows all. */
  allowedGroups?: MetricGroup[] | null;
  /** Values that other layers set, shown under each metric. */
  context?: {
    map: Record<string, PickerContext[]>;
    ownId: string;
    provenance: Record<string, string>;
    labelOf: (layer: string) => string;
  } | null;
}) {
  const id = useId();
  const groups = useMemo(() => {
    if (!version) return [];
    const def = VERSIONS[version];
    return GROUP_ORDER.filter((g) => g === 'base' || !allowedGroups || allowedGroups.includes(g))
      .map((g) => ({ group: g, metrics: def.metrics.filter((m) => m.group === g) }))
      .filter((g) => g.metrics.length > 0);
  }, [version, allowedGroups]);

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
        const anySet = groupMetrics.some(
          (m) =>
            (source[m.key] !== undefined && source[m.key] !== def.notDefined) ||
            (context?.map[m.key]?.length ?? 0) > 0,
        );
        return (
          <details
            key={group}
            className="cvss-group"
            open={!readOnlyGroup && (group === 'base' || anySet) ? true : undefined}
          >
            <summary>
              {GROUP_LABELS[group]}
              {readOnlyGroup && <span className="cvss-group-note"> (from base vector)</span>}
            </summary>
            <div className="cvss-metrics">
              {groupMetrics.map((m) => {
                const current = source[m.key] ?? (m.required ? undefined : def.notDefined ?? undefined);
                const others = readOnlyGroup ? [] : (context?.map[m.key] ?? []);
                const ownSet = !readOnlyGroup && metrics[m.key] !== undefined && metrics[m.key] !== def.notDefined;
                const winner = context?.provenance[m.key];
                let ownNote: string | null = null;
                if (ownSet && others.length > 0 && context && winner !== context.ownId) {
                  ownNote = winner
                    ? `Overridden by ${context.labelOf(winner)}.`
                    : 'Conflicts with another layer.';
                }
                return (
                  <fieldset
                    key={m.key}
                    className="cvss-metric"
                    disabled={disabled || blocked || readOnlyGroup}
                    aria-describedby={others.length > 0 ? `${id}-${m.key}-context` : undefined}
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
                    {others.length > 0 && (
                      <div className="cvss-context" id={`${id}-${m.key}-context`}>
                        {others.map((o) => (
                          <span key={o.label} className="cvss-context-item" data-applied={o.applied || undefined}>
                            {o.label}: {m.values.find((v) => v.code === o.value)?.name ?? o.value}
                            {o.applied ? ' (applied)' : ' (not applied)'}
                          </span>
                        ))}
                        {ownNote && (
                          <span className="cvss-context-item" data-warning>
                            {ownNote}
                          </span>
                        )}
                      </div>
                    )}
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

// ---------------------------------------------------------------------------

/** One-line summary for screen readers: the scores, or the number of problems. */
export function statusMessage(scores: CvssScores | null, issues: CvssIssue[]): string {
  const errors = issues.filter((i) => i.severity === 'error');
  if (errors.length > 0) {
    const count = errors.some((i) => i.code === 'TOO_MANY_ISSUES') ? 'More than 20 problems' : `${errors.length} ${errors.length === 1 ? 'problem' : 'problems'}`;
    return `${count}. ${errors[0].message}`;
  }
  if (!scores) return '';
  const fmt = (v: ScoreValue) => `${v.score.toFixed(1)} ${v.severity}`;
  if (scores.kind === 'v4') return `${scores.nomenclature} ${fmt(scores.score)}.`;
  const names = { base: 'Base', temporal: 'Temporal', threat: 'Threat', environmental: 'Environmental' };
  const parts = [`Base ${fmt(scores.base)}`];
  if (scores.temporalDefined) parts.push(`Temporal ${fmt(scores.temporal)}`);
  if (scores.environmentalDefined) parts.push(`Environmental ${fmt(scores.environmental)}`);
  const final = `Final ${fmt(scores.overall)} (${names[scores.overall.group]}).`;
  return parts.length === 1 ? final : `${final} ${parts.join(', ')}.`;
}

/**
 * Announces a message politely once it has been stable for a moment, so screen
 * readers hear the result after typing pauses instead of on every keystroke.
 */
function Announcer({ message, delay = 800 }: { message: string; delay?: number }) {
  const [spoken, setSpoken] = useState('');
  useEffect(() => {
    const timer = setTimeout(() => setSpoken(message), delay);
    return () => clearTimeout(timer);
  }, [message, delay]);
  return (
    <div className="cvss-sr-only" role="status" aria-live="polite" aria-atomic="true">
      {spoken}
    </div>
  );
}
