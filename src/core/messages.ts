// Message catalogs: every text the components show, and every issue message.
import { VERSIONS } from './definitions';
import type {
  CvssIssue,
  CvssVersion,
  IssueCode,
  IssueParams,
  MetricGroup,
  Severity,
  VersionFamily,
} from './types';

/** Helpers a message function can use to format values in the catalog's language. */
export interface MessageFormat {
  /** A number in the catalog's locale, such as 1,024 or 1.024. */
  number(n: number): string;
  /** A score with one decimal, such as 9.8 or 9,8. */
  score(n: number): string;
  /** A metric's name, such as "Attack Vector". */
  metric(version: CvssVersion, key: string): string;
  /** A value's name, such as "Network". */
  value(version: CvssVersion, key: string, code: string): string;
  group(group: MetricGroup): string;
  /** A layer's display name: its label, or the base vector's name for `base`. */
  layer(id: string): string;
  /** Another issue's message, for issues that quote others. */
  issue(issue: CvssIssue): string;
}

/** Names of one version family's metrics and their values. */
export type MetricNames = Record<string, { name: string; values: Record<string, string> }>;

/** Every text the components show. */
export interface CvssMessages {
  /** BCP 47 language tag, such as `en` or `nl`. Sets number formatting and the `lang` attribute. */
  locale: string;
  severity: Record<Severity, string>;
  groups: Record<MetricGroup, string>;
  /** Name of the "Not Defined" value, used when a metric's own values don't list it. */
  notDefined: string;
  metrics: Record<VersionFamily, MetricNames>;
  issues: { [C in IssueCode]: (params: IssueParams[C], f: MessageFormat) => string };
  ui: {
    vectorLabel: string;
    overlayLabel: string;
    /** Default label of the layer a `CvssInput` edits. */
    thisInput: string;
    baseVector: string;
    version: string;
    versionUnknown: string;
    versionDetected: string;
    versionRequired: string;
    versionFromBase: string;
    alsoApplied: string;
    combined: string;
    error: string;
    note: string;
    goToPosition: (position: number) => string;
    position: (position: number) => string;
    treatAs: (version: string) => string;
    pickerUnavailable: string;
    pickerBlocked: string;
    /** The required metrics a vector still lacks, such as "Still to set: AC, PR.". */
    incomplete: (keys: string[]) => string;
    groupFromBase: string;
    contextValue: (layer: string, value: string, applied: boolean) => string;
    overriddenBy: (layer: string) => string;
    conflictsWithLayer: string;
    score: string;
    base: string;
    temporal: string;
    environmental: string;
    final: string;
    baseDetail: (impact: string, exploitability: string) => string;
    noTemporal: string;
    noEnvironmental: string;
    macroVector: (macroVector: string) => string;
    /** Screen reader summary when the vector has errors. `capped` means more than `count`. */
    statusProblems: (count: number, capped: boolean, first: string) => string;
    /** One score in the screen reader summary, such as "Base 9.8 Critical". */
    statusScore: (name: string, score: string, severity: string) => string;
    /** The final score in the screen reader summary. */
    statusFinal: (score: string, severity: string, group: string) => string;
    /** Joins the scores in the screen reader summary. */
    statusScores: (parts: string[]) => string;
    combinedScore: string;
    sources: string;
    sourcesMetric: string;
    sourcesValue: string;
    sourcesSource: string;
    conflict: string;
    overridden: string;
    seeErrorAbove: string;
  };
}

/** A catalog with any part left out; missing texts fall back to English. */
export type CvssMessagesInput = {
  [K in keyof CvssMessages]?: CvssMessages[K] extends string
    ? string
    : K extends 'metrics'
      ? { [F in VersionFamily]?: Record<string, { name?: string; values?: Record<string, string> }> }
      : Partial<CvssMessages[K]>;
};

const FAMILY: Record<CvssVersion, VersionFamily> = { '2.0': '2.0', '3.0': '3.x', '3.1': '3.x', '4.0': '4.0' };

function namesOf(version: CvssVersion): MetricNames {
  const notDefined = VERSIONS[version].notDefined;
  return Object.fromEntries(
    VERSIONS[version].metrics.map((m) => [
      m.key,
      {
        name: m.name,
        values: Object.fromEntries(m.values.filter((v) => v.code !== notDefined).map((v) => [v.code, v.name])),
      },
    ]),
  );
}

const list = (items: string[]) => items.join(', ');

/** English. The core uses it for `CvssIssue.message`. */
export const en: CvssMessages = {
  locale: 'en',
  severity: { None: 'None', Low: 'Low', Medium: 'Medium', High: 'High', Critical: 'Critical' },
  groups: {
    base: 'Base',
    temporal: 'Temporal',
    threat: 'Threat',
    environmental: 'Environmental',
    supplemental: 'Supplemental',
  },
  notDefined: 'Not Defined',
  metrics: { '2.0': namesOf('2.0'), '3.x': namesOf('3.1'), '4.0': namesOf('4.0') },
  issues: {
    EMPTY: () => 'Enter a CVSS vector.',
    UNKNOWN_PREFIX: (p) => `"${p.text}" isn't a supported CVSS version.`,
    NONSTANDARD_PREFIX: () => 'CVSS 2.0 vectors have no prefix. The prefix is removed on normalization.',
    MISSING_PREFIX: (p) => `The vector has no "${p.prefix}/" prefix.${p.strict ? '' : ' It is added on normalization.'}`,
    AMBIGUOUS_VERSION: () =>
      'This looks like a CVSS 3.x vector without a prefix. Add "CVSS:3.0/" or "CVSS:3.1/", or set the version.',
    UNDETECTABLE_VERSION: () => 'Can\'t determine the CVSS version. Add a prefix such as "CVSS:3.1/", or set the version.',
    VERSION_MISMATCH: (p) =>
      p.source === 'base'
        ? `The vector is CVSS ${p.found}, but the base vector is CVSS ${p.expected}.`
        : `The vector is CVSS ${p.found}, but CVSS ${p.expected} is required.`,
    MALFORMED_SEGMENT: (p) =>
      p.raw === '' ? 'The vector has an empty segment ("//").' : `"${p.raw}" isn't a "metric:value" pair.`,
    UNKNOWN_METRIC: (p) => `"${p.key}" isn't a CVSS ${p.version} metric.`,
    INVALID_VALUE: (p, f) =>
      `"${p.value}" isn't a valid value for ${p.key} (${f.metric(p.version, p.key)}). Valid values: ${list(p.valid)}.`,
    DUPLICATE_METRIC: (p) => `${p.key} appears more than once.`,
    MISSING_METRIC: (p, f) => `${p.key} (${f.metric(p.version, p.key)}) is missing.`,
    METRIC_ORDER: (p) =>
      p.strict
        ? `Metrics aren't in the order the CVSS ${p.version} specification defines.`
        : "Metrics aren't in canonical order. They're reordered on normalization.",
    BASE_METRIC_IN_OVERLAY: (p) => `"${p.key}" is a base metric. Base metrics come from the base vector.`,
    INVALID_BASE_VECTOR: (p, f) =>
      p.issues === null
        ? "The base vector is invalid, so the layers can't be combined."
        : `The base vector is invalid: ${p.issues.map(f.issue).join(' ') || 'unknown version.'}`,
    METRIC_CONFLICT: (p, f) =>
      p.kind === 'requirements'
        ? `${f.layer(p.layer)} sets ${p.key} in both its vector and its security requirements.`
        : `${p.key} is set to different values: ${list(p.values.map((v) => `${f.layer(v.layer)} ${p.key}:${v.value}`))}.`,
    METRIC_NOT_ALLOWED_IN_LAYER: (p, f) =>
      p.kind === 'metric'
        ? `${f.layer(p.layer)} may not set ${p.key}; it only accepts ${list(p.allowed)} metrics.`
        : `${f.layer(p.layer)} has security requirements but doesn't accept environmental metrics.`,
    MISSING_LAYER_VECTOR: (p, f) =>
      `${f.layer(p.layer)} has no CVSS ${p.family} metrics${p.hasRequirements ? '; only its security requirements apply' : ''}.`,
    INVALID_REQUIREMENTS: (p, f) => `${f.layer(p.layer)} has invalid security requirements. Use L, M, H, or X.`,
    DUPLICATE_LAYER_ID: (p) =>
      p.reserved ? '"base" is reserved for the base vector.' : `Layer ID "${p.layer}" is used more than once.`,
    INVALID_CONFLICT_RESOLUTION: (p) => `The conflict rule returned "${p.picked}" for ${p.key}, which no layer set.`,
    TOO_LONG: (p, f) => `The vector is ${f.number(p.length)} characters long; the maximum is ${f.number(p.max)}.`,
    TOO_MANY_ISSUES: (p, f) => `…and ${f.number(p.count)} more ${p.count === 1 ? 'problem' : 'problems'}.`,
  },
  ui: {
    vectorLabel: 'CVSS vector',
    overlayLabel: 'Temporal and environmental metrics',
    thisInput: 'This input',
    baseVector: 'Base vector',
    version: 'Version',
    versionUnknown: 'Version unknown',
    versionDetected: 'detected',
    versionRequired: 'required',
    versionFromBase: 'from base vector',
    alsoApplied: 'Also applied:',
    combined: 'Combined',
    error: 'Error',
    note: 'Note',
    goToPosition: (n) => `Go to position ${n}`,
    position: (n) => `(position ${n})`,
    treatAs: (v) => `Treat as CVSS ${v}`,
    pickerUnavailable: 'Enter a valid vector or set a version to use the metric picker.',
    pickerBlocked: 'Fix the errors in the vector to edit it with the picker.',
    incomplete: (keys) => `Still to set: ${keys.join(', ')}.`,
    groupFromBase: '(from base vector)',
    contextValue: (layer, value, applied) => `${layer}: ${value} (${applied ? 'applied' : 'not applied'})`,
    overriddenBy: (layer) => `Overridden by ${layer}.`,
    conflictsWithLayer: 'Conflicts with another layer.',
    score: 'Score',
    base: 'Base',
    temporal: 'Temporal',
    environmental: 'Environmental',
    final: 'Final',
    baseDetail: (impact, exploitability) => `Impact ${impact} · Exploitability ${exploitability}`,
    noTemporal: 'No temporal metrics set',
    noEnvironmental: 'No environmental metrics set',
    macroVector: (mv) => `MacroVector ${mv}`,
    statusProblems: (count, capped, first) =>
      `${capped ? `More than ${count} problems` : `${count} ${count === 1 ? 'problem' : 'problems'}`}. ${first}`,
    statusScore: (name, score, severity) => `${name} ${score} ${severity}`,
    statusFinal: (score, severity, group) => `Final ${score} ${severity} (${group}).`,
    statusScores: (parts) => `${parts.join(', ')}.`,
    combinedScore: 'Combined CVSS score',
    sources: 'Metric sources',
    sourcesMetric: 'Metric',
    sourcesValue: 'Value',
    sourcesSource: 'Source',
    conflict: 'Conflict',
    overridden: 'Overridden: ',
    seeErrorAbove: 'See the error above.',
  },
};

/** Fills in everything `input` leaves out from `base` (English by default). */
export function resolveMessages(input?: CvssMessagesInput | CvssMessages | null, base: CvssMessages = en): CvssMessages {
  if (!input) return base;
  const metrics = { ...base.metrics };
  for (const family of Object.keys(input.metrics ?? {}) as VersionFamily[]) {
    const merged: MetricNames = { ...metrics[family] };
    for (const [key, m] of Object.entries(input.metrics?.[family] ?? {})) {
      const prev = merged[key] ?? { name: key, values: {} };
      merged[key] = { name: m.name ?? prev.name, values: { ...prev.values, ...m.values } };
    }
    metrics[family] = merged;
  }
  return {
    locale: input.locale ?? base.locale,
    notDefined: input.notDefined ?? base.notDefined,
    severity: { ...base.severity, ...input.severity },
    groups: { ...base.groups, ...input.groups },
    metrics,
    issues: { ...base.issues, ...input.issues } as CvssMessages['issues'],
    ui: { ...base.ui, ...input.ui },
  };
}

const formatters = new Map<string, Intl.NumberFormat[]>();

function numberFormats(locale: string): Intl.NumberFormat[] {
  let f = formatters.get(locale);
  if (!f) {
    f = [
      new Intl.NumberFormat(locale),
      new Intl.NumberFormat(locale, { minimumFractionDigits: 1, maximumFractionDigits: 1 }),
    ];
    formatters.set(locale, f);
  }
  return f;
}

/**
 * Formatting helpers for a catalog. `layerLabel` names layers by ID; without it,
 * layers show their ID, and `base` shows the catalog's name for the base vector.
 */
export function messageFormat(messages: CvssMessages, layerLabel?: (id: string) => string | undefined): MessageFormat {
  const [plain, oneDecimal] = numberFormats(messages.locale);
  const names = (version: CvssVersion) => messages.metrics[FAMILY[version]];
  const f: MessageFormat = {
    number: (n) => plain.format(n),
    score: (n) => oneDecimal.format(n),
    metric: (version, key) => names(version)[key]?.name ?? key,
    value: (version, key, code) =>
      names(version)[key]?.values[code] ?? (code === VERSIONS[version].notDefined ? messages.notDefined : code),
    group: (g) => messages.groups[g],
    layer: (id) => layerLabel?.(id) ?? (id === 'base' ? messages.ui.baseVector : id),
    issue: (issue) => formatIssue(issue, messages, f),
  };
  return f;
}

/**
 * An issue's message in the catalog's language. Falls back to `issue.message`
 * for issues without parameters.
 */
export function formatIssue(issue: CvssIssue, messages: CvssMessages = en, format?: MessageFormat): string {
  if (!issue.params) return issue.message;
  const fn = messages.issues[issue.code] as (p: unknown, f: MessageFormat) => string;
  const labels = (issue.params as { labels?: Record<string, string> }).labels;
  return fn(issue.params, format ?? messageFormat(messages, (id) => labels?.[id]));
}

/** Builds an issue with its English message. */
export function makeIssue<C extends IssueCode>(
  code: C,
  params: IssueParams[C],
  rest: Omit<CvssIssue, 'code' | 'message' | 'params'>,
): CvssIssue {
  const issue = { ...rest, code, params, message: '' };
  issue.message = formatIssue(issue, en);
  return issue;
}
