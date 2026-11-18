import { VERSIONS, getMetricDef } from './definitions';
import { makeIssue } from './messages';
import { scoreV2, scoreV3 } from './score-classic';
import { scoreV4 } from './score-v4';
import type {
  CvssIssue,
  CvssResult,
  CvssScores,
  CvssVersion,
  EvaluateOptions,
} from './types';

interface Segment {
  key: string;
  value: string;
  raw: string;
  start: number;
  end: number;
}

interface Tokenized {
  /** Version named by the prefix, if any. */
  prefixVersion: CvssVersion | null;
  /** True if the prefix is a recognized but non-standard form, like `CVSS2#`. */
  nonstandardPrefix: { start: number; end: number } | null;
  unknownPrefix: { text: string; start: number; end: number } | null;
  segments: Segment[];
  malformed: Array<{ raw: string; start: number; end: number }>;
}

const PREFIX_RE = /^CVSS:(\d+\.\d+)$/;

/** Splits a vector into its prefix and `key:value` segments, keeping character offsets. */
export function tokenize(input: string): Tokenized {
  const out: Tokenized = {
    prefixVersion: null,
    nonstandardPrefix: null,
    unknownPrefix: null,
    segments: [],
    malformed: [],
  };

  // Trim whitespace and an optional pair of parentheses, as in `(AV:N/AC:L/...)`.
  let start = 0;
  let end = input.length;
  while (start < end && /\s/.test(input[start])) start++;
  while (end > start && /\s/.test(input[end - 1])) end--;
  if (input[start] === '(' && input[end - 1] === ')') {
    start++;
    end--;
  }
  // `CVSS2#AV:N/...` is an old NVD form of a 2.0 vector.
  if (input.startsWith('CVSS2#', start)) {
    out.prefixVersion = '2.0';
    out.nonstandardPrefix = { start, end: start + 'CVSS2#'.length };
    start += 'CVSS2#'.length;
  }

  let pos = start;
  let first = true;
  while (pos <= end) {
    let slash = input.indexOf('/', pos);
    if (slash === -1 || slash > end) slash = end;
    const raw = input.slice(pos, slash);
    const segStart = pos;
    pos = slash + 1;

    if (raw === '') {
      // Tolerate a trailing slash; flag empty segments elsewhere.
      if (slash !== end) out.malformed.push({ raw, start: segStart, end: slash });
      first = false;
      continue;
    }

    if (first && raw.startsWith('CVSS:')) {
      first = false;
      const match = PREFIX_RE.exec(raw);
      const version = match?.[1];
      if (version === '3.0' || version === '3.1' || version === '4.0') {
        out.prefixVersion = version;
      } else if (version === '2.0') {
        out.prefixVersion = '2.0';
        out.nonstandardPrefix = { start: segStart, end: slash };
      } else {
        out.unknownPrefix = { text: raw, start: segStart, end: slash };
      }
      continue;
    }
    first = false;

    const colon = raw.indexOf(':');
    if (colon <= 0 || colon === raw.length - 1 || raw.indexOf(':', colon + 1) !== -1) {
      out.malformed.push({ raw, start: segStart, end: slash });
      continue;
    }
    out.segments.push({
      key: raw.slice(0, colon),
      value: raw.slice(colon + 1),
      raw,
      start: segStart,
      end: slash,
    });
  }
  return out;
}

/**
 * Guesses the version of a vector from its prefix or, for unprefixed
 * vectors, from metrics unique to one version.
 * Returns `'3.x'` for an unprefixed 3.x vector, which is ambiguous.
 */
export function detectVersion(input: string): CvssVersion | '3.x' | null {
  if (input.length > DEFAULT_MAX_LENGTH) return null;
  const t = tokenize(input);
  if (t.prefixVersion) return t.prefixVersion;
  return detectFromKeys(t.segments.map((s) => s.key));
}

function detectFromKeys(keys: string[]): CvssVersion | '3.x' | null {
  const has = (k: string) => keys.includes(k);
  if (has('Au') || has('CDP') || has('TD')) return '2.0';
  if (['AT', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA', 'MAT', 'MVC'].some(has)) return '4.0';
  if (['PR', 'UI', 'S', 'MPR', 'MUI', 'MS'].some(has)) return '3.x';
  return null;
}

/** Serializes metrics in canonical order. */
export function serialize(
  version: CvssVersion,
  metrics: Record<string, string>,
  opts: { prefix?: boolean; groups?: 'all' | 'nonBase' } = {},
): string {
  const def = VERSIONS[version];
  const parts: string[] = [];
  if (opts.prefix !== false && def.prefix) parts.push(def.prefix);
  for (const m of def.metrics) {
    if (opts.groups === 'nonBase' && m.group === 'base') continue;
    const v = metrics[m.key];
    if (v !== undefined) parts.push(`${m.key}:${v}`);
  }
  return parts.join('/');
}

export function scoreFor(
  version: CvssVersion,
  metrics: Record<string, string>,
  options: { v2Method?: 'nvd' | 'spec' } = {},
): CvssScores {
  switch (version) {
    case '2.0':
      return scoreV2(metrics, options.v2Method);
    case '3.0':
    case '3.1':
      return scoreV3(metrics, version);
    case '4.0':
      return scoreV4(metrics);
  }
}

const isErr = (i: CvssIssue) => i.severity === 'error';

/** Default maximum input length. The longest valid vector is 178 characters (CVSS 4.0 with every metric set). */
export const DEFAULT_MAX_LENGTH = 1024;

/** Maximum number of issues reported per vector; the rest are summarized in one issue. */
export const MAX_ISSUES = 20;

/** The character range of a segment, for an issue. */
const at = (seg: { start: number; end: number }) => ({ start: seg.start, end: seg.end });

/** Keeps the first MAX_ISSUES issues and replaces the rest with one summary issue. */
export function capIssues(issues: CvssIssue[]): CvssIssue[] {
  if (issues.length <= MAX_ISSUES) return issues;
  const kept = issues.slice(0, MAX_ISSUES);
  const dropped = issues.slice(MAX_ISSUES);
  kept.push(
    makeIssue('TOO_MANY_ISSUES', { count: dropped.length }, { severity: dropped.some(isErr) ? 'error' : 'warning' }),
  );
  return kept;
}

/**
 * Parses, validates, normalizes, and scores a CVSS vector.
 *
 * @example
 * evaluate('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').scores
 * // { kind: 'classic', base: { score: 9.8, severity: 'Critical' }, ... }
 */
export function evaluate(input: string, options: EvaluateOptions = {}): CvssResult {
  return evaluateWithBase(input, options);
}

/**
 * `evaluate`, with the base vector already evaluated. Internal: callers that evaluate several
 * vectors against the same base pass `base` to avoid parsing and scoring it again. `base` must be
 * `evaluate(options.baseVector, { version, strict, maxLength, v2Method })` with the same options.
 */
export function evaluateWithBase(input: string, options: EvaluateOptions = {}, preBase?: CvssResult): CvssResult {
  const { version: mode = 'auto', strict = false, baseVector, maxLength = DEFAULT_MAX_LENGTH, v2Method } = options;
  const overlay = baseVector !== undefined;
  const issues: CvssIssue[] = [];

  const result = (partial: Partial<CvssResult>): CvssResult => ({
    input,
    version: null,
    detectedVersion: null,
    metrics: {},
    effectiveMetrics: {},
    normalized: null,
    combined: null,
    valid: false,
    scores: null,
    overlay,
    ...partial,
    issues: capIssues(issues),
  });

  // Reject oversized input before parsing, so it can't produce unbounded work or issues.
  if (input.length > maxLength) {
    issues.push(makeIssue('TOO_LONG', { length: input.length, max: maxLength }, { severity: 'error' }));
    return result({});
  }

  // In overlay mode, the base vector decides the version.
  let base: CvssResult | null = null;
  if (overlay) {
    base = preBase ?? evaluate(baseVector, { version: mode, strict, maxLength, v2Method });
    if (!base.valid || !base.version) {
      issues.push(makeIssue('INVALID_BASE_VECTOR', { issues: base.issues.filter(isErr) }, { severity: 'error' }));
      return result({});
    }
  }

  const t = tokenize(input);

  if (t.nonstandardPrefix) {
    issues.push(
      makeIssue('NONSTANDARD_PREFIX', {}, {
        severity: 'warning',
        start: t.nonstandardPrefix.start,
        end: t.nonstandardPrefix.end,
      }),
    );
  }

  if (t.segments.length === 0 && t.malformed.length === 0 && !t.unknownPrefix) {
    if (overlay && base) {
      // A prefix alone must still match the base vector's version.
      if (t.prefixVersion && t.prefixVersion !== base.version) {
        issues.push(
          makeIssue(
            'VERSION_MISMATCH',
            { found: t.prefixVersion, expected: base.version!, source: 'base' },
            { severity: 'error' },
          ),
        );
        return result({ version: base.version, detectedVersion: t.prefixVersion });
      }
      // An empty overlay is valid: the result is just the base vector.
      return result({
        version: base.version,
        detectedVersion: t.prefixVersion,
        effectiveMetrics: { ...base.metrics },
        normalized: '',
        combined: base.normalized,
        valid: true,
        scores: base.scores,
      });
    }
    issues.push(makeIssue('EMPTY', {}, { severity: 'error' }));
    return result({ detectedVersion: t.prefixVersion });
  }

  if (t.unknownPrefix) {
    issues.push(
      makeIssue(
        'UNKNOWN_PREFIX',
        { text: t.unknownPrefix.text },
        { severity: 'error', start: t.unknownPrefix.start, end: t.unknownPrefix.end },
      ),
    );
  }

  // --- Determine the version ----------------------------------------------
  const keyGuess = detectFromKeys(t.segments.map((s) => s.key));
  const detectedVersion: CvssVersion | null =
    t.prefixVersion ?? (keyGuess === '3.x' ? null : keyGuess);
  let version: CvssVersion | null = null;

  if (base?.version) {
    version = base.version;
    if (t.prefixVersion && t.prefixVersion !== version) {
      issues.push(
        makeIssue('VERSION_MISMATCH', { found: t.prefixVersion, expected: version, source: 'base' }, { severity: 'error' }),
      );
    }
  } else if (mode !== 'auto') {
    version = mode;
    if (t.prefixVersion && t.prefixVersion !== mode) {
      issues.push(
        makeIssue('VERSION_MISMATCH', { found: t.prefixVersion, expected: mode, source: 'forced' }, { severity: 'error' }),
      );
    } else if (!t.prefixVersion && VERSIONS[mode].prefix) {
      issues.push(
        makeIssue('MISSING_PREFIX', { prefix: VERSIONS[mode].prefix!, strict }, { severity: strict ? 'error' : 'warning' }),
      );
    }
  } else if (t.prefixVersion) {
    version = t.prefixVersion;
  } else if (keyGuess === '3.x') {
    issues.push(makeIssue('AMBIGUOUS_VERSION', {}, { severity: 'error' }));
  } else if (keyGuess) {
    version = keyGuess;
  } else if (!t.unknownPrefix) {
    issues.push(makeIssue('UNDETECTABLE_VERSION', {}, { severity: 'error' }));
  }

  for (const m of t.malformed) {
    issues.push(makeIssue('MALFORMED_SEGMENT', { raw: m.raw }, { severity: 'error', start: m.start, end: m.end }));
  }

  if (!version) {
    return result({ detectedVersion });
  }

  // --- Validate metrics ------------------------------------------------------
  const def = VERSIONS[version];
  const metrics: Record<string, string> = {};
  const order = def.metrics.map((m) => m.key);
  let lastIndex = -1;
  let outOfOrder = false;

  for (const seg of t.segments) {
    const mdef = getMetricDef(version, seg.key);
    if (!mdef) {
      issues.push(makeIssue('UNKNOWN_METRIC', { key: seg.key, version }, { severity: 'error', metric: seg.key, ...at(seg) }));
      continue;
    }
    if (overlay && mdef.group === 'base') {
      issues.push(makeIssue('BASE_METRIC_IN_OVERLAY', { key: seg.key }, { severity: 'error', metric: seg.key, ...at(seg) }));
      continue;
    }
    if (!mdef.values.some((v) => v.code === seg.value)) {
      issues.push(
        makeIssue(
          'INVALID_VALUE',
          { key: seg.key, value: seg.value, version, valid: mdef.values.map((v) => v.code) },
          { severity: 'error', metric: seg.key, ...at(seg) },
        ),
      );
      continue;
    }
    if (seg.key in metrics) {
      issues.push(makeIssue('DUPLICATE_METRIC', { key: seg.key }, { severity: 'error', metric: seg.key, ...at(seg) }));
      continue;
    }
    metrics[seg.key] = seg.value;
    const idx = order.indexOf(seg.key);
    if (idx < lastIndex) outOfOrder = true;
    lastIndex = Math.max(lastIndex, idx);
  }

  if (!overlay) {
    const missing = def.metrics.filter((m) => m.required && !(m.key in metrics));
    for (const m of missing) {
      issues.push(makeIssue('MISSING_METRIC', { key: m.key, version }, { severity: 'error', metric: m.key }));
    }
  }

  if (outOfOrder) {
    issues.push(makeIssue('METRIC_ORDER', { strict, version }, { severity: strict ? 'error' : 'warning' }));
  }

  const effectiveMetrics = base ? { ...base.metrics, ...metrics } : metrics;
  const valid = !issues.some(isErr);
  if (!valid) {
    return result({ version, detectedVersion, metrics, effectiveMetrics });
  }

  const normalized = overlay
    ? serialize(version, metrics, { prefix: false, groups: 'nonBase' })
    : serialize(version, metrics);
  return result({
    version,
    detectedVersion,
    metrics,
    effectiveMetrics,
    normalized,
    combined: serialize(version, effectiveMetrics),
    valid: true,
    scores: scoreFor(version, effectiveMetrics, { v2Method }),
  });
}
