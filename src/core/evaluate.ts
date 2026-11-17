import { VERSIONS, getMetricDef } from './definitions';
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
  nonstandardPrefix: boolean;
  unknownPrefix: { text: string; start: number; end: number } | null;
  segments: Segment[];
  malformed: Array<{ raw: string; start: number; end: number }>;
}

const PREFIX_RE = /^CVSS:(\d+\.\d+)$/;

/** Splits a vector into its prefix and `key:value` segments, keeping character offsets. */
export function tokenize(input: string): Tokenized {
  const out: Tokenized = {
    prefixVersion: null,
    nonstandardPrefix: false,
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
    out.nonstandardPrefix = true;
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
        out.nonstandardPrefix = true;
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

function scoreFor(version: CvssVersion, metrics: Record<string, string>): CvssScores {
  switch (version) {
    case '2.0':
      return scoreV2(metrics);
    case '3.0':
    case '3.1':
      return scoreV3(metrics, version);
    case '4.0':
      return scoreV4(metrics);
  }
}

const isErr = (i: CvssIssue) => i.severity === 'error';

/**
 * Parses, validates, normalizes, and scores a CVSS vector.
 *
 * @example
 * evaluate('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').scores
 * // { kind: 'classic', base: { score: 9.8, severity: 'Critical' }, ... }
 */
export function evaluate(input: string, options: EvaluateOptions = {}): CvssResult {
  const { version: mode = 'auto', strict = false, baseVector } = options;
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
    issues,
    valid: false,
    scores: null,
    overlay,
    ...partial,
  });

  // In overlay mode, the base vector decides the version.
  let base: CvssResult | null = null;
  if (overlay) {
    base = evaluate(baseVector, { version: mode, strict });
    if (!base.valid || !base.version) {
      issues.push({
        severity: 'error',
        code: 'INVALID_BASE_VECTOR',
        message: `The base vector is invalid: ${base.issues.filter(isErr).map((i) => i.message).join(' ') || 'unknown version.'}`,
      });
      return result({});
    }
  }

  const t = tokenize(input);

  if (t.segments.length === 0 && t.malformed.length === 0 && !t.unknownPrefix) {
    if (overlay && base) {
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
    issues.push({ severity: 'error', code: 'EMPTY', message: 'Enter a CVSS vector.' });
    return result({ detectedVersion: t.prefixVersion });
  }

  if (t.unknownPrefix) {
    issues.push({
      severity: 'error',
      code: 'UNKNOWN_PREFIX',
      message: `"${t.unknownPrefix.text}" isn't a supported CVSS version.`,
      start: t.unknownPrefix.start,
      end: t.unknownPrefix.end,
    });
  }
  if (t.nonstandardPrefix) {
    issues.push({
      severity: 'warning',
      code: 'NONSTANDARD_PREFIX',
      message: 'CVSS 2.0 vectors have no prefix. The prefix is removed on normalization.',
    });
  }

  // --- Determine the version ----------------------------------------------
  const keyGuess = detectFromKeys(t.segments.map((s) => s.key));
  const detectedVersion: CvssVersion | null =
    t.prefixVersion ?? (keyGuess === '3.x' ? null : keyGuess);
  let version: CvssVersion | null = null;

  if (base?.version) {
    version = base.version;
    if (t.prefixVersion && t.prefixVersion !== version) {
      issues.push({
        severity: 'error',
        code: 'VERSION_MISMATCH',
        message: `The vector is CVSS ${t.prefixVersion}, but the base vector is CVSS ${version}.`,
      });
    }
  } else if (mode !== 'auto') {
    version = mode;
    if (t.prefixVersion && t.prefixVersion !== mode) {
      issues.push({
        severity: 'error',
        code: 'VERSION_MISMATCH',
        message: `The vector is CVSS ${t.prefixVersion}, but CVSS ${mode} is required.`,
      });
    } else if (!t.prefixVersion && VERSIONS[mode].prefix) {
      issues.push({
        severity: strict ? 'error' : 'warning',
        code: 'MISSING_PREFIX',
        message: `The vector has no "${VERSIONS[mode].prefix}/" prefix.${strict ? '' : ' It is added on normalization.'}`,
      });
    }
  } else if (t.prefixVersion) {
    version = t.prefixVersion;
  } else if (keyGuess === '3.x') {
    issues.push({
      severity: 'error',
      code: 'AMBIGUOUS_VERSION',
      message:
        'This looks like a CVSS 3.x vector without a prefix. Add "CVSS:3.0/" or "CVSS:3.1/", or set the version.',
    });
  } else if (keyGuess) {
    version = keyGuess;
  } else if (!t.unknownPrefix) {
    issues.push({
      severity: 'error',
      code: 'UNDETECTABLE_VERSION',
      message: "Can't determine the CVSS version. Add a prefix such as \"CVSS:3.1/\", or set the version.",
    });
  }

  for (const m of t.malformed) {
    issues.push({
      severity: 'error',
      code: 'MALFORMED_SEGMENT',
      message: m.raw === '' ? 'The vector has an empty segment ("//").' : `"${m.raw}" isn't a "metric:value" pair.`,
      start: m.start,
      end: m.end,
    });
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
      issues.push({
        severity: 'error',
        code: 'UNKNOWN_METRIC',
        metric: seg.key,
        message: `"${seg.key}" isn't a CVSS ${version} metric.`,
        start: seg.start,
        end: seg.end,
      });
      continue;
    }
    if (overlay && mdef.group === 'base') {
      issues.push({
        severity: 'error',
        code: 'BASE_METRIC_IN_OVERLAY',
        metric: seg.key,
        message: `"${seg.key}" is a base metric. Base metrics come from the base vector.`,
        start: seg.start,
        end: seg.end,
      });
      continue;
    }
    if (!mdef.values.some((v) => v.code === seg.value)) {
      issues.push({
        severity: 'error',
        code: 'INVALID_VALUE',
        metric: seg.key,
        message: `"${seg.value}" isn't a valid value for ${seg.key} (${mdef.name}). Valid values: ${mdef.values.map((v) => v.code).join(', ')}.`,
        start: seg.start,
        end: seg.end,
      });
      continue;
    }
    if (seg.key in metrics) {
      issues.push({
        severity: 'error',
        code: 'DUPLICATE_METRIC',
        metric: seg.key,
        message: `${seg.key} appears more than once.`,
        start: seg.start,
        end: seg.end,
      });
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
      issues.push({
        severity: 'error',
        code: 'MISSING_METRIC',
        metric: m.key,
        message: `${m.key} (${m.name}) is missing.`,
      });
    }
  }

  if (outOfOrder) {
    issues.push({
      severity: strict ? 'error' : 'warning',
      code: 'METRIC_ORDER',
      message: strict
        ? `Metrics aren't in the order the CVSS ${version} specification defines.`
        : `Metrics aren't in canonical order. They're reordered on normalization.`,
    });
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
    scores: scoreFor(version, effectiveMetrics),
  });
}
