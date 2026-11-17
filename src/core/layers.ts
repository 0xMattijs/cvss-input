import { VERSIONS, getMetricDef } from './definitions';
import { evaluate, scoreFor, serialize } from './evaluate';
import type {
  CvssIssue,
  CvssLayer,
  CvssVersion,
  LayerOutcome,
  LayeredOptions,
  LayeredResult,
  MetricGroup,
  MetricOverride,
  MetricSource,
  SecurityRequirements,
  VersionFamily,
} from './types';

const DEFAULT_GROUPS: MetricGroup[] = ['temporal', 'threat', 'environmental', 'supplemental'];

export function versionFamily(version: CvssVersion): VersionFamily {
  return version === '3.0' || version === '3.1' ? '3.x' : version;
}

/**
 * Converts version-neutral security requirements to CR, IR, and AR metrics.
 * Every version uses the same L, M, and H codes; unset and `X` are left out.
 */
export function requirementsToMetrics(requirements: SecurityRequirements): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [axis, key] of [['C', 'CR'], ['I', 'IR'], ['A', 'AR']] as const) {
    const level = requirements[axis];
    if (level && level !== 'X') out[key] = level;
  }
  return out;
}

function resolveVector(layer: CvssLayer, version: CvssVersion): string | null {
  if (layer.vector === undefined) return null;
  if (typeof layer.vector === 'string') return layer.vector;
  return layer.vector[versionFamily(version)] ?? null;
}

const isErr = (i: CvssIssue) => i.severity === 'error';

/**
 * Combines a base vector with ordered layers, such as a threat feed and an
 * asset's environmental metrics, and scores the result.
 *
 * Metrics set to "not defined" (`X` or `ND`) don't count as set, so they never
 * override or conflict with another layer.
 *
 * @example
 * evaluateLayers('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', [
 *   { id: 'feed', vector: 'E:F' },
 *   { id: 'asset', requirements: { C: 'H', I: 'L' }, vector: { '3.x': 'MAV:L' }, groups: ['environmental'] },
 * ]).combined
 * // 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/CR:H/IR:L/MAV:L'
 */
export function evaluateLayers(
  baseVector: string,
  layers: CvssLayer[],
  options: LayeredOptions = {},
): LayeredResult {
  const { version: mode = 'auto', strict = false, conflict = 'error' } = options;
  const base = evaluate(baseVector, { version: mode, strict });
  const issues: CvssIssue[] = base.issues.map((i) => ({ ...i, layer: 'base' }));

  const empty = (outcomes: LayerOutcome[]): LayeredResult => ({
    version: base.version,
    base,
    layers: outcomes,
    effectiveMetrics: {},
    provenance: {},
    overrides: [],
    combined: null,
    scores: null,
    issues,
    valid: false,
  });

  if (!base.valid || !base.version || base.normalized === null) {
    issues.push({
      severity: 'error',
      code: 'INVALID_BASE_VECTOR',
      message: 'The base vector is invalid, so the layers can\'t be combined.',
    });
    return empty(
      layers.map((l) => ({ id: l.id, label: l.label ?? l.id, vector: null, result: null, metrics: {}, issues: [] })),
    );
  }

  const version = base.version;
  const def = VERSIONS[version];
  const notDefined = def.notDefined;
  const baseOnly = serialize(
    version,
    Object.fromEntries(Object.entries(base.metrics).filter(([k]) => getMetricDef(version, k)?.group === 'base')),
  );

  // The base vector's own temporal and environmental metrics form an implicit first layer.
  const baseLayer: LayerOutcome = {
    id: 'base',
    label: 'Base vector',
    vector: null,
    result: null,
    metrics: Object.fromEntries(
      Object.entries(base.metrics).filter(
        ([k, v]) => getMetricDef(version, k)?.group !== 'base' && v !== notDefined,
      ),
    ),
    issues: [],
  };

  const seen = new Set<string>(['base']);
  const outcomes: LayerOutcome[] = layers.map((layer) => {
    const label = layer.label ?? layer.id;
    const layerIssues: CvssIssue[] = [];
    const add = (issue: Omit<CvssIssue, 'layer'>) => layerIssues.push({ ...issue, layer: layer.id });

    if (seen.has(layer.id)) {
      add({
        severity: 'error',
        code: 'DUPLICATE_LAYER_ID',
        message: layer.id === 'base' ? '"base" is reserved for the base vector.' : `Layer ID "${layer.id}" is used more than once.`,
      });
    }
    seen.add(layer.id);

    const allowed = layer.groups ?? DEFAULT_GROUPS;
    const metrics: Record<string, string> = {};
    const vector = resolveVector(layer, version);
    let result = null;

    if (vector === null && layer.vector !== undefined) {
      add({
        severity: 'warning',
        code: 'MISSING_LAYER_VECTOR',
        message: `${label} has no CVSS ${versionFamily(version)} metrics${layer.requirements ? '; only its security requirements apply' : ''}.`,
      });
    }

    if (vector !== null && vector.trim() !== '') {
      result = evaluate(vector, { baseVector: baseOnly, version, strict });
      for (const i of result.issues) add(i);
      for (const [key, value] of Object.entries(result.metrics)) {
        const mdef = getMetricDef(version, key);
        if (!mdef || !allowed.includes(mdef.group)) {
          add({
            severity: 'error',
            code: 'METRIC_NOT_ALLOWED_IN_LAYER',
            metric: key,
            message: `${label} may not set ${key}; it only accepts ${allowed.join(', ')} metrics.`,
          });
          continue;
        }
        if (value !== notDefined) metrics[key] = value;
      }
    }

    if (layer.requirements) {
      const levels = Object.values(layer.requirements);
      if (levels.some((l) => !['L', 'M', 'H', 'X'].includes(l as string))) {
        add({
          severity: 'error',
          code: 'INVALID_REQUIREMENTS',
          message: `${label} has invalid security requirements. Use L, M, H, or X.`,
        });
      } else if (!allowed.includes('environmental')) {
        add({
          severity: 'error',
          code: 'METRIC_NOT_ALLOWED_IN_LAYER',
          message: `${label} has security requirements but doesn't accept environmental metrics.`,
        });
      } else {
        for (const [key, value] of Object.entries(requirementsToMetrics(layer.requirements))) {
          if (key in metrics) {
            add({
              severity: 'error',
              code: 'METRIC_CONFLICT',
              metric: key,
              message: `${label} sets ${key} in both its vector and its security requirements.`,
            });
            continue;
          }
          metrics[key] = value;
        }
      }
    }

    return { id: layer.id, label, vector, result, metrics, issues: layerIssues };
  });

  for (const o of outcomes) issues.push(...o.issues);

  // Merge in layer order and apply the conflict rule.
  const ordered = [baseLayer, ...outcomes];
  const effectiveMetrics: Record<string, string> = Object.fromEntries(
    Object.entries(base.metrics).filter(([k]) => getMetricDef(version, k)?.group === 'base'),
  );
  const provenance: Record<string, string> = Object.fromEntries(
    Object.keys(effectiveMetrics).map((k) => [k, 'base']),
  );
  const overrides: MetricOverride[] = [];

  for (const m of def.metrics) {
    if (m.group === 'base') continue;
    const candidates: MetricSource[] = ordered
      .filter((o) => o.metrics[m.key] !== undefined)
      .map((o) => ({ layer: o.id, value: o.metrics[m.key] }));
    if (candidates.length === 0) continue;

    let winner: MetricSource;
    const distinct = new Set(candidates.map((c) => c.value));
    if (distinct.size === 1) {
      winner = candidates[0];
    } else if (conflict === 'error') {
      issues.push({
        severity: 'error',
        code: 'METRIC_CONFLICT',
        metric: m.key,
        message: `${m.key} is set to different values: ${candidates.map((c) => `${labelOf(ordered, c.layer)} ${m.key}:${c.value}`).join(', ')}.`,
      });
      continue;
    } else if (conflict === 'first') {
      winner = candidates[0];
    } else if (conflict === 'last') {
      winner = candidates[candidates.length - 1];
    } else {
      const picked = conflict(m.key, candidates);
      const match = candidates.find((c) => c.value === picked);
      if (!match) {
        issues.push({
          severity: 'error',
          code: 'INVALID_CONFLICT_RESOLUTION',
          metric: m.key,
          message: `The conflict rule returned "${picked}" for ${m.key}, which no layer set.`,
        });
        continue;
      }
      winner = match;
    }

    effectiveMetrics[m.key] = winner.value;
    provenance[m.key] = winner.layer;
    const losers = candidates.filter((c) => c.value !== winner.value);
    if (losers.length > 0) overrides.push({ metric: m.key, winner, overridden: losers });
  }

  const valid = !issues.some(isErr);
  return {
    version,
    base,
    layers: outcomes,
    effectiveMetrics,
    provenance,
    overrides,
    combined: valid ? serialize(version, effectiveMetrics) : null,
    scores: valid ? scoreFor(version, effectiveMetrics) : null,
    issues,
    valid,
  };
}

function labelOf(layers: LayerOutcome[], id: string): string {
  return layers.find((l) => l.id === id)?.label ?? id;
}
