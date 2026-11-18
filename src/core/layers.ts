import { VERSIONS, getMetricDef, versionFamily } from './definitions';
import { capIssues, evaluate, evaluateWithBase, scoreFor, serialize } from './evaluate';
import { en, makeIssue } from './messages';
import type {
  CvssIssue,
  CvssLayer,
  CvssResult,
  CvssVersion,
  LayerOutcome,
  LayeredOptions,
  LayeredResult,
  MetricGroup,
  MetricOverride,
  MetricSource,
  SecurityRequirements,
} from './types';

const DEFAULT_GROUPS: MetricGroup[] = ['temporal', 'threat', 'environmental', 'supplemental'];

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
  return evaluateLayersWithBase(baseVector, layers, options);
}

/**
 * `evaluateLayers`, with the base vector already evaluated. Internal: `preBase` must be
 * `evaluate(baseVector, { version, strict, maxLength, v2Method })` with the same options.
 */
export function evaluateLayersWithBase(
  baseVector: string,
  layers: CvssLayer[],
  options: LayeredOptions = {},
  preBase?: CvssResult,
): LayeredResult {
  const { version: mode = 'auto', strict = false, conflict = 'error', maxLength, v2Method } = options;
  const base = preBase ?? evaluate(baseVector, { version: mode, strict, maxLength, v2Method });
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
    issues.push(makeIssue('INVALID_BASE_VECTOR', { issues: null }, { severity: 'error' }));
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
  // Every layer is checked against the base metrics alone. Evaluate those once, not per layer.
  const baseOnlyOptions = { version, strict, maxLength };
  const baseOnlyResult = evaluate(baseOnly, baseOnlyOptions);

  // The base vector's own temporal and environmental metrics form an implicit first layer.
  const baseLayer: LayerOutcome = {
    id: 'base',
    label: en.ui.baseVector,
    vector: null,
    result: null,
    metrics: Object.fromEntries(
      Object.entries(base.metrics).filter(
        ([k, v]) => getMetricDef(version, k)?.group !== 'base' && v !== notDefined,
      ),
    ),
    issues: [],
  };

  // Display names of the given layers, for issue parameters. The base vector is named by the catalog.
  const labels = (...ids: string[]) => {
    const out: Record<string, string> = {};
    for (const id of ids) {
      const label = id === 'base' ? undefined : layers.find((l) => l.id === id)?.label;
      if (label !== undefined) out[id] = label;
    }
    return Object.keys(out).length > 0 ? { labels: out } : {};
  };

  const seen = new Set<string>(['base']);
  const outcomes: LayerOutcome[] = layers.map((layer) => {
    const label = layer.label ?? layer.id;
    const layerIssues: CvssIssue[] = [];
    const add = (issue: CvssIssue) => layerIssues.push({ ...issue, layer: layer.id });

    if (seen.has(layer.id)) {
      add(makeIssue('DUPLICATE_LAYER_ID', { layer: layer.id, reserved: layer.id === 'base' }, { severity: 'error' }));
    }
    seen.add(layer.id);

    const allowed = layer.groups ?? DEFAULT_GROUPS;
    const metrics: Record<string, string> = {};
    const vector = resolveVector(layer, version);
    let result = null;

    if (vector === null && layer.vector !== undefined) {
      add(
        makeIssue(
          'MISSING_LAYER_VECTOR',
          { layer: layer.id, family: versionFamily(version), hasRequirements: !!layer.requirements, ...labels(layer.id) },
          { severity: 'warning' },
        ),
      );
    }

    if (vector !== null && vector.trim() !== '') {
      result = evaluateWithBase(vector, { ...baseOnlyOptions, baseVector: baseOnly }, baseOnlyResult);
      for (const i of result.issues) add(i);
      for (const [key, value] of Object.entries(result.metrics)) {
        const mdef = getMetricDef(version, key);
        if (!mdef || !allowed.includes(mdef.group)) {
          add(
            makeIssue(
              'METRIC_NOT_ALLOWED_IN_LAYER',
              { kind: 'metric', layer: layer.id, key, allowed, ...labels(layer.id) },
              { severity: 'error', metric: key },
            ),
          );
          continue;
        }
        if (value !== notDefined) metrics[key] = value;
      }
    }

    if (layer.requirements) {
      // Every key is optional, so an explicit `undefined` counts as not set.
      const levels = Object.values(layer.requirements).filter((l) => l !== undefined);
      if (levels.some((l) => !['L', 'M', 'H', 'X'].includes(l as string))) {
        add(makeIssue('INVALID_REQUIREMENTS', { layer: layer.id, ...labels(layer.id) }, { severity: 'error' }));
      } else if (!allowed.includes('environmental')) {
        add(
          makeIssue(
            'METRIC_NOT_ALLOWED_IN_LAYER',
            { kind: 'requirements', layer: layer.id, ...labels(layer.id) },
            { severity: 'error' },
          ),
        );
      } else {
        for (const [key, value] of Object.entries(requirementsToMetrics(layer.requirements))) {
          if (key in metrics) {
            add(
              makeIssue(
                'METRIC_CONFLICT',
                { kind: 'requirements', key, layer: layer.id, ...labels(layer.id) },
                { severity: 'error', metric: key },
              ),
            );
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
      issues.push(
        makeIssue(
          'METRIC_CONFLICT',
          {
            kind: 'layers',
            key: m.key,
            values: candidates.map((c) => ({ layer: c.layer, value: c.value })),
            ...labels(...candidates.map((c) => c.layer)),
          },
          { severity: 'error', metric: m.key },
        ),
      );
      continue;
    } else if (conflict === 'first') {
      winner = candidates[0];
    } else if (conflict === 'last') {
      winner = candidates[candidates.length - 1];
    } else {
      const picked = conflict(m.key, candidates);
      const match = candidates.find((c) => c.value === picked);
      if (!match) {
        issues.push(
          makeIssue('INVALID_CONFLICT_RESOLUTION', { key: m.key, picked: String(picked) }, { severity: 'error', metric: m.key }),
        );
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
    scores: valid ? scoreFor(version, effectiveMetrics, { v2Method }) : null,
    // Each layer's issues are capped on their own; cap the combined list too.
    issues: capIssues(issues),
    valid,
  };
}

