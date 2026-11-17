export type CvssVersion = '2.0' | '3.0' | '3.1' | '4.0';

export type VersionMode = 'auto' | CvssVersion;

export type MetricGroup = 'base' | 'temporal' | 'threat' | 'environmental' | 'supplemental';

export interface MetricValueDef {
  code: string;
  name: string;
}

export interface MetricDef {
  key: string;
  name: string;
  group: MetricGroup;
  /**
   * Values in the order of the official calculator: FIRST's for 3.0, 3.1, and
   * 4.0, NVD's for 2.0. "Not defined" comes first.
   */
  values: MetricValueDef[];
  /**
   * Whether `values` (apart from "not defined") runs from least to most severe
   * (`ascending`) or the reverse (`descending`).
   */
  severity: 'ascending' | 'descending';
  /** Base metrics are mandatory; every other metric has a "not defined" value. */
  required: boolean;
}

/**
 * Order of the values in the picker: `first` follows the official calculator
 * (FIRST, or NVD for 2.0); `ascending` puts the least severe value first, for
 * example None → High; `descending` the most severe. "Not defined" stays first.
 */
export type ValueOrder = 'first' | 'ascending' | 'descending';

export interface VersionDef {
  version: CvssVersion;
  /** Vector prefix, for example `CVSS:3.1`. Version 2.0 has none. */
  prefix: string | null;
  /** "Not defined" value code: `ND` for 2.0, `X` otherwise. */
  notDefined: string | null;
  metrics: MetricDef[];
}

export type Severity = 'None' | 'Low' | 'Medium' | 'High' | 'Critical';

export interface ScoreValue {
  score: number;
  severity: Severity;
}

/**
 * The final score: the most specific score the vector supports. For 2.0 and 3.x,
 * Environmental if any environmental metric is set, otherwise Temporal if any
 * temporal metric is set, otherwise Base. For 4.0, the single score; `group`
 * follows its nomenclature (B → base, BT → threat, BE and BTE → environmental).
 */
export interface OverallScore extends ScoreValue {
  group: 'base' | 'temporal' | 'threat' | 'environmental';
}

export interface ClassicScores {
  kind: 'classic';
  version: '2.0' | '3.0' | '3.1';
  /** The final score. See `OverallScore`. */
  overall: OverallScore;
  base: ScoreValue;
  temporal: ScoreValue;
  environmental: ScoreValue;
  /** True when the vector sets at least one temporal metric. */
  temporalDefined: boolean;
  /** True when the vector sets at least one environmental metric. */
  environmentalDefined: boolean;
  impact: number;
  exploitability: number;
}

export type V4Nomenclature = 'CVSS-B' | 'CVSS-BT' | 'CVSS-BE' | 'CVSS-BTE';

export interface V4Scores {
  kind: 'v4';
  version: '4.0';
  /** The final score: the same value as `score`. See `OverallScore`. */
  overall: OverallScore;
  score: ScoreValue;
  nomenclature: V4Nomenclature;
  macroVector: string;
}

export type CvssScores = ClassicScores | V4Scores;

export type IssueCode =
  | 'EMPTY'
  | 'UNKNOWN_PREFIX'
  | 'NONSTANDARD_PREFIX'
  | 'MISSING_PREFIX'
  | 'AMBIGUOUS_VERSION'
  | 'UNDETECTABLE_VERSION'
  | 'VERSION_MISMATCH'
  | 'MALFORMED_SEGMENT'
  | 'UNKNOWN_METRIC'
  | 'INVALID_VALUE'
  | 'DUPLICATE_METRIC'
  | 'MISSING_METRIC'
  | 'METRIC_ORDER'
  | 'BASE_METRIC_IN_OVERLAY'
  | 'INVALID_BASE_VECTOR'
  | 'METRIC_CONFLICT'
  | 'METRIC_NOT_ALLOWED_IN_LAYER'
  | 'MISSING_LAYER_VECTOR'
  | 'INVALID_REQUIREMENTS'
  | 'DUPLICATE_LAYER_ID'
  | 'INVALID_CONFLICT_RESOLUTION'
  | 'TOO_LONG'
  | 'TOO_MANY_ISSUES';

export interface CvssIssue {
  severity: 'error' | 'warning';
  code: IssueCode;
  message: string;
  metric?: string;
  /** Layer the issue belongs to, for results of `evaluateLayers`. */
  layer?: string;
  /** Character range in the input string, if the issue maps to one. */
  start?: number;
  end?: number;
}

export interface EvaluateOptions {
  /** Force a version, or `auto` to detect it from the vector. Default: `auto`. */
  version?: VersionMode;
  /**
   * When true, metrics out of canonical order and a missing 3.x prefix are errors.
   * When false (default), they are warnings and `normalized` holds the fixed vector.
   */
  strict?: boolean;
  /**
   * A complete vector that supplies the base metrics. When set, the input may
   * only hold temporal, threat, environmental, or supplemental metrics.
   */
  baseVector?: string;
  /**
   * Inputs longer than this are rejected with one `TOO_LONG` error and not parsed.
   * Default: 1024. The longest valid vector is 178 characters (CVSS 4.0 with every metric set).
   */
  maxLength?: number;
  /** CVSS 2.0 temporal and environmental method: `nvd` (default) or `spec`. See `V2Method`. */
  v2Method?: 'nvd' | 'spec';
}

export interface CvssResult {
  input: string;
  /** Version used for validation and scoring, or null if it couldn't be determined. */
  version: CvssVersion | null;
  /** Version that auto-detection found in the input, regardless of the forced version. */
  detectedVersion: CvssVersion | null;
  /** Metrics parsed from the input (valid segments only), keyed by metric. */
  metrics: Record<string, string>;
  /** Input metrics merged with the base vector's metrics in overlay mode. */
  effectiveMetrics: Record<string, string>;
  /** Input rewritten in canonical form, or null when it has errors. */
  normalized: string | null;
  /** Full vector (base vector plus overlay) in canonical form, or null. */
  combined: string | null;
  issues: CvssIssue[];
  valid: boolean;
  scores: CvssScores | null;
  overlay: boolean;
}

// ---------------------------------------------------------------------------
// Layers
// ---------------------------------------------------------------------------

/** Versions that share a metric set: 3.0 and 3.1 use the same metrics. */
export type VersionFamily = '2.0' | '3.x' | '4.0';

export type RequirementLevel = 'L' | 'M' | 'H' | 'X';

/** Version-neutral security requirements, mapped to CR, IR, and AR. */
export interface SecurityRequirements {
  C?: RequirementLevel;
  I?: RequirementLevel;
  A?: RequirementLevel;
}

/**
 * A partial vector from one source, such as a threat feed or an asset,
 * applied on top of a base vector.
 */
export interface CvssLayer {
  /** Unique ID. `base` is reserved for the base vector's own non-base metrics. */
  id: string;
  /** Display name. Defaults to the ID. */
  label?: string;
  /**
   * Metrics in the base vector's version. Pass one string if the layer only
   * ever meets one version family, or one string per family. A prefix is
   * optional. Base metrics aren't allowed.
   */
  vector?: string | Partial<Record<VersionFamily, string>>;
  /** Version-neutral CR, IR, and AR. Applies to every version. */
  requirements?: SecurityRequirements;
  /**
   * Metric groups this layer may set. Default: every group except base.
   * For example, `['environmental']` for an asset.
   */
  groups?: MetricGroup[];
}

export interface MetricSource {
  layer: string;
  value: string;
}

/**
 * How to resolve two layers that set the same metric to different values.
 * `error` (default) reports a conflict; `first` and `last` pick by layer
 * order (the base vector counts as the first layer); a function picks one
 * of the candidate values.
 */
export type ConflictRule =
  | 'error'
  | 'first'
  | 'last'
  | ((metric: string, candidates: MetricSource[]) => string);

export interface LayeredOptions {
  /** Version mode for the base vector. Default: `auto`. */
  version?: VersionMode;
  strict?: boolean;
  conflict?: ConflictRule;
  /** Maximum length of the base vector and of each layer vector. Default: 1024. */
  maxLength?: number;
  /** CVSS 2.0 temporal and environmental method: `nvd` (default) or `spec`. */
  v2Method?: 'nvd' | 'spec';
}

export interface LayerOutcome {
  id: string;
  label: string;
  /** The vector used for the base version, or null if the layer has none. */
  vector: string | null;
  /** Evaluation of `vector` against the base vector, or null. */
  result: CvssResult | null;
  /** Metrics this layer contributes after validation (no "not defined" values). */
  metrics: Record<string, string>;
  issues: CvssIssue[];
}

export interface MetricOverride {
  metric: string;
  winner: MetricSource;
  overridden: MetricSource[];
}

export interface LayeredResult {
  version: CvssVersion | null;
  base: CvssResult;
  layers: LayerOutcome[];
  effectiveMetrics: Record<string, string>;
  /** Layer ID that supplied each metric in `effectiveMetrics`. */
  provenance: Record<string, string>;
  /** Conflicts resolved by the `first`, `last`, or custom rule. */
  overrides: MetricOverride[];
  combined: string | null;
  scores: CvssScores | null;
  /** All issues: base vector, layers, and conflicts. Layer issues carry `layer`. */
  issues: CvssIssue[];
  valid: boolean;
}
