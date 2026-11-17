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
  values: MetricValueDef[];
  /** Base metrics are mandatory; every other metric has a "not defined" value. */
  required: boolean;
}

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

export interface ClassicScores {
  kind: 'classic';
  version: '2.0' | '3.0' | '3.1';
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
  | 'INVALID_BASE_VECTOR';

export interface CvssIssue {
  severity: 'error' | 'warning';
  code: IssueCode;
  message: string;
  metric?: string;
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
