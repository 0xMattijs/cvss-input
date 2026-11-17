import { useMemo } from 'react';
import { VERSIONS } from '../core/definitions';
import { evaluateLayers } from '../core/layers';
import { formatIssue, messageFormat } from '../core/messages';
import type { CvssMessages, CvssMessagesInput } from '../core/messages';
import type { ConflictRule, CvssLayer, LayeredResult, VersionMode } from '../core/types';
import { ScorePanel } from './CvssInput';
import { useCvssMessages } from './messages';

export interface UseCvssLayersOptions {
  version?: VersionMode;
  strict?: boolean;
  conflict?: ConflictRule;
  /** Maximum length of the base vector and of each layer vector. Default: 1024. */
  maxLength?: number;
  /** CVSS 2.0 temporal and environmental method: `nvd` (default) or `spec`. */
  v2Method?: 'nvd' | 'spec';
}

/** Combines a base vector with layers and scores the result. Memoized on content. */
export function useCvssLayers(
  baseVector: string,
  layers: CvssLayer[],
  options: UseCvssLayersOptions = {},
): LayeredResult {
  const { version, strict, conflict, maxLength, v2Method } = options;
  const key = JSON.stringify(layers);
  return useMemo(
    () => evaluateLayers(baseVector, layers, { version, strict, conflict, maxLength, v2Method }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [baseVector, key, version, strict, conflict, maxLength, v2Method],
  );
}

export interface CvssCombinedProps extends UseCvssLayersOptions {
  /** The vulnerability's base vector. */
  baseVector: string;
  /** Layers in order, such as a threat feed and an asset. */
  layers: CvssLayer[];
  /** Heading above the scores. */
  title?: string;
  /** Show the combined vector. Default: true. */
  showVector?: boolean;
  /** Show a table of non-base metrics and the layer that supplied each. Default: true. */
  showSources?: boolean;
  /** Show errors and warnings. Default: true. */
  showIssues?: boolean;
  /** Texts in another language, such as `nl`. Overrides a `CvssMessagesProvider`. Default: English. */
  messages?: CvssMessages | CvssMessagesInput;
  className?: string;
}

/** Read-only view of the score for a base vector combined with its layers. */
export function CvssCombined({
  baseVector,
  layers,
  version,
  strict,
  conflict,
  maxLength,
  v2Method,
  title,
  showVector = true,
  showSources = true,
  showIssues = true,
  messages,
  className,
}: CvssCombinedProps) {
  const msg = useCvssMessages(messages);
  const r = useCvssLayers(baseVector, layers, { version, strict, conflict, maxLength, v2Method });
  const labels: Record<string, string> = { base: msg.ui.baseVector };
  for (const l of r.layers) labels[l.id] = l.label;
  const fmt = messageFormat(msg, (layer) => labels[layer]);
  const ui = msg.ui;
  const def = r.version ? VERSIONS[r.version] : null;

  // Non-base metrics that any layer set, in canonical order.
  const rows = def
    ? def.metrics
        .filter((m) => m.group !== 'base')
        .map((m) => {
          const override = r.overrides.find((o) => o.metric === m.key);
          const conflicting = r.issues.find((i) => i.code === 'METRIC_CONFLICT' && i.metric === m.key && !i.layer);
          return { m, value: r.effectiveMetrics[m.key], source: r.provenance[m.key], override, conflicting };
        })
        .filter((row) => row.value !== undefined || row.conflicting)
    : [];

  return (
    <section
      className={['cvss', 'cvss-combined', className].filter(Boolean).join(' ')}
      lang={msg.locale}
      aria-label={title ?? ui.combinedScore}
    >
      {title && <div className="cvss-label">{title}</div>}
      <div className="cvss-meta">
        <span className="cvss-version" data-empty={!r.version || undefined}>
          {r.version ? `CVSS ${r.version}` : ui.versionUnknown}
        </span>
        {r.layers.map((l) => (
          <span key={l.id} className="cvss-layer-chip">
            {l.label}
          </span>
        ))}
      </div>

      {showIssues && r.issues.length > 0 && (
        <ul className="cvss-issues">
          {r.issues.map((issue, n) => (
            <li key={n} className="cvss-issue" data-severity={issue.severity}>
              <span className="cvss-issue-kind">{issue.severity === 'error' ? ui.error : ui.note}</span>
              <span>
                {issue.layer && <strong>{labels[issue.layer] ?? issue.layer}: </strong>}
                {formatIssue(issue, msg, fmt)}
              </span>
            </li>
          ))}
        </ul>
      )}

      <ScorePanel scores={r.scores} messages={msg} />

      {showVector && r.combined && (
        <div className="cvss-meta">
          <span>{ui.combined}</span>
          <code className="cvss-base-vector">{r.combined}</code>
        </div>
      )}

      {showSources && rows.length > 0 && def && (
        <div className="cvss-table-wrap">
          <table className="cvss-sources">
            <caption>{ui.sources}</caption>
            <thead>
              <tr>
                <th scope="col">{ui.sourcesMetric}</th>
                <th scope="col">{ui.sourcesValue}</th>
                <th scope="col">{ui.sourcesSource}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ m, value, source, override, conflicting }) => (
                <tr key={m.key}>
                  <td>
                    {fmt.metric(r.version!, m.key)} <code>{m.key}</code>
                    <div className="cvss-score-detail">{msg.groups[m.group]}</div>
                  </td>
                  <td>
                    {value !== undefined ? (
                      <>
                        {fmt.value(r.version!, m.key, value)} <code>{value}</code>
                      </>
                    ) : (
                      ui.conflict
                    )}
                  </td>
                  <td>
                    {source !== undefined && labels[source]}
                    {override?.overridden.map((o) => (
                      <div key={o.layer}>
                        <del>
                          <span className="cvss-sr-only">{ui.overridden}</span>
                          {labels[o.layer] ?? o.layer}: <code>{o.value}</code>
                        </del>
                      </div>
                    ))}
                    {conflicting && !source && <span>{ui.seeErrorAbove}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
