// Example: scoring vulnerabilities against assets with layers.
//
// A vulnerability owns the base vector (and sometimes vendor temporal metrics).
// A threat feed owns exploit maturity. An asset owns security requirements and
// modified base metrics. Each source is stored on its own record and combined
// at scoring time with evaluateLayers() or the components below.

import { useState } from 'react';
import { CvssCombined, CvssInput, evaluateLayers, versionFamily } from '../src';
import type {
  ConflictRule,
  CvssLayer,
  RequirementLevel,
  SecurityRequirements,
  VersionFamily,
} from '../src';

// --- Data, as you might store it ------------------------------------------

interface Vulnerability {
  id: string;
  title: string;
  /** Base vector from the advisory. May carry the vendor's own temporal metrics. */
  cvss: string;
}

interface Asset {
  id: string;
  name: string;
  /** Version-neutral: applies to vulnerabilities of every CVSS version. */
  requirements: SecurityRequirements;
  /** Modified base metrics, per version family, because they differ between versions. */
  modified: Partial<Record<VersionFamily, string>>;
}

const VULNERABILITIES: Vulnerability[] = [
  { id: 'VULN-1', title: 'Remote code execution in web framework', cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
  {
    id: 'VULN-2',
    title: 'SQL injection in reporting module',
    cvss: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N/E:P',
  },
  { id: 'VULN-3', title: 'Directory traversal in legacy file server', cvss: 'AV:N/AC:M/Au:N/C:P/I:P/A:N/E:POC' },
];

const INITIAL_ASSETS: Asset[] = [
  {
    id: 'db',
    name: 'Customer database',
    requirements: { C: 'H', I: 'H', A: 'M' },
    // Only reachable from the internal network.
    modified: { '3.x': 'MAV:A', '4.0': 'MAV:A' },
  },
  { id: 'web', name: 'Public website', requirements: { C: 'L', I: 'M', A: 'H' }, modified: {} },
  {
    id: 'build',
    name: 'Build server',
    requirements: { C: 'M', I: 'H', A: 'L' },
    // Requires a logged-in user.
    modified: { '3.x': 'MPR:L', '4.0': 'MPR:L' },
  },
];

/** Exploit maturity from a threat feed, keyed by vulnerability. In the base vector's version. */
const INITIAL_FEED: Record<string, string> = { 'VULN-1': 'E:H', 'VULN-2': 'E:A', 'VULN-3': '' };

// --- Layers ---------------------------------------------------------------

function feedLayer(vector: string): CvssLayer {
  return { id: 'feed', label: 'Threat feed', vector, groups: ['temporal', 'threat'] };
}

function assetLayer(asset: Asset): CvssLayer {
  return {
    id: 'asset',
    label: asset.name,
    requirements: asset.requirements,
    vector: asset.modified,
    groups: ['environmental'],
  };
}

/** Custom rule: take the most mature exploit claim; otherwise the later layer wins. */
const EXPLOIT_RANK = ['U', 'POC', 'P', 'F', 'H', 'A'];
const mostMatureExploit: ConflictRule = (metric, candidates) => {
  if (metric !== 'E') return candidates[candidates.length - 1].value;
  return [...candidates].sort((a, b) => EXPLOIT_RANK.indexOf(b.value) - EXPLOIT_RANK.indexOf(a.value))[0].value;
};

const RULES: Record<string, ConflictRule> = {
  error: 'error',
  first: 'first',
  last: 'last',
  'most mature exploit': mostMatureExploit,
};

// --- UI ---------------------------------------------------------------------

const LEVELS: RequirementLevel[] = ['X', 'L', 'M', 'H'];

export function LayeredExample() {
  const [vulnId, setVulnId] = useState('VULN-1');
  const [assetId, setAssetId] = useState('db');
  const [assets, setAssets] = useState(INITIAL_ASSETS);
  const [feed, setFeed] = useState(INITIAL_FEED);
  const [ruleName, setRuleName] = useState('most mature exploit');

  const vuln = VULNERABILITIES.find((v) => v.id === vulnId)!;
  const asset = assets.find((a) => a.id === assetId)!;
  const conflict = RULES[ruleName];
  const baseVersion = evaluateLayers(vuln.cvss, []).version;
  const family = baseVersion ? versionFamily(baseVersion) : null;

  const updateAsset = (patch: Partial<Asset>) =>
    setAssets((list) => list.map((a) => (a.id === asset.id ? { ...a, ...patch } : a)));

  return (
    <div className="layered">
      <div className="controls">
        <label>
          Vulnerability{' '}
          <select value={vulnId} onChange={(e) => setVulnId(e.target.value)}>
            {VULNERABILITIES.map((v) => (
              <option key={v.id} value={v.id}>
                {v.id}: {v.title}
              </option>
            ))}
          </select>
        </label>
        <label>
          Asset{' '}
          <select value={assetId} onChange={(e) => setAssetId(e.target.value)}>
            {assets.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Conflict rule{' '}
          <select value={ruleName} onChange={(e) => setRuleName(e.target.value)}>
            {Object.keys(RULES).map((r) => (
              <option key={r}>{r}</option>
            ))}
          </select>
        </label>
      </div>

      <p className="hint">
        Base vector from the advisory: <code>{vuln.cvss}</code>
      </p>

      <div className="columns">
        <div className="column">
          <h3>Threat feed for {vuln.id}</h3>
          <CvssInput
            baseVector={vuln.cvss}
            layers={[feedLayer(feed[vuln.id] ?? ''), assetLayer(asset)]}
            layerId="feed"
            value={feed[vuln.id] ?? ''}
            onChange={(v) => setFeed((f) => ({ ...f, [vuln.id]: v }))}
            conflict={conflict}
            label="Exploit maturity from the feed"
          />
        </div>

        <div className="column">
          <h3>Asset: {asset.name}</h3>
          <fieldset className="requirements">
            <legend>Security requirements (all CVSS versions)</legend>
            {(['C', 'I', 'A'] as const).map((axis) => (
              <label key={axis}>
                {{ C: 'Confidentiality', I: 'Integrity', A: 'Availability' }[axis]}{' '}
                <select
                  value={asset.requirements[axis] ?? 'X'}
                  onChange={(e) =>
                    updateAsset({ requirements: { ...asset.requirements, [axis]: e.target.value as RequirementLevel } })
                  }
                >
                  {LEVELS.map((l) => (
                    <option key={l} value={l}>
                      {{ X: 'Not defined', L: 'Low', M: 'Medium', H: 'High' }[l]}
                    </option>
                  ))}
                </select>
              </label>
            ))}
          </fieldset>
          {family && (
            <CvssInput
              baseVector={vuln.cvss}
              layers={[feedLayer(feed[vuln.id] ?? ''), { ...assetLayer(asset), vector: undefined }]}
              layerId="asset"
              value={asset.modified[family] ?? ''}
              onChange={(v) => updateAsset({ modified: { ...asset.modified, [family]: v } })}
              conflict={conflict}
              mode="text"
              label={`Modified base metrics for CVSS ${family}`}
            />
          )}
        </div>
      </div>

      <h3>
        {vuln.id} on {asset.name}
      </h3>
      <CvssCombined
        baseVector={vuln.cvss}
        layers={[feedLayer(feed[vuln.id] ?? ''), assetLayer(asset)]}
        conflict={conflict}
      />

      <h3>Every vulnerability on every asset</h3>
      <div className="matrix-wrap">
        <table className="matrix">
          <thead>
            <tr>
              <th scope="col">Vulnerability</th>
              <th scope="col">Advisory score</th>
              {assets.map((a) => (
                <th key={a.id} scope="col">
                  {a.name}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {VULNERABILITIES.map((v) => {
              const base = evaluateLayers(v.cvss, []);
              return (
                <tr key={v.id}>
                  <th scope="row">{v.id}</th>
                  <td>{headline(base.scores)}</td>
                  {assets.map((a) => {
                    const r = evaluateLayers(v.cvss, [feedLayer(feed[v.id] ?? ''), assetLayer(a)], { conflict });
                    return (
                      <td key={a.id} data-selected={(v.id === vulnId && a.id === assetId) || undefined}>
                        <button
                          type="button"
                          onClick={() => {
                            setVulnId(v.id);
                            setAssetId(a.id);
                          }}
                        >
                          {r.valid ? headline(r.scores) : 'Error'}
                        </button>
                      </td>
                    );
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/** The final score. */
function headline(scores: ReturnType<typeof evaluateLayers>['scores']): string {
  if (!scores) return '—';
  return `${scores.overall.score.toFixed(1)} ${scores.overall.severity}`;
}
