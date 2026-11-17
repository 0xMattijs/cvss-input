# cvss-input

A React component and a framework-free scoring core for CVSS 2.0, 3.0, 3.1, and 4.0 vectors.

- Detects the version from the vector, or validates against a version you set.
- Shows Base, Temporal, and Environmental scores for 2.0 and 3.x, and one labeled score
  (CVSS-B, CVSS-BT, CVSS-BE, or CVSS-BTE) for 4.0.
- Edits a temporal, threat, or environmental overlay on top of a base vector.
- Includes a text field, a metric picker, or both.

## Install

```sh
npm install cvss-input
```

```tsx
import { CvssInput } from 'cvss-input';
import 'cvss-input/styles.css';
```

## Use the component

```tsx
// Auto mode: detect the version and show every score the version defines.
<CvssInput value={vector} onChange={(vector, result) => setVector(vector)} />

// Forced version: validate against CVSS 4.0.
<CvssInput value={vector} onChange={setVector} version="4.0" />

// Overlay: edit only temporal and environmental metrics on a known base vector.
<CvssInput
  value={overlay}             // for example "E:P/RL:O"
  onChange={(overlay, result) => save(overlay, result.combined)}
  baseVector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
/>
```

| Prop | Default | Description |
|---|---|---|
| `value` / `defaultValue` | — / `''` | Controlled or uncontrolled vector string. |
| `onChange` | — | `(value, result) => void`. `result` is a `CvssResult`. |
| `version` | `'auto'` | `'auto'`, `'2.0'`, `'3.0'`, `'3.1'`, or `'4.0'`. |
| `baseVector` | — | Complete vector that supplies the base metrics. The input then accepts only non-base metrics. |
| `strict` | `false` | Treats non-canonical metric order and a missing prefix (forced 3.x or 4.0) as errors. |
| `normalizeOnBlur` | `!strict` | Rewrites a valid vector in canonical form when the text field loses focus. |
| `mode` | `'both'` | `'text'`, `'picker'`, or `'both'`. |
| `defaultPickerVersion` | `'4.0'` | Version the picker starts with for an empty vector in auto mode. |
| `readOnly`, `disabled`, `label`, `className` | | Standard. |

`ScorePanel` and `MetricPicker` are exported separately if you want to compose your own layout.

## Use the core without React

```ts
import { evaluate } from 'cvss-input/core';

const result = evaluate('CVSS:3.1/E:F/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
result.valid;       // true
result.normalized;  // 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F'
result.issues;      // [{ severity: 'warning', code: 'METRIC_ORDER', ... }]
result.scores;      // { kind: 'classic', base: { score: 9.8, severity: 'Critical' }, ... }
```

`evaluate(input, { version, strict, baseVector })` returns:

- `version`: the version used for validation and scoring, and `detectedVersion`: what the input itself says.
- `issues`: errors and warnings with a `code`, a `message`, and, where it applies, `metric` and the `start`/`end` character range in the input.
- `normalized`: the input in canonical form; `combined`: base vector plus overlay.
- `scores`: `null` when the vector has errors.

The React hook `useCvss(vector, options)` returns the same result, memoized.

## Combine sources with layers

Often the metrics come from different places: the base vector belongs to a vulnerability, exploit
maturity to a threat feed, and security requirements to an asset. Store each part on its own record
and combine them at scoring time.

```ts
import { evaluateLayers } from 'cvss-input/core';

const vulnerability = { cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' };
const asset = {
  name: 'Customer database',
  requirements: { C: 'H', I: 'H', A: 'M' },                  // version-neutral
  modified: { '3.x': 'MAV:A', '4.0': 'MAV:A' },              // per version family
};

const result = evaluateLayers(
  vulnerability.cvss,
  [
    { id: 'feed', label: 'Threat feed', vector: 'E:H', groups: ['temporal', 'threat'] },
    {
      id: 'asset',
      label: asset.name,
      requirements: asset.requirements,
      vector: asset.modified,
      groups: ['environmental'],
    },
  ],
  { conflict: 'error' },
);

result.combined;    // 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/CR:H/IR:H/AR:M/MAV:A'
result.scores;      // environmental: { score: 8.8, severity: 'High' }
result.provenance;  // { AV: 'base', …, E: 'feed', CR: 'asset', MAV: 'asset' }
```

Each layer has:

- `id` and an optional `label`. The ID `base` is reserved for the base vector's own temporal and
  environmental metrics, which act as the first layer.
- `vector`: one string, or one string per version family (`'2.0'`, `'3.x'`, `'4.0'`). Modified base
  metrics differ between versions, so an asset that meets vulnerabilities of several versions needs one
  vector per family. If a layer has no vector for the base vector's family, you get a warning and only
  its requirements apply.
- `requirements`: `C`, `I`, and `A` set to `L`, `M`, `H`, or `X`. These become `CR`, `IR`, and `AR` in
  every version.
- `groups`: the metric groups the layer may set. Anything else is an error.

### Conflicts

When two layers set the same metric to different values, the `conflict` option decides:

| Rule | Result |
|---|---|
| `'error'` (default) | A `METRIC_CONFLICT` error; no score. |
| `'first'` | The earliest layer wins. The base vector counts as the first layer. |
| `'last'` | The latest layer wins. |
| A function | `(metric, candidates) => value` picks one of the candidates' values. |

"Not defined" values (`X`, `ND`) never count as set, so they don't conflict. Resolved conflicts are
listed in `result.overrides`.

```ts
// Pessimistic rule: take the most mature exploit claim; otherwise the later layer wins.
const rank = ['U', 'POC', 'P', 'F', 'H', 'A'];
const conflict = (metric, candidates) =>
  metric === 'E'
    ? [...candidates].sort((a, b) => rank.indexOf(b.value) - rank.indexOf(a.value))[0].value
    : candidates.at(-1).value;
```

### Components

Edit one layer while the others apply as context. The picker shows the edited layer's groups only, and
notes under each metric what the other layers set and which value wins:

```tsx
<CvssInput
  baseVector={vulnerability.cvss}
  layers={[assetLayer]}
  layerId="feed"            // the input edits this layer
  value={feedVector}
  onChange={(vector, own, combined) => saveFeed(vector)}
  conflict="last"
/>
```

Without `baseVector`, the input edits the base vector and `layers` apply on top of it.

Show the combined score for one vulnerability and asset pair, with a table of where each metric came
from:

```tsx
<CvssCombined baseVector={vulnerability.cvss} layers={[feedLayer, assetLayer]} conflict="last" />
```

`useCvssLayers(baseVector, layers, options)` returns the same result as `evaluateLayers`, memoized.

For a complete example with three vulnerabilities (CVSS 2.0, 3.1, and 4.0), three assets, a threat feed,
a conflict rule switch, and a vulnerability × asset score matrix, see
[`demo/LayeredExample.tsx`](demo/LayeredExample.tsx) and run `npm run dev`.

## Validation rules

| Situation | Lenient (default) | Strict |
|---|---|---|
| Metrics out of canonical order | Warning; reordered on normalization | Error |
| Forced 3.x or 4.0 version, no prefix | Warning; prefix added | Error |
| Unprefixed 3.x vector in auto mode | Error: 3.0 and 3.1 score differently, so the component offers to add the prefix | Error |
| Prefix conflicts with forced version or base vector | Error | Error |
| Unknown metric, invalid value, duplicate, missing base metric | Error | Error |
| Base metric in an overlay | Error | Error |
| `CVSS2#` prefix or surrounding parentheses on a 2.0 vector | Accepted; removed on normalization | Same |

Metric keys and values are case sensitive, as in the specifications.

## Scoring notes

- **4.0** is ported from the [FIRST reference calculator](https://github.com/FIRSTdotorg/cvss-v4-calculator)
  (BSD-2-Clause), including its MacroVector lookup table. Like the current FIRST calculator, it adds an
  epsilon before rounding so that values such as 5.6499999… round to 5.7.
- **3.0 and 3.1** use their own Roundup functions and their own Environmental formulas for a changed scope.
- **2.0** rounds AdjustedTemporal, as the v2 specification requires, and rounds x.x5 up. Its severity
  ratings are the NVD bands (Low, Medium, High), because CVSS 2.0 defines none.

## Development

```sh
npm test          # unit, component, and differential tests
npm run typecheck
npm run build     # dist/ with ESM, CJS, types, and styles.css
npm run dev       # demo page
```

CI runs the typecheck, tests, and build on Node 22 and 24 with React 18 and 19 for every push to
`master` and every pull request.

### Release

The release workflow publishes to npm with [trusted publishing](https://docs.npmjs.com/trusted-publishers),
so no npm token is stored in GitHub, and npm shows a provenance link to the commit.

1. Update `version` in `package.json` and commit.
2. Tag and push: `git tag v0.2.0 && git push origin v0.2.0`.

The workflow fails if the tag doesn't match `package.json`.

One-time setup on npmjs.com, under the package's **Settings → Trusted publisher**: choose GitHub Actions
and enter owner `0xMattijs`, repository `cvss-input`, workflow `release.yml`, and environment `npm`.

### Tests

The differential tests score 5,000 random vectors per version and compare them with
[ae-cvss-calculator](https://www.npmjs.com/package/ae-cvss-calculator). Base, Temporal, and Environmental
scores for 3.0 and 3.1, and all 4.0 scores, must match exactly. For 2.0, only Base must match exactly:
the reference library doesn't round AdjustedTemporal and lets floating-point noise decide x.x5 cases, so
Temporal and Environmental may differ by 0.1. `test/evaluate.test.ts` pins those boundary cases with
hand-checked values.
