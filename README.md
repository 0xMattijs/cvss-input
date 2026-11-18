# cvss-input

[![npm](https://img.shields.io/npm/v/@alcyonsecurity/cvss-input)](https://www.npmjs.com/package/@alcyonsecurity/cvss-input)

A React component and a framework-free scoring core for CVSS 2.0, 3.0, 3.1, and 4.0 vectors.

**[Try the demo](https://0xmattijs.github.io/cvss-input/)**

- Detects the version from the vector, or validates against a version you set.
- Shows Base, Temporal, and Environmental scores for 2.0 and 3.x, and one labeled score
  (CVSS-B, CVSS-BT, CVSS-BE, or CVSS-BTE) for 4.0.
- Edits a temporal, threat, or environmental overlay on top of a base vector.
- Includes a text field, a metric picker, or both.

## Install

```sh
npm install @alcyonsecurity/cvss-input
```

```tsx
import { CvssInput } from '@alcyonsecurity/cvss-input';
import '@alcyonsecurity/cvss-input/styles.css';
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
| `v2Method` | `'nvd'` | CVSS 2.0 Temporal and Environmental method: `'nvd'` or `'spec'`. See [Scoring notes](#scoring-notes). |
| `maxLength` | `1024` | Longest accepted vector. The field won't accept more, and longer values get one `TOO_LONG` error. |
| `normalizeOnBlur` | `!strict` | Rewrites a valid vector in canonical form when the text field loses focus. |
| `mode` | `'both'` | `'text'`, `'picker'`, or `'both'`. |
| `defaultPickerVersion` | `'4.0'` | Version the picker starts with for an empty vector in auto mode. |
| `valueOrder` | `'first'` | Order of each metric's values in the picker. See [Value order](#value-order). |
| `messages` | English | Texts in another language, such as `nl`. See [Languages](#languages). |
| `readOnly`, `disabled`, `label`, `className` | | Standard. |

`ScorePanel` and `MetricPicker` are exported separately if you want to compose your own layout.

### Value order

`valueOrder` sets the order of each metric's values in the picker:

| Value | Order | Example: 3.1 Attack Vector, Confidentiality |
|---|---|---|
| `'first'` (default) | As in FIRST's calculator for 3.0, 3.1, and 4.0, and NVD's for 2.0 | Network → Physical; None → High |
| `'ascending'` | Least severe value first | Physical → Network; None → High |
| `'descending'` | Most severe value first | Network → Physical; High → None |

FIRST doesn't use one direction: in 3.1, Attack Vector starts with the most severe value and
Confidentiality with the least severe. Not Defined always comes first. In the core, `orderedValues(metric,
order)` returns the values in any of these orders.

## Use the core without React

```ts
import { evaluate } from '@alcyonsecurity/cvss-input/core';

const result = evaluate('CVSS:3.1/E:F/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
result.valid;       // true
result.normalized;  // 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F'
result.issues;      // [{ severity: 'warning', code: 'METRIC_ORDER', ... }]
result.scores;      // { kind: 'classic', base: { score: 9.8, severity: 'Critical' }, ... }
```

`evaluate(input, { version, strict, baseVector, maxLength, v2Method })` returns:

- `version`: the version used for validation and scoring, and `detectedVersion`: what the input itself says.
- `issues`: errors and warnings with a `code`, an English `message`, the `params` the message is built
  from, and, where it applies, `metric` and the `start`/`end` character range in the input.
  `formatIssue(issue, nl)` returns the message in another language. `missingMetrics(issues)` returns
  the required metrics a vector lacks when those are its only errors, or `null`.
- `normalized`: the input in canonical form; `combined`: base vector plus overlay.
- `scores`: `null` when the vector has errors. `scores.overall` is the final score: for 2.0 and 3.x,
  Environmental if any environmental metric is set, otherwise Temporal if any temporal metric is set,
  otherwise Base; for 4.0, the single score. `overall.group` says which one it is, and the component
  labels that cell "Final".

The React hook `useCvss(vector, options)` returns the same result, memoized.

## Combine sources with layers

Often the metrics come from different places: the base vector belongs to a vulnerability, exploit
maturity to a threat feed, and security requirements to an asset. Store each part on its own record
and combine them at scoring time.

```ts
import { evaluateLayers } from '@alcyonsecurity/cvss-input/core';

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

## Languages

The components ship in English (`en`, the default) and Dutch (`nl`). Set the language for a whole app
with a provider, or for one component with the `messages` prop:

```tsx
import { CvssInput, CvssMessagesProvider, nl } from '@alcyonsecurity/cvss-input';

<CvssMessagesProvider messages={nl}>
  <App />
</CvssMessagesProvider>

<CvssInput value={vector} onChange={setVector} messages={nl} />
```

A catalog covers every text: labels and buttons, issue messages, severities, the screen reader
summary, and the names of metrics and values, such as "Aanvalsvector" and "Netwerk". Vector codes such
as `AV:N` stay as they are. Scores follow the language's number format: 9.8 in English, 9,8 in Dutch.
The components set the `lang` attribute, so screen readers pronounce the text in the right language.

To add a language, write a `CvssMessages` object; `src/core/locales/nl.ts` shows a complete one, and
TypeScript reports anything it leaves out. To change a few texts, pass a partial catalog. Anything it
leaves out comes from the provider, or from English:

```tsx
<CvssInput messages={{ ui: { vectorLabel: 'Vulnerability vector' } }} />
```

Issue messages are functions of the issue's `params`, so a translation can order the sentence its own
way and use translated metric names:

```ts
INVALID_VALUE: (p, f) => `"${p.value}" is geen geldige waarde voor ${p.key} (${f.metric(p.version, p.key)}).`,
```

The core keeps `issue.message` in English, for logs and APIs. `formatIssue(issue, messages)` formats an
issue in any language, and `statusMessage(scores, issues, messages)` builds the screen reader summary.

## Validation rules

| Situation | Lenient (default) | Strict |
|---|---|---|
| Metrics out of canonical order | Warning; reordered on normalization | Error |
| Forced 3.x or 4.0 version, no prefix | Warning; prefix added | Error |
| Unprefixed 3.x vector in auto mode | Error: 3.0 and 3.1 score differently, so the component offers to add the prefix | Error |
| Prefix conflicts with forced version or base vector | Error | Error |
| Unknown metric, invalid value, duplicate, missing base metric | Error | Error |
| Only base metrics missing (the vector is still being built) | One row, "Still to set: …": a note while focus is in the component, an error once it leaves or the form is submitted | Same |
| Base metric in an overlay | Error | Error |
| `CVSS2#` prefix or surrounding parentheses on a 2.0 vector | Accepted; removed on normalization | Same |

Metric keys and values are case sensitive, as in the specifications.

The text field marks each issue that has a character range: errors get a wavy red underline, warnings a
dotted amber one. In the issue list, **Go to position N** selects that part of the vector in the field.

## Security

The components render all text through React, which escapes it, so vectors, error messages, and layer
labels can't inject HTML. If you use the core or your own UI, follow these rules:

- **Store the normalized vector, not the raw input.** `onChange` passes exactly what the user typed,
  valid or not, so the text field can show it. Persist `result.normalized` (or `combined` for layers)
  only when `result.valid` is true. Those strings contain only metric names and values from the CVSS
  specifications.
- **Escape `issue.message` when you render it.** Messages quote the offending part of the input, such as
  `"<img …>" isn't a CVSS 3.1 metric`. Insert them as text, never as HTML (no `innerHTML`, no unescaped
  templates).
- **Input length is limited.** `evaluate` rejects input longer than `maxLength` (default 1,024
  characters) with one `TOO_LONG` error and doesn't parse it. The longest valid vector is 178 characters.
  The same limit applies to base vectors and every layer vector, and the text field won't accept more.
  Keep a limit when you validate vectors on a server.
- **Issues are capped.** Each vector reports at most 20 issues; the rest are summarized in one
  `TOO_MANY_ISSUES` issue.

## Accessibility

The components aim for WCAG 2.2 AA:

- The picker uses native radio buttons in labeled fieldsets: Tab moves between metrics, arrow keys change
  the value, and every control shows a visible focus outline. Collapsed groups open with Enter or Space.
- Errors are linked to the text field with `aria-describedby`. A polite status message summarizes the
  result, such as "Final 9.8 Critical (Base)." or "2 problems. …", after typing pauses, instead of
  announcing every keystroke.
- The underlines in the text field are decoration only. Each issue in the list has a
  **Go to position N** button that moves focus to the field and selects the bad part, so keyboard and
  screen reader users reach the same place.
- Notes about other layers are linked to their metric's radio group, and overridden values in
  `CvssCombined` are labeled for screen readers.
- Text meets 4.5:1 contrast and control borders and focus outlines meet 3:1, in light and dark mode.
  Severity is always shown as text, not only as color.
- In forced-colors modes such as Windows High Contrast, selected options and issue underlines use
  system highlight colors.

`test/a11y.test.tsx` runs axe-core on every component state, and `test/contrast.test.ts` checks the color
tokens. If you override `--cvss-*` colors, check their contrast too.

## Scoring notes

- **4.0** is ported from the [FIRST reference calculator](https://github.com/FIRSTdotorg/cvss-v4-calculator)
  (BSD-2-Clause), including its MacroVector lookup table. Like the current FIRST calculator, it adds an
  epsilon before rounding so that values such as 5.6499999… round to 5.7.
- **3.0 and 3.1** use their own Roundup functions and their own Environmental formulas for a changed scope.
  The 3.1 code matches FIRST's official calculator (`cvsscalc31.js`).
- **2.0** Temporal and Environmental scores follow NVD's CVSS 2.0 calculator by default, because most
  published 2.0 scores come from it. NVD's calculator differs from the 2.0 specification: it doesn't round
  AdjustedBase or AdjustedTemporal, and it uses the rounded Exploitability subscore. As a result, about 15%
  of fully specified 2.0 Environmental scores differ by 0.1 between the two methods. Pass
  `v2Method: 'spec'` (or the `v2Method="spec"` prop) for the literal specification. Base scores are the
  same either way. Severity ratings are the NVD bands (Low, Medium, High), because CVSS 2.0 defines none.

## Development

```sh
npm test          # unit, component, and differential tests
npm run typecheck
npm run build     # dist/ with ESM, CJS, types, and styles.css
npm run dev       # demo page
npm run build:demo  # static demo in demo/dist
```

The demo deploys to GitHub Pages on every push to `master`.

CI runs the typecheck, tests, and build on Node 22 and 24 with React 18 and 19 for every push to
`master` and every pull request.

### Release

The release workflow publishes to npm with [trusted publishing](https://docs.npmjs.com/trusted-publishers),
so no npm token is stored in GitHub, and npm shows a provenance link to the commit.

1. In `CHANGELOG.md`, rename `## [Unreleased]` to the new version with today's date, such as
   `## [0.2.0] - 2026-12-01`, and add an empty `## [Unreleased]` above it.
2. Update `version` in `package.json` and commit.
3. Tag and push: `git tag v0.2.0 && git push origin v0.2.0`.

Before publishing, the workflow checks that the tag matches `package.json` and that `CHANGELOG.md` has a
dated entry for the version. After publishing, it creates a GitHub release with that entry as the notes.

One-time setup on npmjs.com, under the package's **Settings → Trusted publisher**: choose GitHub Actions
and enter owner `0xMattijs`, repository `cvss-input`, workflow `release.yml`, and environment `npm`.

### Tests

- **Official scores.** `test/nvd.test.ts` checks 2,169 unique vectors and scores from the NVD CVE API,
  calculated by NVD or by the CNA that reported the CVE: Base scores for every version, and 126 CVSS 4.0
  vectors with threat metrics. All match. Regenerate the fixture with
  `node scripts/fetch-nvd-fixtures.mjs`. NVD publishes no 2.0 or 3.x Temporal or Environmental scores.
- **Differential tests.** `test/differential.test.ts` scores 5,000 random vectors per version, with
  temporal and environmental metrics set, and compares them with
  [ae-cvss-calculator](https://www.npmjs.com/package/ae-cvss-calculator). Everything must match exactly,
  except that under 0.5% of 2.0 Temporal and Environmental scores may differ by 0.1, where the two
  implementations round floating-point values differently.
- **Hand-checked cases.** `test/evaluate.test.ts` pins 2.0 rounding cases for both methods.
