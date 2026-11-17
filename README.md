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

The differential tests score 5,000 random vectors per version and compare them with
[ae-cvss-calculator](https://www.npmjs.com/package/ae-cvss-calculator). Base, Temporal, and Environmental
scores for 3.0 and 3.1, and all 4.0 scores, must match exactly. For 2.0, only Base must match exactly:
the reference library doesn't round AdjustedTemporal and lets floating-point noise decide x.x5 cases, so
Temporal and Environmental may differ by 0.1. `test/evaluate.test.ts` pins those boundary cases with
hand-checked values.
