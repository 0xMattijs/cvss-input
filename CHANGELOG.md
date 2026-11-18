# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/).

Each release needs a dated entry, such as `## [0.2.0] - 2026-12-01`, before you tag it: the release
workflow checks the entry and uses it as the GitHub release notes. Collect changes under
`## [Unreleased]` until then.

## [Unreleased]

## [0.1.0] - 2026-11-18

First release.

### Added

- `CvssInput`: a React component to enter a CVSS vector as text, with a metric picker, or both. It
  shows the scores the version defines and explains every problem in the vector.
- Support for CVSS 2.0, 3.0, 3.1, and 4.0. Auto mode detects the version; a forced version validates
  the vector against it.
- Overlays: with `baseVector`, the input accepts only temporal, threat, and environmental metrics on
  top of a known base vector.
- Layered scoring: `evaluateLayers`, `useCvssLayers`, and `CvssCombined` combine a vulnerability's base
  vector with other sources, such as a threat feed or an asset's security requirements. Conflicts
  between layers are errors by default, or resolved by a rule you choose.
- A final score in every result (`scores.overall`): the Environmental score if any environmental
  metric is set, otherwise Temporal, otherwise Base. For 4.0, the single score with its nomenclature.
- Lenient mode (the default) accepts metrics in any order and rewrites the vector in canonical order
  when the field loses focus. Strict mode treats that as an error.
- Error marks in the text field, and a **Go to position** button for each issue that selects the bad
  part of the vector.
- Languages: English and Dutch catalogs (`en`, `nl`) for every text, including metric and value names
  and issue messages. Set one with `CvssMessagesProvider` or the `messages` prop. Scores follow the
  language's number format. Issues carry `params`, and `formatIssue` formats them in any language.
- `valueOrder`: shows each metric's values as in FIRST's calculator (the default), least severe first,
  or most severe first.
- `v2Method`: CVSS 2.0 Temporal and Environmental scores as NVD's calculator computes them (the
  default), or exactly as the specification describes.
- A scoring core without React, exported as `cvss-input/core`.
- Accessibility: native radio groups, a debounced status message for screen readers, WCAG 2.2 AA
  contrast in light and dark mode, and support for forced-colors mode.
- Input limits: vectors longer than `maxLength` (1,024 characters by default) aren't parsed, and each
  vector reports at most 20 issues.

### Verified

- Base scores match NVD for 2,169 published vectors across all four versions.
- Scores match an independent implementation (ae-cvss-calculator) on 5,000 random vectors per version.
