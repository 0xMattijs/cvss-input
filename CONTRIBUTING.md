# Contributing

Thanks for helping improve cvss-input. This guide explains how to report problems and send changes.

## Report a bug or request a feature

Open an [issue](https://github.com/0xMattijs/cvss-input/issues). For a scoring bug, include:

- The vector string.
- The score you got and the score you expected.
- Where the expected score comes from, such as the FIRST calculator or an NVD record.

To report a security vulnerability, don't open a public issue. Use
[private vulnerability reporting](https://github.com/0xMattijs/cvss-input/security/advisories/new)
instead.

## Send a change

All changes go through a pull request. For a large change, open an issue first so we can agree on the
approach.

1. Fork the repository and create a branch from `master`.
2. Install dependencies with `npm ci`. You need Node 22 or later.
3. Make your change and add or update tests.
4. Run the checks:

   ```sh
   npm run typecheck
   npm test
   npm run build
   ```

5. Add a line to `CHANGELOG.md` under `## [Unreleased]`, in the matching section, such as `### Added`
   or `### Fixed`. Skip this step for changes that users don't notice, such as test or CI changes.
6. Open a pull request against `master`.

CI runs the same checks on Node 22 and 24 with React 18 and 19. Before the pull request can merge, all
four jobs must pass and the repository owner must approve it.

To try the component in a browser, run `npm run dev` to start the demo page.

## Guidelines

- **Scoring changes.** Scores must match the official calculators. Explain the source of the expected
  score in the pull request, and add a test case in `test/evaluate.test.ts`. The NVD and differential
  tests in `test/nvd.test.ts` and `test/differential.test.ts` must keep passing.
- **User-facing text.** Every text the component shows comes from a message catalog. When you add or
  change a text, update both the English catalog in `src/core/messages.ts` and the Dutch catalog in
  `src/core/locales/nl.ts`. If you don't speak Dutch, say so in the pull request, and the maintainer
  will translate it.
- **Accessibility.** The component meets WCAG contrast and keyboard requirements. `test/a11y.test.tsx`
  and `test/contrast.test.ts` check this; extend them when you add a new state or color.
- **Commit messages.** Write a short summary in the imperative mood, such as
  `Fix rounding of 3.0 Environmental scores`.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
