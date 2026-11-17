// @vitest-environment node
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
// @ts-expect-error: plain JavaScript script without type declarations
import { changelogSection } from '../scripts/changelog-section.mjs';

const read = (file: string) => readFileSync(new URL(`../${file}`, import.meta.url), 'utf8');

describe('changelog', () => {
  it('has an entry for the version in package.json', () => {
    const { version } = JSON.parse(read('package.json'));
    expect(changelogSection(read('CHANGELOG.md'), version).body).toContain('### ');
  });

  const sample = [
    '# Changelog',
    '## [Unreleased]',
    '## [1.2.0] - 2026-12-01',
    '### Fixed',
    '- A bug.',
    '## [1.10.0] - Unreleased',
    '### Added',
    '- A feature.',
    '## [1.1.0]',
    '',
  ].join('\n');

  it('returns the entry up to the next heading', () => {
    expect(changelogSection(sample, '1.2.0', { dated: true })).toEqual({
      date: '2026-12-01',
      body: '### Fixed\n- A bug.',
    });
  });

  it('matches the version exactly', () => {
    expect(changelogSection(sample, '1.10.0').body).toBe('### Added\n- A feature.');
    expect(() => changelogSection(sample, '1.1')).toThrow('no entry for 1.1');
  });

  it('requires a release date when asked', () => {
    expect(() => changelogSection(sample, '1.10.0', { dated: true })).toThrow('no release date');
  });

  it('rejects an empty entry', () => {
    expect(() => changelogSection(sample, '1.1.0')).toThrow('is empty');
  });
});
