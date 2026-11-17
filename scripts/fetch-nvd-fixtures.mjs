// Builds test/fixtures/nvd-scores.json from the NVD CVE API: one entry per unique
// (version, vector, score) published by NVD or a CNA.
//
// Usage:
//   node scripts/fetch-nvd-fixtures.mjs                # download sample pages, then build
//   node scripts/fetch-nvd-fixtures.mjs --pages <dir>  # build from pages already downloaded
//
// Without an API key, NVD allows 5 requests per 30 seconds, so downloads pause between pages.

import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const PAGE_SIZE = 2000;
const OUT = new URL('../test/fixtures/nvd-scores.json', import.meta.url);
const METRIC_KEYS = { cvssMetricV2: '2.0', cvssMetricV30: '3.0', cvssMetricV31: '3.1', cvssMetricV40: '4.0' };

async function download(dir) {
  const head = await fetchJson(`${API}?resultsPerPage=1&startIndex=0`);
  const total = head.totalResults;
  // Spread pages across the whole range: old CVEs carry 2.0 scores, new ones 3.x and 4.0.
  const starts = [];
  for (let s = 0; s < total; s += 40000) starts.push(s);
  starts.push(Math.max(0, total - PAGE_SIZE));
  for (const start of starts) {
    const page = await fetchJson(`${API}?resultsPerPage=${PAGE_SIZE}&startIndex=${start}`);
    writeFileSync(join(dir, `page-${start}.json`), JSON.stringify(page));
    console.log(`page ${start}: ${page.vulnerabilities.length} CVEs`);
    await new Promise((r) => setTimeout(r, 7000));
  }
}

async function fetchJson(url) {
  const res = await fetch(url, { headers: { 'User-Agent': 'cvss-test-fixtures' } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} for ${url}`);
  return res.json();
}

function build(dir) {
  const records = new Map();
  for (const file of readdirSync(dir).filter((f) => f.endsWith('.json'))) {
    const data = JSON.parse(readFileSync(join(dir, file), 'utf8'));
    for (const { cve } of data.vulnerabilities) {
      for (const [key, version] of Object.entries(METRIC_KEYS)) {
        for (const metric of cve.metrics?.[key] ?? []) {
          const { vectorString, baseScore } = metric.cvssData;
          if (typeof vectorString !== 'string' || typeof baseScore !== 'number') continue;
          const id = `${version}|${vectorString}|${baseScore}`;
          if (!records.has(id)) records.set(id, [version, vectorString, baseScore, cve.id]);
        }
      }
    }
  }
  const rows = [...records.values()].sort((a, b) => a[0].localeCompare(b[0]) || a[1].localeCompare(b[1]));
  const body = rows.map((r) => '  ' + JSON.stringify(r)).join(',\n');
  writeFileSync(
    OUT,
    `{\n "source": "NVD CVE API 2.0 (${API})",\n "fields": ["version", "vector", "baseScore", "exampleCve"],\n "rows": [\n${body}\n ]\n}\n`,
  );
  console.log(`wrote ${rows.length} rows to ${OUT.pathname}`);
}

const pagesFlag = process.argv.indexOf('--pages');
let dir;
if (pagesFlag >= 0) {
  dir = process.argv[pagesFlag + 1];
} else {
  dir = join(tmpdir(), `nvd-pages-${Date.now()}`);
  mkdirSync(dir);
  try {
    await download(dir);
    build(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
if (pagesFlag >= 0) build(dir);
