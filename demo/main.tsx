import { StrictMode, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { CvssInput } from '../src';
import type { VersionMode } from '../src';
import '../src/react/styles.css';
import './demo.css';
import { LayeredExample } from './LayeredExample';

const BASE = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';

function Demo() {
  const [vector, setVector] = useState('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/E:P');
  const [version, setVersion] = useState<VersionMode>('auto');
  const [strict, setStrict] = useState(false);
  const [overlay, setOverlay] = useState('E:F/RL:O');

  return (
    <main>
      <h1>cvss-input</h1>
      <p className="hint">
        A React component and scoring core for CVSS 2.0, 3.0, 3.1, and 4.0 vectors.{' '}
        <a href="https://github.com/0xMattijs/cvss-input">Source on GitHub</a>
      </p>

      <section>
        <h2>Auto or forced version</h2>
        <div className="controls">
          <label>
            Version{' '}
            <select value={version} onChange={(e) => setVersion(e.target.value as VersionMode)}>
              {['auto', '2.0', '3.0', '3.1', '4.0'].map((v) => (
                <option key={v}>{v}</option>
              ))}
            </select>
          </label>
          <label>
            <input type="checkbox" checked={strict} onChange={(e) => setStrict(e.target.checked)} /> Strict
          </label>
        </div>
        <div className="samples">
          {[
            'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/E:P',
            'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P',
            'AV:N/AC:L/Au:N/C:P/I:P/A:P/E:F/RL:OF/RC:C',
            'CVSS:3.1/E:F/A:H/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H',
            'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            '',
          ].map((s) => (
            <button key={s} type="button" onClick={() => setVector(s)}>
              {s === '' ? '(empty)' : s.length > 34 ? s.slice(0, 34) + '…' : s}
            </button>
          ))}
        </div>
        <CvssInput value={vector} onChange={setVector} version={version} strict={strict} />
      </section>

      <section>
        <h2>Temporal and environmental on a base vector</h2>
        <CvssInput value={overlay} onChange={setOverlay} baseVector={BASE} />
      </section>

      <section>
        <h2>Vulnerabilities on assets (layers)</h2>
        <p className="hint">
          The base vector belongs to the vulnerability, exploit maturity to a threat feed, and
          security requirements and modified metrics to the asset. See demo/LayeredExample.tsx.
        </p>
        <LayeredExample />
      </section>
    </main>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Demo />
  </StrictMode>,
);
