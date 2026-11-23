import { useEffect, useState } from 'react';
import { authorityParams, fingerprints } from '../services/account.js';
import { formatDate } from '../format.js';

export default function KeysPanel({ session, abeKey, refreshKey }) {
  const [fps, setFps] = useState(null);
  const [authority, setAuthority] = useState(null);

  useEffect(() => {
    fingerprints(session).then(setFps);
    authorityParams().then(setAuthority).catch(() => {});
  }, [session]);

  return (
    <div className="stack-lg">
      <section className="card">
        <div className="row-between">
          <h2>My attributes</h2>
          <button type="button" onClick={refreshKey}>Refresh key</button>
        </div>
        {abeKey ? (
          <>
            <div className="chips">
              {abeKey.attributes.map((a) => <span key={a} className="chip static">{a}</span>)}
            </div>
            <p className="hint">
              Attribute key version {abeKey.version}, issued {formatDate(abeKey.issuedAt)}. The <code>user:</code> attribute is
              added automatically so people can share with you by name. Ask an administrator to change your attributes.
            </p>
          </>
        ) : (
          <p className="muted">Loading…</p>
        )}
      </section>
      <section className="card">
        <h2>Fingerprints</h2>
        <p className="muted">Compare these with other people over a separate channel to detect key substitution.</p>
        <dl className="kv">
          <dt>Your encryption key</dt>
          <dd><code>{fps?.enc}</code></dd>
          <dt>Your signing key</dt>
          <dd><code>{fps?.sig}</code></dd>
          <dt>Attribute authority</dt>
          <dd><code>{authority?.fingerprint}</code></dd>
        </dl>
      </section>
    </div>
  );
}
