import { useCallback, useEffect, useState } from 'react';
import { listFiles, describe, download } from '../services/files.js';
import { formatBytes, formatDate } from '../format.js';
import { useFileNames, NameCell } from './useFileNames.jsx';

const NO_FILES = [];

export default function SharedFiles({ session, abeKey, refreshKey }) {
  const [files, setFiles] = useState(NO_FILES);
  const [busy, setBusy] = useState(null);
  const [message, setMessage] = useState(null);

  const reload = useCallback(() => listFiles('shared').then(setFiles).catch((e) => setMessage({ error: e.message })), []);
  useEffect(() => {
    reload();
    refreshKey(); // attributes may have changed since sign-in
  }, [reload, refreshKey]);

  const describeShared = useCallback((id) => describe(session, abeKey, id), [session, abeKey]);
  const names = useFileNames(abeKey ? files : NO_FILES, describeShared);

  async function onDownload(id) {
    setMessage(null);
    try {
      const key = (await refreshKey()) ?? abeKey; // pick up attribute changes before decrypting
      const meta = await download(session, key, id, setBusy);
      setMessage({ ok: `Verified owner signature and decrypted “${meta.name}”.` });
    } catch (err) {
      setMessage({ error: err.message });
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="card">
      <div className="row-between">
        <h2>Shared with me</h2>
        <button type="button" onClick={() => { reload(); refreshKey(); }}>Refresh</button>
      </div>
      <p className="muted">Files whose access policy your current attributes satisfy.</p>
      {message?.error && <p className="error" role="alert">{message.error}</p>}
      {message?.ok && <p className="success" role="status">{message.ok}</p>}
      {busy && <p className="muted">{busy.stage}…</p>}
      {!abeKey && <p className="muted">Waiting for your attribute key…</p>}
      {files.length === 0 ? (
        <p className="muted">Nothing here yet.</p>
      ) : (
        <table>
          <thead>
            <tr><th>Name</th><th>Owner</th><th>Policy</th><th>Size</th><th>Shared</th><th /></tr>
          </thead>
          <tbody>
            {files.map((f) => (
              <tr key={f.id}>
                <td><NameCell entry={names[f.id]} /></td>
                <td>{f.ownerUsername}</td>
                <td><code className="policy">{f.policy}</code></td>
                <td>{formatBytes(f.size)}</td>
                <td>{formatDate(f.updatedAt || f.createdAt)}</td>
                <td className="actions">
                  <button type="button" className="primary" disabled={!abeKey || Boolean(busy)} onClick={() => onDownload(f.id)}>Download</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
