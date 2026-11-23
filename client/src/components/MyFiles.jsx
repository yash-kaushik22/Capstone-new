import { useCallback, useEffect, useState } from 'react';
import { api } from '../api.js';
import { uploadFile, listFiles, describe, download, changePolicy, deleteFile } from '../services/files.js';
import { formatBytes, formatDate } from '../format.js';
import PolicyEditor, { checkPolicy } from './PolicyEditor.jsx';
import { useFileNames, NameCell } from './useFileNames.jsx';

function Progress({ progress }) {
  if (!progress) return null;
  return (
    <div className="progress">
      <span>{progress.stage}…</span>
      {progress.value == null ? <progress /> : <progress value={progress.value} max={1} />}
    </div>
  );
}

export default function MyFiles({ session }) {
  const [files, setFiles] = useState([]);
  const [file, setFile] = useState(null);
  const [policy, setPolicy] = useState('');
  const [limit, setLimit] = useState(null);
  const [progress, setProgress] = useState(null);
  const [message, setMessage] = useState(null);
  const [editing, setEditing] = useState(null); // { id, policy }

  const reload = useCallback(() => listFiles('owned').then(setFiles).catch((e) => setMessage({ error: e.message })), []);
  useEffect(() => {
    reload();
    api.get('/api/meta').then((m) => setLimit(m.maxUploadBytes)).catch(() => {});
  }, [reload]);

  const describeOwn = useCallback((id) => describe(session, null, id), [session]);
  const names = useFileNames(files, describeOwn);

  const check = policy.trim() ? checkPolicy(policy) : { error: 'Enter an access policy' };
  const tooBig = file && limit && file.size + 1024 > limit;

  async function onUpload(e) {
    e.preventDefault();
    if (!file || check.error || tooBig) return;
    setMessage(null);
    try {
      await uploadFile(session, file, policy, setProgress);
      setMessage({ ok: `Encrypted and uploaded “${file.name}”.` });
      setFile(null);
      e.target.reset();
      reload();
    } catch (err) {
      setMessage({ error: err.message });
    } finally {
      setProgress(null);
    }
  }

  async function run(fn, okText) {
    setMessage(null);
    try {
      await fn();
      if (okText) setMessage({ ok: okText });
    } catch (err) {
      setMessage({ error: err.message });
    } finally {
      setProgress(null);
    }
  }

  async function savePolicy() {
    const c = checkPolicy(editing.policy);
    if (c.error) return setMessage({ error: c.error });
    await run(async () => {
      await changePolicy(session, editing.id, editing.policy);
      setEditing(null);
      await reload();
    }, 'Policy updated. Users who already downloaded the file keep their copy.');
  }

  return (
    <div className="stack-lg">
      <section className="card">
        <h2>Encrypt and share a file</h2>
        <form onSubmit={onUpload} className="stack">
          <label>
            File
            <input type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} required />
          </label>
          {file && <p className="hint">{formatBytes(file.size)}{tooBig && <span className="warn"> exceeds the {formatBytes(limit)} limit</span>}</p>}
          <PolicyEditor value={policy} onChange={setPolicy} />
          <button type="submit" className="primary" disabled={!file || Boolean(check.error) || tooBig || Boolean(progress)}>
            Encrypt &amp; upload
          </button>
          <Progress progress={progress} />
        </form>
      </section>

      {message?.error && <p className="error" role="alert">{message.error}</p>}
      {message?.ok && <p className="success" role="status">{message.ok}</p>}

      <section className="card">
        <h2>My files</h2>
        {files.length === 0 ? (
          <p className="muted">You have not uploaded anything yet.</p>
        ) : (
          <table>
            <thead>
              <tr><th>Name</th><th>Policy</th><th>Size</th><th>Uploaded</th><th /></tr>
            </thead>
            <tbody>
              {files.map((f) => (
                <tr key={f.id}>
                  <td><NameCell entry={names[f.id]} /></td>
                  <td>
                    {editing?.id === f.id ? (
                      <div className="stack">
                        <PolicyEditor id={`p-${f.id}`} value={editing.policy} onChange={(p) => setEditing({ id: f.id, policy: p })} />
                        <div className="inline">
                          <button type="button" className="primary" onClick={savePolicy}>Save</button>
                          <button type="button" onClick={() => setEditing(null)}>Cancel</button>
                        </div>
                      </div>
                    ) : (
                      <code className="policy">{f.policy}</code>
                    )}
                  </td>
                  <td>{formatBytes(f.size)}</td>
                  <td>{formatDate(f.createdAt)}</td>
                  <td className="actions">
                    <button type="button" onClick={() => run(() => download(session, null, f.id, setProgress))}>Download</button>
                    <button type="button" onClick={() => setEditing({ id: f.id, policy: f.policy })}>Change policy</button>
                    <button
                      type="button"
                      className="danger"
                      onClick={() => window.confirm('Delete this file for everyone?') && run(async () => { await deleteFile(f.id); await reload(); }, 'File deleted.')}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
