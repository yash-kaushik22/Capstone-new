import { useCallback, useEffect, useState } from 'react';
import { api } from '../api.js';
import { formatDate, splitAttributes } from '../format.js';

function UserRow({ user, record, onSaved, onError }) {
  const [text, setText] = useState((record?.attributes ?? []).join(', '));
  const [saving, setSaving] = useState(false);

  async function save() {
    setSaving(true);
    try {
      await api.put(`/authority/admin/users/${user.id}/attributes`, { username: user.username, attributes: splitAttributes(text) });
      await onSaved();
    } catch (err) {
      onError(`${user.username}: ${err.message}`);
    } finally {
      setSaving(false);
    }
  }

  async function unlock() {
    try {
      await api.post(`/api/admin/users/${user.id}/unlock`);
      await onSaved();
    } catch (err) {
      onError(err.message);
    }
  }

  return (
    <tr>
      <td>
        {user.username} {user.role === 'admin' && <span className="badge">admin</span>}
        {user.locked && <span className="badge warn">locked</span>}
      </td>
      <td>
        <input value={text} onChange={(e) => setText(e.target.value)} placeholder="no attributes" aria-label={`Attributes for ${user.username}`} />
      </td>
      <td>{record?.version ?? 0}</td>
      <td className="actions">
        <button type="button" className="primary" disabled={saving} onClick={save}>Save</button>
        {user.locked && <button type="button" onClick={unlock}>Unlock</button>}
      </td>
    </tr>
  );
}

export default function AdminPanel() {
  const [users, setUsers] = useState([]);
  const [records, setRecords] = useState({});
  const [events, setEvents] = useState([]);
  const [error, setError] = useState('');

  const load = useCallback(
    () =>
      Promise.all([
        api.get('/api/admin/users'),
        api.get('/authority/admin/users'),
        api.get('/api/admin/audit?limit=100'),
        api.get('/authority/admin/audit?limit=50'),
      ]).then(
        ([u, a, apiAudit, authAudit]) => {
          setUsers(u.users);
          setRecords(Object.fromEntries(a.users.map((r) => [r.userId, r])));
          const merged = [
            ...apiAudit.events.map((e) => ({ ...e, source: 'api', actor: e.username })),
            ...authAudit.events.map((e) => ({ ...e, source: 'authority', outcome: 'ok' })),
          ].sort((x, y) => new Date(y.at) - new Date(x.at));
          setEvents(merged.slice(0, 150));
          setError('');
        },
        (err) => setError(err.message),
      ),
    [],
  );

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="stack-lg">
      {error && <p className="error" role="alert">{error}</p>}
      <section className="card">
        <h2>Users and attributes</h2>
        <p className="muted">
          Attributes are <code>key:value</code> pairs. Saving issues the user a new attribute key and immediately changes
          which files the server will release to them.
        </p>
        <table>
          <thead>
            <tr><th>User</th><th>Attributes</th><th>Version</th><th /></tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <UserRow key={`${u.id}-${records[u.id]?.version ?? 0}`} user={u} record={records[u.id]} onSaved={load} onError={setError} />
            ))}
          </tbody>
        </table>
      </section>
      <section className="card">
        <div className="row-between">
          <h2>Audit log</h2>
          <button type="button" onClick={load}>Refresh</button>
        </div>
        <table className="compact">
          <thead>
            <tr><th>Time</th><th>Source</th><th>Actor</th><th>Action</th><th>Target</th><th>Outcome</th></tr>
          </thead>
          <tbody>
            {events.map((e, i) => (
              <tr key={`${e.source}-${e.id ?? e._id ?? i}`}>
                <td>{formatDate(e.at)}</td>
                <td>{e.source}</td>
                <td>{e.actor ?? '—'}</td>
                <td>{e.action}</td>
                <td className="mono">{e.target ?? ''}</td>
                <td className={e.outcome === 'denied' ? 'warn' : ''}>{e.outcome}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
