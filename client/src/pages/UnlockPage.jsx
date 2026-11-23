import { useState } from 'react';
import { unlock } from '../services/account.js';

export default function UnlockPage({ me, onSession, onSignOut }) {
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      onSession(await unlock(me, password));
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  }

  return (
    <main className="auth">
      <section className="card auth-card">
        <h1>Unlock</h1>
        <p className="muted">
          Signed in as <strong>{me.user.username}</strong>. Your keys are kept only in memory, so enter your password to
          unlock them for this tab.
        </p>
        <form onSubmit={submit} className="stack">
          <input type="hidden" autoComplete="username" value={me.user.username} readOnly />
          <label>
            Password
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required autoFocus />
          </label>
          {error && <p className="error" role="alert">{error}</p>}
          <button type="submit" className="primary" disabled={busy}>{busy ? 'Unlocking…' : 'Unlock'}</button>
          <button type="button" className="link" onClick={onSignOut}>Sign out</button>
        </form>
      </section>
    </main>
  );
}
