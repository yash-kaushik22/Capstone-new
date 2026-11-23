import { useState } from 'react';
import { login, register } from '../services/account.js';
import { passwordProblems } from '../format.js';

export default function AuthPage({ onSession }) {
  const [mode, setMode] = useState('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');

  const problems = mode === 'register' ? passwordProblems(password) : [];
  const mismatch = mode === 'register' && confirm && confirm !== password;

  async function submit(e) {
    e.preventDefault();
    setError('');
    if (mode === 'register' && (problems.length || confirm !== password)) return;
    try {
      setBusy(mode === 'register' ? 'Generating your keys…' : 'Deriving keys…');
      const session = mode === 'register' ? await register(username, password) : await login(username, password);
      onSession(session);
    } catch (err) {
      setError(err.message);
      setBusy('');
    }
  }

  return (
    <main className="auth">
      <section className="card auth-card">
        <h1>SecureShare</h1>
        <p className="muted">
          Files are encrypted in your browser and shared by attribute policy. The server never sees your password,
          your keys or your files.
        </p>
        <div className="segmented" role="tablist">
          <button type="button" role="tab" aria-selected={mode === 'login'} className={mode === 'login' ? 'on' : ''} onClick={() => setMode('login')}>Sign in</button>
          <button type="button" role="tab" aria-selected={mode === 'register'} className={mode === 'register' ? 'on' : ''} onClick={() => setMode('register')}>Create account</button>
        </div>
        <form onSubmit={submit} className="stack">
          <label>
            Username
            <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required minLength={3} maxLength={32} pattern="[A-Za-z0-9_]+" />
          </label>
          <label>
            Password
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete={mode === 'login' ? 'current-password' : 'new-password'} required />
          </label>
          {mode === 'register' && (
            <>
              <label>
                Confirm password
                <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" required />
              </label>
              {password && problems.length > 0 && <p className="hint warn">Use {problems.join(' and ')}.</p>}
              {mismatch && <p className="hint warn">Passwords do not match.</p>}
              <p className="hint">Your password also unlocks your private keys. If you forget it, nobody can recover your files.</p>
            </>
          )}
          {error && <p className="error" role="alert">{error}</p>}
          <button type="submit" className="primary" disabled={Boolean(busy)}>{busy || (mode === 'login' ? 'Sign in' : 'Create account')}</button>
        </form>
      </section>
    </main>
  );
}
