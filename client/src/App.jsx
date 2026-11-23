import { useEffect, useState } from 'react';
import AuthPage from './pages/AuthPage.jsx';
import UnlockPage from './pages/UnlockPage.jsx';
import Dashboard from './pages/Dashboard.jsx';
import { currentSession, logout } from './services/account.js';

export default function App() {
  const [state, setState] = useState({ phase: 'loading' });

  useEffect(() => {
    currentSession()
      .then((me) => setState({ phase: 'locked', me }))
      .catch(() => setState({ phase: 'signedOut' }));
  }, []);

  const signOut = async () => {
    await logout().catch(() => {});
    setState({ phase: 'signedOut' }); // in-memory keys are dropped with the state
  };

  if (state.phase === 'loading') return <div className="center muted">Loading…</div>;
  if (state.phase === 'signedOut') return <AuthPage onSession={(session) => setState({ phase: 'ready', session })} />;
  if (state.phase === 'locked') {
    return <UnlockPage me={state.me} onSession={(session) => setState({ phase: 'ready', session })} onSignOut={signOut} />;
  }
  return <Dashboard session={state.session} onSignOut={signOut} />;
}
