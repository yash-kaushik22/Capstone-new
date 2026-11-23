import { useCallback, useEffect, useRef, useState } from 'react';
import { fetchAbeKey } from '../services/account.js';
import MyFiles from '../components/MyFiles.jsx';
import SharedFiles from '../components/SharedFiles.jsx';
import KeysPanel from '../components/KeysPanel.jsx';
import AdminPanel from '../components/AdminPanel.jsx';

export default function Dashboard({ session, onSignOut }) {
  const isAdmin = session.user.role === 'admin';
  const [tab, setTab] = useState('mine');
  const [abeKey, setAbeKey] = useState(null);
  const [abeError, setAbeError] = useState('');
  const keyRef = useRef(null);

  const refreshKey = useCallback(
    () =>
      fetchAbeKey(session).then(
        (fresh) => {
          setAbeError('');
          // Keep the same object when nothing changed so dependent views do not re-decrypt.
          const prev = keyRef.current;
          if (prev && prev.version === fresh.version && prev.attributes.join() === fresh.attributes.join()) return prev;
          keyRef.current = fresh;
          setAbeKey(fresh);
          return fresh;
        },
        (err) => {
          setAbeError(err.message);
          return null;
        },
      ),
    [session],
  );

  useEffect(() => {
    refreshKey();
    const onFocus = () => refreshKey();
    window.addEventListener('focus', onFocus);
    return () => window.removeEventListener('focus', onFocus);
  }, [refreshKey]);

  const tabs = [
    ['mine', 'My files'],
    ['shared', 'Shared with me'],
    ['keys', 'Keys & attributes'],
    ...(isAdmin ? [['admin', 'Administration']] : []),
  ];

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">SecureShare</div>
        <nav className="tabs" role="tablist">
          {tabs.map(([id, label]) => (
            <button key={id} type="button" role="tab" aria-selected={tab === id} className={tab === id ? 'on' : ''} onClick={() => setTab(id)}>
              {label}
            </button>
          ))}
        </nav>
        <div className="who">
          <span>{session.user.username}</span>
          {isAdmin && <span className="badge">admin</span>}
          <button type="button" className="link" onClick={onSignOut}>Sign out</button>
        </div>
      </header>
      {abeError && <div className="banner warn">Could not load your attribute key: {abeError}</div>}
      <main className="content">
        {tab === 'mine' && <MyFiles session={session} />}
        {tab === 'shared' && <SharedFiles session={session} abeKey={abeKey} refreshKey={refreshKey} />}
        {tab === 'keys' && <KeysPanel session={session} abeKey={abeKey} refreshKey={refreshKey} />}
        {tab === 'admin' && isAdmin && <AdminPanel />}
      </main>
    </div>
  );
}
