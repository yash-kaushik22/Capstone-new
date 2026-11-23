import { useEffect, useMemo, useState } from 'react';
import { policy as policyLib } from '@secureshare/crypto';
import { api } from '../api.js';

/** Validate a policy as the user types; returns { canonical, attributes } or { error }. */
export function checkPolicy(text) {
  try {
    const ast = policyLib.parsePolicy(text);
    return { canonical: policyLib.formatPolicy(ast), attributes: policyLib.attributesOf(ast) };
  } catch (err) {
    return { error: err.message };
  }
}

function append(text, piece, op) {
  const t = text.trim();
  if (!t) return piece;
  return op === 'OR' ? `(${t}) OR ${piece}` : `${t} AND ${piece}`;
}

export default function PolicyEditor({ value, onChange, id = 'policy' }) {
  const [catalog, setCatalog] = useState([]);
  const [userName, setUserName] = useState('');
  const result = useMemo(() => (value.trim() ? checkPolicy(value) : null), [value]);

  useEffect(() => {
    api.get('/authority/catalog').then((r) => setCatalog(r.attributes)).catch(() => setCatalog([]));
  }, []);

  function addUser() {
    const name = userName.trim().toLowerCase();
    if (!/^[a-z0-9_]{3,32}$/.test(name)) return;
    onChange(append(value, `user:${name}`, 'OR'));
    setUserName('');
  }

  return (
    <div className="policy-editor">
      <label htmlFor={id}>Access policy</label>
      <textarea
        id={id}
        rows={2}
        value={value}
        spellCheck={false}
        placeholder="e.g. (dept:cse AND role:faculty) OR user:alice"
        onChange={(e) => onChange(e.target.value)}
      />
      {result?.error && <p className="hint warn">{result.error}</p>}
      {result?.canonical && (
        <p className="hint ok">
          Readable by anyone whose attributes satisfy <code>{result.canonical}</code>
        </p>
      )}
      {catalog.length > 0 && (
        <div className="chips" aria-label="Known attributes">
          {catalog.map((a) => (
            <button key={a} type="button" className="chip" title="Add with AND" onClick={() => onChange(append(value, a, 'AND'))}>
              {a}
            </button>
          ))}
        </div>
      )}
      <div className="inline">
        <input value={userName} onChange={(e) => setUserName(e.target.value)} placeholder="username" aria-label="Also allow user" />
        <button type="button" onClick={addUser}>Also allow user</button>
      </div>
    </div>
  );
}
