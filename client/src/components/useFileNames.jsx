import { useEffect, useState } from 'react';

/**
 * Decrypt file names one at a time (CP-ABE unwrapping takes ~100 ms per file).
 * `describe(id)` returns {name,type,size}; failures are shown per file.
 */
export function useFileNames(files, describe, limit = 50) {
  const [names, setNames] = useState({});
  useEffect(() => {
    let cancelled = false;
    (async () => {
      for (const f of files.slice(0, limit)) {
        if (cancelled) return;
        try {
          const meta = await describe(f.id);
          if (!cancelled) setNames((n) => ({ ...n, [f.id]: { name: meta.name } }));
        } catch (err) {
          if (!cancelled) setNames((n) => ({ ...n, [f.id]: { error: err.message } }));
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [files, describe, limit]);
  return names;
}

export function NameCell({ entry }) {
  if (!entry) return <span className="muted">decrypting…</span>;
  if (entry.error) return <span className="warn" title={entry.error}>🔒 cannot decrypt</span>;
  return <span className="filename">{entry.name}</span>;
}
