import { useState } from 'react';
import { storage } from '../platform/storage';

/** Local earlier drafts are shown only on request, never migrated or published. */
export function LegacyDrafts({ prefixes }: { prefixes: string[] }) {
  const [drafts, setDrafts] = useState<{ key: string; title: string; body: string }[]>();const [error, setError] = useState('');
  async function read() {
    try {
      const keys = [...new Set((await Promise.all(prefixes.map(p => storage.keys(p)))).flat())].sort();
      if (keys.length > 100) throw new Error('Too many saved drafts to display safely. Original data is preserved.');
      const values = [];
      for (const key of keys) {
        const value = await storage.get<unknown>(key);
        if (!value || typeof value !== 'object' || !('body' in value) || typeof value.body !== 'string' || value.body.length > 100000
          || !('title' in value) || typeof value.title !== 'string' || value.title.length > 100000) throw new Error('A saved draft could not be read. Original data is preserved.');
        if (value.title || value.body) values.push({ key, title: value.title, body: value.body });
      }
      setDrafts(values);setError('');
    } catch { setError('Saved drafts could not be read safely. Original data is preserved.'); }
  }
  return <section aria-label="Earlier saved drafts"><button onClick={() => void read()}>View saved drafts from this earlier version</button>
    <p>You can copy text into a new private-authorship post. This does not publish, migrate, delete or give authorship to an earlier post.</p>
    {drafts && !drafts.length && <p>No nonempty saved drafts in this earlier discussion scope.</p>}
    {drafts?.map(d => <article key={d.key}><h3>{d.title || 'Comment draft'}</h3><pre className="wallet-post-body">{d.body}</pre></article>)}
    {error && <p role="alert">{error}</p>}
  </section>;
}
