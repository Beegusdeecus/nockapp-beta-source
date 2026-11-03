import type { ExternalReference, PostReference } from '../model';
import { parsePostUrl } from '../urls';
import { Icon } from './Icon';
export function References({ references, onSelect }: { references: ExternalReference[]; onSelect: (post: PostReference) => void }) {
  if (!references.length) return null;
  return <div className="reference-links" aria-label="Referenced links">{references.map((ref) => {
    let post: PostReference | undefined;
    try { post = parsePostUrl(ref.url); } catch { /* General external reference. */ }
    return post ? <button key={ref.url} className="reference-link" onClick={() => onSelect(post!)} title="Inspect this post’s NockApp discussions"><Icon name="x" size={12} /><span>…/{post.postId}</span><Icon name="arrow" size={12} /></button>
      : <a key={ref.url} className="reference-link" href={ref.url} target="_blank" rel="noreferrer noopener"><span>{new URL(ref.url).hostname}</span><Icon name="external" size={12} /></a>;
  })}</div>;
}
