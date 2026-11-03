import type { ReactNode } from 'react';

export function PostBody({ body, onReference, className }: { body: string; onReference: (number: string) => void; className: string }) {
  const parts: ReactNode[] = [];
  const pattern = />>([1-9]\d{0,15})(?!\d)/g;
  let start = 0;
  for (const match of body.matchAll(pattern)) {
    parts.push(body.slice(start, match.index));
    const number = match[1];
    parts.push(<button key={match.index} className="post-quote" onClick={() => onReference(number)} aria-label={`Go to post No.${number}`}>{match[0]}</button>);
    start = match.index! + match[0].length;
  }
  parts.push(body.slice(start));
  return <p className={className}>{parts}</p>;
}
export function PostId({ number, onCopied }: { number: string; onCopied: (message: string) => void }) {
  return <button className="post-id" aria-label={`Copy reference to post No.${number}`} title="Copy this post’s >>ID reference" onClick={() => {
    void navigator.clipboard.writeText(`>>${number}`).then(() => onCopied(`Reference >>${number} copied.`)).catch(() => onCopied(`Use >>${number} to reference this post.`));
  }}>No.{number}</button>;
}
