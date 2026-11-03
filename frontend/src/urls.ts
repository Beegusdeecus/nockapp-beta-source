import type { ExternalReference, PostReference } from './model';

const hosts = new Set(['x.com', 'www.x.com', 'twitter.com', 'www.twitter.com', 'mobile.twitter.com']);

export function parsePostUrl(input: string): PostReference {
  let url: URL;
  try { url = new URL(input.trim()); } catch { throw new Error('Enter a complete X post URL, such as https://x.com/name/status/123456.'); }
  if (!['https:', 'http:'].includes(url.protocol) || !hosts.has(url.hostname) || url.username || url.password || url.port) {
    throw new Error('Use a post link from x.com or twitter.com.');
  }
  const match = url.pathname.match(/^\/(?:[a-zA-Z0-9_]{1,15}|i)\/status\/(\d+)(?:\/(?:photo|video)\/\d+)?\/?$/)
    ?? url.pathname.match(/^\/i\/web\/status\/(\d+)\/?$/);
  if (!match || /^0+$/.test(match[1]) || match[1].length > 20) throw new Error('This is not an individual post link. Copy a post or reply’s permalink.');
  // IDs are strings: real snowflakes exceed JavaScript's safe integer range.
  const postId = match[1].replace(/^0+(?=\d)/, '');
  return { postId, url: `https://x.com/i/status/${postId}` };
}

export function extractReferences(body: string, initial: ExternalReference[] = []): ExternalReference[] {
  const refs = new Map(initial.map((r) => [r.postId ?? r.url, r]));
  for (const raw of body.match(/https?:\/\/[^\s<>"']+/g) ?? []) {
    const text = raw.replace(/[.,!?;:)\]}]+$/, '');
    try {
      const url = new URL(text);
      if (url.username || url.password) continue;
      let ref: ExternalReference = { url: url.href };
      if (hosts.has(url.hostname)) { ref = parsePostUrl(text); }
      refs.set(ref.postId ?? ref.url, ref);
    } catch { /* Ordinary text stays readable even when a URL is incomplete. */ }
  }
  return [...refs.values()].slice(0, 20);
}

export function relativeTime(time: number): string {
  const minutes = Math.max(0, Math.floor((Date.now() - time) / 60_000));
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  if (minutes < 1440) return `${Math.floor(minutes / 60)}h ago`;
  return `${Math.floor(minutes / 1440)}d ago`;
}
