import { test, expect } from '@playwright/test';
import { extractReferences, parsePostUrl } from '../src/urls';
import { DemoCredentialVerifier } from '../src/credentials';

test('post URL normalization preserves exact snowflakes and ignores tracking', () => {
  for (const url of ['https://x.com/someone/status/1900000000000000001?s=20', 'https://twitter.com/other/status/1900000000000000001#reply', 'http://www.twitter.com/name/status/1900000000000000001/photo/1', 'https://x.com/i/web/status/1900000000000000001']) {
    expect(parsePostUrl(url)).toEqual({ postId: '1900000000000000001', url: 'https://x.com/i/status/1900000000000000001' });
  }
  expect(parsePostUrl('https://x.com/reply_author/status/123456').postId).toBe('123456');
});
test('invalid, deceptive and unsupported URLs fail safely', () => {
  for (const url of ['', 'not a url', 'https://x.com/home', 'https://x.com/name/status/nope', 'https://x.com/name/status/0', 'https://x.com.evil.test/name/status/123', 'javascript:alert(1)', 'https://user:password@x.com/name/status/123', 'https://x.com:444/name/status/123', 'https://example.com/a/status/123', 'https://x.com/name/status/123/something', 'https://x.com/name/status/123456789012345678901']) expect(() => parsePostUrl(url)).toThrow();
});
test('zero, one and multiple references, X deduplication and generic links', () => {
  expect(extractReferences('No links here.')).toEqual([]);
  const refs = extractReferences('See https://twitter.com/a/status/123?s=1 and https://x.com/b/status/123. Also https://example.org/research and https://x.com/c/status/456.');
  expect(refs.map((r) => r.postId ?? r.url)).toEqual(['123', 'https://example.org/research', '456']);
  expect(extractReferences('https://x.com/home')).toEqual([]);
});
test('demo verifier never upgrades a claim to cryptographic verification', async () => {
  const verifier = new DemoCredentialVerifier();
  for (const kind of ['x-account', 'followers-1k', 'followers-10k', 'followed-by'] as const) expect((await verifier.verify({ kind })).status).toBe('demo');
});
