/** Consent binding for selected public history; native verification proves authorship. */
import { canonicalAscii } from './authoredWallet';
import { object, exact } from './zkidWire';
import type { PublicIntent } from './data/publicIntents';
import type { PublicExport } from './publicDiscussion';
export function parseHistoryNumbers(input: string): number[] {
  if (!input.trim()) return [];
  if (!/^[1-9][0-9]*(?:\s*,\s*[1-9][0-9]*){0,14}$/.test(input.trim())) throw Error('Enter up to 15 distinct earlier post numbers, separated by commas.');
  const numbers = input.trim().split(',').map(v => Number(v.trim()));
  if (numbers.some(n => !Number.isSafeInteger(n)) || new Set(numbers).size !== numbers.length) throw Error('Earlier post numbers must be distinct supported integers.');
  return numbers;
}
const mismatch = () => Error('The selected authorship links do not match the saved post. Nothing was published by this action. Keep the saved operation.');
export function assertHistoryBinding(intent: PublicIntent, binding: unknown): void {
  if (!intent.history) return; // Legacy saved requests are never reinterpreted.
  if (!object(binding) || !object(binding.core) || !object(binding.core.context)) throw mismatch();
  const { submission_id: _id, ...scope } = binding.core.context;
  const core = binding.core;
  if (canonicalAscii(scope) !== canonicalAscii(intent.scope) || canonicalAscii({post:core.post,selection:core.selection,thread:core.thread,references:core.references})
    !== canonicalAscii({post:intent.post,selection:intent.selection,thread:intent.thread,references:intent.references}) || typeof binding.history !== 'string' || binding.history.length > 21848) throw mismatch();
  try {
    const raw = atob(binding.history);if (btoa(raw) !== binding.history) throw mismatch();
    const text = new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(raw,c=>c.charCodeAt(0)));
    const evidence = JSON.parse(text);
    if (!object(evidence) || !exact(evidence,['profile','records','proof']) || evidence.profile !== 'nockapp-attached-historical-authorship-v5'
      || canonicalAscii(evidence) !== text || !object(evidence.proof) || canonicalAscii(evidence.records) !== canonicalAscii(intent.history.records)) throw mismatch();
  } catch { throw mismatch(); }
}
export async function assertHistoryExport(intent: PublicIntent, value: PublicExport): Promise<void> {
  if (!intent.history) return;
  if (canonicalAscii(value.scope) !== canonicalAscii(intent.scope)) throw mismatch();
  const raw = Uint8Array.from(atob(value.bundle_base64),c=>c.charCodeAt(0));
  if (!raw.length || raw.length > 65536) throw mismatch();
  const hash = '0x'+[...new Uint8Array(await crypto.subtle.digest('SHA-256',raw))].map(b=>b.toString(16).padStart(2,'0')).join('');
  const text = new TextDecoder('utf-8',{fatal:true}).decode(raw);const bundle = JSON.parse(text);
  if (hash !== value.bundle_hash || canonicalAscii(bundle) !== text || !object(bundle) || !object(bundle.unsigned) || !object(bundle.unsigned.evidence)) throw mismatch();
  assertHistoryBinding(intent,{core:bundle.unsigned.core,history:bundle.unsigned.evidence.history});
}
