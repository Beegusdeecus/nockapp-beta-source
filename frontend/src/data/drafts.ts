import { api } from '../platform/browser';
import type { CredentialClaim, PassportFact, ZkidFact } from '../model';
import { validZkidFacts } from '../zkidWire';
import { validFacts } from '../postScope';
import { exclusive, isExtension, storage } from '../platform/storage';
import { validCredentials } from './repository';

export type Draft = { title: string; body: string; credentials: CredentialClaim[]; passportFacts?: PassportFact[]; zkidFacts?: ZkidFact[] };
type StoredDraft = Draft & { recoveredLegacyKeys?: string[] };
const empty = (): Draft => ({ title: '', body: '', credentials: [] });
function normalize(value: StoredDraft | undefined): StoredDraft {
  if (!value) return empty();
  if (typeof value.title !== 'string' || typeof value.body !== 'string'
    || (value.credentials !== undefined && !validCredentials(value.credentials))
    || (value.passportFacts !== undefined && !validFacts(value.passportFacts))
    || (value.zkidFacts !== undefined && !validZkidFacts(value.zkidFacts))
    || (value.recoveredLegacyKeys !== undefined && (!Array.isArray(value.recoveredLegacyKeys) || value.recoveredLegacyKeys.some((k) => typeof k !== 'string')))) {
    throw new Error('This draft could not be read. Saved data has been preserved.');
  }
  return { ...value, credentials: value.credentials ?? [] };
}

export function readDraft(key: string, legacyTargets: Record<string, string> = {}): Promise<Draft> {
  return exclusive(`draft:${key}`, async () => {
    const storageKey = `draft:${key}`;
    const draft = normalize(await storage.get<StoredDraft>(storageKey));
    const match = key.match(/^reply:(.+):root$/);
    if (match) {
      const prefix = `draft:reply:${match[1]}:`;
      const seen = new Set(draft.recoveredLegacyKeys ?? []);
      const keys = (await storage.keys(prefix)).filter((k) => k !== storageKey && !seen.has(k)).sort();
      for (const oldKey of keys) {
        const old = normalize(await storage.get<StoredDraft>(oldKey));
        if (old.body.trim()) {
          const number = legacyTargets[oldKey.slice(prefix.length)];
          draft.body += `${draft.body ? '\n\n' : ''}${number ? `>>${number}\n` : ''}${old.body}`;
        }
        seen.add(oldKey);
      }
      if (keys.length) {
        // Body and source markers are saved together. A failed write cannot mark
        // an unsaved recovery complete, or duplicate it on the next attempt.
        draft.recoveredLegacyKeys = [...seen];
        await storage.set(storageKey, draft);
      }
    }
    return { title: draft.title, body: draft.body, credentials: draft.credentials,
      ...(draft.passportFacts?.length ? { passportFacts: draft.passportFacts } : {}),
      ...(draft.zkidFacts?.length ? { zkidFacts: draft.zkidFacts } : {}) };
  });
}
export function persistDraft(key: string, draft: Draft): Promise<void> {
  return exclusive(`draft:${key}`, async () => {
    const previous = normalize(await storage.get<StoredDraft>(`draft:${key}`));
    // Retain recovery markers even when a successful post clears the draft.
    await storage.set(`draft:${key}`, { ...draft, recoveredLegacyKeys: previous.recoveredLegacyKeys });
  });
}

export function clearDraftIfUnchanged(key: string, submitted: Draft): Promise<boolean> {
  return exclusive(`draft:${key}`, async () => {
    const current = normalize(await storage.get<StoredDraft>(`draft:${key}`));
    const same = current.title === submitted.title && current.body === submitted.body
      && JSON.stringify(current.credentials) === JSON.stringify(submitted.credentials)
      && JSON.stringify(current.passportFacts ?? []) === JSON.stringify(submitted.passportFacts ?? [])
      && JSON.stringify(current.zkidFacts ?? []) === JSON.stringify(submitted.zkidFacts ?? []);
    if (!same) return false;
    await storage.set(`draft:${key}`, { ...empty(), recoveredLegacyKeys: current.recoveredLegacyKeys });return true;
  });
}

export function isDraftRequest(value: unknown): value is { type: 'save-draft'; key: string; draft: Draft } {
  if (!value || typeof value !== 'object') return false;
  const message = value as { type?: string; key?: string; draft?: Draft };
  return message.type === 'save-draft' && typeof message.key === 'string'
    && /^(thread|reply):/.test(message.key) && !!message.draft
    && typeof message.draft.title === 'string' && typeof message.draft.body === 'string'
    && validCredentials(message.draft.credentials)
    && (message.draft.passportFacts === undefined || validFacts(message.draft.passportFacts))
    && (message.draft.zkidFacts === undefined || validZkidFacts(message.draft.zkidFacts));
}
export async function writeDraft(key: string, draft: Draft): Promise<void> {
  if (!isExtension) return persistDraft(key, draft);
  // Send immediately from the input event. The worker completes this write even
  // if the panel reloads before its asynchronous storage work has finished.
  const result = await api().runtime.sendMessage({ type: 'save-draft', key, draft }) as { ok: boolean; error?: string };
  if (!result?.ok) throw new Error(result?.error ?? 'Could not save your draft.');
}
