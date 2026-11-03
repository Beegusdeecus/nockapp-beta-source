import { api } from './browser';
import type { Selection } from '../model';
import { isExtension, storage } from './storage';

export async function windowKey(): Promise<string> {
  return isExtension ? String((await api().windows.getCurrent()).id) : 'preview';
}
export async function getSelection(key: string): Promise<Selection | undefined> {
  if (!isExtension) return undefined;
  return (await api().storage.session.get(`selection:${key}`))[`selection:${key}`] as Selection | undefined;
}
export function subscribeSelection(key: string, callback: (selection: Selection) => void): () => void {
  if (!isExtension) return () => {};
  const listener = (changes: Record<string, chrome.storage.StorageChange>, area: string) => {
    const value = changes[`selection:${key}`]?.newValue as Selection | undefined;
    if (area === 'session' && value) callback(value);
  };
  api().storage.onChanged.addListener(listener);
  return () => api().storage.onChanged.removeListener(listener);
}
export async function saveNavigation(key: string, value: unknown) { await storage.set(`navigation:${key}`, value); }
