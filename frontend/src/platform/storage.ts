import { api } from './browser';
export const isExtension = !!api()?.runtime?.id;

export interface StorageAdapter {
  get<T>(key: string): Promise<T | undefined>;
  set<T>(key: string, value: T): Promise<void>;
  keys(prefix: string): Promise<string[]>;
}

export const storage: StorageAdapter = {
  async get<T>(key: string) {
    if (isExtension) return (await api().storage.local.get(key))[key] as T | undefined;
    const raw = localStorage.getItem(key);
    return raw === null ? undefined : JSON.parse(raw) as T;
  },
  async set(key, value) {
    if (isExtension) await api().storage.local.set({ [key]: value });
    else localStorage.setItem(key, JSON.stringify(value));
  },
  async keys(prefix) {
    const keys = isExtension ? Object.keys(await api().storage.local.get(null)) : Object.keys(localStorage);
    return keys.filter((key) => key.startsWith(prefix));
  },
};

// Chrome panels share an origin. A named Web Lock prevents lost concurrent writes.
export function exclusive<T>(name: string, work: () => Promise<T>): Promise<T> {
  return navigator.locks.request(`nockapp:${name}`, work);
}

export function subscribeStorage(key: string, callback: () => void): () => void {
  if (isExtension) {
    const listener = (changes: Record<string, chrome.storage.StorageChange>, area: string) => {
      if (area === 'local' && changes[key]) callback();
    };
    api().storage.onChanged.addListener(listener);
    return () => api().storage.onChanged.removeListener(listener);
  }
  const listener = (event: StorageEvent) => { if (event.key === key) callback(); };
  window.addEventListener('storage', listener);
  return () => window.removeEventListener('storage', listener);
}
