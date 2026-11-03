/** Firefox's browser namespace provides promises; Chrome uses chrome. */
type ExtensionAPI = typeof chrome & { sidebarAction?: { open(): Promise<void> } };
export function api(): ExtensionAPI {
  return (globalThis as unknown as { browser?: ExtensionAPI }).browser
    ?? globalThis.chrome;
}
export const isFirefox = () => !!api()?.sidebarAction;
