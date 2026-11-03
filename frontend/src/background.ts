import { attachAuthoredDiscussion, AUTHORED_PORT } from './authoredDiscussion';
import { attachPublicDiscussion, PUBLIC_PORT } from './publicDiscussion';
import { parsePostUrl } from './urls';
import type { Selection } from './model';
import { isDraftRequest, persistDraft } from './data/drafts';
import { attachXSourceFlow } from './xSourceFlow';
import { api, isFirefox } from './platform/browser';
import { attachPublicPostFlow } from './publicPostFlow';
import { attachZkidFacts, FACT_PORT } from './zkidFacts';
import { attachBaseDiscussion, BASE_PORT } from './baseDiscussion';
import { attachBundleDiscussion, BUNDLE_PORT } from './bundleDiscussion';

api().runtime.onConnect.addListener((port) => {
  if (port.name === PUBLIC_PORT && port.sender?.id === api().runtime.id) {
    const url=port.sender.url??'';const base=api().runtime.getURL('public-wallet.html');
    if(url===api().runtime.getURL('public-tickets.html')) { attachPublicDiscussion(port,undefined,true);return; }
    const wallet=url.startsWith(base+'#post=') && /^#post=[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(url.slice(base.length));
    if (url === api().runtime.getURL('sidepanel.html') || wallet) { attachPublicDiscussion(port,wallet?url.slice(base.length+6):undefined);return; }
  }
  if (port.name === AUTHORED_PORT && port.sender?.id === api().runtime.id) {
    const url = port.sender.url ?? '';const walletBase = api().runtime.getURL('wallet-post.html');
    const wallet = url.startsWith(walletBase + '#post=') && /^#post=[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(url.slice(walletBase.length));
    if (url === api().runtime.getURL('sidepanel.html') || wallet) { attachAuthoredDiscussion(port, wallet, wallet ? url.slice(walletBase.length + 6) : undefined);return; }
  }

  if (port.name === BUNDLE_PORT && port.sender?.id === api().runtime.id && port.sender.url === api().runtime.getURL('sidepanel.html')) {
    attachBundleDiscussion(port);return;
  }
  if (port.name === BASE_PORT && port.sender?.id === api().runtime.id && port.sender.url === api().runtime.getURL('sidepanel.html')) {
    attachBaseDiscussion(port);return;
  }
  if (port.name === FACT_PORT && port.sender?.id === api().runtime.id && port.sender.url === api().runtime.getURL('sidepanel.html')) {
    attachZkidFacts(port);return;
  }
  if (port.name === 'zkid-public-post' && port.sender?.id === api().runtime.id
      && port.sender.url === api().runtime.getURL('public-post.html')) {
    attachPublicPostFlow(port); return;
  }
  if (port.name !== 'x-source-flow' || port.sender?.id !== api().runtime.id
      || port.sender.url !== api().runtime.getURL('x-connect.html')) return;
  attachXSourceFlow(port);
});

api().runtime.onMessage.addListener((message: unknown, sender, respond) => {
  if (sender.id !== api().runtime.id || !isDraftRequest(message)) return;
  void persistDraft(message.key, message.draft).then(() => respond({ ok: true })).catch((error: unknown) => {
    respond({ ok: false, error: error instanceof Error ? error.message : 'Could not save your draft.' });
  });
  return true;
});

const menuId = 'discuss-on-nockapp';
api().runtime.onInstalled.addListener(() => {
  const create = () => {
    api().contextMenus.create({
      id: menuId, title: 'Discuss on NockApp', contexts: ['link'],
      targetUrlPatterns: ['*://x.com/*/status/*', '*://twitter.com/*/status/*', '*://www.x.com/*/status/*', '*://www.twitter.com/*/status/*', '*://mobile.twitter.com/*/status/*'],
    });
  };
  // Keep Chrome's original callback path for the declared Chrome 116 minimum.
  if (isFirefox()) void api().contextMenus.removeAll().then(create);
  else api().contextMenus.removeAll(create);
});

function openSelection(windowId: number, url?: string) {
  // Open synchronously in the gesture callback. Awaiting storage first can lose
  // Chrome's user activation. The panel subscribes before reading the selection.
  const sidebar = api().sidebarAction;
  const opening = sidebar ? sidebar.open() : api().sidePanel.open({ windowId });
  let selection: Selection = { kind: 'help', at: Date.now(), nonce: crypto.randomUUID() };
  try { selection = { ...selection, kind: 'post', post: parsePostUrl(url ?? '') }; } catch { /* Timeline/restricted tab: show instructions. */ }
  void api().storage.session.set({ [`selection:${windowId}`]: selection }).catch(() => {
    void api().action.setBadgeText({ text: '!' });
    void api().action.setTitle({ title: 'NockApp could not save the selected link. Try again.' });
  });
  void opening.catch(() => {
    void api().action.setBadgeText({ text: '!' });
    void api().action.setTitle({ title: 'NockApp could not open. Try clicking the extension icon again.' });
  });
  void api().action.setBadgeText({ text: '' });
  void api().action.setTitle({ title: 'Discuss on NockApp' });
}
api().action.onClicked.addListener((tab) => { if (tab.windowId !== undefined) openSelection(tab.windowId, tab.url); });
api().contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === menuId && tab?.windowId !== undefined) openSelection(tab.windowId, info.linkUrl);
});
// Discussion selection still has no navigation observers or network calls.
// X capture is scoped separately to an explicit, temporary connection flow.
