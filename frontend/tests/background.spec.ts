import { test, expect } from '@playwright/test';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

test('ticket wallet admission requires its exact separate page and extension identity',async()=>{
  let onConnect:(p:chrome.runtime.Port)=>void=()=>{};const noop={addListener:()=>{}};const id='a'.repeat(32),base=`chrome-extension://${id}/public-tickets.html`;
  Object.defineProperty(globalThis,'chrome',{configurable:true,value:{runtime:{id,getURL:(n:string)=>`chrome-extension://${id}/${n}`,onConnect:{addListener:(fn:typeof onConnect)=>{onConnect=fn;}},onMessage:noop,onInstalled:noop},action:{onClicked:noop},contextMenus:{onClicked:noop}}});
  try{
    await import(`${pathToFileURL(resolve('dist/background.js')).href}?tickets=${Date.now()}`);let admitted=0;
    const port=(url:string,sender=id)=>({name:'nockapp-permissionless-discussion',sender:{id:sender,url},onMessage:{addListener:()=>{admitted++;}},onDisconnect:noop,postMessage:()=>{}} as unknown as chrome.runtime.Port);
    for(const url of [base+'?extra=1',base+'#fragment',base.replace('public-tickets','public-ticket')])onConnect(port(url));
    onConnect(port(base,'b'.repeat(32)));expect(admitted).toBe(0);onConnect(port(base));expect(admitted).toBe(1);
  }finally{Reflect.deleteProperty(globalThis,'chrome');}
});

test('built background admits public-post commands only from its exact dedicated page', async () => {
  let onConnect: (port: chrome.runtime.Port) => void = () => {};
  const noop = { addListener: () => {} };
  const extensionId = 'a'.repeat(32);const page = `chrome-extension://${extensionId}/public-post.html`;
  Object.defineProperty(globalThis, 'chrome', { configurable: true, value: {
    runtime: { id: extensionId, getURL: (name: string) => `chrome-extension://${extensionId}/${name}`,
      onConnect: { addListener: (fn: typeof onConnect) => { onConnect = fn; } }, onMessage: noop, onInstalled: noop },
    action: { onClicked: noop }, contextMenus: { onClicked: noop },
  } });
  const admitted: unknown[] = [];
  const port = (id: string, url: string) => ({ name: 'zkid-public-post', sender: { id, url },
    onMessage: noop, onDisconnect: noop, postMessage: (value: unknown) => admitted.push(value) }) as unknown as chrome.runtime.Port;
  try {
    await import(`${pathToFileURL(resolve('dist/background.js')).href}?public=${Date.now()}`);
    onConnect(port('b'.repeat(32), page));onConnect(port(extensionId, `chrome-extension://${extensionId}/sidepanel.html`));
    onConnect(port(extensionId, page + '?unapproved'));expect(admitted).toEqual([]);
    onConnect(port(extensionId, page));expect(admitted).toMatchObject([{ state: 'ready', verified: false }]);
  } finally { Reflect.deleteProperty(globalThis, 'chrome'); }
});

for (const firefox of [false, true]) test(`built ${firefox ? 'Firefox' : 'Chrome'} background handles toolbar gestures synchronously without observing navigation`, async () => {
  const calls: string[] = [];
  const selections: Record<string, unknown>[] = [];
  let installed = () => {};
  let action: (tab: { windowId: number; url?: string }) => void = () => {};
  let menu: (info: { menuItemId: string; linkUrl: string }, tab: { windowId: number; url: string }) => void = () => {};
  let createdMenu: unknown;
  const stub = {
    runtime: { onConnect: { addListener: () => {} }, onMessage: { addListener: () => {} }, onInstalled: { addListener: (fn: typeof installed) => { installed = fn; } } },
    contextMenus: {
      removeAll: async (callback?: () => void) => { callback?.(); }, create: (config: unknown) => { createdMenu = config; },
      onClicked: { addListener: (fn: typeof menu) => { menu = fn; } },
    },
    action: {
      onClicked: { addListener: (fn: typeof action) => { action = fn; } },
      setBadgeText: async () => {}, setTitle: async () => {},
    },
    sidePanel: { open: async (options: unknown) => { calls.push(`open:${JSON.stringify(options)}`); } },
    storage: { session: { set: async (value: Record<string, unknown>) => { calls.push('store'); selections.push(value); } } },
  };
  Object.defineProperty(globalThis, 'chrome', { value: stub, configurable: true });
  if (firefox) Object.defineProperty(globalThis, 'browser', { value: { ...stub,
    sidebarAction: { open: async () => { calls.push('open:firefox'); } },
  }, configurable: true });
  try {
    await import(`${pathToFileURL(resolve('dist/background.js')).href}?test=${Date.now()}`);
    installed();
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(createdMenu).toMatchObject({ id: 'discuss-on-nockapp', title: 'Discuss on NockApp', contexts: ['link'] });
    action({ windowId: 7, url: 'https://x.com/demo/status/1900000000000000001?s=12' });
    expect(calls.slice(0, 2)).toEqual([firefox ? 'open:firefox' : 'open:{"windowId":7}', 'store']);
    expect(selections[0]).toMatchObject({ 'selection:7': { kind: 'post', post: { postId: '1900000000000000001', url: 'https://x.com/i/status/1900000000000000001' } } });
    menu({ menuItemId: 'discuss-on-nockapp', linkUrl: 'https://twitter.com/reply/status/1900000000000000002' }, { windowId: 8, url: 'https://x.com/home' });
    expect(selections[1]).toMatchObject({ 'selection:8': { kind: 'post', post: { postId: '1900000000000000002' } } });
    action({ windowId: 7, url: 'https://x.com/home' });
    expect(selections[2]).toMatchObject({ 'selection:7': { kind: 'help' } });
    action({ windowId: 7 });
    expect(selections[3]).toMatchObject({ 'selection:7': { kind: 'help' } });
    expect(calls.filter((c) => c.startsWith('open:'))).toHaveLength(4);
  } finally { Reflect.deleteProperty(globalThis, 'chrome'); Reflect.deleteProperty(globalThis, 'browser'); }
});

test('bundle native port admits only the exact installed side panel', async () => {
  let onConnect: (port: chrome.runtime.Port) => void = () => {};
  const noop = { addListener: () => {} };const extensionId = 'a'.repeat(32);
  Object.defineProperty(globalThis, 'chrome', { configurable: true, value: {
    runtime: { id: extensionId, getURL: (name: string) => `chrome-extension://${extensionId}/${name}`,
      onConnect: { addListener: (fn: typeof onConnect) => { onConnect = fn; } }, onMessage: noop, onInstalled: noop },
    action: { onClicked: noop }, contextMenus: { onClicked: noop },
  } });
  let admitted = 0;
  const port = (id: string, url: string) => ({ name: 'bundle-discussion', sender: { id, url },
    onMessage: { addListener: () => { admitted++; } }, onDisconnect: noop }) as unknown as chrome.runtime.Port;
  try {
    await import(`${pathToFileURL(resolve('dist/background.js')).href}?bundle=${Date.now()}`);
    const url = `chrome-extension://${extensionId}/sidepanel.html`;
    onConnect(port('b'.repeat(32), url));onConnect(port(extensionId, url + '?unapproved'));onConnect(port(extensionId, url + '#fragment'));
    onConnect(port(extensionId, `chrome-extension://${extensionId}/public-post.html`));expect(admitted).toBe(0);
    onConnect(port(extensionId, url));expect(admitted).toBe(1);
  } finally { Reflect.deleteProperty(globalThis, 'chrome'); }
});

test('v4 wallet page has exact sender admission and cannot initialize identities or address a different post', async () => {
  let onConnect: (port: chrome.runtime.Port) => void = () => {};const noop = { addListener: () => {} };const id = 'a'.repeat(32);
  let native = 0;let admitted = 0;let receive: (v: unknown) => void = () => {};const replies: unknown[] = [];
  Object.defineProperty(globalThis, 'chrome', { configurable: true, value: {
    runtime: { id, getURL: (name: string) => `chrome-extension://${id}/${name}`, connectNative: () => { native++;throw new Error('Must reject before native'); },
      onConnect: { addListener: (fn: typeof onConnect) => { onConnect = fn; } }, onMessage: noop, onInstalled: noop },
    action: { onClicked: noop }, contextMenus: { onClicked: noop },
  } });
  const post = '11111111-1111-4111-8111-111111111111';const url = `chrome-extension://${id}/wallet-post.html#post=${post}`;
  const port = (senderId: string, senderUrl: string) => ({ name: 'nockapp-authored-discussion', sender: { id: senderId, url: senderUrl },
    onMessage: { addListener: (fn: typeof receive) => { admitted++;receive = fn; } }, onDisconnect: noop, postMessage: (v: unknown) => replies.push(v) }) as unknown as chrome.runtime.Port;
  try {
    await import(`${pathToFileURL(resolve('dist/background.js')).href}?authored=${Date.now()}`);
    for (const value of [url + '&extra=1', url.replace('#post=', '?post='), `chrome-extension://${id}/public-post.html`, url.replace(post, 'bad')]) onConnect(port(id, value));
    onConnect(port('b'.repeat(32), url));expect(admitted).toBe(0);
    onConnect(port(id, url));expect(admitted).toBe(1);
    for (const [operation, body] of [['bundle-initialize-identity', { approve_private_key_setup: true }],
      ['bundle-recover', { post_id: '22222222-2222-4222-8222-222222222222' }]]) receive({ version: 'nockapp-authored-discussion-4', operation, body });
    expect(native).toBe(0);expect(replies).toEqual(Array(2).fill({ version: 'nockapp-authored-discussion-4', error: 'message-schema' }));
    onConnect(port(id, `chrome-extension://${id}/sidepanel.html`));expect(admitted).toBe(2);
  } finally { Reflect.deleteProperty(globalThis, 'chrome'); }
});

test('public port admits only named installed pages and well-formed forum links', async () => {
  let connect: (port: chrome.runtime.Port) => void = () => {};
  const noop = { addListener: () => {} };const id = 'a'.repeat(32);const base = `chrome-extension://${id}/`;
  Object.defineProperty(globalThis, 'chrome', { configurable: true, value: {
    runtime: { id, getURL: (name: string) => base + name, onConnect: { addListener: (fn: typeof connect) => { connect = fn; } }, onMessage: noop, onInstalled: noop },
    action: { onClicked: noop }, contextMenus: { onClicked: noop },
  } });
  const admitted: string[] = [];
  const port = (sender: string, url: string) => ({ name: 'nockapp-permissionless-discussion', sender: { id: sender, url },
    onMessage: { addListener: () => admitted.push(url) }, onDisconnect: noop, postMessage: () => {} }) as unknown as chrome.runtime.Port;
  try {
    await import(`${pathToFileURL(resolve('dist/background.js')).href}?permissionless=${Date.now()}`);
    for (const [sender, url] of [[id, base + 'sidepanel.html?extra'], [id, base + 'wallet-post.html#post=11111111-1111-4111-8111-111111111111'],
      [id, base + 'forum.html?post=3&extra=1'],[id,base+'forum.html?post=0'],[id,base+'forum.html/other'],[id,base+'forum.html?new=comment'],[id, base + 'public-post.html'], ['b'.repeat(32), base + 'sidepanel.html'], [id, 'https://attacker.example/sidepanel.html']]) connect(port(sender, url));
    expect(admitted).toEqual([]);const allowed=['sidepanel.html','legacy.html','forum.html?post=3#post-3','forum.html?new=thread'];for(const url of allowed)connect(port(id,base+url));expect(admitted).toEqual(allowed.map(url=>base+url));
  } finally { Reflect.deleteProperty(globalThis, 'chrome'); }
});

test('public wallet page admission requires its exact post fragment and stays distinct from v4',async()=>{
  let onConnect:(p:chrome.runtime.Port)=>void=()=>{};const noop={addListener:()=>{}};const id='a'.repeat(32),base=`chrome-extension://${id}/public-wallet.html`;
  Object.defineProperty(globalThis,'chrome',{configurable:true,value:{runtime:{id,getURL:(n:string)=>`chrome-extension://${id}/${n}`,onConnect:{addListener:(fn:typeof onConnect)=>{onConnect=fn;}},onMessage:noop,onInstalled:noop},action:{onClicked:noop},contextMenus:{onClicked:noop}}});
  const admitted:string[]=[];const port=(url:string)=>({name:'nockapp-permissionless-discussion',sender:{id,url},onMessage:{addListener:()=>admitted.push(url)},onDisconnect:noop,postMessage:()=>{}}) as unknown as chrome.runtime.Port;
  try{await import(`${pathToFileURL(resolve('dist/background.js')).href}?publicwallet=${Date.now()}`);
    for(const url of [base,base+'#post=bad',base+'?extra#post=22222222-2222-4222-8222-222222222222',base+'#post=22222222-2222-4222-8222-222222222222&other=1'])onConnect(port(url));
    expect(admitted).toEqual([]);onConnect(port(base+'#post=22222222-2222-4222-8222-222222222222'));expect(admitted).toHaveLength(1);
  }finally{Reflect.deleteProperty(globalThis,'chrome');}
});
