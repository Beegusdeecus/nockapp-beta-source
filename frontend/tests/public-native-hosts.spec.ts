import {test,expect} from '@playwright/test';
import {readFileSync} from 'node:fs';
import {attachPublicDiscussion,PUBLIC_NATIVE_HOST,PUBLIC_VERSION} from '../src/publicDiscussion';
const vectors=JSON.parse(readFileSync(new URL('./fixtures/public-native-contract-v6-20261101.json',import.meta.url),'utf8')).vectors;
const result=(op:string)=>structuredClone(vectors.find((v:any)=>v.operation===op).result);
function harness(options:{missingNew?:boolean;badNew?:boolean;loseMutation?:boolean}={}){
  const old=Object.getOwnPropertyDescriptor(globalThis,'chrome');const dials:string[]=[];const sent:{host:string;operation:string}[]=[];const replies:any[]=[];
  const uiMessages:((v:any)=>void)[]=[];const uiLost:(()=>void)[]=[];
  Object.defineProperty(globalThis,'chrome',{configurable:true,value:{runtime:{connectNative:(host:string)=>{
    dials.push(host);const messages=new Set<(v:any)=>void>();const lost=new Set<()=>void>();
    return {onMessage:{addListener:(f:(v:any)=>void)=>messages.add(f),removeListener:(f:(v:any)=>void)=>messages.delete(f)},
      onDisconnect:{addListener:(f:()=>void)=>lost.add(f),removeListener:(f:()=>void)=>lost.delete(f)},disconnect:()=>{},postMessage:(m:any)=>{
        sent.push({host,operation:m.operation});
        queueMicrotask(()=>{
          if(host===PUBLIC_NATIVE_HOST&&options.missingNew||m.operation!=='public-capabilities'&&options.loseMutation){for(const f of lost)f();return;}
          const value=result(m.operation);if(options.badNew&&host===PUBLIC_NATIVE_HOST)value.secret='not-permitted';
          for(const f of messages)f({profile:m.profile,id:m.id,status:'ok',laboratory:true,verified:false,result:value});
        });
      }};
  }}}});
  const ui={onMessage:{addListener:(f:(v:any)=>void)=>uiMessages.push(f)},onDisconnect:{addListener:(f:()=>void)=>uiLost.push(f)},postMessage:(v:any)=>replies.push(v)} as unknown as chrome.runtime.Port;
  attachPublicDiscussion(ui);
  return {dials,sent,replies,send:async(operation:string,body={})=>{uiMessages.forEach(f=>f({version:PUBLIC_VERSION,operation,body}));await new Promise(r=>setTimeout(r,0));},
    close:()=>{uiLost.forEach(f=>f());if(old)Object.defineProperty(globalThis,'chrome',old);else Reflect.deleteProperty(globalThis,'chrome');}};
}
test('public discovery prefers the separate host and keeps later operations on it',async()=>{
  const h=harness();try{
    await h.send('public-capabilities');await h.send('public-outbox',{after:0,limit:4});
    expect(h.dials).toEqual([PUBLIC_NATIVE_HOST,PUBLIC_NATIVE_HOST]);expect(h.replies.every(r=>r.result)).toBe(true);
  }finally{h.close();}
});
test('an older public installation remains usable after only read-only capability fallback',async()=>{
  const h=harness({missingNew:true});try{
    await h.send('public-capabilities');await h.send('public-outbox',{after:0,limit:4});
    expect(h.dials).toEqual([PUBLIC_NATIVE_HOST,'com.nockapp.zkid','com.nockapp.zkid']);
    expect(h.sent.slice(0,2).every(v=>v.operation==='public-capabilities')).toBe(true);expect(h.replies.every(r=>r.result)).toBe(true);
  }finally{h.close();}
});
test('an invalid reply from the new host cannot downgrade discovery to the original helper',async()=>{
  const h=harness({badNew:true});try{
    await h.send('public-capabilities');expect(h.dials).toEqual([PUBLIC_NATIVE_HOST]);expect(h.replies[0].error).toBe('unsupported-helper');
  }finally{h.close();}
});
test('loss of a mutating operation never retries it on the original helper',async()=>{
  const h=harness({loseMutation:true});try{
    await h.send('public-capabilities');await h.send('public-initialize-identity',{approve_private_key_setup:true});
    expect(h.dials).toEqual([PUBLIC_NATIVE_HOST,PUBLIC_NATIVE_HOST]);expect(h.sent.filter(v=>v.operation==='public-initialize-identity')).toHaveLength(1);
    expect(h.replies.at(-1).error).toBe('helper-unavailable');
  }finally{h.close();}
});
test('failed fresh discovery cannot retain an older host binding for later operations',async()=>{
  const old=harness({missingNew:true});try{await old.send('public-capabilities');}finally{old.close();}
  const next=harness({badNew:true});try{
    await next.send('public-capabilities');await next.send('public-outbox',{after:0,limit:4});
    expect(next.dials).toEqual([PUBLIC_NATIVE_HOST,PUBLIC_NATIVE_HOST]);
    expect(next.replies.every(v=>v.error==='unsupported-helper')).toBe(true);
  }finally{next.close();}
});
