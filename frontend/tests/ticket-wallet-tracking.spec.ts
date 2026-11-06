import {test,expect} from '@playwright/test';
import {storage} from '../src/platform/storage';
import {beginWalletTracking,recordWalletReply,readWalletDiagnostic,walletFailure,TICKET_WALLET_KEY} from '../src/data/ticketWalletTracking';
const batch='ab'.repeat(32);const original={...storage};const locks=Object.getOwnPropertyDescriptor(navigator,'locks');let data:Map<string,unknown>;
test.beforeEach(()=>{let queue:Promise<unknown>=Promise.resolve();data=new Map([['private-sentinel',{preserved:true}]]);Object.defineProperty(navigator,'locks',{configurable:true,value:{request:<T>(_key:string,f:()=>Promise<T>)=>{const result=queue.then(f);queue=result.then(()=>undefined,()=>undefined);return result;}}});storage.get=async<T>(key:string)=>structuredClone(data.get(key)) as T;storage.set=async(key,value)=>{data.set(key,structuredClone(value));};});
test.afterEach(()=>{expect(data.get('private-sentinel')).toEqual({preserved:true});Object.assign(storage,original);if(locks)Object.defineProperty(navigator,'locks',locks);else Reflect.deleteProperty(navigator,'locks');});
test('ID exists before wallet reply, survives a lost reply, and tracks only its exact batch',async()=>{
 const id=await beginWalletTracking(batch);expect(id).toMatch(/^0x[0-9a-f]{64}$/);
 await recordWalletReply(batch,id,undefined,{code:-32000,message:'PRIVATE-ERROR'});
 expect(data.get(TICKET_WALLET_KEY)).toEqual({profile:'nockapp-ticket-wallet-display-v2',batch,id,error:-32000});
 const calls:any[]=[];const provider=async()=>({request:async(v:any)=>{calls.push(v);return{id,chainId:'0x14a34',atomic:true,status:100};}});
 expect((await readWalletDiagnostic(batch,provider)).state).toBe('pending');expect(calls).toEqual([{method:'wallet_getCallsStatus',params:[id]}]);
 expect((await readWalletDiagnostic('ef'.repeat(32),provider)).state).toBe('untracked');expect(calls).toHaveLength(1);
 await expect(beginWalletTracking(batch)).rejects.toThrow('already prepared');
});
test('matching wallet reply stores no arbitrary fields; different IDs cannot replace the committed ID',async()=>{
 const id=await beginWalletTracking(batch);await recordWalletReply(batch,id,{id,secret:'PRIVATE',receipts:['PRIVATE']});
 expect(JSON.stringify(data.get(TICKET_WALLET_KEY))).not.toContain('PRIVATE');
 await expect(recordWalletReply(batch,id,{id:'wrong'})).rejects.toThrow('different');expect((data.get(TICKET_WALLET_KEY) as any).id).toBe(id);
});
test('wallet success/failure stays diagnostic and foreign/partial/malformed replies do not confirm anything',async()=>{
 const id=await beginWalletTracking(batch);
 for(const [code,state] of [[100,'pending'],[200,'included'],[400,'failed'],[500,'failed'],[600,'failed']] as const)
  expect((await readWalletDiagnostic(batch,async()=>({request:async()=>({id,chainId:'0x14a34',atomic:true,status:code})}))).state).toBe(state);
 for(const change of [{id:'wrong'},{chainId:'0x1'},{atomic:false},{status:999},{status:'200'}])
  expect((await readWalletDiagnostic(batch,async()=>({request:async()=>({id,chainId:'0x14a34',atomic:true,status:200,...change})}))).state).toBe('unavailable');
});
test('older lost-ID state stays unchanged and no wallet ID is retroactively invented',async()=>{
 const old={profile:'nockapp-ticket-wallet-display-v1',batch,id:null,error:4001};data.set(TICKET_WALLET_KEY,old);
 expect((await readWalletDiagnostic(batch,async()=>{throw Error('must-not-connect');})).state).toBe('rejected');
 await expect(beginWalletTracking(batch)).rejects.toThrow('already prepared');expect(data.get(TICKET_WALLET_KEY)).toEqual(old);
 data.delete(TICKET_WALLET_KEY);expect((await readWalletDiagnostic(batch,async()=>{throw Error('must-not-connect');})).state).toBe('untracked');expect(data.has(TICKET_WALLET_KEY)).toBe(false);
});
test('rejected request remains visible when wallet has no status; outages cannot authorize a retry',async()=>{
 const id=await beginWalletTracking(batch);await recordWalletReply(batch,id,undefined,{code:4001,message:'PRIVATE'});
 expect((await readWalletDiagnostic(batch,async()=>{throw Error('unknown-id');})).state).toBe('rejected');
 expect(walletFailure({code:-32601})).toContain('does not support');
 storage.get=async()=>{throw Error('synthetic-storage-unavailable');};expect((await readWalletDiagnostic(batch,async()=>{throw Error('must-not-connect');})).state).toBe('unavailable');
});

test('shared durable claim admits only one concurrent caller and keeps wallet size errors explicit',async()=>{
 const result=await Promise.allSettled([beginWalletTracking(batch),beginWalletTracking(batch)]);expect(result.filter(r=>r.status==='fulfilled')).toHaveLength(1);
 expect(walletFailure({code:5740})).toContain('too many calls');expect(walletFailure({code:5720})).toContain('already knows');
 const id=(data.get(TICKET_WALLET_KEY) as any).id;await recordWalletReply(batch,id,undefined,{code:5740});
 expect((await readWalletDiagnostic(batch,async()=>{throw Error('no-wallet-status');})).message).toContain('too many calls');
});
