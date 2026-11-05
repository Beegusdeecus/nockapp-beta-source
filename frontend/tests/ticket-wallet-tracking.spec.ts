import {test,expect} from '@playwright/test';
import {storage} from '../src/platform/storage';
import {saveWalletTracking,walletTrackingStatus,walletFailure,TICKET_WALLET_KEY} from '../src/data/ticketWalletTracking';
const batch='ab'.repeat(32),id='0x'+'cd'.repeat(32);const original={...storage};let data:Map<string,unknown>;
test.beforeEach(()=>{data=new Map([['private-sentinel',{preserved:true}]]);storage.get=async<T>(key:string)=>structuredClone(data.get(key)) as T;storage.set=async(key,value)=>{data.set(key,structuredClone(value));};});
test.afterEach(()=>{expect(data.get('private-sentinel')).toEqual({preserved:true});Object.assign(storage,original);});
test('wallet tracking persists only a bounded ID and matches the exact batch after reload',async()=>{
 await saveWalletTracking(batch,{id,secret:'DO-NOT-STORE',receipts:['DO-NOT-STORE']});
 expect(data.get(TICKET_WALLET_KEY)).toEqual({profile:'nockapp-ticket-wallet-display-v1',batch,id,error:null});
 const calls:any[]=[];const provider=async()=>({request:async(v:any)=>{calls.push(v);return{id,chainId:'0x14a34',atomic:true,status:100};}});
 expect(await walletTrackingStatus(batch,provider)).toContain('still processing');expect(calls).toEqual([{method:'wallet_getCallsStatus',params:[id]}]);
 expect(await walletTrackingStatus('ef'.repeat(32),provider)).toContain('no wallet tracking ID');expect(calls).toHaveLength(1);
});
test('wallet success is diagnostic only and failure never offers payment retry',async()=>{
 await saveWalletTracking(batch,{id});
 for(const [code,text] of [[100,'still processing'],[200,'Independently checking'],[400,'remains locked'],[500,'Gas may have been spent'],[600,'remains locked']] as const){
  const result=await walletTrackingStatus(batch,async()=>({request:async()=>({id,chainId:'0x14a34',atomic:true,status:code})}));expect(result).toContain(text);
 }
 for(const change of [{id:'wrong'},{chainId:'0x1'},{atomic:false},{status:999},{status:'200'}])
  expect(await walletTrackingStatus(batch,async()=>({request:async()=>({id,chainId:'0x14a34',atomic:true,status:200,...change})}))).toContain('status is unavailable');
});
test('rejection is retained without arbitrary wallet text; malformed replies cannot invent tracking',async()=>{
 await saveWalletTracking(batch,undefined,{code:4001,message:'PRIVATE-DO-NOT-DISPLAY'});
 expect(await walletTrackingStatus(batch,async()=>{throw Error('must-not-connect');})).toContain('MetaMask rejected');
 expect(JSON.stringify(data.get(TICKET_WALLET_KEY))).not.toContain('PRIVATE');expect(walletFailure({code:-32601})).toContain('does not support');
 for(const reply of [{},null,{id:''},{id:'a'.repeat(8195)},{id:'line\nbreak'}])await expect(saveWalletTracking(batch,reply)).rejects.toThrow('no usable');
});
test('wallet and tracking outages cannot masquerade as chain confirmation',async()=>{
 await saveWalletTracking(batch,{id});expect(await walletTrackingStatus(batch,async()=>{throw Error('synthetic-unavailable');})).toContain('onchain checks continue');
 storage.get=async()=>{throw Error('synthetic-storage-unavailable');};expect(await walletTrackingStatus(batch,async()=>{throw Error('must-not-connect');})).toContain('could not be read');
});
