import { publicOperation, type PublicPage, type PublicRow } from './publicDiscussion';
import { api } from './platform/browser';

export function canonicalNumber(value:string):number {
  const text=value.trim().replace(/^(?:No\.?\s*|>>)/i,'');
  if(!/^[1-9][0-9]{0,15}$/.test(text)||!Number.isSafeInteger(Number(text)))throw Error('Enter a post number, such as 3.');
  return Number(text);
}
export const forumURL=(number:string)=>api().runtime.getURL(`forum.html?post=${canonicalNumber(number)}#post-${canonicalNumber(number)}`);
export const readable=(row:PublicRow)=>row.state==='finalized'&&row.proofs_verified===true&&!!row.post;
export type ThreadRead={selected:PublicRow;root?:PublicRow;posts:PublicRow[];checked:number;total:number;complete:boolean};

// Read each four-record range once. A targeted range supplies both the selected
// post and its neighbours; ranges already verified are reused only inside this
// read, under the same verifier version and finite canonical high-water mark.
export async function readThread(number:number,signal:AbortSignal,update:(value:ThreadRead)=>void){
  const rangeStart=(n:number)=>Math.floor((n-1)/4)*4;
  const ranges=new Map<number,PublicPage>();
  async function range(n:number){
    const after=rangeStart(n);const existing=ranges.get(after);if(existing)return existing;
    const numbers=Array.from({length:Math.min(4,Number.MAX_SAFE_INTEGER-after)},(_,i)=>after+i+1);
    const page=await publicOperation<PublicPage>('public-numbers',{numbers},signal);ranges.set(after,page);return page;
  }
  const first=await range(number);const selected=first.posts.find(r=>r.post_number===String(number))!;
  const total=Number(first.next_number)-1;const version=first.verifier_version;
  function admit(page:PublicPage){
    if(page.verifier_version!==version||Number(page.next_number)-1<total)throw Error('The verifier or public index changed. Reload this thread.');
  }
  let root=readable(selected)&&selected.post!.kind==='thread'?selected:undefined;
  const expected=readable(selected)&&selected.post!.kind==='comment'?selected.thread:undefined;
  if(expected?.number){
    const p=await range(canonicalNumber(expected.number));admit(p);const candidate=p.posts.find(r=>r.post_number===expected.number)!;
    if(candidate.bundle_hash!==expected.bundle_hash)throw Error('The thread reference does not match its canonical post.');
    if(readable(candidate)&&candidate.post!.kind==='thread')root=candidate;
    else {update({selected,root:candidate,posts:[selected],checked:0,total,complete:true});return;}
  }
  if(!root&&!expected||expected&&selected.relationship_state!=='valid'){update({selected,posts:[],checked:0,total,complete:true});return;}
  const comments=new Map<string,PublicRow>();
  function collect(page:PublicPage){
    admit(page);
    for(const row of page.posts){
      if(Number(row.post_number)>total)continue;
      if(root&&row.post_number===root.post_number&&row.bundle_hash!==root.bundle_hash)throw Error('The canonical thread changed. Reload this thread.');
      if(!root&&row.bundle_hash===expected?.bundle_hash&&readable(row)&&row.post!.kind==='thread')root=row;
      if(readable(row)&&row.post!.kind==='comment'&&row.relationship_state==='valid'&&row.thread?.bundle_hash===(root?.bundle_hash??expected?.bundle_hash)){
        const prior=comments.get(row.post_number);if(prior&&prior.bundle_hash!==row.bundle_hash)throw Error('A canonical reply changed. Reload this thread.');
        comments.set(row.post_number,row);
      }
    }
  }
  for(const page of ranges.values())collect(page);
  const emit=(checked:number)=>update({selected,root,posts:[...comments.values()].sort((a,b)=>Number(a.post_number)-Number(b.post_number)),checked,total,complete:checked===total});
  emit(0); // Display verified content before searching the remaining history.
  let after=0;
  while(after<total){
    const cached=ranges.get(after);
    if(cached){after=Math.min(total,after+4);}
    else {
      const page=await publicOperation<PublicPage>('public-page',{after,limit:4},signal);
      if(page.next_after<=after)throw Error('The public index could not be read completely. Reload this thread.');
      collect(page);after=Math.min(total,page.next_after);
    }
    emit(after);
  }
}
