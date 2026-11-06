import { useEffect, useRef, useState } from 'react';
import { publicOperation, PublicOperationError, type PublicPage, type PublicRow } from '../publicDiscussion';
import { canonicalNumber, forumURL, readable, readThread, type ThreadRead } from '../canonicalForum';
import { api } from '../platform/browser';
import { PublicDiscussion, type Capabilities } from './PublicDiscussion';
import { PostBody } from './PostBody';
import '../forum.css';

type Caps=Capabilities;
function Post({row,preview=false}:{row:PublicRow;preview?:boolean}){
  const valid=readable(row);const href=forumURL(row.post_number);
  return <article className={`forum-post ${preview?'forum-preview':''}`} id={`post-${row.post_number}`} tabIndex={-1}>
    <header><a href={href} target={preview?'_blank':undefined} rel="noopener" aria-label={`Open post No.${row.post_number}`}>No.{row.post_number}</a><span>Anonymous</span>{valid&&<span className="forum-kind">{row.post!.kind==='thread'?'Thread':'Reply'}</span>}</header>
    {valid?<>
      {row.post!.title&&<h2><a href={href} target={preview?'_blank':undefined} rel="noopener">{row.post!.title}</a></h2>}
      {preview?<a className="forum-excerpt" href={href} target="_blank" rel="noopener">{row.post!.body}</a>:<PostBody body={row.post!.body} className="post-body" onReference={n=>void api().tabs.create({url:forumURL(n)})}/>}
      <div className="forum-badges" aria-label={`Verified badges for No.${row.post_number}`}>
        {row.display?.address&&<span title="Wallet authorization checked for this post">{row.display.address}</span>}
        {row.display?.followers&&<span title="Eligibility checked when this post was indexed">Followers &gt; {row.display.followers.threshold.toLocaleString()}</span>}
        {row.display?.history&&<span>Same author: {row.display.history.map(r=>r.number?<a key={r.bundle_hash} href={forumURL(r.number)} target="_blank" rel="noopener">No.{r.number}</a>:<span key={r.bundle_hash}> Earlier post</span>)}</span>}
      </div>
      {row.relationship_state!=='valid'&&<p className="forum-muted">The connection to its thread could not be verified.</p>}
    </>:<p className="forum-unavailable">{row.state==='unassigned'?'This number has not been published.':row.state==='content-unavailable'?'Post unavailable — its files could not be downloaded.':row.state==='invalid'?'Post unavailable — its content or authorship failed verification.':'Post unavailable — verification could not be completed.'}</p>}
  </article>;
}
export function CanonicalForum(){
  const params=new URLSearchParams(location.search);const raw=params.get('post');const isTab=location.pathname.endsWith('/forum.html');const composing=params.get('new')==='thread';
  const [caps,setCaps]=useState<Caps>();const [page,setPage]=useState<PublicPage>();const [thread,setThread]=useState<ThreadRead>();
  const [after,setAfter]=useState(0);const [refresh,setRefresh]=useState(0);const [input,setInput]=useState(raw??'');
  const [busy,setBusy]=useState(true);const [error,setError]=useState('');const [updateRequired,setUpdateRequired]=useState(false);const [menu,setMenu]=useState(false);
  const [status,setStatus]=useState('Connecting to NockApp…');const focusDone=useRef(false);const loadedView=useRef('');
  useEffect(()=>{
    let live=true;const control=new AbortController();setBusy(true);setError('');setUpdateRequired(false);
    const key=`${raw??'feed'}:${after}:${composing}`;
    if(loadedView.current!==key){loadedView.current=key;setPage(undefined);setThread(undefined);focusDone.current=false;}
    void(async()=>{
      try{
        if(isTab&&!/^(?:\?post=[1-9][0-9]{0,15}|\?new=thread)?$/.test(location.search))throw Error('Use a post link, or look up its number in the sidebar.');
        if(raw)canonicalNumber(raw);
        const c=await publicOperation<Caps>('public-capabilities',{},control.signal);if(!live)return;setCaps(c);
        if(composing){setStatus('');return;}
        setStatus(raw?'Finding the thread and checking its posts…':'Loading posts and checking their proofs…');
        if(raw){await readThread(canonicalNumber(raw),control.signal,value=>{if(live){setThread(value);setStatus(value.complete?'':`Checking public posts: ${value.checked.toLocaleString()} of ${value.total.toLocaleString()}…`);}});}
        else {const p=await publicOperation<PublicPage>('public-page',{after,limit:4},control.signal);if(live){setPage(p);setStatus('');}}
      }catch(e){if(live){setError((e instanceof Error?e.message:'Posts could not be loaded.')+' Previously checked posts remain visible; this refresh did not complete.');setUpdateRequired(e instanceof PublicOperationError&&e.code==='extension-update-required');}}
      finally{if(live)setBusy(false);}
    })();return()=>{live=false;control.abort();};
  },[after,refresh,raw,composing]);
  useEffect(()=>{
    if(!raw||!thread?.complete||focusDone.current)return;focusDone.current=true;
    document.getElementById(`post-${canonicalNumber(raw)}`)?.scrollIntoView({block:'center'});
  },[raw,thread]);
  useEffect(()=>{if(isTab)return;const timer=setInterval(()=>{if(document.visibilityState==='visible'&&!busy&&!menu)setRefresh(v=>v+1);},30000);return()=>clearInterval(timer);},[isTab,busy,menu]);
  useEffect(()=>{
    // Run only after the visible read finishes. The installed helper bounds
    // reconciliation to four due operations per pass; it sends individual
    // hashes, never the owner's publication history, to the storage service.
    if(!caps||busy||composing||raw)return;
    let live=true;let checking=false;const control=new AbortController();
    const recover=async()=>{if(!live||checking||document.visibilityState==='hidden')return;checking=true;
      try{await publicOperation('public-outbox',{after:0,limit:4},control.signal);}
      catch{/* Preserve the feed and retry later; never submit another index. */}
      finally{checking=false;}};
    void recover();const timer=setInterval(()=>void recover(),30000);
    const visible=()=>{if(document.visibilityState==='visible')void recover();};document.addEventListener('visibilitychange',visible);
    return()=>{live=false;control.abort();clearInterval(timer);document.removeEventListener('visibilitychange',visible);};
  },[!!caps,busy,composing,raw]);
  function search(e:React.FormEvent){e.preventDefault();try{void api().tabs.create({url:forumURL(input)});setError('');}catch{setError('Enter a post number, such as 3.');}}
  const root=thread?.root;const canReply=root&&readable(root)&&root.post!.kind==='thread'&&root.relationship_state==='valid';
  const posts=root?[root,...thread!.posts.filter(r=>r.post_number!==root.post_number)]:thread?[thread.selected]:page?.posts??[];
  return <main className={`canonical-forum ${isTab?'forum-tab':'forum-sidebar'}`}>
    <header className="forum-header"><a className="forum-brand" href={api().runtime.getURL('sidepanel.html')}>nockapp.</a><span className="forum-network">Base Sepolia beta</span><button aria-label="Open menu" aria-expanded={menu} onClick={()=>setMenu(v=>!v)}>Menu</button></header>
    {menu&&<aside className="forum-menu" aria-label="NockApp menu"><button onClick={()=>void api().tabs.create({url:api().runtime.getURL('public-tickets.html')})}>Publication tickets</button><a href={api().runtime.getURL('legacy.html')} target="_blank" rel="noopener">Earlier versions and local archive</a>{caps&&<PublicDiscussion mode="settings" initialCapabilities={caps}/>}</aside>}
    <nav className="forum-toolbar" aria-label="Forum navigation"><button className="forum-primary" onClick={()=>void api().tabs.create({url:api().runtime.getURL('forum.html?new=thread')})}>New thread</button><form onSubmit={search}><label className="sr-only" htmlFor="post-search">Post number</label><input id="post-search" placeholder="Post No." inputMode="numeric" value={input} onChange={e=>setInput(e.target.value)}/><button type="submit">Go</button></form></nav>
    {error&&<div role="alert"><p>{error}</p><button onClick={()=>updateRequired?api().runtime.reload():setRefresh(v=>v+1)}>{updateRequired?'Reload NockApp extension':'Retry loading'}</button></div>}
    {busy&&<section className="forum-progress" aria-live="polite"><progress aria-label="Loading verified posts" max={thread?.total||undefined} value={thread?.total?thread.checked:undefined}/><p>{status}</p></section>}
    {!raw&&!composing&&<h1 className="forum-title">Posts</h1>}
    {raw&&<div className="forum-thread-heading"><h1>{canReply?`Thread No.${root.post_number}`:`Post No.${raw}`}</h1><p className="forum-muted">Bookmark this page or look up any post by its number.</p></div>}
    <section className="forum-records" aria-label={raw?'Thread posts':'Canonical posts'}>{posts.map(row=><Post key={row.post_number} row={row} preview={!isTab}/> )}</section>
    {!busy&&!error&&!raw&&!composing&&!posts.length&&<p className="forum-empty">No published posts yet. Start a thread.</p>}
    {page&&<nav className="forum-pagination" aria-label="Post pages"><button disabled={busy||after===0} onClick={()=>setAfter(Math.max(0,after-4))}>Previous</button><span>{page.posts.length?`${after+1}–${page.next_after}`:'0'} of {Number(page.next_number)-1}</span><button disabled={busy||!page.more} onClick={()=>setAfter(page.next_after)}>Next</button></nav>}
    {raw&&thread?.complete&&<p className="forum-muted">{canReply?`${thread.posts.length} ${thread.posts.length===1?'reply':'replies'} · checked through post No.${thread.total}. Missing files cannot be assigned to a thread.`:'The full thread cannot be reconstructed from the available verified files.'}</p>}
    {caps&&composing&&<section className="forum-compose"><h1>New thread</h1><PublicDiscussion mode="editor" initialCapabilities={caps} onPublished={n=>{location.href=forumURL(n);}}/></section>}
    {caps&&raw&&canReply&&<section className="forum-compose"><h2>Reply to this thread</h2><PublicDiscussion key={root.bundle_hash} mode="editor" root={root} initialCapabilities={caps} onPublished={()=>setRefresh(v=>v+1)}/></section>}
    <footer className="forum-footer">Posts and badges are verified automatically. Reading is free.</footer>
  </main>;
}
