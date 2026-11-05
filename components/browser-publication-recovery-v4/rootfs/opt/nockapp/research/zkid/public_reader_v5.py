"""Bounded independent public log/content/proof composition for protocol5.

One RPC-finalized snapshot per page; no remote validity verdict or private DB.
All requested allocated numbers survive content/proof failure. Page completeness
means only the explicitly requested numbers, never the complete public log.
"""
from concurrent.futures import ThreadPoolExecutor
from authorship_v5 import reference,verify as verify_author
from base_protocol import words
from indexed_authorship_v5 import verify_indexed_bundle
from policy import require,timestamp
from public_bundle_v5 import decode

MAX_RECORDS=32


class PublicDiscussionReader:
    def __init__(self,index,content,native,*,count_native=None,issuer_views=None,
            bundle_verifier=verify_indexed_bundle,proof_cache=None,historical_only=False):
        self.index=index;self.content=content;self.native=native
        self.count_native=count_native
        # Public authority adapter: at(record) and current(finalized block).
        # It must authenticate its chain/definition, not trust bundle issuer data.
        self.issuer_views=issuer_views
        require(type(historical_only) is bool,'v5-reader-policy')
        require(proof_cache is None or historical_only,'historical-cache-policy-required')
        self.bundle_verifier=bundle_verifier;self.proof_cache=proof_cache;self.historical_only=historical_only

    def resolve_original(self,ref):
        """Public original bytes/time for a holder's explicit history proof.

        Inclusion is independently checked here; the history primitive still
        verifies the original authorship itself. No remote validity verdict.
        """
        reference(ref);index=self.index
        require(ref['protocol']==5 and ref['chain_id']==index.chain_id and ref['contract']==index.contract,'v5-reference-deployment')
        final=index.anchor()
        if ref['number'] is None:
            fields=words(index._call('records(bytes32)',ref['bundle_hash'],tag=final['number']))
            require(len(fields)==3,'v5-reference-record');number=int.from_bytes(fields[0],'big')
        else:number=int(ref['number'])
        r=index._record(number,final)
        require(r['bundle_hash']==ref['bundle_hash'],'v5-reference-hash')
        raw=self.content.fetch(r['bundle_hash']);decode(raw,r['bundle_hash']);index.finish(final)
        return raw,r['indexed_at']

    def read_page(self,after,limit,now):
        require(type(after) is int and 0<=after<2**53 and type(limit) is int and 1<=limit<=4,'v5-page-cursor')
        page=self.read_numbers(None,now,_page=(after,limit))
        cursor=after+len(page['posts'])
        return {**page,'after':after,'next_after':cursor,'more':cursor<int(page['next_number'])-1}

    def read_numbers(self,numbers,now,*,_page=None):
        require((_page is not None and numbers is None) or (type(numbers) is list and 1<=len(numbers)<=8
            and all(type(n) is int and 0<n<2**53 for n in numbers)
            and len(set(numbers))==len(numbers)),'v5-page-limit');timestamp(now)
        index=self.index;final=index.anchor()
        require(int(final['timestamp'],16)<=now,'v5-reader-time')
        next_number=int(index._call('nextPostNumber()',tag=final['number']),16)
        require(0<next_number<=2**53,'v5-index-next-number')
        if _page is not None:
            after,limit=_page
            require(type(after) is int and 0<=after<next_number and type(limit) is int and 1<=limit<=4,'v5-page-cursor')
            numbers=list(range(after+1,min(next_number,after+limit+1)))
        records={};raws={};failed_content=set();originals={};dependencies={}
        def record(n):
            require(0<n<next_number,'v5-reference-unassigned')
            if n not in records:
                require(len(records)<MAX_RECORDS,'v5-page-work-limit')
                records[n]=index._record(n,final)
            return records[n]
        # Authenticate requested canonical allocations before following optional
        # references, so optional work cannot exhaust their budget or hide rows.
        allocated=[n for n in numbers if n<next_number]
        if len(allocated)>1 and getattr(index.rpc,'public_read_batching',False) is True:
            # Public inclusion data only, at most four requests in flight.
            # Complete the bounded preload before optional dependency work.
            with ThreadPoolExecutor(max_workers=min(4,len(allocated))) as pool:
                observed=list(pool.map(lambda n:index._record(n,final),allocated))
            records.update(zip(allocated,observed))
        else:
            for n in allocated:record(n)
        def data(r):
            h=r['bundle_hash']
            require(h not in failed_content,'v5-content-unavailable')
            if h not in raws:
                try:raws[h]=self.content.fetch(h)
                except Exception:
                    failed_content.add(h);raise
            return raws[h]
        def resolve(ref):
            reference(ref)
            require(ref['protocol']==5 and ref['chain_id']==index.chain_id
                and ref['contract']==index.contract,'v5-reference-deployment')
            if ref['number'] is None:
                fields=words(index._call('records(bytes32)',ref['bundle_hash'],tag=final['number']))
                require(len(fields)==3,'v5-reference-record');n=int.from_bytes(fields[0],'big')
            else:n=int(ref['number'])
            r=record(n);require(r['bundle_hash']==ref['bundle_hash'],'v5-reference-hash')
            dependencies[n]=r
            return data(r),r['indexed_at']
        where={'protocol':5,'chain_id':index.chain_id,'application':index.application,'contract':index.contract}
        def root(ref,when):
            key=ref['bundle_hash']
            raw,t=resolve(ref)
            if key not in originals:
                v=decode(raw,key);u=v['unsigned'];c=u['core']
                require(all(c['context'][k]==where[k] for k in where)
                    and c['post']['kind']=='thread' and c['post']['created_at']<=t
                    and verify_author(self.native,u,v['authorship']),'v5-thread-root')
                originals[key]=t
            require(originals[key]<=when,'v5-thread-future')
        rows=[]
        for n in numbers:
            if n>=next_number:
                rows.append({'post_number':str(n),'state':'unassigned','canonical_indexed':False,'proofs_verified':False})
                continue
            r=record(n);row={**r,'state':'content-unavailable'};rows.append(row)
            try:raw=data(r)
            except Exception:continue
            if self.native is None:
                row['state']='verification-unavailable';continue
            row['state']='invalid'
            try:
                u=decode(raw,r['bundle_hash'])['unsigned'] # Hash/schema checked even on a cache hit.
                checked=None;dependencies.clear()
                if self.proof_cache is not None:
                    checked=self.proof_cache.get(index.scope,r,lambda dep:record(int(dep['post_number']))==dep)
                if checked is None:
                    legacy=current=None
                    if (self.issuer_views is not None and u['core']['selection']['followers_threshold'] is not None
                            and u['evidence']['followers'] is not None):
                        try:
                            legacy=self.issuer_views.at(r)
                            if not self.historical_only:current=self.issuer_views.current(final)
                        except Exception:pass
                    checked=self.bundle_verifier(raw,r['bundle_hash'],where,r['indexed_at'],now,self.native,
                        count_native=self.count_native,issuer_view=legacy,current_issuer_view=current,resolve_history=resolve)
                    s=u['core']['selection'];display=checked['display']
                    complete=(not s['address'] or display['address'] is not None) and (s['followers_threshold'] is None
                        or display['followers'] is not None) and (u['evidence']['history'] is None or display['history'] is not None)
                    if self.proof_cache is not None and complete:
                        self.proof_cache.put(index.scope,r,checked,list(dependencies.values()))
                row.update(checked,state='finalized',proofs_verified=True,relationship_state='valid')
                if checked['thread'] is not None:
                    try:root(checked['thread'],r['indexed_at'])
                    except Exception:row['relationship_state']='unverified'
            except Exception:pass
        index.finish(final)
        return {'profile':'nockapp-public-page-v5','posts':rows,'requested_numbers':[str(n) for n in numbers],
            'next_number':str(next_number),'finalized_block':{'number':final['number'],'hash':final['hash']},
            'whole_log_complete':False,'checked_records':len(records),'rpc_finality_trusted':True}
