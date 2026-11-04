//! Versioned hidden-date renewal credential. Internal private pipes only.
//! This component does not authenticate Twitter or deploy a trusted issuer.
use credx::{create_domain_proof_generator,indexmap::indexmap,prelude::*};
use credx::knox::{bbs::BbsScheme,accumulator::vb20::{Element,MembershipWitness}};
use credx::knox::short_group_sig_core::short_group_traits::BlindSignatureContext as _;
use credx::prelude::blsful::inner_types::{G1Projective,Scalar};
use nockapp_authorship_v4::{secret_scalar,point,Scope};
use serde::{Serialize,Deserialize};
use std::{collections::{BTreeMap,BTreeSet},io::{Read,Write}};

const PROFILE:&str="nockapp-renewal-count-v3";
const PRESENTATION:&str="nockapp-hidden-renewal-presentation-v3";
const INTERNAL:&str="nockapp-renewal-internal-v3";
const POLICY:&str="6e3cf51ea945e356af60b8d99d710b49ef561d1430cd829fa64068aa2f9f4a92";
const MAX_COUNT:u64=(1u64<<53)-1;
const MAX_TIME:u64=(1u64<<32)-1;
const LIMIT:usize=262144;
const LABELS:[&str;9]=["revocation","secret","source","policy","issued_at","renew_by","controlled","follower_count","issuance_binding"];
type Proof=Presentation<BbsScheme>;
type Bundle=CredentialBundle<BbsScheme>;

fn schema_named(profile:&str,labels:&[&str;9])->CredentialSchema {
    let claims=labels.iter().enumerate().map(|(i,label)|ClaimSchema {
        label:(*label).into(),claim_type:match i {0=>ClaimType::Revocation,1=>ClaimType::Scalar,4..=7=>ClaimType::Number,_=>ClaimType::Hashed},
        print_friendly:false,validators:vec![],
    }).collect::<Vec<_>>();
    let mut s=CredentialSchema::new(Some(profile),None,&["secret"],&claims).unwrap();s.id=profile.into();s
}
fn schema()->CredentialSchema {schema_named(PROFILE,&LABELS)}
fn original_schema()->CredentialSchema {
    schema_named("nockapp-zkid-domain-application-lab-v1",&["revocation","secret","source","policy","start","expiry","controlled","follower_ge_10000","issuance_binding"])
}
fn key_ok(public:&IssuerPublic<BbsScheme>)->bool {
    let k=&public.verifying_key;k.is_invalid().unwrap_u8()==0 && *k==k.compress().decompress()
}
fn schema_is(public:&IssuerPublic<BbsScheme>,s:CredentialSchema)->bool {
    key_ok(public) && serde_json::to_value(&public.schema).ok()==serde_json::to_value(s).ok()
}
fn projected(mut public:IssuerPublic<BbsScheme>)->Option<IssuerPublic<BbsScheme>> {
    if !schema_is(&public,original_schema()) {return None;}
    public.schema=schema();Some(public)
}
fn issuer_projection(mut issuer:Issuer<BbsScheme>)->Option<Issuer<BbsScheme>> {
    projected(IssuerPublic::from(&issuer))?;issuer.schema=schema();Some(issuer)
}
fn same(a:&IssuerPublic<BbsScheme>,b:&IssuerPublic<BbsScheme>)->bool {
    let mut a=serde_json::to_value(a).unwrap();let mut b=serde_json::to_value(b).unwrap();
    a.as_object_mut().unwrap().remove("revocation_registry");b.as_object_mut().unwrap().remove("revocation_registry");a==b
}
fn hash(v:&str)->bool {v.len()==64 && v.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) && !v.bytes().all(|b|b==b'0')}
fn number(v:Option<&ClaimData>)->Option<i64> {match v {Some(ClaimData::Number(c))=>Some(c.value as i64),_=>None}}
fn hashed(v:Option<&ClaimData>,s:&str)->bool {matches!(v,Some(ClaimData::Hashed(c)) if c.value==s.as_bytes())}

fn leap(y:u64)->bool {y%4==0 && (y%100!=0 || y%400==0)}
fn month_days(y:u64,m:u64)->u64 {match m {2=>if leap(y){29}else{28},4|6|9|11=>30,_=>31}}
// Bounded UTC calendar arithmetic, no new dependency. Limit is explicit2106,
// not a fixed approximation such as180 days. Preserve time-of-day; clamp dates.
fn six_months(start:u64)->Option<u64> {
    if start==0 || start>MAX_TIME {return None;}
    let mut days=start/86400;let mut y=1970;
    while days>=if leap(y){366}else{365} {days-=if leap(y){366}else{365};y+=1;}
    let mut m=1;while days>=month_days(y,m) {days-=month_days(y,m);m+=1;}
    let d=days+1;m+=6;if m>12 {m-=12;y+=1;}
    let d=d.min(month_days(y,m));
    let total=(1970..y).map(|v|if leap(v){366}else{365}).sum::<u64>()
        +(1..m).map(|v|month_days(y,v)).sum::<u64>()+d-1;
    let end=total*86400+start%86400;(end<=MAX_TIME).then_some(end)
}

#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Attributes {source:String,policy:String,issued_at:u64,renew_by:u64,controlled:u8,followers:u64,binding:String}
fn valid_attrs(a:&Attributes)->bool {
    a.source=="twitterapi.io" && a.policy==POLICY && a.controlled==1 && a.followers<=MAX_COUNT
        && hash(&a.binding) && six_months(a.issued_at)==Some(a.renew_by)
}
fn known(a:&Attributes,handle:&str)->BTreeMap<String,ClaimData> {
    BTreeMap::from([
        ("revocation".into(),RevocationClaim::from(handle).into()),("source".into(),HashedClaim::from(a.source.as_str()).into()),
        ("policy".into(),HashedClaim::from(a.policy.as_str()).into()),("issued_at".into(),NumberClaim::from(a.issued_at as isize).into()),
        ("renew_by".into(),NumberClaim::from(a.renew_by as isize).into()),("controlled".into(),NumberClaim::from(1isize).into()),
        ("follower_count".into(),NumberClaim::from(a.followers as isize).into()),("issuance_binding".into(),HashedClaim::from(a.binding.as_str()).into()),
    ])
}
fn received(bundle:&Bundle,a:&Attributes,s:Scalar)->bool {
    let c=&bundle.credential.claims;c.len()==9 && matches!(c[1],ClaimData::Scalar(v) if v.value==s)
        && hashed(c.get(2),&a.source) && hashed(c.get(3),&a.policy) && number(c.get(4))==Some(a.issued_at as i64)
        && number(c.get(5))==Some(a.renew_by as i64) && number(c.get(6))==Some(1)
        && number(c.get(7))==Some(a.followers as i64) && hashed(c.get(8),&a.binding)
}
fn staged(issuer:&Issuer<BbsScheme>,handle:&str)->Option<Issuer<BbsScheme>> {
    if !issuer.revocation_registry.elements.contains(handle) || issuer.revocation_registry.active.contains(handle) {return None;}
    let mut s=issuer.clone();s.revocation_registry.value.add_assign(&s.revocation_key,Element::hash(handle.as_bytes()));
    s.revocation_registry.active.insert(handle.into());Some(s)
}
fn receipt_schema(public:&IssuerPublic<BbsScheme>)->PresentationSchema<BbsScheme> {
    PresentationSchema::new_with_id(&[SignatureStatement {id:"receipt".into(),issuer:public.clone(),
        disclosed:BTreeSet::from(["issuance_binding".into()])}.into()],"nockapp-renewal-replacement-receipt-v3")
}
fn receipt_nonce(binding:&str)->Vec<u8> {serde_json::to_vec(&[PROFILE,"replacement-receipt",binding]).unwrap()}
fn receipt_valid(p:&Proof,public:&IssuerPublic<BbsScheme>,binding:&str)->bool {
    p.proofs.len()==1 && p.disclosed_messages.len()==1
        && matches!(p.proofs.get("receipt"),Some(PresentationProofs::Signature(v)) if v.id=="receipt")
        && p.disclosed_messages.get("receipt").is_some_and(|v|v.len()==1 && hashed(v.get("issuance_binding"),binding))
        && p.verify(&receipt_schema(public),&receipt_nonce(binding)).is_ok()
}

#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Trust {issuer:IssuerPublic<BbsScheme>,policy:String,scope:String,threshold:u64,window_start:u64,window_end:u64,
    registry_sequence:u64,current_sequence:u64,indexed_at:u64}
fn trust_ok(t:&Trust)->bool {
    t.policy==POLICY && schema_is(&t.issuer,schema()) && hash(&t.scope) && t.threshold<MAX_COUNT
        && t.window_start>0 && t.window_end<=MAX_TIME && t.window_end.checked_sub(t.window_start)==Some(60)
        && t.registry_sequence<1u64<<53 && t.current_sequence==t.registry_sequence
        && t.window_start<=t.indexed_at && t.indexed_at<t.window_end
}
fn proof_schema(t:&Trust)->Option<PresentationSchema<BbsScheme>> {
    if !trust_ok(t) {return None;}
    let mut statements=vec![
        SignatureStatement {id:"credential".into(),issuer:t.issuer.clone(),disclosed:BTreeSet::from(["source".into(),"policy".into(),"controlled".into()])}.into(),
        RevocationStatement {id:"active".into(),reference_id:"credential".into(),claim:0,
            accumulator:t.issuer.revocation_registry,verification_key:t.issuer.revocation_verifying_key}.into(),
    ];
    for (label,claim,lo,hi) in [("followers",7,t.threshold+1,MAX_COUNT),("issued",4,0,t.window_start),("expiry",5,t.window_end,MAX_TIME)] {
        let commitment=format!("{label}-commitment");
        statements.push(CommitmentStatement {id:commitment.clone(),reference_id:"credential".into(),claim,
            message_generator:create_domain_proof_generator(format!("NOCKAPP/RENEWAL/v3/{label}/message").as_bytes()),
            blinder_generator:create_domain_proof_generator(format!("NOCKAPP/RENEWAL/v3/{label}/blinder").as_bytes())}.into());
        statements.push(RangeStatement {id:format!("{label}-range"),reference_id:commitment,signature_id:"credential".into(),claim,
            lower:Some(lo as isize),upper:Some(hi as isize)}.into());
    }
    statements.push(CommitmentStatement {id:"post-author".into(),reference_id:"credential".into(),claim:1,
        message_generator:Scope::Post {intent_sha256:t.scope.clone()}.base()?,blinder_generator:G1Projective::IDENTITY}.into());
    Some(PresentationSchema::new_with_id(&statements,PRESENTATION))
}
fn nonce(t:&Trust)->Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"profile":PRESENTATION,"policy":POLICY,"scope":t.scope,
        "threshold":t.threshold,"window_start":t.window_start,"window_end":t.window_end,"registry_sequence":t.registry_sequence})).unwrap()
}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicProof {profile:String,#[serde(deserialize_with="decode_proof")]proof:Proof}
fn decode_proof<'de,D:serde::Deserializer<'de>>(d:D)->Result<Proof,D::Error> {
    use serde::de::Error;
    let mut raw=serde_json::Value::deserialize(d)?;let mut ranges=vec![];
    for id in ["followers-range","issued-range","expiry-range"] {
        if let Some(value)=raw.get_mut("proofs").and_then(serde_json::Value::as_object_mut).and_then(|v|v.remove(id)) {ranges.push((id,value));}
    }
    let bytes=serde_json::to_vec(&raw).map_err(D::Error::custom)?;
    let mut result:Proof=serde_json::from_slice(&bytes).map_err(D::Error::custom)?;
    for (id,value) in ranges {
        #[derive(Deserialize)] #[serde(deny_unknown_fields)] struct Wire {id:String,proof:Vec<u8>}
        #[derive(Deserialize)] #[serde(deny_unknown_fields)] struct Variant {#[serde(rename="Range")]range:Wire}
        let v:Variant=serde_json::from_value(value).map_err(D::Error::custom)?;
        if v.range.id!=id || v.range.proof.is_empty() || v.range.proof.len()>8192 {return Err(D::Error::custom("range bytes"));}
        let decoder=serde::de::value::BorrowedBytesDeserializer::<serde::de::value::Error>::new(&v.range.proof);
        let p=Deserialize::deserialize(decoder).map_err(D::Error::custom)?;
        result.proofs.insert(id.into(),PresentationProofs::Range(Box::new(credx::presentation::RangeProof {id:id.into(),proof:p})));
    }
    Ok(result)
}
fn verify(p:&PublicProof,t:&Trust,expected:&str)->bool {
    let Some(schema)=proof_schema(t) else {return false;};let p0=&p.proof;
    if p.profile!=PRESENTATION || p0.proofs.len()!=9 || p0.disclosed_messages.len()!=1
        || p0.proofs.iter().any(|(id,p)|p.id()!=id) {return false;}
    for (id,kind) in [("credential",0),("active",1),("followers-commitment",2),("followers-range",3),
        ("issued-commitment",2),("issued-range",3),("expiry-commitment",2),("expiry-range",3),("post-author",2)] {
        let Some(p)=p0.proofs.get(id) else {return false;};
        if !matches!((kind,p),(0,PresentationProofs::Signature(_))|(1,PresentationProofs::Revocation(_))
            |(2,PresentationProofs::Commitment(_))|(3,PresentationProofs::Range(_))) {return false;}
    }
    let Some(v)=p0.disclosed_messages.get("credential") else {return false;};
    if v.keys().cloned().collect::<BTreeSet<_>>()!=BTreeSet::from(["source".into(),"policy".into(),"controlled".into()])
        || !hashed(v.get("source"),"twitterapi.io") || !hashed(v.get("policy"),POLICY) || number(v.get("controlled"))!=Some(1) {return false;}
    if !matches!(&p0.proofs["post-author"],PresentationProofs::Commitment(v) if v.commitment!=G1Projective::IDENTITY && point(v.commitment)==expected) {return false;}
    p0.verify(&schema,&nonce(t)).is_ok()
}
fn present(bundle:Bundle,t:&Trust,expected:&str)->Option<PublicProof> {
    let s=proof_schema(t)?;if !same(&bundle.issuer,&t.issuer) || bundle.credential.claims.len()!=9 {return None;}
    let c=&bundle.credential.claims;let count=number(c.get(7))?;let issued=number(c.get(4))?;let end=number(c.get(5))?;
    if count<0 || count as u64>MAX_COUNT || count as u64<=t.threshold || issued<0 || issued as u64>t.window_start
        || end<0 || (end as u64)<t.window_end || six_months(issued as u64)!=Some(end as u64) {return None;}
    let secret=match c[1] {ClaimData::Scalar(v)=>v.value,_=>return None};
    if nockapp_authorship_v4::encode_secret(secret).is_none() || point(Scope::Post{intent_sha256:t.scope.clone()}.base()?*secret)!=expected {return None;}
    let proof=Presentation::create(&indexmap!{"credential".into()=>bundle.credential.into()},&s,&nonce(t)).ok()?;
    let out=PublicProof {profile:PRESENTATION.into(),proof};verify(&out,t,expected).then_some(out)
}

// Private activation is independent of a public follower threshold. In
// particular, a genuine credential with zero followers can be held/activated.
// The proof is verified locally and never exported as a publication claim.
fn active(bundle:Bundle,public:&IssuerPublic<BbsScheme>,expected_secret:&str,now:u64)->bool {
    let Some(secret)=secret_scalar(expected_secret) else {return false;};
    if !schema_is(public,schema()) || !same(&bundle.issuer,public) || bundle.credential.claims.len()!=9 {return false;}
    let c=&bundle.credential.claims;
    if !matches!(c[1],ClaimData::Scalar(v) if v.value==secret) || !hashed(c.get(2),"twitterapi.io")
        || !hashed(c.get(3),POLICY) || number(c.get(6))!=Some(1) {return false;}
    let (Some(start),Some(end),Some(count))=(number(c.get(4)),number(c.get(5)),number(c.get(7))) else {return false;};
    if start<0 || end<0 || count<0 || count as u64>MAX_COUNT || six_months(start as u64)!=Some(end as u64)
        || now<(start as u64) || now>=(end as u64) || bundle.issuer.revocation_registry!=public.revocation_registry {return false;}
    let s=PresentationSchema::new_with_id(&[
        SignatureStatement {id:"credential".into(),issuer:public.clone(),disclosed:BTreeSet::new()}.into(),
        RevocationStatement {id:"active".into(),reference_id:"credential".into(),claim:0,
            accumulator:public.revocation_registry,verification_key:public.revocation_verifying_key}.into(),
    ],"nockapp-renewal-private-activation-v3");
    let nonce=credx::random_string(32,rand::thread_rng());
    let Ok(p)=Presentation::create(&indexmap!{"credential".into()=>bundle.credential.into()},&s,nonce.as_bytes()) else {return false;};
    p.verify(&s,nonce.as_bytes()).is_ok()
}

#[derive(Serialize,Deserialize)] #[serde(deny_unknown_fields)]
struct Pending {secret:Scalar,request:BlindCredentialRequest<BbsScheme>,blinder:Scalar}
#[derive(Serialize,Deserialize)] #[serde(deny_unknown_fields)]
struct Input {profile:String,call:Call}
#[derive(Serialize,Deserialize)] #[serde(deny_unknown_fields)]
enum Call {
    #[serde(rename="lab-setup")] LabSetup {capacity:usize},
    #[serde(rename="public-view")] PublicView {public:IssuerPublic<BbsScheme>},
    #[serde(rename="prepare")] Prepare {public:IssuerPublic<BbsScheme>,secret:String},
    #[serde(rename="validate-request")] ValidateRequest {issuer:Issuer<BbsScheme>,request:BlindCredentialRequest<BbsScheme>},
    #[serde(rename="activate")] Activate {credential:Bundle,public:IssuerPublic<BbsScheme>,expected_secret:String,now:u64},
    #[serde(rename="stage")] Stage {issuer:Issuer<BbsScheme>,request:BlindCredentialRequest<BbsScheme>,handle:String,attributes:Attributes},
    #[serde(rename="receive")] Receive {pending:Pending,bundle:BlindCredentialBundle<BbsScheme>,public:IssuerPublic<BbsScheme>,attributes:Attributes},
    #[serde(rename="commit")] Commit {issuer:Issuer<BbsScheme>,handle:String,old_handle:Option<String>,ack:Proof,attributes:Attributes},
    #[serde(rename="witness")] Witness {issuer:Issuer<BbsScheme>,handle:String},
    #[serde(rename="refresh")] Refresh {credential:Bundle,public:IssuerPublic<BbsScheme>,witness:MembershipWitness},
    #[serde(rename="present")] Present {credential:Bundle,trust:Trust,expected_author:String},
    #[serde(rename="verify")] Verify {public_input:PublicProof,trust:Trust,expected_author:String},
    #[serde(rename="calendar")] Calendar {issued_at:u64},
}
fn execute(c:Call)->Option<serde_json::Value> {
    match c {
        Call::LabSetup {capacity}=> {
            if !(2..=1000).contains(&capacity) {return None;}
            let (_,mut issuer)=Issuer::<BbsScheme>::new(&original_schema());
            let handles=(0..capacity).map(|_|credx::random_string(32,rand::thread_rng())).collect::<Vec<_>>();
            issuer.revocation_registry.add(&handles);
            issuer.revoke_credentials(&handles.iter().map(RevocationClaim::from).collect::<Vec<_>>()).ok()?;
            Some(serde_json::json!({"issuer":issuer,"public":IssuerPublic::from(&issuer),"handles":handles}))
        },
        Call::PublicView {public}=>Some(serde_json::json!({"public":projected(public)?})),
        Call::Prepare {public,secret}=> {
            if !schema_is(&public,schema()) {return None;}let secret=secret_scalar(&secret)?;
            let hidden=BTreeMap::from([("secret".into(),ScalarClaim::from(secret).into())]);
            let (request,blinder)=BlindCredentialRequest::new(&public,&hidden).ok()?;
            Some(serde_json::json!({"request":request,"pending":Pending{secret,request:request.clone(),blinder}}))
        },
        Call::ValidateRequest {issuer,request}=> {
            let issuer=issuer_projection(issuer)?;
            if request.blind_claim_labels!=vec!["secret"] || request.blind_signature_context.proofs.len()!=1
                || !request.blind_signature_context.verify(&[0usize,2,3,4,5,6,7,8],&issuer.signing_key,request.nonce).ok()? {return None;}
            Some(serde_json::json!({"valid":true}))
        },
        Call::Activate {credential,public,expected_secret,now}=>Some(serde_json::json!({"accepted":active(credential,&public,&expected_secret,now)})),
        Call::Stage {issuer,request,handle,attributes}=> {
            if !valid_attrs(&attributes) || request.blind_claim_labels!=vec!["secret"] || request.blind_signature_context.proofs.len()!=1 {return None;}
            let issuer=issuer_projection(issuer)?;
            if !request.blind_signature_context.verify(&[0usize,2,3,4,5,6,7,8],&issuer.signing_key,request.nonce).ok()? {return None;}
            let mut next=staged(&issuer,&handle)?;
            let bundle=next.blind_sign_credential(&request,&known(&attributes,&handle)).ok()?;
            Some(serde_json::json!({"bundle":bundle}))
        },
        Call::Receive {pending,bundle,public,attributes}=> {
            if !valid_attrs(&attributes) || !schema_is(&public,schema()) || !same(&bundle.issuer,&public)
                || pending.secret==Scalar::ZERO {return None;}
            let hidden=BTreeMap::from([("secret".into(),ScalarClaim::from(pending.secret).into())]);
            let credential=bundle.to_unblinded(&hidden,pending.blinder).ok()?;
            if !received(&credential,&attributes,pending.secret) {return None;}
            let ack=Presentation::create(&indexmap!{"receipt".into()=>credential.credential.clone().into()},
                &receipt_schema(&credential.issuer),&receipt_nonce(&attributes.binding)).ok()?;
            if !receipt_valid(&ack,&credential.issuer,&attributes.binding) {return None;}
            Some(serde_json::json!({"credential":credential,"ack":ack}))
        },
        Call::Commit {issuer,handle,old_handle,ack,attributes}=> {
            if !valid_attrs(&attributes) {return None;}
            let mut next=staged(&issuer_projection(issuer)?,&handle)?;
            if !receipt_valid(&ack,&IssuerPublic::from(&next),&attributes.binding) {return None;}
            if let Some(old)=old_handle {next.revoke_credentials(&[RevocationClaim::from(old)]).ok()?;}
            next.schema=original_schema();Some(serde_json::json!({"issuer":next,"public":IssuerPublic::from(&next)}))
        },
        Call::Witness {issuer,handle}=> {
            let next=issuer_projection(issuer)?;let witness=next.update_revocation_handle(RevocationClaim::from(handle)).ok()?;
            Some(serde_json::json!({"public":IssuerPublic::from(&next),"witness":witness}))
        },
        Call::Refresh {mut credential,public,witness}=> {
            if !schema_is(&public,schema()) || !same(&credential.issuer,&public) {return None;}
            credential.update_revocation_handle(witness,public.revocation_registry);Some(serde_json::json!({"credential":credential}))
        },
        Call::Present {credential,trust,expected_author}=>Some(serde_json::json!({"presentation":present(credential,&trust,&expected_author)?})),
        Call::Verify {public_input,trust,expected_author}=>Some(serde_json::json!({"accepted":verify(&public_input,&trust,&expected_author)})),
        Call::Calendar {issued_at}=>Some(serde_json::json!({"renew_by":six_months(issued_at)?})),
    }
}
fn run()->Option<()> {
    if std::env::args().collect::<Vec<_>>()!=vec![std::env::args().next()?,"--internal-renewal".into()] {return None;}
    let mut data=vec![];std::io::stdin().take((LIMIT+1) as u64).read_to_end(&mut data).ok()?;
    if data.len()>LIMIT {return None;}
    let input:Input=nockapp_authorship_v4::author_v4::decode_rpc(&data)?;
    if input.profile!=INTERNAL {return None;}
    let out=serde_json::to_vec(&serde_json::json!({"profile":INTERNAL,"result":execute(input.call)?})).ok()?;
    if out.len()>LIMIT {return None;}std::io::stdout().write_all(&out).ok()?;Some(())
}
fn main() {std::panic::set_hook(Box::new(|_|{}));if run().is_none(){std::process::exit(1);}}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn calendar_month_end_and_leap_year_boundaries() {
        assert_eq!(six_months(1756684800),Some(1772323200)); //2025-09-01 ->2026-03-01
        assert_eq!(six_months(0),None);assert_eq!(six_months(MAX_TIME),None);
    }
}
