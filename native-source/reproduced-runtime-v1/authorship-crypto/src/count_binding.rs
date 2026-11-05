//! Same signed hidden holder claim in the strict range and per-post pseudonym.
//! Reuses unchanged count-v2 schema/key/range machinery under a distinct nonce
//! and presentation schema ID. This never treats a legacy proof as authored.
use super::*;
use crate::{encode_secret,point,secret_scalar,Scope};
const AUTH_PROFILE: &str="nockapp-authored-count-presentation-v4";
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundTrust { pub legacy: Trust, pub intent_sha256: String }
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundProof {
    pub profile: String,
    #[serde(deserialize_with="decode_count_proof")]
    pub proof: Proof,
}
fn author_schema(t: &BoundTrust) -> Option<PresentationSchema<BbsScheme>> {
    let c=&t.legacy.challenge;
    if c.identity || c.scope!=t.intent_sha256 || c.facts!=["account-controlled","followers-more-than"]
        || c.threshold.is_none() { return None; }
    let mut base=schema(&t.legacy)?;
    let author=CommitmentStatement {
        id:"post-author".into(),reference_id:"credential".into(),claim:1,
        message_generator:Scope::Post { intent_sha256:t.intent_sha256.clone() }.base()?,
        blinder_generator:G1Projective::IDENTITY,
    };
    base.statements.insert("post-author".into(),author.into());base.id=AUTH_PROFILE.into();Some(base)
}
fn nonce(t: &BoundTrust) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"profile":AUTH_PROFILE,"intent_sha256":t.intent_sha256,
        "challenge":t.legacy.challenge})).unwrap()
}
pub fn prepare(public: IssuerPublic<BbsScheme>,secret: &str) -> Option<serde_json::Value> {
    let secret=secret_scalar(secret)?;let key=&public.verifying_key;
    if key.is_invalid().unwrap_u8()!=0 || *key!=key.compress().decompress()
        || serde_json::to_value(&public.schema).ok()?!=serde_json::to_value(credential_schema()).ok()? { return None; }
    let hidden=BTreeMap::from([("secret".into(),ScalarClaim::from(secret).into())]);
    let (request,blinder)=BlindCredentialRequest::new(&public,&hidden).ok()?;
    Some(serde_json::json!({"request":request,"pending":{"secret":secret,"request":request,"blinder":blinder},
        "local_zkid":create_domain_proof_generator(DOMAIN)*secret}))
}
pub fn present_bound(credential: Bundle,t: &BoundTrust,expected_author: &str) -> Option<BoundProof> {
    let schema=author_schema(t)?;
    let mut actual=serde_json::to_value(&credential.issuer).ok()?;
    let mut expected=serde_json::to_value(&t.legacy.issuer).ok()?;
    actual.as_object_mut()?.remove("revocation_registry");expected.as_object_mut()?.remove("revocation_registry");
    if actual!=expected || credential.credential.claims.len()!=LABELS.len() { return None; }
    let count=number(credential.credential.claims.get(7))?;
    if count<0 || count as u64>MAX_COUNT || (count as u64)<=t.legacy.challenge.threshold? { return None; }
    let secret=match credential.credential.claims[1] { ClaimData::Scalar(s)=>s.value,_=>return None };
    encode_secret(secret)?;
    let base=Scope::Post { intent_sha256:t.intent_sha256.clone() }.base()?;
    if point(base*secret)!=expected_author { return None; }
    let proof=Presentation::create(&indexmap!{"credential".into()=>credential.credential.into()},&schema,&nonce(t)).ok()?;
    Some(BoundProof { profile:AUTH_PROFILE.into(),proof })
}
pub fn verify_bound(input: &BoundProof,t: &BoundTrust,expected_author: &str) -> bool {
    let Some(schema)=author_schema(t) else { return false; };
    let c=&t.legacy.challenge;let proof=&input.proof;
    if input.profile!=AUTH_PROFILE || c.registry_sequence!=t.legacy.current_sequence
        || t.legacy.now<c.created_at || t.legacy.now>=c.expires_at { return false; }
    let keys=["credential","active","followers-commitment","followers-range","post-author"];
    if proof.proofs.len()!=keys.len() || keys.iter().any(|k|!proof.proofs.contains_key(*k))
        || proof.proofs.iter().any(|(id,p)|p.id()!=id) || proof.disclosed_messages.len()!=1
        || !matches!(proof.proofs["credential"],PresentationProofs::Signature(_))
        || !matches!(proof.proofs["active"],PresentationProofs::Revocation(_))
        || !matches!(proof.proofs["followers-commitment"],PresentationProofs::Commitment(_))
        || !matches!(proof.proofs["followers-range"],PresentationProofs::Range(_)) { return false; }
    match &proof.proofs["post-author"] {
        PresentationProofs::Commitment(p) if p.commitment!=G1Projective::IDENTITY && point(p.commitment)==expected_author=>(),
        _=>return false,
    }
    let Some(disclosed)=proof.disclosed_messages.get("credential") else { return false; };
    if Some(disclosed.keys().cloned().collect::<BTreeSet<_>>())!=disclosure(c)
        || !hashed(disclosed.get("source"),SOURCE) || !hashed(disclosed.get("policy"),&t.legacy.policy)
        || number(disclosed.get("controlled"))!=Some(1) { return false; }
    let (Some(start),Some(expiry))=(number(disclosed.get("start")),number(disclosed.get("expiry"))) else { return false; };
    if start<0 || start%3600!=0 || expiry.checked_sub(start)!=Some(86400)
        || t.legacy.now<(start as u64) || t.legacy.now>=(expiry as u64) { return false; }
    proof.verify(&schema,&nonce(t)).is_ok()
}

/// Strict duplicate/unknown-field RPC boundary reused from the pinned count adapter.
pub fn decode_rpc<T: serde::de::DeserializeOwned+Serialize>(bytes: &[u8]) -> Option<T> { decode(bytes) }
