//! Versioned G1 Schnorr authorization and selective equality proofs.
//! This is a component candidate, not an audited protocol or deployed service.
//! No G2 public key/signature under the holder scalar may be published: that
//! would permit pairing-based comparison of these G1 pseudonyms.
use credx::create_domain_proof_generator;
use credx::prelude::blsful::inner_types::{Field, G1Affine, G1Projective, Scalar};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

pub const PROFILE: &str = "nockapp-private-authorship-v4";
const ROOT_DOMAIN: &[u8] = b"nockapp/zkid/domain-research/v1";
const POST_DOMAIN: &[u8] = b"nockapp/authorship/v4/post/";
pub const MAX_STATEMENTS: usize = 17;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    let mut out = [0; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2*i..2*i+2], 16).ok()?;
    }
    Some(out)
}
pub fn point(p: G1Projective) -> String { hex(&G1Affine::from(p).to_compressed()) }
fn parse_point(s: &str) -> Option<G1Projective> {
    let affine = Option::<G1Affine>::from(G1Affine::from_compressed(&unhex::<48>(s)?))?;
    let p = G1Projective::from(affine);
    (p != G1Projective::IDENTITY).then_some(p)
}
fn scalar(s: &str) -> Option<Scalar> {
    Option::<Scalar>::from(Scalar::from_le_bytes(&unhex::<32>(s)?))
}
pub fn secret_scalar(s: &str) -> Option<Scalar> {
    scalar(s).filter(|v| *v != Scalar::ZERO)
}
pub fn encode_secret(s: Scalar) -> Option<String> {
    (s != Scalar::ZERO).then(|| hex(&s.to_le_bytes()))
}
pub fn generate_secret() -> String {
    encode_secret(random_nonzero()).unwrap()
}
fn random_nonzero() -> Scalar {
    loop {
        let n = Scalar::random(rand::rngs::OsRng);
        if n != Scalar::ZERO { return n; }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag="kind", deny_unknown_fields)]
pub enum Scope {
    #[serde(rename="signing-identity")]
    Identity,
    #[serde(rename="post")]
    Post { intent_sha256: String },
}
impl Scope {
    pub fn base(&self) -> Option<G1Projective> {
        let domain = match self {
            Self::Identity => ROOT_DOMAIN.to_vec(),
            Self::Post { intent_sha256 } => {
                let bytes = unhex::<32>(intent_sha256)?;
                if bytes == [0;32] { return None; }
                [POST_DOMAIN, &bytes].concat()
            }
        };
        let base = create_domain_proof_generator(&domain);
        (base != G1Projective::IDENTITY).then_some(base)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub profile: String,
    pub statements: Vec<Statement>,
    pub response: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    pub scope: Scope,
    pub pseudonym: String,
    pub nonce_commitment: String,
}
fn bases(scopes: &[Scope]) -> Option<Vec<G1Projective>> {
    if scopes.is_empty() || scopes.len() > MAX_STATEMENTS { return None; }
    for (i, scope) in scopes.iter().enumerate() {
        if scopes[..i].contains(scope) { return None; }
    }
    scopes.iter().map(Scope::base).collect()
}
fn challenge(statements: &[Statement], context: &str) -> Option<Scalar> {
    let ctx = unhex::<32>(context)?;
    if ctx == [0;32] { return None; }
    let mut t = Transcript::new(b"nockapp/authorship/v4/schnorr-equality");
    t.append_message(b"profile", PROFILE.as_bytes());
    t.append_message(b"context-sha256", &ctx);
    t.append_u64(b"statement-count", statements.len() as u64);
    for s in statements {
        t.append_message(b"scope", &serde_json::to_vec(&s.scope).ok()?);
        t.append_message(b"base", &G1Affine::from(s.scope.base()?).to_compressed());
        t.append_message(b"pseudonym", &unhex::<48>(&s.pseudonym)?);
        t.append_message(b"nonce-commitment", &unhex::<48>(&s.nonce_commitment)?);
    }
    let mut wide = [0;64];
    t.challenge_bytes(b"challenge", &mut wide);
    let c = Scalar::from_bytes_wide(&wide);
    (c != Scalar::ZERO).then_some(c)
}
pub fn pseudonym(secret: &str, scope: &Scope) -> Option<String> {
    Some(point(scope.base()? * secret_scalar(secret)?))
}
pub fn prove(secret: &str, scopes: &[Scope], context: &str) -> Option<Proof> {
    let s = secret_scalar(secret)?;
    let bs = bases(scopes)?;
    let k = random_nonzero();
    let statements: Vec<_> = scopes.iter().zip(bs).map(|(scope, b)| Statement {
        scope: scope.clone(), pseudonym: point(b*s), nonce_commitment: point(b*k),
    }).collect();
    let response = hex(&(k + challenge(&statements, context)?*s).to_le_bytes());
    Some(Proof { profile: PROFILE.into(), statements, response })
}
/// Expected scopes/context are reconstructed by the verifier, never trusted
/// merely because a prover embedded them. Expected public address/commitments
/// must additionally match the returned pseudonyms at the calling boundary.
pub fn verify(proof: &Proof, expected_scopes: &[Scope], context: &str) -> bool {
    let Some(bs) = bases(expected_scopes) else { return false; };
    if proof.profile != PROFILE || proof.statements.len()!=expected_scopes.len()
        || proof.statements.iter().zip(expected_scopes).any(|(s,e)| &s.scope!=e) {
        return false;
    }
    let Some(z) = scalar(&proof.response) else { return false; };
    let Some(c) = challenge(&proof.statements,context) else { return false; };
    proof.statements.iter().zip(bs).all(|(st,b)| {
        match (parse_point(&st.pseudonym),parse_point(&st.nonce_commitment)) {
            (Some(p),Some(t)) => b*z == t+p*c,
            _ => false,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn post(n: u8) -> Scope { Scope::Post { intent_sha256: format!("{n:02x}").repeat(32) } }
    fn ctx() -> String { "ab".repeat(32) }
    #[test]
    fn ordinary_authorization_is_randomized_and_content_bound() {
        let secret=generate_secret(); let scopes=[post(1)];
        let a=prove(&secret,&scopes,&ctx()).unwrap();
        let b=prove(&secret,&scopes,&ctx()).unwrap();
        assert!(verify(&a,&scopes,&ctx())); assert!(verify(&b,&scopes,&ctx()));
        assert_eq!(a.statements[0].pseudonym,b.statements[0].pseudonym);
        assert_ne!(a.statements[0].nonce_commitment,b.statements[0].nonce_commitment);
        assert_ne!(a.response,b.response);
        assert!(!verify(&a,&[post(2)],&ctx()));
        assert!(!verify(&a,&scopes,&"ac".repeat(32)));
        assert_ne!(pseudonym(&secret,&post(1)),pseudonym(&secret,&post(2)));
        assert_ne!(pseudonym(&secret,&post(1)),pseudonym(&secret,&Scope::Identity));
    }
    #[test]
    fn selected_posts_and_optional_address_share_one_controller() {
        let secret=generate_secret();let scopes=[post(1),post(2),Scope::Identity];
        let proof=prove(&secret,&scopes,&ctx()).unwrap();assert!(verify(&proof,&scopes,&ctx()));
        for (s,scope) in proof.statements.iter().zip(&scopes) {
            assert_eq!(Some(s.pseudonym.clone()),pseudonym(&secret,scope));
        }
        let mut splice=proof.clone();
        splice.statements[1]=prove(&generate_secret(),&[post(2)],&ctx()).unwrap().statements.remove(0);
        assert!(!verify(&splice,&scopes,&ctx()));
        let mut reordered=proof.clone();reordered.statements.swap(0,1);
        assert!(!verify(&reordered,&scopes,&ctx()));
        assert!(!verify(&proof,&scopes[..2],&ctx()));
    }
    #[test]
    fn rejects_degenerate_and_malformed_values() {
        let secret=generate_secret();let scopes=[post(1)];
        assert!(prove(&"00".repeat(32),&scopes,&ctx()).is_none());
        assert!(prove(&secret,&[],&ctx()).is_none());
        assert!(prove(&secret,&[post(1),post(1)],&ctx()).is_none());
        assert!(prove(&secret,&[post(0)],&ctx()).is_none());
        assert!(prove(&secret,&scopes,&"00".repeat(32)).is_none());
        let good=prove(&secret,&scopes,&ctx()).unwrap();
        for text in ["00".repeat(48),"ff".repeat(48),"c0".to_owned()+&"00".repeat(47),"AA".repeat(48)] {
            let mut bad=good.clone();bad.statements[0].pseudonym=text;
            assert!(!verify(&bad,&scopes,&ctx()));
        }
        let mut bad=good.clone();bad.response="ff".repeat(32);assert!(!verify(&bad,&scopes,&ctx()));
        let mut bad=good.clone();bad.profile="v3".into();assert!(!verify(&bad,&scopes,&ctx()));
        let mut bad=good.clone();bad.response="00".repeat(32);assert!(!verify(&bad,&scopes,&ctx()));
    }
    #[test]
    fn fresh_ownership_challenge_cannot_be_replayed_as_post_or_claim() {
        let secret=generate_secret();let scopes=[Scope::Identity];
        let proof=prove(&secret,&scopes,&ctx()).unwrap();
        assert!(verify(&proof,&scopes,&ctx()));
        assert!(!verify(&proof,&scopes,&"ba".repeat(32)));
        assert!(!verify(&proof,&[post(1)],&ctx()));
    }
}

#[cfg(feature="private-authorship-v4")]
#[allow(dead_code)]
#[path="../../count-crypto/src/application.rs"]
mod count_compat;
#[cfg(feature="private-authorship-v4")]
pub use count_compat::author_v4;
