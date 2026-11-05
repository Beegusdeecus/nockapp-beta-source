//! Application-level research acceptance. No network or production trust setup.
use credx::knox::accumulator::vb20::Element;
use credx::knox::bbs::BbsScheme;
use credx::prelude::blsful::inner_types::{G1Projective, Scalar};
use credx::{create_domain_proof_generator, indexmap::indexmap, prelude::*};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};

pub mod rpc;

// Upstream structs do not uniformly reject unknown JSON fields. Reject duplicate
// keys before typed parsing, then require a lossless public representation.
// This also catches duplicate IDs in upstream's sequence-encoded maps.
struct StrictJson(serde_json::Value);
impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = StrictJson;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("bounded public JSON")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictJson(serde_json::Value::Null))
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(StrictJson(v.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(StrictJson(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(StrictJson(v.into()))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(StrictJson(v.into()))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(StrictJson(v.into()))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = a.next_element::<StrictJson>()? {
                    values.push(value.0);
                }
                Ok(StrictJson(serde_json::Value::Array(values)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = a.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate public field"));
                    }
                    values.insert(key, a.next_value::<StrictJson>()?.0);
                }
                Ok(StrictJson(serde_json::Value::Object(values)))
            }
        }
        d.deserialize_any(Visitor)
    }
}

fn decode<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> Option<T> {
    let raw = serde_json::from_slice::<StrictJson>(bytes).ok()?.0;
    // Some upstream group decoders borrow from the original JSON strings.
    // Decode from those bytes, after the strict structural pass.
    let value: T = serde_json::from_slice(bytes).ok()?;
    if serde_json::to_value(&value).ok()? != raw {
        return None;
    }
    Some(value)
}

const PROFILE: &str = "nockapp-zkid-count-application-v2";
const DOMAIN: &[u8] = b"nockapp/zkid/domain-research/v1";
const SOURCE: &str = "twitterapi.io";
const COUNT_POLICY: &str = "c4e45d3d041449f204249d2069bf922606ca8e70143d4175cdc4054ee452da29";
const MAX_COUNT: u64 = (1u64 << 53) - 1;
const LABELS: [&str; 9] = [
    "revocation",
    "secret",
    "source",
    "policy",
    "start",
    "expiry",
    "controlled",
    "follower_count",
    "issuance_binding",
];
type Proof = Presentation<BbsScheme>;
type Bundle = CredentialBundle<BbsScheme>;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    profile: String,
    nonce: String,
    scope: String,
    facts: Vec<String>,
    identity: bool,
    threshold: Option<u64>,
    registry_sequence: u64,
    created_at: u64,
    expires_at: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    issuer: IssuerPublic<BbsScheme>,
    policy: String,
    challenge: Challenge,
    current_sequence: u64,
    now: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicInput {
    #[serde(deserialize_with = "decode_count_proof")]
    proof: Proof,
    claimed_id: Option<G1Projective>,
}

// The pinned Bulletproof dependency serializes bytes as a JSON integer array,
// but its visitor accepts only a byte deserializer. Adapt that public wire
// boundary locally; do not patch or relax the pinned cryptographic library.
fn decode_count_proof<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Proof, D::Error> {
    use serde::de::Error;
    let mut raw = StrictJson::deserialize(d)?.0;
    let range = raw.get_mut("proofs").and_then(serde_json::Value::as_object_mut)
        .and_then(|p| p.remove("followers-range"));
    let bytes = serde_json::to_vec(&raw).map_err(D::Error::custom)?;
    let mut proof: Proof = serde_json::from_slice(&bytes).map_err(D::Error::custom)?;
    if let Some(range) = range {
        #[derive(Deserialize)] #[serde(deny_unknown_fields)]
        struct Wire { id: String, proof: Vec<u8> }
        #[derive(Deserialize)] #[serde(deny_unknown_fields)]
        struct Variant { #[serde(rename = "Range")] range: Wire }
        let value: Variant = serde_json::from_value(range).map_err(D::Error::custom)?;
        if value.range.proof.is_empty() || value.range.proof.len() > 8192 { return Err(D::Error::custom("range bytes")); }
        let decoder = serde::de::value::BorrowedBytesDeserializer::<serde::de::value::Error>::new(&value.range.proof);
        let inner = Deserialize::deserialize(decoder).map_err(D::Error::custom)?;
        proof.proofs.insert("followers-range".into(), PresentationProofs::Range(Box::new(
            credx::presentation::RangeProof { id: value.range.id, proof: inner })));
    }
    Ok(proof)
}

fn hidden_range(c: &Challenge) -> bool {
    c.threshold.is_some() && !c.facts.iter().any(|f| f == "follower-count")
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptTrust {
    issuer: IssuerPublic<BbsScheme>,
    binding: String,
}

fn receipt_schema(issuer: &IssuerPublic<BbsScheme>) -> PresentationSchema<BbsScheme> {
    PresentationSchema::new_with_id(
        &[SignatureStatement {
            id: "receipt".into(),
            issuer: issuer.clone(),
            disclosed: BTreeSet::from(["issuance_binding".into()]),
        }
        .into()],
        &format!("{PROFILE}/receipt"),
    )
}

fn receipt_nonce(binding: &str) -> Vec<u8> {
    serde_json::to_vec(&[PROFILE, "replacement-receipt", binding]).unwrap()
}

fn receipt(bundle: &Bundle, binding: &str) -> Proof {
    Presentation::create(
        &indexmap! { "receipt".into() => bundle.credential.clone().into() },
        &receipt_schema(&bundle.issuer),
        &receipt_nonce(binding),
    )
    .unwrap()
}

fn verify_receipt(proof: &Proof, trusted: &ReceiptTrust) -> bool {
    if proof.proofs.len() != 1
        || proof.disclosed_messages.len() != 1
        || !matches!(proof.proofs.get("receipt"), Some(PresentationProofs::Signature(p)) if p.id == "receipt")
    {
        return false;
    }
    let values = match proof.disclosed_messages.get("receipt") {
        Some(v) => v,
        None => return false,
    };
    values.len() == 1
        && hashed(values.get("issuance_binding"), &trusted.binding)
        && proof
            .verify(
                &receipt_schema(&trusted.issuer),
                &receipt_nonce(&trusted.binding),
            )
            .is_ok()
}

fn credential_schema() -> CredentialSchema {
    let claims = LABELS
        .iter()
        .enumerate()
        .map(|(i, label)| ClaimSchema {
            label: (*label).into(),
            claim_type: match i {
                0 => ClaimType::Revocation,
                1 => ClaimType::Scalar,
                4..=7 => ClaimType::Number,
                _ => ClaimType::Hashed,
            },
            print_friendly: false,
            validators: vec![],
        })
        .collect::<Vec<_>>();
    let mut schema = CredentialSchema::new(Some(PROFILE), None, &["secret"], &claims).unwrap();
    schema.id = PROFILE.into();
    schema
}

fn legacy_schema() -> CredentialSchema {
    let mut labels = LABELS;
    labels[7] = "follower_ge_10000";
    let claims = labels.iter().enumerate().map(|(i, label)| ClaimSchema {
        label: (*label).into(), claim_type: match i {
            0 => ClaimType::Revocation, 1 => ClaimType::Scalar,
            4..=7 => ClaimType::Number, _ => ClaimType::Hashed,
        }, print_friendly: false, validators: vec![],
    }).collect::<Vec<_>>();
    let profile = "nockapp-zkid-domain-application-lab-v1";
    let mut schema = CredentialSchema::new(Some(profile), None, &["secret"], &claims).unwrap();
    schema.id = profile.into();schema
}

fn disclosure(challenge: &Challenge) -> Option<BTreeSet<String>> {
    if challenge.profile != PROFILE
        || challenge.nonce.len() != 64
        || !challenge.nonce.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        || challenge.nonce.bytes().all(|c| c == b'0')
        || challenge.scope.len() != 64
        || !challenge.scope.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        || challenge.facts.is_empty()
        || challenge.facts.len() > 3
        || !challenge.facts.windows(2).all(|w| w[0] < w[1])
        || challenge.created_at == 0 || challenge.expires_at >= (1u64 << 53)
        || challenge.registry_sequence >= (1u64 << 53)
        || challenge.expires_at.checked_sub(challenge.created_at) != Some(60)
    {
        return None;
    }
    let ranged = challenge.facts.iter().any(|f| f == "followers-more-than");
    if ranged != challenge.threshold.is_some()
        || challenge.threshold.is_some_and(|v| v >= MAX_COUNT)
    {
        return None;
    }
    let mut result = ["source", "policy", "start", "expiry"]
        .map(String::from)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    for fact in &challenge.facts {
        if !seen.insert(fact) {
            return None;
        }
        if fact == "followers-more-than" { continue; }
        result.insert(
            match fact.as_str() {
                "account-controlled" => "controlled",
                "follower-count" => "follower_count",
                _ => return None,
            }
            .into(),
        );
    }
    Some(result)
}

fn schema(trust: &Trust) -> Option<PresentationSchema<BbsScheme>> {
    let disclosed = disclosure(&trust.challenge)?;
    if trust.policy != COUNT_POLICY { return None; }
    // The raw public-key type accepts supplied message bases. Enforce the
    // upstream hash-derived expansion; an issuer must not choose the secret's
    // message base equal to the public domain base and recognize the final ID.
    let key = &trust.issuer.verifying_key;
    if key.is_invalid().unwrap_u8() != 0 || *key != key.compress().decompress() {
        return None;
    }
    if serde_json::to_value(&trust.issuer.schema).ok()?
        != serde_json::to_value(credential_schema()).ok()?
    {
        return None;
    }
    let mut statements = vec![
        SignatureStatement {
            id: "credential".into(),
            disclosed,
            issuer: trust.issuer.clone(),
        }
        .into(),
        RevocationStatement {
            id: "active".into(),
            reference_id: "credential".into(),
            claim: 0,
            accumulator: trust.issuer.revocation_registry,
            verification_key: trust.issuer.revocation_verifying_key,
        }
        .into(),
    ];
    if hidden_range(&trust.challenge) {
        let threshold = trust.challenge.threshold?;
        // credx binds this Pedersen commitment to the exact signed claim, and
        // its Bulletproof to this commitment and the presentation transcript.
        statements.push(CommitmentStatement {
            id: "followers-commitment".into(), reference_id: "credential".into(), claim: 7,
            message_generator: create_domain_proof_generator(b"NOCKAPP/COUNT/v2/message"),
            blinder_generator: create_domain_proof_generator(b"NOCKAPP/COUNT/v2/blinder"),
        }.into());
        statements.push(RangeStatement {
            id: "followers-range".into(), reference_id: "followers-commitment".into(),
            signature_id: "credential".into(), claim: 7,
            lower: Some((threshold + 1) as isize), upper: Some(MAX_COUNT as isize),
        }.into());
    }
    if trust.challenge.identity {
        statements.push(
            CommitmentStatement {
                id: "zkid".into(),
                reference_id: "credential".into(),
                claim: 1,
                message_generator: create_domain_proof_generator(DOMAIN),
                blinder_generator: G1Projective::IDENTITY,
            }
            .into(),
        );
    }
    Some(PresentationSchema::new_with_id(&statements, PROFILE))
}

fn present(bundle: &Bundle, trust: &Trust) -> Proof {
    Presentation::create(
        &indexmap! { "credential".into() => bundle.credential.clone().into() },
        &schema(trust).unwrap(),
        &serde_json::to_vec(&trust.challenge).unwrap(),
    )
    .unwrap()
}

fn hashed(claim: Option<&ClaimData>, expected: &str) -> bool {
    matches!(claim, Some(ClaimData::Hashed(c)) if c.value == expected.as_bytes())
}

fn number(claim: Option<&ClaimData>) -> Option<i64> {
    match claim {
        Some(ClaimData::Number(c)) => Some(c.value as i64),
        _ => None,
    }
}

fn verify(input: &PublicInput, trust: &Trust) -> bool {
    let c = &trust.challenge;
    if c.registry_sequence != trust.current_sequence
        || trust.now < c.created_at
        || trust.now >= c.expires_at
    {
        return false;
    }
    let expected_schema = match schema(trust) {
        Some(s) => s,
        None => return false,
    };
    let proof = &input.proof;
    let mut expected_keys = if c.identity {
        vec!["credential", "active", "zkid"]
    } else {
        vec!["credential", "active"]
    };
    if hidden_range(c) { expected_keys.extend(["followers-commitment", "followers-range"]); }
    if proof.proofs.len() != expected_keys.len()
        || !expected_keys
            .iter()
            .all(|id| proof.proofs.contains_key(*id))
        || proof.proofs.iter().any(|(id, p)| p.id() != id)
        || proof.disclosed_messages.len() != 1
        || !proof.disclosed_messages.contains_key("credential")
    {
        return false;
    }
    if !matches!(proof.proofs["credential"], PresentationProofs::Signature(_))
        || !matches!(proof.proofs["active"], PresentationProofs::Revocation(_))
    {
        return false;
    }
    if hidden_range(c) && (!matches!(proof.proofs["followers-commitment"], PresentationProofs::Commitment(_))
        || !matches!(proof.proofs["followers-range"], PresentationProofs::Range(_))) { return false; }
    if c.identity {
        match (&input.claimed_id, &proof.proofs["zkid"]) {
            (Some(id), PresentationProofs::Commitment(p))
                if *id != G1Projective::IDENTITY && *id == p.commitment =>
            {
                ()
            }
            _ => return false,
        }
    } else if input.claimed_id.is_some() {
        return false;
    }
    let disclosed = &proof.disclosed_messages["credential"];
    let keys = disclosed.keys().cloned().collect::<BTreeSet<_>>();
    if Some(keys) != disclosure(c)
        || !hashed(disclosed.get("source"), SOURCE)
        || !hashed(disclosed.get("policy"), &trust.policy)
    {
        return false;
    }
    let (start, expiry) = match (
        number(disclosed.get("start")),
        number(disclosed.get("expiry")),
    ) {
        (Some(s), Some(e)) if s >= 0 && s % 3600 == 0 && e.checked_sub(s) == Some(86400) => {
            (s as u64, e as u64)
        }
        _ => return false,
    };
    if trust.now < start || trust.now >= expiry {
        return false;
    }
    for label in ["controlled"] {
        if disclosed.contains_key(label) && number(disclosed.get(label)) != Some(1) {
            return false;
        }
    }
    if disclosed.contains_key("follower_count") {
        match number(disclosed.get("follower_count")) {
            Some(v) if v >= 0 && (v as u64) <= MAX_COUNT
                && c.threshold.is_none_or(|t| (v as u64) > t) => (),
            _ => return false,
        }
    }
    proof
        .verify(&expected_schema, &serde_json::to_vec(c).unwrap())
        .is_ok()
}

fn staged_activation(issuer: &Issuer<BbsScheme>, handle: &str) -> Issuer<BbsScheme> {
    assert!(issuer.revocation_registry.elements.contains(handle));
    assert!(!issuer.revocation_registry.active.contains(handle));
    let mut staged = issuer.clone();
    staged
        .revocation_registry
        .value
        .add_assign(&staged.revocation_key, Element::hash(handle.as_bytes()));
    staged.revocation_registry.active.insert(handle.into());
    staged
}

