//! Application-level research acceptance. No network or production trust setup.
use credx::knox::accumulator::vb20::Element;
use credx::knox::bbs::BbsScheme;
use credx::prelude::blsful::inner_types::{G1Projective, Scalar};
use credx::{create_domain_proof_generator, indexmap::indexmap, prelude::*};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::process::{Command, Stdio};

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

const PROFILE: &str = "nockapp-zkid-domain-application-lab-v1";
const DOMAIN: &[u8] = b"nockapp/zkid/domain-research/v1";
const SOURCE: &str = "twitterapi.io";
const POLICY: &str = "synthetic-source-policy-for-application-acceptance";
const LABELS: [&str; 9] = [
    "revocation",
    "secret",
    "source",
    "policy",
    "start",
    "expiry",
    "controlled",
    "follower_ge_10000",
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
    proof: Proof,
    claimed_id: Option<G1Projective>,
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

fn disclosure(challenge: &Challenge) -> Option<BTreeSet<String>> {
    if challenge.profile != PROFILE
        || challenge.nonce.len() != 64
        || !challenge.nonce.bytes().all(|c| c.is_ascii_hexdigit())
        || challenge.scope.is_empty()
        || challenge.scope.len() > 128
        || challenge.facts.is_empty()
        || challenge.facts.len() > 2
        || challenge.expires_at.checked_sub(challenge.created_at) != Some(60)
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
        result.insert(
            match fact.as_str() {
                "account-controlled" => "controlled",
                "followers-at-least-10000" => "follower_ge_10000",
                _ => return None,
            }
            .into(),
        );
    }
    Some(result)
}

fn schema(trust: &Trust) -> Option<PresentationSchema<BbsScheme>> {
    let disclosed = disclosure(&trust.challenge)?;
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
    let expected_keys = if c.identity {
        vec!["credential", "active", "zkid"]
    } else {
        vec!["credential", "active"]
    };
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
    for label in ["controlled", "follower_ge_10000"] {
        if disclosed.contains_key(label) && number(disclosed.get(label)) != Some(1) {
            return false;
        }
    }
    proof
        .verify(&expected_schema, &serde_json::to_vec(c).unwrap())
        .is_ok()
}

// This entry point receives only a public proof. The separately supplied public
// trust file belongs to the verifier; it is never read from the proof bundle.
// No positive hardware attestation or durable replay state is asserted here.
pub fn verify_child(path: &str, receipt_mode: bool) -> bool {
    let mut trust_bytes = Vec::new();
    let mut proof_bytes = Vec::new();
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    if file.take(65537).read_to_end(&mut trust_bytes).is_err()
        || std::io::stdin()
            .take(65537)
            .read_to_end(&mut proof_bytes)
            .is_err()
        || trust_bytes.len() > 65536
        || proof_bytes.len() > 65536
    {
        return false;
    }
    if receipt_mode {
        let trust: ReceiptTrust = match decode(&trust_bytes) {
            Some(t) => t,
            None => return false,
        };
        let proof: Proof = match decode(&proof_bytes) {
            Some(p) => p,
            None => return false,
        };
        return verify_receipt(&proof, &trust);
    }
    let trust: Trust = match decode(&trust_bytes) {
        Some(t) => t,
        None => return false,
    };
    let input: PublicInput = match decode(&proof_bytes) {
        Some(p) => p,
        None => return false,
    };
    verify(&input, &trust)
}

fn independent(proof: &Proof, claimed_id: Option<G1Projective>, trust: &Trust) -> bool {
    let public_input = serde_json::to_vec(&PublicInput {
        proof: proof.clone(),
        claimed_id,
    })
    .unwrap();
    independent_bytes(&public_input, trust)
}

fn independent_bytes(public_input: &[u8], trust: &Trust) -> bool {
    independent_mode(
        public_input,
        &serde_json::to_vec(trust).unwrap(),
        "--verify-app-candidate",
    )
}

fn independent_receipt(proof: &Proof, trust: &ReceiptTrust) -> bool {
    independent_mode(
        &serde_json::to_vec(proof).unwrap(),
        &serde_json::to_vec(trust).unwrap(),
        "--verify-receipt-candidate",
    )
}

fn independent_mode(public_input: &[u8], trust_bytes: &[u8], flag: &str) -> bool {
    use std::os::unix::fs::OpenOptionsExt;
    let path = std::env::temp_dir().join(format!(
        "nockapp-zkid-public-trust-{}.json",
        credx::random_string(16, rand::thread_rng())
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(trust_bytes).unwrap();
    drop(file);
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg(flag)
        .arg(&path)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("RAYON_NUM_THREADS", "2")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let wrote = child.stdin.take().unwrap().write_all(public_input).is_ok();
    let result = child.wait_with_output().unwrap();
    std::fs::remove_file(path).unwrap();
    assert!(
        result.stderr.is_empty(),
        "public verifier must not print diagnostics"
    );
    wrote
        && result.status.success()
        && result.stdout == b"{\"accepted\":true,\"laboratory_only\":true}\n"
}

fn issue(
    issuer: &mut Issuer<BbsScheme>,
    secret: Scalar,
    handle: &str,
    binding: &str,
    now: u64,
    followers: i64,
) -> Bundle {
    let hidden = BTreeMap::from([("secret".into(), ScalarClaim::from(secret).into())]);
    let (request, blinder) =
        BlindCredentialRequest::new(&IssuerPublic::from(&*issuer), &hidden).unwrap();
    let start = (now / 3600 * 3600) as isize;
    let known = BTreeMap::from([
        ("revocation".into(), RevocationClaim::from(handle).into()),
        ("source".into(), HashedClaim::from(SOURCE).into()),
        ("policy".into(), HashedClaim::from(POLICY).into()),
        ("start".into(), NumberClaim::from(start).into()),
        ("expiry".into(), NumberClaim::from(start + 86400).into()),
        ("controlled".into(), NumberClaim::from(1isize).into()),
        (
            "follower_ge_10000".into(),
            NumberClaim::from(followers as isize).into(),
        ),
        ("issuance_binding".into(), HashedClaim::from(binding).into()),
    ]);
    issuer
        .blind_sign_credential(&request, &known)
        .unwrap()
        .to_unblinded(&hidden, blinder)
        .unwrap()
}

// The native high-level issuer starts with all not-yet-revoked handles eligible.
// Pre-exclude a finite pool before any public trust root is enrolled. Activation
// adds exactly one reserved handle using the upstream accumulator operation.
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

fn commit_with_receipt(
    staged: &Issuer<BbsScheme>,
    ack: &Proof,
    binding: &str,
    old_handle: &str,
) -> Option<Issuer<BbsScheme>> {
    let expected = ReceiptTrust {
        issuer: IssuerPublic::from(staged),
        binding: binding.into(),
    };
    if !verify_receipt(ack, &expected) {
        return None;
    }
    let mut committed = staged.clone();
    committed
        .revoke_credentials(&[RevocationClaim::from(old_handle)])
        .ok()?;
    Some(committed)
}

pub fn checks(export_directory: Option<&std::path::Path>) -> BTreeMap<String, bool> {
    let mut checks = BTreeMap::new();
    macro_rules! check {
        ($name:expr, $condition:expr) => {{
            let ok = $condition;
            assert!(ok, "{}", $name);
            checks.insert(format!("application_{}", $name), ok);
        }};
    }
    let (_, mut issuer) = Issuer::<BbsScheme>::new(&credential_schema());
    let handles = [
        "synthetic-pool-incumbent",
        "synthetic-pool-replacement",
        "synthetic-pool-low-followers",
    ]
    .map(String::from);
    issuer.revocation_registry.add(&handles);
    issuer
        .revoke_credentials(
            &handles
                .iter()
                .map(RevocationClaim::from)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    issuer = staged_activation(&issuer, &handles[0]);
    let now = 1_793_012_400u64;
    let incumbent = issue(
        &mut issuer,
        Scalar::from(42u64),
        &handles[0],
        "synthetic-session-1",
        now,
        1,
    );
    let challenge = Challenge {
        profile: PROFILE.into(),
        nonce: "ab".repeat(32),
        scope: "nockapp:synthetic-post:1".into(),
        facts: vec![
            "account-controlled".into(),
            "followers-at-least-10000".into(),
        ],
        identity: true,
        registry_sequence: 1,
        created_at: now,
        expires_at: now + 60,
    };
    let trust = Trust {
        issuer: IssuerPublic::from(&issuer),
        policy: POLICY.into(),
        challenge,
        current_sequence: 1,
        now,
    };
    let id = create_domain_proof_generator(DOMAIN) * Scalar::from(42u64);
    let proof = present(&incumbent, &trust);
    if let Some(directory) = export_directory {
        // Exactly these public projections are exported. Never serialize the
        // issuer, bundle or holder scalar into an evidence directory.
        std::fs::create_dir(directory).unwrap();
        for (name, bytes) in [
            ("verifier-trust.json", serde_json::to_vec(&trust).unwrap()),
            (
                "public-proof.json",
                serde_json::to_vec(&PublicInput {
                    proof: proof.clone(),
                    claimed_id: Some(id),
                })
                .unwrap(),
            ),
        ] {
            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(directory.join(name))
                .unwrap();
            out.write_all(&bytes).unwrap();
            out.write_all(b"\n").unwrap();
        }
    }
    let public_trust_bytes = serde_json::to_vec(&trust).unwrap();
    check!(
        "trusted_config_strict_json",
        serde_json::from_slice::<StrictJson>(&public_trust_bytes).is_ok()
    );
    check!(
        "trusted_config_typed_json",
        serde_json::from_slice::<Trust>(&public_trust_bytes).is_ok()
    );
    check!(
        "trusted_config_strict_roundtrip",
        decode::<Trust>(&public_trust_bytes).is_some()
    );
    check!(
        "public_proof_strict_roundtrip",
        decode::<PublicInput>(
            &serde_json::to_vec(&PublicInput {
                proof: proof.clone(),
                claimed_id: Some(id)
            })
            .unwrap()
        )
        .is_some()
    );
    let mut bad_parameters = trust.clone();
    let mut bad_key = serde_json::to_value(&bad_parameters.issuer.verifying_key).unwrap();
    bad_key["y"][1] = serde_json::to_value(create_domain_proof_generator(DOMAIN)).unwrap();
    bad_parameters.issuer.verifying_key =
        serde_json::from_slice(&serde_json::to_vec(&bad_key).unwrap()).unwrap();
    check!(
        "issuer_selected_domain_message_base_rejected",
        schema(&bad_parameters).is_none()
    );
    check!(
        "dated_facts_and_id_independent_acceptance",
        independent(&proof, Some(id), &trust)
    );
    let mut wrong = trust.clone();
    wrong.policy = "wrong policy".into();
    check!(
        "wrong_policy_rejected",
        !independent(&proof, Some(id), &wrong)
    );
    let mut wrong = trust.clone();
    wrong.challenge.scope = "nockapp:another-post".into();
    check!(
        "wrong_scope_rejected",
        !independent(&proof, Some(id), &wrong)
    );
    let mut wrong = trust.clone();
    wrong.challenge.nonce = "cd".repeat(32);
    check!(
        "wrong_nonce_rejected",
        !independent(&proof, Some(id), &wrong)
    );
    let mut wrong = trust.clone();
    wrong.now = now + 60;
    check!(
        "action_deadline_rejected",
        !independent(&proof, Some(id), &wrong)
    );
    let mut wrong = trust.clone();
    wrong.current_sequence = 2;
    check!(
        "old_registry_sequence_rejected",
        !independent(&proof, Some(id), &wrong)
    );
    let mut wrong = trust.clone();
    wrong.now = now - 1;
    check!(
        "future_action_rejected",
        !independent(&proof, Some(id), &wrong)
    );
    let mut anonymous = trust.clone();
    anonymous.challenge.identity = false;
    let anonymous_proof = present(&incumbent, &anonymous);
    check!(
        "anonymous_facts_independent_acceptance",
        independent(&anonymous_proof, None, &anonymous)
    );
    check!(
        "anonymous_mode_has_no_identity_statement",
        !anonymous_proof.proofs.contains_key("zkid")
    );
    check!(
        "anonymous_mode_rejects_attached_id",
        !independent(&anonymous_proof, Some(id), &anonymous)
    );
    let mut tampered = proof.clone();
    tampered
        .disclosed_messages
        .get_mut("credential")
        .unwrap()
        .insert(
            "expiry".into(),
            NumberClaim::from((now + 86400 + 3600) as isize).into(),
        );
    check!(
        "changed_expiry_rejected",
        !independent(&tampered, Some(id), &trust)
    );
    let mut expired = trust.clone();
    expired.now = now / 3600 * 3600 + 86400;
    expired.challenge.created_at = expired.now;
    expired.challenge.expires_at = expired.now + 60;
    check!(
        "fresh_proof_of_expired_credential_rejected",
        !independent(&present(&incumbent, &expired), Some(id), &expired)
    );
    let mut premature = trust.clone();
    premature.now = now / 3600 * 3600 - 1;
    premature.challenge.created_at = premature.now;
    premature.challenge.expires_at = premature.now + 60;
    check!(
        "fresh_proof_of_not_yet_valid_credential_rejected",
        !independent(&present(&incumbent, &premature), Some(id), &premature)
    );
    let disclosed = &proof.disclosed_messages["credential"];
    check!(
        "secret_account_handle_and_binding_hidden",
        !disclosed.contains_key("secret")
            && !disclosed.contains_key("revocation")
            && !disclosed.contains_key("issuance_binding")
            && disclosed.len() == 6
    );
    let mut staged = staged_activation(&issuer, &handles[1]);
    let mut replacement = issue(
        &mut staged,
        Scalar::from(43u64),
        &handles[1],
        "synthetic-session-2",
        now,
        1,
    );
    let replacement_id = create_domain_proof_generator(DOMAIN) * Scalar::from(43u64);
    check!(
        "pending_replacement_unusable",
        !independent(&present(&replacement, &trust), Some(replacement_id), &trust)
    );
    check!(
        "pending_replacement_preserves_incumbent",
        independent(&present(&incumbent, &trust), Some(id), &trust)
    );
    let ack = receipt(&replacement, "synthetic-session-2");
    let ack_trust = ReceiptTrust {
        issuer: IssuerPublic::from(&staged),
        binding: "synthetic-session-2".into(),
    };
    check!(
        "receipt_independent_acceptance",
        independent_receipt(&ack, &ack_trust)
    );
    check!(
        "receipt_does_not_disclose_secret_or_identity",
        ack.proofs.len() == 1
            && ack.disclosed_messages["receipt"].len() == 1
            && ack.disclosed_messages["receipt"].contains_key("issuance_binding")
    );
    let old_ack = receipt(&incumbent, "synthetic-session-2");
    check!(
        "incumbent_cannot_acknowledge_replacement",
        !independent_receipt(&old_ack, &ack_trust)
    );
    check!(
        "failed_receipt_does_not_commit",
        commit_with_receipt(&staged, &old_ack, "synthetic-session-2", &handles[0]).is_none()
    );
    check!(
        "failed_receipt_preserves_incumbent",
        independent(&present(&incumbent, &trust), Some(id), &trust)
    );
    check!(
        "wrong_session_receipt_rejected",
        commit_with_receipt(&staged, &ack, "wrong session", &handles[0]).is_none()
    );
    check!(
        "receipt_cannot_be_used_as_action_proof",
        !independent(&ack, Some(replacement_id), &trust)
    );
    let committed_state =
        commit_with_receipt(&staged, &ack, "synthetic-session-2", &handles[0]).unwrap();
    issuer = serde_json::from_slice(&serde_json::to_vec(&committed_state).unwrap()).unwrap();
    replacement.update_revocation_handle(
        issuer
            .update_revocation_handle(RevocationClaim::from(&handles[1]))
            .unwrap(),
        issuer.revocation_registry.value,
    );
    let mut committed = trust.clone();
    committed.issuer = IssuerPublic::from(&issuer);
    committed.current_sequence = 2;
    committed.challenge.registry_sequence = 2;
    check!(
        "replacement_valid_after_issuer_serialization",
        independent(
            &present(&replacement, &committed),
            Some(replacement_id),
            &committed
        )
    );
    check!(
        "incumbent_revoked_after_commit",
        !independent(&present(&incumbent, &committed), Some(id), &committed)
    );
    check!(
        "replacement_cannot_use_incumbent_identity",
        !independent(&present(&replacement, &committed), Some(id), &committed)
    );
    check!(
        "revoked_handle_cannot_get_updated_witness",
        issuer
            .update_revocation_handle(RevocationClaim::from(&handles[0]))
            .is_err()
    );
    let mut low_issuer = staged_activation(&issuer, &handles[2]);
    let low = issue(
        &mut low_issuer,
        Scalar::from(44u64),
        &handles[2],
        "synthetic-session-3",
        now,
        0,
    );
    let low_id = create_domain_proof_generator(DOMAIN) * Scalar::from(44u64);
    let mut low_trust = committed.clone();
    low_trust.issuer = IssuerPublic::from(&low_issuer);
    check!(
        "insufficient_followers_rejected",
        !independent(&present(&low, &low_trust), Some(low_id), &low_trust)
    );
    let mut lying = present(&low, &low_trust);
    lying
        .disclosed_messages
        .get_mut("credential")
        .unwrap()
        .insert("follower_ge_10000".into(), NumberClaim::from(1isize).into());
    check!(
        "unsigned_positive_follower_claim_rejected",
        !independent(&lying, Some(low_id), &low_trust)
    );
    low_trust.challenge.facts = vec!["account-controlled".into()];
    check!(
        "control_only_does_not_require_followers",
        independent(&present(&low, &low_trust), Some(low_id), &low_trust)
    );
    check!(
        "malformed_public_input_rejected",
        !independent_bytes(b"{not json}", &trust)
    );
    let mut extra = serde_json::to_value(PublicInput {
        proof: proof.clone(),
        claimed_id: Some(id),
    })
    .unwrap();
    extra["untrusted_policy"] = serde_json::json!("forged");
    check!(
        "unknown_outer_fields_rejected",
        !independent_bytes(&serde_json::to_vec(&extra).unwrap(), &trust)
    );
    let mut nested = serde_json::to_value(PublicInput {
        proof: proof.clone(),
        claimed_id: Some(id),
    })
    .unwrap();
    nested["proof"]["untrusted_policy"] = serde_json::json!("forged");
    check!(
        "unknown_nested_fields_rejected",
        !independent_bytes(&serde_json::to_vec(&nested).unwrap(), &trust)
    );
    let plain = serde_json::to_vec(&PublicInput {
        proof: proof.clone(),
        claimed_id: Some(id),
    })
    .unwrap();
    let mut duplicate = b"{\"claimed_id\":null,".to_vec();
    duplicate.extend_from_slice(&plain[1..]);
    check!(
        "duplicate_json_fields_rejected",
        !independent_bytes(&duplicate, &trust)
    );
    check!(
        "oversized_public_input_rejected",
        !independent_bytes(&vec![b' '; 65537], &trust)
    );
    let mut deep = vec![b'['; 200];
    deep.extend(std::iter::repeat_n(b']', 200));
    check!(
        "excessive_json_depth_rejected",
        !independent_bytes(&deep, &trust)
    );
    let mut altered_id = proof.clone();
    if let PresentationProofs::Signature(p) = altered_id.proofs.get_mut("credential").unwrap() {
        p.id = "another statement".into();
    }
    check!(
        "mismatched_inner_statement_id_rejected",
        !independent(&altered_id, Some(id), &trust)
    );
    checks
}
