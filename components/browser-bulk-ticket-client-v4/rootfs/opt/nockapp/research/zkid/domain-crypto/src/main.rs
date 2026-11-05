//! Synthetic feasibility experiment, never a production issuer.
//! Uses the upstream composite commitment proof with its blinding base set to
//! the identity: C = H(domain) * secret. The signature response is shared by
//! upstream with the commitment proof. This configuration requires review;
//! passing negative tests is not a security proof or an upstream endorsement.
use credx::knox::bbs::BbsScheme;
use credx::prelude::blsful::inner_types::{G1Projective, Scalar};
use credx::{create_domain_proof_generator, indexmap::indexmap, prelude::*};
use std::collections::{BTreeMap, BTreeSet};

mod application;

const DOMAIN: &[u8] = b"nockapp/zkid/domain-research/v1";
type Proof = Presentation<BbsScheme>;
type Bundle = CredentialBundle<BbsScheme>;

fn schema(public: &IssuerPublic<BbsScheme>, domain: &[u8]) -> PresentationSchema<BbsScheme> {
    PresentationSchema::new(&[
        SignatureStatement {
            id: "credential".into(),
            disclosed: BTreeSet::new(),
            issuer: public.clone(),
        }
        .into(),
        RevocationStatement {
            id: "active".into(),
            reference_id: "credential".into(),
            accumulator: public.revocation_registry,
            verification_key: public.revocation_verifying_key,
            claim: 0,
        }
        .into(),
        CommitmentStatement {
            id: "zkid".into(),
            reference_id: "credential".into(),
            claim: 1,
            message_generator: create_domain_proof_generator(domain),
            blinder_generator: G1Projective::IDENTITY,
        }
        .into(),
    ])
}

fn issue(issuer: &mut Issuer<BbsScheme>, secret: Scalar, handle: &str) -> Bundle {
    let public = IssuerPublic::from(&*issuer);
    let hidden = BTreeMap::from([("secret".into(), ScalarClaim::from(secret).into())]);
    let (request, blinder) = BlindCredentialRequest::new(&public, &hidden).unwrap();
    // The upstream convenience request.verify() passes hidden indices where
    // BBS expects known indices. Its signing path independently verifies the
    // context using the actual known claims; use that path (and test tampering).
    let known = BTreeMap::from([("revocation".into(), RevocationClaim::from(handle).into())]);
    issuer
        .blind_sign_credential(&request, &known)
        .unwrap()
        .to_unblinded(&hidden, blinder)
        .unwrap()
}

fn present(bundle: &Bundle, schema: &PresentationSchema<BbsScheme>, nonce: &[u8]) -> Proof {
    Presentation::create(
        &indexmap! { "credential".into() => bundle.credential.clone().into() },
        schema,
        nonce,
    )
    .unwrap()
}

fn nym(proof: &Proof) -> G1Projective {
    match &proof.proofs["zkid"] {
        PresentationProofs::Commitment(c) => c.commitment,
        _ => panic!("expected commitment"),
    }
}

// Real integration must reconstruct its own fixed schema/current registry and
// compare the claimed ID. A proof-selected schema or old registry is not trust.
fn accepts(
    proof: &Proof,
    expected: G1Projective,
    schema: &PresentationSchema<BbsScheme>,
    nonce: &[u8],
) -> bool {
    if expected == G1Projective::IDENTITY || proof.proofs.len() != 3 {
        return false;
    }
    if !matches!(
        proof.proofs.get("credential"),
        Some(PresentationProofs::Signature(_))
    ) || !matches!(
        proof.proofs.get("active"),
        Some(PresentationProofs::Revocation(_))
    ) || !matches!(
        proof.proofs.get("zkid"),
        Some(PresentationProofs::Commitment(_))
    ) {
        return false;
    }
    nym(proof) == expected && proof.verify(schema, nonce).is_ok()
}

fn main() {
    let mode = std::env::args().nth(1);
    if mode.as_deref() == Some("--internal-crypto") {
        std::panic::set_hook(Box::new(|_| {}));
        let accepted = std::panic::catch_unwind(application::rpc::run).unwrap_or(false);
        if !accepted {
            println!("{{\"error\":\"crypto-rejected\"}}");
        }
        std::process::exit(if accepted { 0 } else { 1 });
    }
    if matches!(
        mode.as_deref(),
        Some("--verify-app-candidate" | "--verify-receipt-candidate")
    ) {
        // Fail closed without logging malformed proof fields or panic details.
        std::panic::set_hook(Box::new(|_| {}));
        let accepted = std::panic::catch_unwind(|| {
            std::env::args()
                .nth(2)
                .map(|path| {
                    application::verify_child(
                        &path,
                        mode.as_deref() == Some("--verify-receipt-candidate"),
                    )
                })
                .unwrap_or(false)
        })
        .unwrap_or(false);
        println!("{{\"accepted\":{},\"laboratory_only\":true}}", accepted);
        std::process::exit(if accepted { 0 } else { 1 });
    }
    // No logger is installed. All data below is synthetic and ephemeral.
    let credential_schema = CredentialSchema::new(
        Some("NockApp research"),
        None,
        &["secret"],
        &[
            ClaimSchema {
                claim_type: ClaimType::Revocation,
                label: "revocation".into(),
                print_friendly: false,
                validators: vec![],
            },
            ClaimSchema {
                claim_type: ClaimType::Scalar,
                label: "secret".into(),
                print_friendly: false,
                validators: vec![],
            },
        ],
    )
    .unwrap();
    let (_, mut issuer) = Issuer::<BbsScheme>::new(&credential_schema);
    let secret = Scalar::from(42u64); // public synthetic fixture, not key generation
    let mut incumbent = issue(&mut issuer, secret, "synthetic-incumbent");
    let public = IssuerPublic::from(&issuer);
    let current = schema(&public, DOMAIN);
    let nonce = b"synthetic-verifier-nonce-1";
    let expected = create_domain_proof_generator(DOMAIN) * secret;
    let proof = present(&incumbent, &current, nonce);
    let again = present(&incumbent, &current, nonce);
    let mut checks = BTreeMap::new();
    macro_rules! check {
        ($name:expr, $condition:expr) => {{
            let ok = $condition;
            assert!(ok, "{}", $name);
            checks.insert($name.to_string(), ok);
        }};
    }
    let hidden = BTreeMap::from([("secret".into(), ScalarClaim::from(secret).into())]);
    let (mut bad_request, _) = BlindCredentialRequest::new(&public, &hidden).unwrap();
    bad_request.blind_signature_context.commitment += G1Projective::GENERATOR;
    let known = BTreeMap::from([(
        "revocation".into(),
        RevocationClaim::from("synthetic-bad-request").into(),
    )]);
    // Upstream mutates registry bookkeeping before context verification. Isolate
    // failure here; any eventual issuer adapter must transact on staged state.
    let mut staged_issuer = issuer.clone();
    check!(
        "tampered_blind_request_rejected_by_signing_path",
        staged_issuer
            .blind_sign_credential(&bad_request, &known)
            .is_err()
    );
    check!(
        "blind_credential_same_secret_domain_and_nonrevocation",
        accepts(&proof, expected, &current, nonce)
    );
    check!(
        "stable_id_for_same_secret_and_domain",
        nym(&again) == expected
    );
    check!(
        "randomized_presentations",
        serde_json::to_vec(&proof).unwrap() != serde_json::to_vec(&again).unwrap()
    );
    check!(
        "arbitrary_alias_rejected",
        !accepts(&proof, expected + G1Projective::GENERATOR, &current, nonce)
    );
    check!(
        "wrong_nonce_rejected",
        !accepts(&proof, expected, &current, b"other nonce")
    );
    check!(
        "wrong_domain_rejected",
        !accepts(&proof, expected, &schema(&public, b"another app"), nonce)
    );
    let another_domain = schema(&public, b"another app");
    let domain_proof = present(&incumbent, &another_domain, nonce);
    check!(
        "distinct_domain_distinct_id",
        nym(&domain_proof) != expected
    );
    let mut tampered = proof.clone();
    if let PresentationProofs::Commitment(c) = tampered.proofs.get_mut("zkid").unwrap() {
        c.commitment += G1Projective::GENERATOR;
    }
    check!(
        "tampered_id_and_claim_together_rejected",
        !accepts(&tampered, nym(&tampered), &current, nonce)
    );
    // With an identity blinding base, commitment blinder responses do not
    // affect verification. Swapping the same deterministic C is harmless;
    // swapping a different credential's C must fail even if its ID is claimed.
    let other = issue(&mut issuer, Scalar::from(44u64), "synthetic-other");
    let other_proof = present(&other, &current, nonce);
    let mut spliced = proof.clone();
    spliced
        .proofs
        .insert("zkid".into(), other_proof.proofs["zkid"].clone());
    check!(
        "different_secret_proof_splicing_rejected",
        !accepts(&spliced, nym(&spliced), &current, nonce)
    );
    for missing in ["credential", "active", "zkid"] {
        let mut incomplete = proof.clone();
        incomplete.proofs.shift_remove(missing);
        check!(
            format!("missing_{}_rejected", missing),
            !accepts(&incomplete, expected, &current, nonce)
        );
    }
    let replacement_secret = Scalar::from(43u64);
    let mut replacement = issue(&mut issuer, replacement_secret, "synthetic-replacement");
    let replacement_id = create_domain_proof_generator(DOMAIN) * replacement_secret;
    check!("replacement_changes_id", replacement_id != expected);
    check!(
        "pending_replacement_preserves_incumbent",
        accepts(
            &present(&incumbent, &current, nonce),
            expected,
            &current,
            nonce
        )
    );
    issuer
        .revoke_credentials(&[RevocationClaim::from("synthetic-incumbent")])
        .unwrap();
    replacement.update_revocation_handle(
        issuer
            .update_revocation_handle(RevocationClaim::from("synthetic-replacement"))
            .unwrap(),
        issuer.revocation_registry.value,
    );
    let refreshed = schema(&IssuerPublic::from(&issuer), DOMAIN);
    check!(
        "old_proof_rejected_by_new_registry",
        !accepts(&proof, expected, &refreshed, nonce)
    );
    let revoked = present(&incumbent, &refreshed, nonce);
    check!(
        "revoked_credential_new_proof_rejected",
        !accepts(&revoked, expected, &refreshed, nonce)
    );
    let replacement_proof = present(&replacement, &refreshed, nonce);
    check!(
        "replacement_valid_after_revocation",
        accepts(&replacement_proof, replacement_id, &refreshed, nonce)
    );
    check!(
        "replacement_cannot_claim_old_id",
        !accepts(&replacement_proof, expected, &refreshed, nonce)
    );
    incumbent.credential.claims[1] = ScalarClaim::from(replacement_secret).into();
    let changed_secret = present(&incumbent, &refreshed, nonce);
    check!(
        "changing_signed_secret_rejected",
        !accepts(&changed_secret, replacement_id, &refreshed, nonce)
    );
    let zero = issue(&mut issuer, Scalar::ZERO, "synthetic-zero");
    let zero_schema = schema(&IssuerPublic::from(&issuer), DOMAIN);
    let zero_proof = present(&zero, &zero_schema, nonce);
    check!(
        "zero_identity_rejected",
        !accepts(&zero_proof, G1Projective::IDENTITY, &zero_schema, nonce)
    );
    let export = if mode.as_deref() == Some("--export-public-fixture") {
        Some(std::path::PathBuf::from(
            std::env::args().nth(2).expect("public fixture directory"),
        ))
    } else {
        None
    };
    checks.extend(application::checks(export.as_deref()));
    println!(
        "{}",
        serde_json::json!({"profile":"nockapp-zkid-domain-feasibility-v1", "production_ready":false, "checks":checks})
    );
}
