//! Internal one-shot crypto worker. Private anonymous pipes only: this is NOT
//! an external signing API, issuer server, or substitute for the source policy.
use super::*;
use credx::knox::accumulator::vb20::MembershipWitness;
use credx::knox::short_group_sig_core::short_group_traits::BlindSignatureContext as _;
use credx::prelude::blsful::inner_types::Field;

const INTERNAL: &str = "nockapp-zkid-internal-count-v2";
const LIMIT: usize = 262144;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attributes {
    source: String,
    policy: String,
    start: u64,
    expiry: u64,
    controlled: u8,
    followers: u64,
    binding: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    secret: Scalar,
    request: BlindCredentialRequest<BbsScheme>,
    blinder: Scalar,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    profile: String,
    call: Call,
}

#[derive(Serialize, Deserialize)]
// External tagging lets upstream proof decoders borrow strings directly from
// the original JSON. Adjacent tagging buffers Content and breaks that API.
#[serde(deny_unknown_fields)]
enum Call {
    #[serde(rename = "legacy-public-count-view")]
    LegacyPublicCountView { public: IssuerPublic<BbsScheme> },
    #[serde(rename = "legacy-validate-count-request")]
    LegacyValidateCountRequest { issuer: Issuer<BbsScheme>, request: BlindCredentialRequest<BbsScheme> },
    #[serde(rename = "legacy-stage-count")]
    LegacyStageCount { issuer: Issuer<BbsScheme>, request: BlindCredentialRequest<BbsScheme>,
        handle: String, attributes: Attributes },
    #[serde(rename = "legacy-commit-count")]
    LegacyCommitCount { issuer: Issuer<BbsScheme>, handle: String, old_handle: Option<String>,
        ack: Proof, attributes: Attributes },
    #[serde(rename = "validate-request")]
    ValidateRequest {
        issuer: Issuer<BbsScheme>,
        request: BlindCredentialRequest<BbsScheme>,
    },
    #[serde(rename = "setup")]
    Setup { capacity: usize },
    #[serde(rename = "prepare")]
    Prepare { public: IssuerPublic<BbsScheme> },
    #[serde(rename = "stage")]
    Stage {
        issuer: Issuer<BbsScheme>,
        request: BlindCredentialRequest<BbsScheme>,
        handle: String,
        attributes: Attributes,
    },
    #[serde(rename = "receive")]
    Receive {
        pending: Pending,
        bundle: BlindCredentialBundle<BbsScheme>,
        public: IssuerPublic<BbsScheme>,
        attributes: Attributes,
    },
    #[serde(rename = "commit")]
    Commit {
        issuer: Issuer<BbsScheme>,
        handle: String,
        old_handle: Option<String>,
        ack: Proof,
        attributes: Attributes,
    },
    #[serde(rename = "present")]
    Present { credential: Bundle, trust: Trust },
    #[serde(rename = "verify")]
    Verify {
        public_input: PublicInput,
        trust: Trust,
    },
    #[serde(rename = "witness")]
    Witness {
        issuer: Issuer<BbsScheme>,
        handle: String,
    },
    #[serde(rename = "refresh")]
    Refresh {
        credential: Bundle,
        public: IssuerPublic<BbsScheme>,
        witness: MembershipWitness,
    },
}

fn valid_legacy(public: &IssuerPublic<BbsScheme>) -> bool {
    let key = &public.verifying_key;
    key.is_invalid().unwrap_u8() == 0 && *key == key.compress().decompress()
        && serde_json::to_value(&public.schema).unwrap() == serde_json::to_value(legacy_schema()).unwrap()
}

fn count_issuer(mut issuer: Issuer<BbsScheme>) -> Option<Issuer<BbsScheme>> {
    if !valid_legacy(&IssuerPublic::from(&issuer)) { return None; }
    issuer.schema = credential_schema();Some(issuer)
}

fn valid_public(public: &IssuerPublic<BbsScheme>) -> bool {
    let key = &public.verifying_key;
    key.is_invalid().unwrap_u8() == 0
        && *key == key.compress().decompress()
        && serde_json::to_value(&public.schema).unwrap()
            == serde_json::to_value(credential_schema()).unwrap()
}

fn same_definition(a: &IssuerPublic<BbsScheme>, b: &IssuerPublic<BbsScheme>) -> bool {
    let mut a = serde_json::to_value(a).unwrap();
    let mut b = serde_json::to_value(b).unwrap();
    a.as_object_mut().unwrap().remove("revocation_registry");
    b.as_object_mut().unwrap().remove("revocation_registry");
    a == b
}

fn valid_attributes(a: &Attributes) -> bool {
    a.source == SOURCE
        && a.policy.len() == 64
        && a.policy
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        && a.start > 0
        && a.start < (1u64 << 53)
        && a.start % 3600 == 0
        && a.expiry.checked_sub(a.start) == Some(86400)
        && a.expiry < (1u64 << 53)
        && a.controlled == 1
        && a.followers <= MAX_COUNT
        && a.policy == COUNT_POLICY
        && a.binding.len() == 64
        && a.binding
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn known(a: &Attributes, handle: &str) -> BTreeMap<String, ClaimData> {
    BTreeMap::from([
        ("revocation".into(), RevocationClaim::from(handle).into()),
        ("source".into(), HashedClaim::from(a.source.as_str()).into()),
        ("policy".into(), HashedClaim::from(a.policy.as_str()).into()),
        ("start".into(), NumberClaim::from(a.start as isize).into()),
        ("expiry".into(), NumberClaim::from(a.expiry as isize).into()),
        (
            "controlled".into(),
            NumberClaim::from(a.controlled as isize).into(),
        ),
        (
            "follower_count".into(),
            NumberClaim::from(a.followers as isize).into(),
        ),
        (
            "issuance_binding".into(),
            HashedClaim::from(a.binding.as_str()).into(),
        ),
    ])
}

fn received_attributes(bundle: &Bundle, a: &Attributes, secret: Scalar) -> bool {
    if bundle.credential.claims.len() != LABELS.len() {
        return false;
    }
    let claims = &bundle.credential.claims;
    matches!(claims[1], ClaimData::Scalar(c) if c.value == secret)
        && hashed(Some(&claims[2]), &a.source)
        && hashed(Some(&claims[3]), &a.policy)
        && number(Some(&claims[4])) == Some(a.start as i64)
        && number(Some(&claims[5])) == Some(a.expiry as i64)
        && number(Some(&claims[6])) == Some(a.controlled as i64)
        && number(Some(&claims[7])) == Some(a.followers as i64)
        && hashed(Some(&claims[8]), &a.binding)
}

fn execute(call: Call) -> Option<serde_json::Value> {
    match call {
        Call::LegacyPublicCountView { mut public } => {
            if !valid_legacy(&public) { return None; }
            public.schema = credential_schema();Some(serde_json::json!({"public":public}))
        }
        Call::LegacyValidateCountRequest { issuer, request } => {
            execute(Call::ValidateRequest { issuer:count_issuer(issuer)?,request })
        }
        Call::LegacyStageCount { issuer, request, handle, attributes } => {
            execute(Call::Stage { issuer:count_issuer(issuer)?,request,handle,attributes })
        }
        Call::LegacyCommitCount { issuer, handle, old_handle, ack, attributes } => {
            if !valid_attributes(&attributes) { return None; }
            let issuer = count_issuer(issuer)?;
            let mut staged = staged_activation(&issuer, &handle);
            let trust = ReceiptTrust { issuer:IssuerPublic::from(&staged), binding:attributes.binding };
            if !verify_receipt(&ack, &trust) { return None; }
            if let Some(old) = old_handle {
                staged.revoke_credentials(&[RevocationClaim::from(old)]).ok()?;
            }
            staged.schema = legacy_schema();
            Some(serde_json::json!({"public":IssuerPublic::from(&staged),"issuer":staged}))
        }
        Call::ValidateRequest { issuer, request } => {
            if !valid_public(&IssuerPublic::from(&issuer))
                || request.blind_claim_labels != vec!["secret"]
                || request.blind_signature_context.proofs.len() != 1
            {
                return None;
            }
            let known = [0usize, 2, 3, 4, 5, 6, 7, 8];
            if !request
                .blind_signature_context
                .verify(&known, &issuer.signing_key, request.nonce)
                .ok()?
            {
                return None;
            }
            Some(serde_json::json!({"valid":true}))
        }
        Call::Setup { capacity } => {
            if !(2..=1000).contains(&capacity) {
                return None;
            }
            let (_, mut issuer) = Issuer::<BbsScheme>::new(&credential_schema());
            let handles = (0..capacity)
                .map(|_| credx::random_string(32, rand::thread_rng()))
                .collect::<Vec<_>>();
            issuer.revocation_registry.add(&handles);
            issuer
                .revoke_credentials(
                    &handles
                        .iter()
                        .map(RevocationClaim::from)
                        .collect::<Vec<_>>(),
                )
                .ok()?;
            Some(
                serde_json::json!({"public":IssuerPublic::from(&issuer),"issuer":issuer,"handles":handles}),
            )
        }
        Call::Prepare { public } => {
            if !valid_public(&public) {
                return None;
            }
            let mut secret = Scalar::ZERO;
            while secret == Scalar::ZERO {
                secret = Scalar::random(rand::thread_rng());
            }
            let hidden = BTreeMap::from([("secret".into(), ScalarClaim::from(secret).into())]);
            let (request, blinder) = BlindCredentialRequest::new(&public, &hidden).ok()?;
            Some(
                serde_json::json!({"request":request,"pending":Pending {secret,request:request.clone(),blinder},
                "local_zkid":create_domain_proof_generator(DOMAIN)*secret}),
            )
        }
        Call::Stage {
            issuer,
            request,
            handle,
            attributes,
        } => {
            if !valid_attributes(&attributes)
                || !valid_public(&IssuerPublic::from(&issuer))
                || request.blind_claim_labels != vec!["secret"]
            {
                return None;
            }
            let mut staged = staged_activation(&issuer, &handle);
            let bundle = staged
                .blind_sign_credential(&request, &known(&attributes, &handle))
                .ok()?;
            Some(serde_json::json!({"bundle":bundle}))
        }
        Call::Receive {
            pending,
            bundle,
            public,
            attributes,
        } => {
            if !valid_attributes(&attributes)
                || !valid_public(&public)
                || !same_definition(&bundle.issuer, &public)
                || pending.secret == Scalar::ZERO
            {
                return None;
            }
            let hidden =
                BTreeMap::from([("secret".into(), ScalarClaim::from(pending.secret).into())]);
            let received = bundle.to_unblinded(&hidden, pending.blinder).ok()?;
            if !received_attributes(&received, &attributes, pending.secret) {
                return None;
            }
            let ack = receipt(&received, &attributes.binding);
            let expected = ReceiptTrust {
                issuer: received.issuer.clone(),
                binding: attributes.binding,
            };
            if !verify_receipt(&ack, &expected) {
                return None;
            }
            Some(
                serde_json::json!({"credential":received,"ack":ack,"local_zkid":create_domain_proof_generator(DOMAIN)*pending.secret}),
            )
        }
        Call::Commit {
            issuer,
            handle,
            old_handle,
            ack,
            attributes,
        } => {
            if !valid_attributes(&attributes) || !valid_public(&IssuerPublic::from(&issuer)) {
                return None;
            }
            let mut staged = staged_activation(&issuer, &handle);
            let expected = ReceiptTrust {
                issuer: IssuerPublic::from(&staged),
                binding: attributes.binding,
            };
            if !verify_receipt(&ack, &expected) {
                return None;
            }
            if let Some(old) = old_handle {
                staged
                    .revoke_credentials(&[RevocationClaim::from(old)])
                    .ok()?;
            }
            Some(serde_json::json!({"public":IssuerPublic::from(&staged),"issuer":staged}))
        }
        Call::Present { credential, trust } => {
            if !same_definition(&credential.issuer, &trust.issuer)
                || schema(&trust).is_none()
                || credential.credential.claims.len() != LABELS.len()
            {
                return None;
            }
            // Avoid out-of-range prover errors/panics and reject an unsatisfied
            // predicate locally. The verifier still checks the linked proof.
            let count = number(credential.credential.claims.get(7))?;
            if count < 0 || (count as u64) > MAX_COUNT
                || trust.challenge.threshold.is_some_and(|t| (count as u64) <= t) { return None; }
            let secret = match credential.credential.claims[1] {
                ClaimData::Scalar(s) => s.value,
                _ => return None,
            };
            let proof = present(&credential, &trust);
            let claimed_id = if trust.challenge.identity {
                Some(create_domain_proof_generator(DOMAIN) * secret)
            } else {
                None
            };
            Some(serde_json::to_value(PublicInput { proof, claimed_id }).ok()?)
        }
        Call::Verify {
            public_input,
            trust,
        } => Some(
            serde_json::json!({"accepted":verify(&public_input,&trust),"laboratory_only":true}),
        ),
        Call::Witness { issuer, handle } => {
            let witness = issuer
                .update_revocation_handle(RevocationClaim::from(handle))
                .ok()?;
            Some(serde_json::json!({"witness":witness,"public":IssuerPublic::from(&issuer)}))
        }
        Call::Refresh {
            mut credential,
            public,
            witness,
        } => {
            if !valid_public(&public) || !same_definition(&credential.issuer, &public) {
                return None;
            }
            credential.update_revocation_handle(witness, public.revocation_registry);
            Some(serde_json::json!({"credential":credential}))
        }
    }
}

pub fn run() -> bool {
    let mut data = Vec::new();
    if std::io::stdin()
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut data)
        .is_err()
        || data.len() > LIMIT
    {
        return false;
    }
    let input: Input = match decode(&data) {
        Some(v) => v,
        None => return false,
    };
    if input.profile != INTERNAL {
        return false;
    }
    let result = match execute(input.call) {
        Some(v) => v,
        None => return false,
    };
    let bytes =
        serde_json::to_vec(&serde_json::json!({"profile":INTERNAL,"result":result})).unwrap();
    if bytes.len() > LIMIT {
        return false;
    }
    std::io::stdout().write_all(&bytes).is_ok()
}
