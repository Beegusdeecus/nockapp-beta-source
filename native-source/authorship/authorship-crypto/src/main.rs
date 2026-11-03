//! One-shot private-pipe interface. Never pass secret material as arguments.
use nockapp_authorship_v4::{generate_secret, prove, pseudonym, verify, Proof, Scope};
use serde::{Deserialize,Serialize};
use credx::{prelude::*,knox::bbs::BbsScheme};
use nockapp_authorship_v4::author_v4::{self,BoundTrust,BoundProof};
use std::io::{Read, Write};
const INTERNAL: &str="nockapp-authorship-internal-v4";
#[derive(Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
struct Input { profile: String, call: Call }
#[derive(Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
enum Call {
    #[serde(rename="normalize-held-scalar")]
    NormalizeHeldScalar { scalar: credx::prelude::blsful::inner_types::Scalar },
    #[serde(rename="prepare-count")]
    PrepareCount { public: IssuerPublic<BbsScheme>, secret: String },
    #[serde(rename="present-count")]
    PresentCount { credential: CredentialBundle<BbsScheme>, trust: BoundTrust, expected_author: String },
    #[serde(rename="verify-count")]
    VerifyCount { public_input: BoundProof, trust: BoundTrust, expected_author: String },
    #[serde(rename="generate")]
    Generate {},
    #[serde(rename="prove")]
    Prove { secret: String, scopes: Vec<Scope>, context: String },
    #[serde(rename="verify")]
    Verify { proof: Proof, scopes: Vec<Scope>, context: String },
    #[serde(rename="pseudonym")]
    Pseudonym { secret: String, scope: Scope },
}
fn run() -> Option<()> {
    if std::env::args().collect::<Vec<_>>()!=vec![std::env::args().next()?,"--internal-authorship".into()] { return None; }
    let mut input=Vec::new();std::io::stdin().take(65537).read_to_end(&mut input).ok()?;
    if input.len()>65536 { return None; }
    let input: Input=author_v4::decode_rpc(&input)?;
    if input.profile!=INTERNAL { return None; }
    let value=match input.call {
        Call::NormalizeHeldScalar { scalar }=> {
            let secret=nockapp_authorship_v4::encode_secret(scalar)?;
            serde_json::json!({"material":{"scalar":secret},"root":pseudonym(&secret,&Scope::Identity)?,"legacy_root":Scope::Identity.base()?*scalar})
        },
        Call::PrepareCount { public,secret }=> author_v4::prepare(public,&secret)?,
        Call::PresentCount { credential,trust,expected_author }=>serde_json::json!({"presentation":author_v4::present_bound(credential,&trust,&expected_author)?}),
        Call::VerifyCount { public_input,trust,expected_author }=>serde_json::json!({"accepted":author_v4::verify_bound(&public_input,&trust,&expected_author)}),
        Call::Generate {} => serde_json::json!({"secret":generate_secret()}),
        Call::Prove { secret,scopes,context } => serde_json::json!({"proof":prove(&secret,&scopes,&context)?}),
        Call::Verify { proof,scopes,context } => serde_json::json!({"accepted":verify(&proof,&scopes,&context)}),
        Call::Pseudonym { secret,scope } => serde_json::json!({"pseudonym":pseudonym(&secret,&scope)?}),
    };
    std::io::stdout().write_all(&serde_json::to_vec(&serde_json::json!({"profile":INTERNAL,"result":value})).ok()?).ok()?;
    Some(())
}
fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    if run().is_none() { std::process::exit(1); }
}
