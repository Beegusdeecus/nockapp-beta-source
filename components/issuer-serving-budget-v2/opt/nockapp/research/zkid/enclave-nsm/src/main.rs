//! NSM attestation only. No keys, credentials, signing interface or simulation.
use aws_nitro_enclaves_nsm_api::{
    api::{Request, Response},
    driver::{nsm_exit, nsm_init, nsm_process_request},
};
use serde::Deserialize;
use std::io::{self, Read, Write};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    nonce: Vec<u8>,
    public_key: Vec<u8>,
    user_data: Vec<u8>,
}

fn run() -> Option<()> {
    let mut bytes = Vec::new();
    io::stdin().take(8193).read_to_end(&mut bytes).ok()?;
    if bytes.len() > 8192 { return None; }
    let value: Input = serde_json::from_slice(&bytes).ok()?;
    // 33-byte channel key or 294-byte RSA-2048 DER SPKI, fixed application use.
    // NSM signs opaque bytes; the measured Python owner validates actual keys.
    if value.nonce.len() != 32 || value.user_data.len() != 32
        || !matches!(value.public_key.len(), 33 | 294) { return None; }
    let fd = nsm_init();
    if fd < 0 { return None; }
    let response = nsm_process_request(fd, Request::Attestation {
        nonce: Some(value.nonce.into()),
        public_key: Some(value.public_key.into()),
        user_data: Some(value.user_data.into()),
    });
    nsm_exit(fd);
    match response {
        Response::Attestation { document } if !document.is_empty() && document.len() <= 32768 => {
            let output = serde_json::to_vec(&serde_json::json!({"document":document})).ok()?;
            io::stdout().write_all(&output).ok()?;
            Some(())
        }
        _ => None,
    }
}

fn main() {
    if run().is_none() { std::process::exit(1); }
}
