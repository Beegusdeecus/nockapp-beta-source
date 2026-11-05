//! Versioned raw-count native worker. No networking or persistent key creation.
mod application;
fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    if std::env::args().collect::<Vec<_>>().get(1).map(String::as_str) != Some("--internal-crypto")
        || !application::rpc::run() { std::process::exit(1); }
}

#[cfg(feature="private-authorship-v4")]
pub use nockapp_authorship_v4::{encode_secret,point,secret_scalar,Scope};
