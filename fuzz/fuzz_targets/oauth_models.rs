#![no_main]

use libfuzzer_sys::fuzz_target;
use runonmine_oauth::{AuthorizationRequest, ClientRegistrationRequest, TokenRequest};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<AuthorizationRequest>(data);
    let _ = serde_json::from_slice::<ClientRegistrationRequest>(data);
    let _ = serde_json::from_slice::<TokenRequest>(data);
});
