#![no_main]

use libfuzzer_sys::fuzz_target;
use runonmine_oauth::{AuthorizationRequest, DynamicClientRequest, TokenRequest};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<AuthorizationRequest>(data);
    let _ = serde_json::from_slice::<DynamicClientRequest>(data);
    let _ = serde_json::from_slice::<TokenRequest>(data);
});
