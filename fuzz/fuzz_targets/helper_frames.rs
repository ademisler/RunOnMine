#![no_main]

use libfuzzer_sys::fuzz_target;
use runonmine_platform::helper::protocol::HelperRequest;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<HelperRequest>(data);
});
