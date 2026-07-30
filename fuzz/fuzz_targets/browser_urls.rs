#![no_main]

use libfuzzer_sys::fuzz_target;
use runonmine_browser::BrowserPolicy;
use url::Url;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(url) = Url::parse(text) else {
        return;
    };
    let policy = BrowserPolicy::restricted();
    let _ = policy.ensure_target_allowed(&url);
    let _ = policy.ensure_request_allowed(&url);
});
