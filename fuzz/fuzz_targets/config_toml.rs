#![no_main]

use libfuzzer_sys::fuzz_target;
use runonmine_core::AppConfig;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1_048_576 {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(config) = toml::from_str::<AppConfig>(text) {
        let _ = config.validate();
    }
});
