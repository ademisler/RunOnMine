#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() <= 65_536 {
        runonmine_mcp::fuzzing::exercise_session_headers_and_bindings(data);
    }
});
