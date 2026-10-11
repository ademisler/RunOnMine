#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() <= 4 * 1024 * 1024 {
        runonmine_connectors::installer::fuzzing::exercise_archive_parsers(data);
    }
});
