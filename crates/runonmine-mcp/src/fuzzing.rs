//! Hidden fuzz harnesses that exercise production state transitions.

/// Exercise MCP session header validation and binding transitions.
pub fn exercise_session_headers_and_bindings(data: &[u8]) {
    crate::http::exercise_fuzz_session_state(data);
}
