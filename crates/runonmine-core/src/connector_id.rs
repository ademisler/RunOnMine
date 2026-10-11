use anyhow::{Result, bail};

pub const CONNECTOR_ID_MIN_LEN: usize = 8;
pub const CONNECTOR_ID_MAX_LEN: usize = 64;

#[must_use]
pub fn connector_id_is_valid(value: &str) -> bool {
    let bytes = value.as_bytes();
    (CONNECTOR_ID_MIN_LEN..=CONNECTOR_ID_MAX_LEN).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

pub fn validate_connector_id(value: &str) -> Result<()> {
    if !connector_id_is_valid(value) {
        bail!(
            "connector id must be 8-64 lowercase ASCII letters, digits, '-' or '_', with an alphanumeric first and last character"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connector_ids_require_robust_lowercase_token_shape() {
        for valid in [
            "local-http",
            "connector_01",
            "00000000-0000-4000-8000-000000000123",
        ] {
            assert!(connector_id_is_valid(valid), "expected valid: {valid}");
        }
        for invalid in [
            "short",
            "UPPERCASE-ID",
            "-starts-bad",
            "ends-bad_",
            "contains.dot",
            "contains space",
        ] {
            assert!(
                !connector_id_is_valid(invalid),
                "expected invalid: {invalid}"
            );
        }
    }
}
