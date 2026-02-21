use super::error::ApiError;

/// Maximum allowed length for rule identifiers.
pub const MAX_ID_LENGTH: usize = 256;

/// Maximum allowed length for scope/mode/action string fields.
pub const MAX_SHORT_STRING_LENGTH: usize = 128;

/// Maximum allowed length for pattern fields (host, SNI, path, domain).
pub const MAX_PATTERN_LENGTH: usize = 512;

/// Validate that a string field does not exceed `max_len` bytes.
pub fn validate_string_length(
    field_name: &str,
    value: &str,
    max_len: usize,
) -> Result<(), ApiError> {
    if value.len() > max_len {
        return Err(ApiError::BadRequest {
            code: "VALIDATION_ERROR",
            message: format!(
                "{field_name} exceeds maximum length of {max_len} characters (got {})",
                value.len()
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_length() {
        assert!(validate_string_length("id", "fw-001", MAX_ID_LENGTH).is_ok());
    }

    #[test]
    fn rejects_oversized_string() {
        let long = "x".repeat(MAX_ID_LENGTH + 1);
        let err = validate_string_length("id", &long, MAX_ID_LENGTH);
        assert!(err.is_err());
    }

    #[test]
    fn exactly_at_limit_is_ok() {
        let exact = "x".repeat(MAX_ID_LENGTH);
        assert!(validate_string_length("id", &exact, MAX_ID_LENGTH).is_ok());
    }
}
