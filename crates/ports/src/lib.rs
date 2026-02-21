#![forbid(unsafe_code)]

pub mod primary;
pub mod secondary;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
