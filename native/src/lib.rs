use napi_derive::napi;

/// Minimal native entry point used to verify the mixed Rust/TypeScript setup.
#[napi]
pub fn native_ready() -> bool {
    true
}
