//! Small deterministic encoder used for transcript hashing/signing.
//! It avoids serde-version-dependent binary formats in cryptographic transcripts.

/// Ghi chuoi domain theo dinh dang bytes vao bo dem.
pub fn put_domain(out: &mut Vec<u8>, domain: &str) {
    put_bytes(out, domain.as_bytes());
}

/// Ghi mang bytes co do dai vao bo dem.
pub fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Ghi chuoi UTF-8 vao bo dem.
pub fn put_str(out: &mut Vec<u8>, value: &str) {
    put_bytes(out, value.as_bytes());
}

/// Ghi so nguyen 64-bit dang big-endian vao bo dem.
pub fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}
