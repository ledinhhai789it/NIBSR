//! NIBSR research prototype.
//!
//! This crate implements the paper's protocol engineering layer: key generation,
//! issue, obtain, VerifyR, and three revocation-list modes (SET, Bloom filter,
//! Merkle tree).
//!
//! Version 0.2 replaces the former development backend with a real pairing-based
//! SPS-EQ NIBS backend over BLS12-381. The implementation is still a research
//! prototype and has not been independently audited.

pub mod backend;
pub mod encoding;
pub mod error;
pub mod nibsr;
pub mod revocation;
pub mod types;

pub use backend::{compute_tag, random_nonce, ReceiverKeyPair, SignerKeyPair, SpsEqNibsBackend};
pub use error::NibsrError;
pub use nibsr::{verify_r, VerifyDecision, VerifyR, XacThucR, XacThucRKetQua};
pub use revocation::{BloomRevocationList, MerkleRevocationList, RevocationList, SetRevocationList};
pub use types::{Authorization, Credential, Nonce, Presignature, ReceiverPublicKey, RevocationEntry, SignerPublicKey, Tag};
