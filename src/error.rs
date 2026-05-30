use thiserror::Error;

#[derive(Debug, Error)]
pub enum NibsrError {
    #[error("invalid signature")]
    InvalidSignature,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid tag")]
    InvalidTag,

    #[error("invalid binding proof between pkR, nonce and final NIBS message")]
    InvalidBindingProof,

    #[error("receiver key does not match the presignature")]
    ReceiverMismatch,

    #[error("credential is not valid at the requested time")]
    OutsideValidityWindow,

    #[error("malformed data: {0}")]
    Malformed(&'static str),
}
