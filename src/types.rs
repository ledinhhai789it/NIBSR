use crate::encoding::{put_bytes, put_domain, put_str, put_u64};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use std::fmt;

pub type Nonce = [u8; 32];
pub type Tag = [u8; 32];

/// Signer public key for the SPS-EQ backend.
/// Encoding: compressed G2 point pk_1 || compressed G2 point pk_2.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SignerPublicKey(pub Vec<u8>);

/// Receiver public key for the SPS-EQ backend.
/// Encoding: compressed G1 point pk_R = g_1^{sk_R}.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReceiverPublicKey(pub Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authorization {
    /// Application payload protected by the credential, e.g. an access statement.
    pub message: Vec<u8>,
    /// Example: "read:ehr:patient-42" or "wallet:withdraw:small".
    pub scope: String,
    /// Application/session context. This is included in the tag binding.
    pub context: String,
    pub not_before: u64,
    pub not_after: u64,
}

impl Authorization {
    /// Tao doi tuong uy quyen tam thoi.
    pub fn new(
        message: impl Into<Vec<u8>>,
        scope: impl Into<String>,
        context: impl Into<String>,
        not_before: u64,
        not_after: u64,
    ) -> Self {
        Self {
            message: message.into(),
            scope: scope.into(),
            context: context.into(),
            not_before,
            not_after,
        }
    }

    /// Kiem tra uy quyen co hop le tai thoi diem cho truoc hay khong.
    pub fn is_valid_at(&self, now: u64) -> bool {
        self.not_before <= now && now <= self.not_after
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Presignature {
    pub signer_pk: SignerPublicKey,
    pub pk_r: ReceiverPublicKey,
    pub nonce: Nonce,
    pub auth: Authorization,
    /// SPS-EQ presignature bytes over (pk_R, H(nonce || authorization)).
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub signer_pk: SignerPublicKey,
    pub pk_r: ReceiverPublicKey,
    pub nonce: Nonce,
    pub auth: Authorization,
    /// Final NIBS message m = H(nonce || authorization)^{sk_R^{-1}}, encoded as a compressed G1 point.
    pub nibs_message: Vec<u8>,
    /// Final signature package: adapted SPS-EQ signature plus Chaum-Pedersen binding proof.
    pub sigma: Vec<u8>,
    /// τ = H("NIBSR/TAG" || pk || pkR || nonce || authorization || m || sigma).
    pub tag: Tag,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationEntry {
    pub id: ReceiverPublicKey,
    pub tau: Tag,
    pub scope: String,
    pub not_before: u64,
    pub not_after: u64,
}

impl RevocationEntry {
    /// Tao entry thu hoi tu mot credential.
    pub fn from_credential(cred: &Credential) -> Self {
        Self {
            id: cred.pk_r.clone(),
            tau: cred.tag,
            scope: cred.auth.scope.clone(),
            not_before: cred.auth.not_before,
            not_after: cred.auth.not_after,
        }
    }

    /// Tao khoa tra cuu thu hoi tu (id, tau).
    pub fn lookup_key(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_domain(&mut out, "NIBSR/REVOCATION-KEY/v1");
        put_bytes(&mut out, &self.id.0);
        put_bytes(&mut out, &self.tau);
        out
    }

    /// Implements the policy check corresponding to
    /// Φ(y) ≡ (scope* ⊆ scope_y) ∧ (t* ∈ valid(y)).
    /// Kiem tra entry thu hoi co bao phu scope/thoi gian yeu cau hay khong.
    pub fn covers(&self, requested_scope: &str, requested_time: u64) -> bool {
        scope_covers(&self.scope, requested_scope)
            && self.not_before <= requested_time
            && requested_time <= self.not_after
    }
}

/// Kiem tra scope bi thu hoi co bao phu scope dang yeu cau hay khong.
pub fn scope_covers(revoked_scope: &str, requested_scope: &str) -> bool {
    revoked_scope == "*" || revoked_scope == requested_scope || requested_scope.starts_with(revoked_scope)
}

/// Bam toan bo danh sach thu hoi thanh digest co thu tu xac dinh.
pub fn hash_revocation_entries(entries: &[RevocationEntry]) -> [u8; 32] {
    let mut keys: Vec<Vec<u8>> = entries.iter().map(RevocationEntry::lookup_key).collect();
    keys.sort();

    let mut h = Sha256::new();
    h.update(b"NIBSR/REVOCATION-DIGEST/v1");
    for key in keys {
        h.update((key.len() as u64).to_be_bytes());
        h.update(key);
    }
    h.finalize().into()
}

/// Ma hoa Authorization theo dinh dang canonical cho hash/chu ky.
pub fn encode_authorization(out: &mut Vec<u8>, auth: &Authorization) {
    put_bytes(out, &auth.message);
    put_str(out, &auth.scope);
    put_str(out, &auth.context);
    put_u64(out, auth.not_before);
    put_u64(out, auth.not_after);
}

impl fmt::Display for SignerPublicKey {
    /// Hien thi khoa cong khai signer dang hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl fmt::Display for ReceiverPublicKey {
    /// Hien thi khoa cong khai receiver dang hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}
