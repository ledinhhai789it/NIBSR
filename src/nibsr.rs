use crate::backend::SpsEqNibsBackend;
use crate::error::NibsrError;
use crate::revocation::RevocationList;
use crate::types::Credential;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyDecision {
    Accept,
    RejectRevoked,
    RejectInvalid(String),
    RejectOutsideValidityWindow,
}

/// Xac thuc credential theo NIBSR, gom kiem tra chu ky va doi chieu danh sach thu hoi.
#[allow(non_snake_case)]
pub fn XacThucR(cred: &Credential, rev_list: &RevocationList, now: u64) -> VerifyDecision {
    verify_r(cred, rev_list, now)
}

/// Ham VerifyR theo dung ten trong tai lieu.
#[allow(non_snake_case)]
pub fn VerifyR(cred: &Credential, rev_list: &RevocationList, now: u64) -> VerifyDecision {
    verify_r(cred, rev_list, now)
}

/// Xac thuc credential va tra ve ket qua bool/error de xu ly theo luong ung dung.
#[allow(non_snake_case)]
pub fn XacThucRKetQua(cred: &Credential, rev_list: &RevocationList, now: u64) -> Result<bool, NibsrError> {
    verify_r_result(cred, rev_list, now)
}

/// NIBSR.VerifyR(pk, pkR, (m, σ), nonce, RevList).
///
/// The function first verifies the SPS-EQ NIBS signature and the binding proof,
/// then checks whether the corresponding (ID, τ) pair is present in the
/// revocation structure.
/// Ham verify chinh: hop le + khong nam trong RevList thi Accept.
pub fn verify_r(cred: &Credential, rev_list: &RevocationList, now: u64) -> VerifyDecision {
    if !cred.auth.is_valid_at(now) {
        return VerifyDecision::RejectOutsideValidityWindow;
    }

    if let Err(err) = SpsEqNibsBackend::verify_base(cred) {
        return VerifyDecision::RejectInvalid(err.to_string());
    }

    if rev_list.verify_tag(&cred.pk_r, &cred.tag, &cred.auth.scope, now) {
        VerifyDecision::RejectRevoked
    } else {
        VerifyDecision::Accept
    }
}

/// Bien the verify tra ve Result<bool, NibsrError>.
pub fn verify_r_result(cred: &Credential, rev_list: &RevocationList, now: u64) -> Result<bool, NibsrError> {
    if !cred.auth.is_valid_at(now) {
        return Err(NibsrError::OutsideValidityWindow);
    }
    SpsEqNibsBackend::verify_base(cred)?;
    Ok(!rev_list.verify_tag(&cred.pk_r, &cred.tag, &cred.auth.scope, now))
}
