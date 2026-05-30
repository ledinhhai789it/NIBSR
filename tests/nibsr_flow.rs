use nibsr::{
    random_nonce, Authorization, ReceiverKeyPair, RevocationEntry, RevocationList, SignerKeyPair,
    SpsEqNibsBackend, VerifyDecision, XacThucR,
};

/// Tao bo du lieu mau gom credential hop le va moc thoi gian kiem tra.
#[allow(non_snake_case)]
fn TaoCredentialMau() -> (nibsr::Credential, u64) {
    let now = 1_800_000_000u64;
    let signer = SignerKeyPair::generate();
    let receiver = ReceiverKeyPair::generate();
    let auth = Authorization::new(
        b"temporary authorization".to_vec(),
        "wallet:pay:small",
        "test/context",
        now - 10,
        now + 10,
    );
    let psig = SpsEqNibsBackend::issue(&signer, receiver.public(), random_nonce(), auth);
    let cred = SpsEqNibsBackend::obtain(&receiver, psig).unwrap();
    (cred, now)
}

/// Tao danh sach thu hoi theo mode.
#[allow(non_snake_case)]
fn TaoDanhSachTheoMode(mode: &str) -> RevocationList {
    match mode {
        "set" => RevocationList::TaoSet(),
        "bloom" => RevocationList::TaoBloom(8192, 7),
        "merkle" => RevocationList::TaoMerkle(),
        other => panic!("mode khong ho tro: {other}"),
    }
}

/// Kiem tra case hop le khi credential chua bi thu hoi.
#[test]
fn accepts_when_not_revoked() {
    let (cred, now) = TaoCredentialMau();
    let rev_list = RevocationList::TaoSet();
    assert_eq!(XacThucR(&cred, &rev_list, now), VerifyDecision::Accept);
}

/// Kiem tra case bi tu choi sau khi thu hoi bang mode Set.
#[test]
fn rejects_after_revocation_set_mode() {
    let (cred, now) = TaoCredentialMau();
    let mut rev_list = RevocationList::TaoSet();
    rev_list.Them(RevocationEntry::from_credential(&cred));
    assert_eq!(XacThucR(&cred, &rev_list, now), VerifyDecision::RejectRevoked);
}

/// Kiem tra case bi tu choi sau khi thu hoi bang mode Merkle.
#[test]
fn rejects_after_revocation_merkle_mode() {
    let (cred, now) = TaoCredentialMau();
    let mut rev_list = RevocationList::TaoMerkle();
    rev_list.Them(RevocationEntry::from_credential(&cred));
    assert_eq!(XacThucR(&cred, &rev_list, now), VerifyDecision::RejectRevoked);
}

/// Chay bang test them/xoa thu hoi cho ca 3 mode.
#[test]
fn bang_test_them_xoa_theo_tung_mode() {
    let modes = ["set", "bloom", "merkle"];
    for mode in modes {
        let (cred, now) = TaoCredentialMau();
        let mut rev_list = TaoDanhSachTheoMode(mode);
        let entry = RevocationEntry::from_credential(&cred);

        assert_eq!(XacThucR(&cred, &rev_list, now), VerifyDecision::Accept, "mode={mode} truoc khi them");
        rev_list.Them(entry.clone());
        assert_eq!(XacThucR(&cred, &rev_list, now), VerifyDecision::RejectRevoked, "mode={mode} sau khi them");
        rev_list.Xoa(&entry);
        assert_eq!(XacThucR(&cred, &rev_list, now), VerifyDecision::Accept, "mode={mode} sau khi xoa");
    }
}

/// Kiem tra credential bi sua message se bi reject invalid.
#[test]
fn rejects_tampered_message() {
    let (mut cred, now) = TaoCredentialMau();
    cred.auth.message = b"tampered authorization".to_vec();
    let rev_list = RevocationList::TaoSet();
    match XacThucR(&cred, &rev_list, now) {
        VerifyDecision::RejectInvalid(_) => {}
        other => panic!("expected invalid credential, got {other:?}"),
    }
}

/// Kiem tra credential bi sua tag se bi reject invalid.
#[test]
fn rejects_tampered_tag() {
    let (mut cred, now) = TaoCredentialMau();
    cred.tag[0] ^= 0x01;
    let rev_list = RevocationList::TaoSet();
    match XacThucR(&cred, &rev_list, now) {
        VerifyDecision::RejectInvalid(_) => {}
        other => panic!("expected invalid tag, got {other:?}"),
    }
}

/// Kiem tra credential bi tu choi khi verify ngoai cua so hieu luc.
#[test]
fn rejects_outside_validity_window() {
    let (cred, now) = TaoCredentialMau();
    let rev_list = RevocationList::TaoSet();
    let too_early = now - 100;
    let too_late = now + 100;
    assert_eq!(XacThucR(&cred, &rev_list, too_early), VerifyDecision::RejectOutsideValidityWindow);
    assert_eq!(XacThucR(&cred, &rev_list, too_late), VerifyDecision::RejectOutsideValidityWindow);
}
