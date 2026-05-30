use clap::Parser;
use nibsr::{random_nonce, Authorization, ReceiverKeyPair, RevocationEntry, RevocationList, SignerKeyPair, SpsEqNibsBackend, VerifyDecision, XacThucR};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser, Debug)]
#[command(name = "nibsr-demo")]
#[command(about = "Run a small NIBSR issue/obtain/verify/revoke demonstration")]
struct Args {
    /// Revocation mode: set, bloom, or merkle.
    #[arg(long, default_value = "set")]
    mode: String,
}

/// Lay moc thoi gian Unix hien tai theo giay.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs()
}

/// Chay demo issue/obtain/verify/revoke theo mode duoc truyen vao.
fn main() {
    let args = Args::parse();
    let now = now_unix();

    let signer = SignerKeyPair::generate();
    let receiver = ReceiverKeyPair::generate();
    let nonce = random_nonce();

    let auth = Authorization::new(
        b"temporary authorization token for medical-record:42".to_vec(),
        "ehr:read:record-42",
        "demo/ehr/session-001",
        now,
        now + 3600,
    );

    let psig = SpsEqNibsBackend::issue(&signer, receiver.public(), nonce, auth);
    let cred = SpsEqNibsBackend::obtain(&receiver, psig).expect("obtain must succeed");

    let mut rev_list = match args.mode.as_str() {
        "set" => RevocationList::TaoSet(),
        "bloom" => RevocationList::TaoBloom(8192, 7),
        "merkle" => RevocationList::TaoMerkle(),
        other => panic!("unknown revocation mode: {other}"),
    };

    println!("Signer pk:  {}", cred.signer_pk);
    println!("Receiver pk: {}", cred.pk_r);
    println!("Tag tau:     {}", hex::encode(cred.tag));
    println!("Digest before revoke: {}", hex::encode(rev_list.publish_digest()));
    println!("Verify before revoke: {:?}", XacThucR(&cred, &rev_list, now));

    rev_list.Them(RevocationEntry::from_credential(&cred));

    println!("Digest after revoke:  {}", hex::encode(rev_list.publish_digest()));
    println!("Verify after revoke:  {:?}", XacThucR(&cred, &rev_list, now));

    assert_eq!(XacThucR(&cred, &rev_list, now), VerifyDecision::RejectRevoked);
}
