use nibsr::{
    random_nonce, Authorization, ReceiverKeyPair, RevocationEntry, RevocationList, SignerKeyPair,
    SpsEqNibsBackend, VerifyDecision, VerifyR,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::time::Instant;

#[derive(Clone, Debug)]
struct BuocCase {
    so: usize,
    mo_ta: String,
    input: String,
    output: VerifyDecision,
    thoi_gian_us: u128,
}

#[derive(Clone, Debug)]
struct BaoCaoMode {
    mode: String,
    now: u64,
    scope: String,
    not_before: u64,
    not_after: u64,
    pk_r_hex: String,
    tau_hex: String,
    rev_digest_ban_dau_hex: String,
    message_sha256: String,
    nibs_message_sha256: String,
    sigma_sha256: String,
    issue_us: u128,
    obtain_us: u128,
    buoc_list: Vec<BuocCase>,
    tong_verify_us: u128,
}

/// Chuyen mang bytes sang chuoi hex.
fn hex32(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Bam SHA-256 du lieu va tra ve hex.
fn bam_hex(data: &[u8]) -> String {
    let d: [u8; 32] = Sha256::digest(data).into();
    hex::encode(d)
}

/// Tao credential mau va do thoi gian giai doan Issue/Obtain.
fn tao_credential_mau() -> (nibsr::Credential, u64, u128, u128) {
    let now = 1_800_000_000u64;
    let signer = SignerKeyPair::KeyGen();
    let receiver = ReceiverKeyPair::RKeyGen();
    let auth = Authorization::new(
        b"temporary authorization".to_vec(),
        "wallet:pay:small",
        "cases/context",
        now - 10,
        now + 10,
    );

    let t_issue = Instant::now();
    let psig = SpsEqNibsBackend::Issue(&signer, receiver.public(), random_nonce(), auth);
    let issue_us = t_issue.elapsed().as_micros();

    let t_obtain = Instant::now();
    let cred = SpsEqNibsBackend::Obtain(&receiver, psig).expect("obtain must succeed");
    let obtain_us = t_obtain.elapsed().as_micros();

    (cred, now, issue_us, obtain_us)
}

/// Chay mot lan VerifyR va dong goi ket qua buoc test.
fn do_verify(so: usize, mo_ta: &str, input: String, cred: &nibsr::Credential, rev_list: &RevocationList, verify_time: u64) -> BuocCase {
    let t = Instant::now();
    let output = VerifyR(cred, rev_list, verify_time);
    let thoi_gian_us = t.elapsed().as_micros();
    BuocCase {
        so,
        mo_ta: mo_ta.to_string(),
        input,
        output,
        thoi_gian_us,
    }
}

/// Chay tron bo cac case cho mot mode revocation.
fn chay_case_theo_mode(mode: &str) -> BaoCaoMode {
    let (cred, now, issue_us, obtain_us) = tao_credential_mau();
    let entry = RevocationEntry::from_credential(&cred);

    let mut rev_list = match mode {
        "set" => RevocationList::TaoSet(),
        "bloom" => RevocationList::TaoBloom(8192, 7),
        "merkle" => RevocationList::TaoMerkle(),
        other => panic!("mode khong ho tro: {other}"),
    };

    let mut buoc_list = Vec::new();

    buoc_list.push(do_verify(
        1,
        "Chua them vao RevList",
        format!(
            "action=none, verify_time={}, rev_digest={}",
            now,
            hex32(&rev_list.PublishDigest())
        ),
        &cred,
        &rev_list,
        now,
    ));

    rev_list.Add(entry.clone());
    buoc_list.push(do_verify(
        2,
        "Da them vao RevList (Add)",
        format!(
            "action=Add(id={}, tau={}), verify_time={}, rev_digest={}",
            hex::encode(&entry.id.0),
            hex32(&entry.tau),
            now,
            hex32(&rev_list.PublishDigest())
        ),
        &cred,
        &rev_list,
        now,
    ));

    rev_list.Remove(&entry);
    buoc_list.push(do_verify(
        3,
        "Da xoa khoi RevList (Remove)",
        format!(
            "action=Remove(id={}, tau={}), verify_time={}, rev_digest={}",
            hex::encode(&entry.id.0),
            hex32(&entry.tau),
            now,
            hex32(&rev_list.PublishDigest())
        ),
        &cred,
        &rev_list,
        now,
    ));

    let mut cred_sai_message = cred.clone();
    cred_sai_message.auth.message = b"tampered authorization".to_vec();
    buoc_list.push(do_verify(
        4,
        "Sua message credential",
        format!(
            "action=tamper_message, old_msg_sha256={}, new_msg_sha256={}",
            bam_hex(&cred.auth.message),
            bam_hex(&cred_sai_message.auth.message)
        ),
        &cred_sai_message,
        &rev_list,
        now,
    ));

    let mut cred_sai_tag = cred.clone();
    cred_sai_tag.tag[0] ^= 0x01;
    buoc_list.push(do_verify(
        5,
        "Sua tag credential",
        format!(
            "action=tamper_tag, old_tau={}, new_tau={}",
            hex32(&cred.tag),
            hex32(&cred_sai_tag.tag)
        ),
        &cred_sai_tag,
        &rev_list,
        now,
    ));

    buoc_list.push(do_verify(
        6,
        "Verify truoc not_before",
        format!("verify_time={} (< not_before={})", now - 100, cred.auth.not_before),
        &cred,
        &rev_list,
        now - 100,
    ));

    buoc_list.push(do_verify(
        7,
        "Verify sau not_after",
        format!("verify_time={} (> not_after={})", now + 100, cred.auth.not_after),
        &cred,
        &rev_list,
        now + 100,
    ));

    assert_eq!(buoc_list[0].output, VerifyDecision::Accept);
    assert_eq!(buoc_list[1].output, VerifyDecision::RejectRevoked);
    assert_eq!(buoc_list[2].output, VerifyDecision::Accept);
    assert!(matches!(buoc_list[3].output, VerifyDecision::RejectInvalid(_)));
    assert!(matches!(buoc_list[4].output, VerifyDecision::RejectInvalid(_)));
    assert_eq!(buoc_list[5].output, VerifyDecision::RejectOutsideValidityWindow);
    assert_eq!(buoc_list[6].output, VerifyDecision::RejectOutsideValidityWindow);

    let tong_verify_us = buoc_list.iter().map(|x| x.thoi_gian_us).sum();

    BaoCaoMode {
        mode: mode.to_string(),
        now,
        scope: cred.auth.scope.clone(),
        not_before: cred.auth.not_before,
        not_after: cred.auth.not_after,
        pk_r_hex: hex::encode(&cred.pk_r.0),
        tau_hex: hex32(&cred.tag),
        rev_digest_ban_dau_hex: hex32(&match mode {
            "set" => RevocationList::TaoSet().PublishDigest(),
            "bloom" => RevocationList::TaoBloom(8192, 7).PublishDigest(),
            "merkle" => RevocationList::TaoMerkle().PublishDigest(),
            _ => unreachable!(),
        }),
        message_sha256: bam_hex(&cred.auth.message),
        nibs_message_sha256: bam_hex(&cred.nibs_message),
        sigma_sha256: bam_hex(&cred.sigma),
        issue_us,
        obtain_us,
        buoc_list,
        tong_verify_us,
    }
}

/// Doi microseconds sang milliseconds.
fn us_to_ms2(us: u128) -> f64 {
    (us as f64) / 1000.0
}

/// Tao bieu do Mermaid tong thoi gian theo mode.
fn tao_mermaid_hieu_nang_tong_mode(ds: &[BaoCaoMode]) -> String {
    let mut tong_values_ms: Vec<f64> = Vec::new();
    for m in ["set", "bloom", "merkle"] {
        if let Some(r) = ds.iter().find(|x| x.mode == m) {
            tong_values_ms.push(us_to_ms2(r.issue_us + r.obtain_us + r.tong_verify_us));
        }
    }
    let max_val = tong_values_ms
        .iter()
        .copied()
        .fold(0.0_f64, |a, b| if a > b { a } else { b });
    let y_max = (max_val * 1.2).ceil();
    let mut lines = vec![
        "```mermaid".to_string(),
        "xychart-beta".to_string(),
        "    title \"Tong thoi gian theo mode (ms)\"".to_string(),
        "    x-axis [set, bloom, merkle]".to_string(),
        format!("    y-axis \"ms\" 0 --> {:.0}", y_max),
    ];

    let mut values = Vec::new();
    for m in ["set", "bloom", "merkle"] {
        if let Some(r) = ds.iter().find(|x| x.mode == m) {
            values.push(format!("{:.3}", us_to_ms2(r.issue_us + r.obtain_us + r.tong_verify_us)));
        }
    }
    lines.push(format!("    bar [{}]", values.join(", ")));
    lines.push("```".to_string());
    lines.join("\n")
}

/// Tao bieu do Mermaid thanh phan thoi gian theo mode.
fn tao_mermaid_hieu_nang_thanh_phan(ds: &[BaoCaoMode]) -> String {
    let max_us = ds
        .iter()
        .map(|r| r.issue_us.max(r.obtain_us).max(r.tong_verify_us))
        .max()
        .unwrap_or(1);
    let y_max = (us_to_ms2(max_us) * 1.2).ceil();
    let mut lines = vec![
        "```mermaid".to_string(),
        "xychart-beta".to_string(),
        "    title \"Thanh phan thoi gian theo mode (ms)\"".to_string(),
        "    x-axis [set, bloom, merkle]".to_string(),
        format!("    y-axis \"ms\" 0 --> {:.0}", y_max),
    ];

    let mut issue = Vec::new();
    let mut obtain = Vec::new();
    let mut verify = Vec::new();
    for m in ["set", "bloom", "merkle"] {
        if let Some(r) = ds.iter().find(|x| x.mode == m) {
            issue.push(format!("{:.3}", us_to_ms2(r.issue_us)));
            obtain.push(format!("{:.3}", us_to_ms2(r.obtain_us)));
            verify.push(format!("{:.3}", us_to_ms2(r.tong_verify_us)));
        }
    }
    lines.push(format!("    bar [{}]", issue.join(", ")));
    lines.push(format!("    bar [{}]", obtain.join(", ")));
    lines.push(format!("    bar [{}]", verify.join(", ")));
    lines.push("```".to_string());
    lines.join("\n")
}

/// Tao noi dung markdown cho bao cao ket qua thuc nghiem.
fn tao_noi_dung_md(ds: &[BaoCaoMode], tong_ms: u128) -> String {
    let mut out = String::new();
    out.push_str("# Kết Quả Thực Nghiệm NIBSR\n\n");
    out.push_str("Tài liệu này được tạo tự động bởi `cargo run --bin cases`. Mỗi lần chạy sẽ ghi đè toàn bộ nội dung.\n\n");
    out.push_str("## Mục tiêu\n\n");
    out.push_str("Đánh giá các trường hợp VerifyR theo bài báo: chưa thu hồi, thu hồi, bỏ thu hồi, sửa dữ liệu, và ngoài cửa sổ hiệu lực.\n\n");

    for mode in ds {
        out.push_str(&format!("## Mode: {}\n\n", mode.mode));
        out.push_str("### Dữ liệu đầu vào cơ sở\n\n");
        out.push_str(&format!("- `now`: {}\n", mode.now));
        out.push_str(&format!("- `scope`: `{}`\n", mode.scope));
        out.push_str(&format!("- `not_before`: {}\n", mode.not_before));
        out.push_str(&format!("- `not_after`: {}\n", mode.not_after));
        out.push_str(&format!("- `pk_r` (hex): `{}`\n", mode.pk_r_hex));
        out.push_str(&format!("- `tau` (hex): `{}`\n", mode.tau_hex));
        out.push_str(&format!("- `rev_digest_ban_dau` (hex): `{}`\n", mode.rev_digest_ban_dau_hex));
        out.push_str(&format!("- `message_sha256`: `{}`\n", mode.message_sha256));
        out.push_str(&format!("- `nibs_message_sha256`: `{}`\n", mode.nibs_message_sha256));
        out.push_str(&format!("- `sigma_sha256`: `{}`\n\n", mode.sigma_sha256));

        out.push_str("### Trình tự test Input -> Output\n\n");
        for b in &mode.buoc_list {
            out.push_str(&format!(
                "{}. `{}`\n- Input: `{}`\n- Output: `{:?}`\n- Thoi gian buoc: `{}` us\n\n",
                b.so, b.mo_ta, b.input, b.output, b.thoi_gian_us
            ));
        }

        out.push_str("### Hiệu năng theo giai đoạn\n\n");
        out.push_str("| Giai đoạn | Thời gian (us) |\n");
        out.push_str("|---|---:|\n");
        out.push_str(&format!("| Issue | {} |\n", mode.issue_us));
        out.push_str(&format!("| Obtain | {} |\n", mode.obtain_us));
        out.push_str(&format!("| Tong 7 lan VerifyR | {} |\n", mode.tong_verify_us));
        out.push_str(&format!("| Tổng mode | {} |\n\n", mode.issue_us + mode.obtain_us + mode.tong_verify_us));
    }

    out.push_str("## Tổng hợp số liệu hiệu năng\n\n");
    out.push_str("| Mode | Issue (us) | Obtain (us) | Tong VerifyR (us) | Tong mode (us) | Tong mode (ms) |\n");
    out.push_str("|---|---:|---:|---:|---:|---:|\n");
    for m in ["set", "bloom", "merkle"] {
        if let Some(r) = ds.iter().find(|x| x.mode == m) {
            let tong_mode = r.issue_us + r.obtain_us + r.tong_verify_us;
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {:.3} |\n",
                r.mode,
                r.issue_us,
                r.obtain_us,
                r.tong_verify_us,
                tong_mode,
                us_to_ms2(tong_mode)
            ));
        }
    }
    out.push('\n');

    out.push_str("## Biểu đồ hiệu năng tổng mode\n\n");
    out.push_str(&tao_mermaid_hieu_nang_tong_mode(ds));
    out.push_str("\n\n");
    out.push_str("Chú thích: trục X theo mode `[set, bloom, merkle]`, giá trị trên cột là **ms**.\n\n");

    out.push_str("## Biểu đồ thành phần hiệu năng\n\n");
    out.push_str(&tao_mermaid_hieu_nang_thanh_phan(ds));
    out.push_str("\n\n");
    out.push_str("Chú thích: cột 1 = Issue, cột 2 = Obtain, cột 3 = Tổng 7 lần VerifyR (đơn vị ms, theo cùng thứ tự mode).\n\n");

    out.push_str("## Biểu đồ cột có số liệu ở đầu cột\n\n");
    out.push_str("```text\n");
    out.push_str("Tổng thời gian theo mode (ms)\n\n");
    for m in ["set", "bloom", "merkle"] {
        if let Some(r) = ds.iter().find(|x| x.mode == m) {
            let tong_ms_mode = us_to_ms2(r.issue_us + r.obtain_us + r.tong_verify_us);
            let cot = (tong_ms_mode / 20.0).round() as usize;
            out.push_str(&format!("{:>8.3} ms\n", tong_ms_mode));
            out.push_str(&format!("{:>8} |{}\n\n", m, "█".repeat(cot.max(1))));
        }
    }
    out.push_str("```");
    out.push_str("\n\n");

    out.push_str("## Tổng thời gian chạy\n\n");
    out.push_str(&format!("- Tổng thời gian sinh báo cáo: **{} ms**\n", tong_ms));

    out
}

/// Diem vao chuong trinh: chay test cases va ghi de ketqua.md.
fn main() {
    let t_tong = Instant::now();
    let bao_cao = vec![
        chay_case_theo_mode("set"),
        chay_case_theo_mode("bloom"),
        chay_case_theo_mode("merkle"),
    ];

    let tong_ms = t_tong.elapsed().as_millis();
    let md = tao_noi_dung_md(&bao_cao, tong_ms);
    fs::write("ketqua.md", md).expect("khong the ghi file ketqua.md");

    println!("Da ghi ket qua vao file ketqua.md (ghi de moi lan chay).");
    println!("Tong thoi gian chay: {} ms", tong_ms);
}
