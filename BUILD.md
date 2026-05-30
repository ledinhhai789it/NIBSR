# Huong Dan Build Va Chay NIBSR

## Lenh build/chay
```bash
cd nibsr-rust
cargo run --bin nibsr-demo -- --mode set
cargo run --bin nibsr-demo -- --mode bloom
cargo run --bin nibsr-demo -- --mode merkle
cargo run --bin cases
cargo test
```

## Lenh chay du lieu test (chi tiet)
```bash
cd nibsr-rust

# Chay toan bo test
cargo test

# Chay 1 lenh tong hop tat ca truong hop va in ket qua theo thu tu tieng Viet
cargo run --bin cases

# Hien log khi chay test
cargo test -- --nocapture

# Chay file test flow NIBSR
cargo test --test nibsr_flow -- --nocapture

# Chay rieng case them/xoa trong set-bloom-merkle
cargo test bang_test_them_xoa_theo_tung_mode -- --nocapture
```

## Bo tham so chay thuat toan
- `mode`: `set` | `bloom` | `merkle`
- `now`: moc thoi gian Unix giay (demo dung thoi gian hien tai; test dung moc co dinh `1_800_000_000`)
- `auth.not_before`, `auth.not_after`: cua so hieu luc cua uy quyen tam thoi
- `RevocationEntry(id, tau, scope, not_before, not_after)`: phan tu thu hoi duoc tao tu credential

## Ten ham theo tai lieu (da bo sung trong code)
- `KeyGen` (Signer)
- `RKeyGen` (Receiver)
- `Issue`
- `Obtain`
- `VerifyR`
- `Add`
- `Remove`
- `PublishDigest`
- `Prune`

## Ket qua verify theo cac buoc
1. Chua them vao RevList: `VerifyDecision::Accept`
2. Them vao RevList: `VerifyDecision::RejectRevoked`
3. Xoa khoi RevList: `VerifyDecision::Accept`
4. Sua message/tag (du lieu bi can thiep): `VerifyDecision::RejectInvalid(...)`
5. Kiem tra ngoai cua so hieu luc: `VerifyDecision::RejectOutsideValidityWindow`

## Ghi chu mode Bloom
- Bloom filter co the co false positive trong ly thuyet.
- Trong test hien tai, moi case chi chen 1 entry roi xoa entry do, vi vay verify quay lai `Accept`.
