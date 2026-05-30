# NIBSR Rust: Non-Interactive Revocable Blind Signatures

> **Một prototype nghiên cứu bằng Rust cho NIBSR với backend SPS-EQ trên BLS12-381, hỗ trợ thu hồi bằng Set / Bloom filter / Merkle tree, kèm luồng thực nghiệm tái lập được.**

## Tóm tắt

Dự án này hiện thực hóa một phiên bản nghiên cứu của **Non-Interactive Revocable Blind Signatures (NIBSR)** theo hướng kỹ thuật hệ thống, tập trung vào:

- ký mù không tương tác,
- ràng buộc khả năng thu hồi theo `(pkR, tau)`,
- kiểm chứng hiệu lực theo cửa sổ thời gian,
- vận hành đa chế độ danh sách thu hồi (`Set`, `Bloom`, `Merkle`).

Phiên bản hiện tại dùng backend mật mã ghép cặp (**SPS-EQ NIBS trên BLS12-381**), thay cho backend mô phỏng trước đó.

## Đóng góp chính

1. **Hiện thực đầy đủ pipeline NIBSR**
- `KeyGen` / `RKeyGen`
- `Issue`
- `Obtain`
- `VerifyR`
- `Add` / `Remove` / `PublishDigest` / `Prune`

2. **Ràng buộc thu hồi an toàn hơn ở tầng triển khai**
- Tag thu hồi:
  - `tau = H("NIBSR/TAG" || pk || pkR || nonce || authorization || m || sigma)`
- Kèm **Chaum-Pedersen DLEQ proof** để ràng buộc `(pkR, nonce, authorization)` với thông điệp NIBS cuối, giảm nguy cơ tráo đổi ngữ cảnh kiểm chứng.

3. **Hỗ trợ nhiều mô hình Revocation List**
- `Set`: đơn giản, chính xác tuyệt đối.
- `Bloom`: tối ưu bộ nhớ/tốc độ, chấp nhận false positive lý thuyết.
- `Merkle`: có digest rõ ràng để công bố trạng thái danh sách.

4. **Khả năng tái lập thực nghiệm**
- Binary `cases` chạy toàn bộ tình huống kiểm thử trong một lần.
- Tự sinh file `ketqua.md` (ghi đè mỗi lần chạy) với:
  - input thật → output thật,
  - thời gian từng bước,
  - tổng thời gian,
  - biểu đồ hiệu năng.

## Kiến trúc hệ thống

### 1) Thành phần

- **Signer**: phát hành presignature trên đại diện thông điệp.
- **Receiver**: chuyển presignature thành credential hợp lệ với khóa riêng của mình.
- **Verifier**: chạy `VerifyR` để quyết định chấp nhận hay từ chối.
- **Revocation Manager**: duy trì danh sách thu hồi theo mode.

### 2) Dòng dữ liệu mức cao

1. Signer tạo khóa và phát hành `Presignature`.
2. Receiver chạy `Obtain` để tạo `Credential` hoàn chỉnh.
3. Verifier chạy `VerifyR`:
- xác thực mật mã cơ sở,
- kiểm tra cửa sổ hiệu lực,
- đối chiếu `RevocationList`.
4. Khi cần thu hồi, hệ thống thêm entry `(id=pkR, tau, scope, time-window)` vào danh sách.

## Cơ sở mật mã (tóm lược)

Backend dùng SPS-EQ NIBS theo dạng:

- `KeyGen`: `sk = (x1, x2)`, `pk = (g2^x1, g2^x2)`
- `RKeyGen`: `skR = x`, `pkR = g1^x`
- `Issue`: `psig = SignEQ(sk, (pkR, H(nonce || authorization)))`
- `Obtain`:
  - `m = H(nonce || authorization)^(1/skR)`
  - `sigma = ChgRepEQ(psig, 1/skR)`
- `Verify`: `VerifyEQ(pk, (g1, m), sigma)`

Biến thể revocable thêm bằng chứng DLEQ để neo ràng buộc giữa khóa người nhận và transcript ngữ cảnh.

## Quy tắc quyết định VerifyR

`VerifyR = Accept` khi và chỉ khi:

1. Credential hợp lệ ở tầng mật mã (`verify_base`),
2. thời gian kiểm chứng nằm trong `[not_before, not_after]`,
3. `(pkR, tau)` **không** thuộc danh sách thu hồi áp dụng.

Các nhánh từ chối chính:
- `RejectRevoked`
- `RejectInvalid(...)`
- `RejectOutsideValidityWindow`

## Cấu trúc mã nguồn

- `src/backend.rs`: backend SPS-EQ NIBS + DLEQ.
- `src/nibsr.rs`: logic `VerifyR` và decision.
- `src/revocation/`:
  - `set.rs`
  - `bloom.rs`
  - `merkle.rs`
  - `mod.rs` (dispatcher + API thống nhất)
- `src/types.rs`: kiểu dữ liệu giao thức.
- `src/bin/demo.rs`: demo ngắn theo mode.
- `src/bin/cases.rs`: thực nghiệm đầy đủ, sinh `ketqua.md`.
- `tests/nibsr_flow.rs`: test tích hợp theo các tình huống chính.

## API chính (đã đặt tên bám tài liệu)

- Khóa và phát hành:
  - `SignerKeyPair::KeyGen()`
  - `ReceiverKeyPair::RKeyGen()`
  - `SpsEqNibsBackend::Issue(...)`
  - `SpsEqNibsBackend::Obtain(...)`
- Kiểm chứng:
  - `VerifyR(...)`
- Thu hồi:
  - `RevocationList::Add(...)`
  - `RevocationList::Remove(...)`
  - `RevocationList::PublishDigest()`
  - `RevocationList::Prune(...)`

## Cách chạy

### 1) Demo nhanh

```bash
cd nibsr-rust
cargo run --bin nibsr-demo -- --mode set
cargo run --bin nibsr-demo -- --mode bloom
cargo run --bin nibsr-demo -- --mode merkle
```

### 2) Chạy toàn bộ kiểm thử

```bash
cd nibsr-rust
cargo test
```

### 3) Chạy thực nghiệm một lần cho tất cả trường hợp

```bash
cd nibsr-rust
cargo run --bin cases
```

Lệnh trên sẽ tạo/ghi đè file:

- `ketqua.md`

## Thực nghiệm và tái lập kết quả

Binary `cases` thực thi cùng một bộ tình huống trên cả 3 mode `set/bloom/merkle`:

1. Chưa thu hồi → kỳ vọng `Accept`
2. Add vào RevList → kỳ vọng `RejectRevoked`
3. Remove khỏi RevList → kỳ vọng `Accept`
4. Sửa message → kỳ vọng `RejectInvalid(...)`
5. Sửa tag → kỳ vọng `RejectInvalid(...)`
6. Verify trước `not_before` → kỳ vọng `RejectOutsideValidityWindow`
7. Verify sau `not_after` → kỳ vọng `RejectOutsideValidityWindow`

Trong `ketqua.md`, mỗi bước có:

- dữ liệu đầu vào thực tế,
- kết quả đầu ra thực tế,
- thời gian chạy của bước,
- tổng hợp hiệu năng theo giai đoạn,
- biểu đồ trực quan.

## Tính đúng đắn thực dụng

- `Set` và `Merkle`: tra cứu chính xác (không false positive).
- `Bloom`: có thể false positive theo bản chất cấu trúc, không false negative (khi vận hành đúng).
- `VerifyR` kiểm tra theo thứ tự bảo toàn an toàn: thời gian hiệu lực → xác thực mật mã → tra cứu thu hồi.

## Hạn chế hiện tại

- Đây là **prototype nghiên cứu**, chưa phải thư viện production.
- Chưa tích hợp đầy đủ pipeline benchmark dài hạn (nhiều kích thước tập dữ liệu, nhiều cấu hình phần cứng).
- Một số quyết định kỹ thuật phục vụ tính minh họa và khả năng đọc mã.

## Khuyến nghị cho production

1. Đánh giá bảo mật độc lập (crypto + implementation audit).
2. Chuẩn hóa profile tham số theo môi trường triển khai thực tế.
3. Tích hợp đo đạc hiệu năng có kiểm soát (nhiều lần chạy, median/p95/p99).
4. Ràng buộc versioning chặt cho định dạng dữ liệu và tag domain separation.

## Giấy phép

- MIT (xem `LICENSE-MIT`).

## Trích dẫn

Nếu bạn sử dụng project này cho báo cáo/học thuật, nên trích dẫn:

- Bài báo NIBSR gốc bạn đang tham chiếu.
- Kho mã này như một hiện thực prototype thực nghiệm.
