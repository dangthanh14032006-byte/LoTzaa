# SecureChat — Ứng dụng chat an toàn (C# / .NET 8)

Ứng dụng chat 1–1 mã hóa đầu-cuối, dùng mô hình **lai (hybrid)**:

| Thành phần | Thuật toán | Vai trò |
|---|---|---|
| Nội dung tin nhắn | **AES-256-GCM** | Mã hóa đối xứng nhanh, có xác thực (AEAD) |
| Trao khóa phiên | **ElGamal 2048-bit** (RFC 3526, nhóm 14) | Mã hóa khóa AES bằng khóa công khai người nhận |
| Trao khóa phiên (bổ sung) | **RSA-2048-OAEP-SHA256** | Mã hóa song song khóa AES bằng RSA, độc lập với ElGamal |
| Toàn vẹn tầng ứng dụng | **SHA-256** | Băm bản rõ, người nhận đối chiếu sau khi giải mã |
| Checksum tham khảo | **MD5** | Chỉ để so sánh hiệu năng / phát hiện lỗi nhanh — **không** dùng để xác thực |
| Xác thực & chống chối bỏ | **Chữ ký số ElGamal** | Người gửi ký SHA-256 của toàn bộ gói tin |
| Mật khẩu tài khoản | **PBKDF2-HMAC-SHA256** (200.000 vòng) | Băm mật khẩu phía server, không lưu bản rõ |

Kiến trúc **client-server qua TCP**: server chỉ định tuyến (relay) và lưu trữ các gói tin **đã mã hóa** — không có khả năng đọc nội dung (mã hóa đầu-cuối thật sự). Khóa riêng ElGamal và RSA không bao giờ rời máy client; được lưu trên đĩa dưới dạng mã hóa bằng mật khẩu người dùng.

## Giới thiệu về mã hóa RSA

**RSA** (Rivest–Shamir–Adleman, 1977) là thuật toán mã hóa bất đối xứng (khóa công khai) dựa trên độ khó của bài toán **phân tích thừa số nguyên tố** của một số nguyên rất lớn. Đây là một trong những thuật toán khóa công khai được sử dụng rộng rãi nhất thế giới (TLS/HTTPS, SSH, chữ ký số, PGP...).

**Nguyên lý hoạt động:**
1. **Sinh khóa**: chọn hai số nguyên tố lớn ngẫu nhiên `p`, `q` (mỗi số ~1024-bit để có khóa 2048-bit), tính `n = p·q` và hàm Euler `φ(n) = (p-1)(q-1)`. Chọn số mũ công khai `e` (thường là 65537) rồi tính số mũ bí mật `d` sao cho `e·d ≡ 1 (mod φ(n))`.
   - Khóa công khai: `(n, e)` — chia sẻ tự do.
   - Khóa riêng: `(n, d)` — giữ bí mật tuyệt đối.
2. **Mã hóa**: `c = m^e mod n`.
3. **Giải mã**: `m = c^d mod n`.
4. An toàn của RSA dựa trên việc: biết `n` nhưng không biết `p`, `q` thì gần như không thể suy ra `d` từ `e` trong thời gian khả thi với khóa đủ lớn (2048-bit trở lên).

**Cách dự án này dùng RSA** (`Core/Crypto/RsaCipher.cs`):
- Kích thước khóa: **2048-bit** (`RsaCipher.KeySizeBits`), sinh bằng `RSA.Create(2048)` của .NET, xuất/nhập dạng chuẩn `SubjectPublicKeyInfo` (khóa công khai) và `PKCS#8` (khóa riêng).
- Đệm (padding): **OAEP với SHA-256** (`RSAEncryptionPadding.OaepSHA256`) — chống các kiểu tấn công vào RSA "trần" (textbook RSA), đảm bảo mã hóa xác suất (cùng bản rõ mã hai lần cho ra hai bản mã khác nhau).
- RSA **không** dùng để mã hóa trực tiếp nội dung tin nhắn (RSA-2048/OAEP-SHA256 chỉ mã hóa được tối đa ~190 byte mỗi lần, quá nhỏ và quá chậm cho dữ liệu lớn). Thay vào đó, RSA chỉ dùng để **bọc khóa phiên AES-256 (32 byte)** — đúng mô hình mã hóa lai (hybrid) chuẩn.
- Trong `HybridEncryption`, khóa AES phiên được bọc **song song bằng cả ElGamal lẫn RSA** (`WrappedSessionKey` và `WrappedSessionKeyRsa`), người nhận có thể mở khóa bằng một trong hai cơ chế tùy khóa riêng nào có sẵn — vừa minh họa cả hai kiểu mã hóa bất đối xứng, vừa cho phép so sánh trực tiếp hiệu năng/kích thước giữa ElGamal và RSA trên cùng một gói tin.
- Khóa riêng RSA được lưu trên đĩa **ở dạng đã mã hóa** bằng khóa dẫn xuất từ mật khẩu người dùng (PBKDF2 + AES-GCM), giống hệt cách bảo vệ khóa riêng ElGamal.

**So sánh nhanh RSA vs. ElGamal trong dự án:**

| | RSA-2048-OAEP | ElGamal 2048-bit (nhóm RFC 3526) |
|---|---|---|
| Bài toán khó nền tảng | Phân tích thừa số nguyên tố | Logarit rời rạc (Discrete Log) |
| Kích thước bản mã (bọc khóa AES 32B) | ~256 byte | ~512 byte (hai thành phần `c1`, `c2`) |
| Tốc độ mã hóa/giải mã | Nhanh hơn (số mũ công khai `e` nhỏ) | Chậm hơn một chút (luôn cần lũy thừa modulo với số mũ ngẫu nhiên `k`) |
| Vai trò trong dự án | Mã hóa (bọc) khóa phiên | Mã hóa (bọc) khóa phiên **+** ký số |
| Mức an toàn ước tính | ~112-bit | ~110-bit |

## Cấu trúc dự án

```
SecureChat/
├── SecureChat.sln
├── Core/                          # thư viện dùng chung
│   ├── Crypto/
│   │   ├── BigIntUtil.cs          # tiện ích số lớn (random, modinv, base64)
│   │   ├── HashUtil.cs            # SHA-256, MD5, HMAC, PBKDF2, vân tay khóa
│   │   ├── AesGcmCipher.cs        # AES-256-GCM
│   │   ├── ElGamal.cs             # mã hóa bất đối xứng ElGamal (2048-bit)
│   │   ├── ElGamalSigner.cs       # chữ ký số ElGamal
│   │   ├── RsaCipher.cs           # mã hóa bất đối xứng RSA-2048-OAEP-SHA256 (bọc khóa phiên)
│   │   ├── HybridEncryption.cs    # điều phối AES+ElGamal+RSA+SHA-256/MD5+chữ ký, đo hiệu năng
│   │   └── KeyStore.cs            # lưu/nạp khóa riêng (mã hóa bằng mật khẩu)
│   └── Protocol/
│       ├── WireModels.cs          # các DTO JSON trao đổi qua mạng
│       └── WireCodec.cs           # đóng gói/mở gói JSON theo dòng trên TCP
├── Server/
│   ├── UserStore.cs               # tài khoản (username, PBKDF2 hash, khóa công khai)
│   ├── ChatHistoryStore.cs        # lưu lịch sử (chỉ dữ liệu đã mã hóa)
│   ├── ChatServer.cs              # vòng lặp TCP, định tuyến gói tin
│   └── Program.cs
└── Client/
    ├── ChatClient.cs              # kết nối, đăng ký/đăng nhập, mã hóa/giải mã, gửi/nhận
    └── Program.cs                 # giao diện console
```

## Build & chạy

Yêu cầu: [.NET 8 SDK](https://dotnet.microsoft.com/download).

```bash
cd SecureChat
dotnet build

# Terminal 1: chạy server (mặc định cổng 5050)
dotnet run --project Server

# Terminal 2, 3, ...: chạy client (mỗi người dùng một terminal)
dotnet run --project Client
```

Trong client: chọn **1) Đăng ký** (lần đầu, sẽ sinh cặp khóa ElGamal **và** RSA cục bộ) hoặc **2) Đăng nhập**, sau đó dùng các lệnh:

```
/users              liệt kê người dùng (online/offline)
/msg <user> <nd>     gửi tin nhắn đã mã hóa
/history <user>      tải & giải mã lịch sử hội thoại
/benchmark           đo thời gian mã hóa/giải mã & kích thước dữ liệu, nhiều cỡ tin nhắn
/quit
```

## Đối chiếu với 11 yêu cầu tối thiểu

1. **Đăng ký/đăng nhập** — `Server/UserStore.cs` (PBKDF2-SHA256, salt riêng mỗi tài khoản) + `Client/ChatClient.cs` (`RegisterAsync`/`LoginAsync`).
2. **Danh sách người dùng** — `PacketType.ListUsersRequest/Response`, lệnh `/users` (kèm trạng thái online/offline).
3. **Chat 1–1** — mỗi gói `EncryptedEnvelope` có `SenderId`/`ReceiverId` xác định, server định tuyến theo cặp.
4. **Gửi/nhận thời gian thực** — TCP giữ kết nối liên tục; server chuyển tiếp (`ChatIncoming`) ngay khi người nhận đang online; vòng lặp đọc nền (`ReadLoopAsync`) hiển thị tin đến ngay lập tức.
5. **Lưu lịch sử tin nhắn** — `Server/ChatHistoryStore.cs` lưu từng cặp hội thoại thành file JSON (chỉ chứa dữ liệu **đã mã hóa**); `/history <user>` tải và giải mã lại phía client.
6. **Mã hóa tin nhắn** — `HybridEncryption.Encrypt`: AES-256-GCM cho nội dung + khóa phiên được bọc song song bằng ElGamal **và** RSA-OAEP-SHA256.
7. **Giải mã ở phía người nhận** — `HybridEncryption.Decrypt`: mở khóa phiên bằng ElGamal hoặc RSA (khóa riêng người nhận), giải mã AES-GCM, đối chiếu SHA-256/MD5, xác minh chữ ký.
8. **Quản lý khóa** — `Core/Crypto/KeyStore.cs`: sinh, lưu (mã hóa bằng mật khẩu qua PBKDF2 + AES-GCM), nạp lại khóa riêng ElGamal **và** RSA; server chỉ giữ khóa công khai từng người dùng.
9. **Đánh giá thời gian mã hóa/giải mã** — `CryptoMetrics.EncryptMs/DecryptMs` đính kèm mỗi lần gửi/nhận; lệnh `/benchmark` đo trên nhiều cỡ dữ liệu (16 B → 64 KB), có thể so sánh chi phí ElGamal và RSA.
10. **Đánh giá kích thước dữ liệu sau mã hóa** — `CryptoMetrics.CiphertextBytes`/`Overhead`; `/benchmark` in bảng hệ số phình theo từng cỡ tin nhắn.
11. **Đánh giá mức độ an toàn & khả năng triển khai** — xem phần dưới.

## Đánh giá mức độ an toàn và khả năng triển khai

### Điểm mạnh
- **Mã hóa đầu-cuối thật sự**: server không bao giờ thấy khóa riêng hay bản rõ; chỉ relay và lưu dữ liệu đã mã hóa.
- **AES-256-GCM** là AEAD đã được kiểm chứng rộng rãi (NIST, TLS 1.3), vừa mã hóa vừa xác thực nội dung trong một bước — chống sửa đổi bản mã hiệu quả hơn mã hóa CBC thuần.
- **ElGamal 2048-bit** trên nhóm an toàn RFC 3526 (p nguyên tố an toàn, xác minh bằng kiểm tra Miller-Rabin) cho mức an toàn ước tính ~110 bit — tương đương RSA-2048, đủ dùng cho ứng dụng học tập/demo nhưng nên nâng lên 3072-bit (nhóm 15, ~128-bit an toàn) cho triển khai thực tế dài hạn.
- **RSA-2048-OAEP-SHA256** dùng đệm OAEP (không phải PKCS#1 v1.5) nên chống được các tấn công padding-oracle cổ điển (kiểu Bleichenbacher); mức an toàn ước tính ~112-bit, tương đương ElGamal 2048-bit trong dự án này — việc bọc khóa phiên bằng cả hai thuật toán giúp minh họa trực quan sự tương đồng/khác biệt giữa hai bài toán khó nền tảng (phân tích thừa số vs. logarit rời rạc).
- **Chữ ký số ElGamal** cung cấp xác thực nguồn gốc & chống chối bỏ độc lập với toàn vẹn AEAD — hai lớp bảo vệ khác mục đích (AEAD chống sửa đổi trên đường truyền; chữ ký chứng minh ai đã tạo ra gói tin).
- **Mật khẩu không lưu bản rõ**: PBKDF2-HMAC-SHA256 200.000 vòng + salt ngẫu nhiên 128-bit/tài khoản, chống tấn công dò từ điển/rainbow table.
- **Khóa riêng được bảo vệ tại chỗ**: cả khóa riêng ElGamal lẫn RSA đều được mã hóa bằng khóa dẫn xuất từ mật khẩu (PBKDF2) trước khi ghi đĩa; mất file khóa mà không có mật khẩu thì vô giá trị với kẻ tấn công.

### Hạn chế đã biết (và hướng khắc phục nếu triển khai thật)
- **MD5 chỉ mang tính tham khảo**: đã bị phá vỡ về khả năng chống va chạm từ lâu, tuyệt đối không dùng để xác thực bảo mật — hệ thống này chỉ dùng MD5 song song với SHA-256 để minh họa/so sánh hiệu năng theo yêu cầu đề bài, quyết định tin cậy luôn dựa trên SHA-256 + chữ ký số.
- **Bọc khóa song song bằng hai thuật toán (ElGamal + RSA) làm tăng kích thước gói tin**: mỗi tin nhắn giờ cõng thêm cả `WrappedSessionKeyRsa` bên cạnh `WrappedSessionKey` (ElGamal) — tốt cho mục đích so sánh/demo nhưng dư thừa cho triển khai thật; nên chọn **một** cơ chế bọc khóa duy nhất (RSA hoặc ElGamal) khi đưa vào sản phẩm.
- **Chưa có Forward Secrecy**: khóa ElGamal/RSA của mỗi người dùng là cố định lâu dài; nếu bị lộ, có thể giải mã được cả các tin nhắn cũ đã lưu (nếu kẻ tấn công có bản ghi). Triển khai thật nên dùng giao thức có trao khóa tạm thời mỗi phiên (ví dụ Diffie-Hellman tạm thời, theo mô hình Signal/X3DH) thay vì mã hóa khóa AES trực tiếp bằng khóa tĩnh.
- **Không xác thực khóa công khai (không có PKI/CA)**: client tin tưởng khóa công khai (ElGamal lẫn RSA) do server cung cấp khi tra cứu — dễ bị tấn công người đứng giữa (MITM) nếu server bị xâm nhập hoặc giả mạo. Cần bổ sung xác minh vân tay khóa (`HashUtil.FingerprintSha256`) qua kênh riêng, hoặc hạ tầng khóa công khai (PKI).
- **Không mã hóa kênh vận chuyển (TLS)**: giao thức hiện dùng TCP thuần; dù nội dung tin nhắn đã mã hóa đầu-cuối, siêu dữ liệu (ai nhắn cho ai, khi nào) vẫn lộ trên đường truyền và khi đăng nhập, gói `LoginRequest` gửi mật khẩu dạng rõ tới server. **Bắt buộc** bọc thêm TLS (SslStream) trước khi triển khai ngoài môi trường tin cậy cục bộ.
- **Sinh số ngẫu nhiên cho ElGamal (k)**: dùng `RandomNumberGenerator` (CSPRNG hệ điều hành) — an toàn, nhưng khác với DSA/ECDSA, ElGamal cổ điển nhạy với việc tái sử dụng k giữa hai chữ ký (lộ khóa riêng); code đã đảm bảo k mới hoàn toàn ngẫu nhiên mỗi lần ký, không tái sử dụng. RSA/OAEP không có vấn đề tương tự vì phần ngẫu nhiên nằm trong đệm OAEP, được .NET xử lý nội bộ theo chuẩn.
- **Không có giới hạn tốc độ / khóa tài khoản**: server hiện chưa chống brute-force đăng nhập (rate limiting, khóa tạm sau nhiều lần sai) — cần bổ sung trước khi triển khai công khai.
- **Không nén dữ liệu**: hệ số phình khá lớn với tin nhắn ngắn (chi phí cố định mỗi gói do bọc khóa hai lần — ElGamal 2×256 byte + RSA 256 byte + chữ ký 512 byte), phù hợp cho chat văn bản nhưng kém hiệu quả nếu dùng cho dữ liệu lớn/streaming — nên chuyển sang trao khóa một lần theo phiên đăng nhập (không ký/bọc khóa lại cho mỗi tin nhắn).

### Khả năng triển khai
Phù hợp làm **đồ án minh họa** đầy đủ vòng đời mã hóa đầu-cuối (sinh khóa → trao khóa bằng cả ElGamal lẫn RSA → mã hóa → truyền → xác thực → giải mã) và đo lường hiệu năng/kích thước theo yêu cầu, đồng thời cho phép so sánh trực tiếp hai thuật toán bất đối xứng phổ biến nhất. Để triển khai sản phẩm thực tế cần bổ sung tối thiểu: chọn một cơ chế bọc khóa duy nhất, TLS cho kênh vận chuyển, Forward Secrecy (trao khóa theo phiên), xác minh khóa công khai (vân tay/PKI), và cơ chế chống brute-force ở server.
